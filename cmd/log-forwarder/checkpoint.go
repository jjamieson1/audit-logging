package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Checkpoint struct {
	FilePath  string `json:"file_path"`
	Offset    int64  `json:"offset"`
	Dev       uint64 `json:"dev"`
	Inode     uint64 `json:"inode"`
	UpdatedAt string `json:"updated_at"`
}

func LoadCheckpoint(path string) (Checkpoint, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Checkpoint{}, nil
		}
		return Checkpoint{}, fmt.Errorf("open checkpoint: %w", err)
	}
	defer file.Close()

	var cp Checkpoint
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cp); err != nil {
		return Checkpoint{}, fmt.Errorf("decode checkpoint: %w", err)
	}

	if cp.Offset < 0 {
		cp.Offset = 0
	}

	return cp, nil
}

func SaveCheckpoint(path string, cp Checkpoint) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir checkpoint dir: %w", err)
	}

	cp.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	bytes, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	tmpPath := path + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open checkpoint temp file: %w", err)
	}

	if _, err := tmpFile.Write(append(bytes, '\n')); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write checkpoint temp file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil && !isIgnorableSyncErr(err) {
		_ = tmpFile.Close()
		return fmt.Errorf("sync checkpoint temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close checkpoint temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace checkpoint: %w", err)
	}

	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync checkpoint directory: %w", err)
	}

	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	if _, err := dir.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil && !isIgnorableSyncErr(err) {
		return err
	}

	return nil
}

func isIgnorableSyncErr(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP)
}
