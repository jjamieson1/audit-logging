package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

type FileIdentity struct {
	Dev   uint64
	Inode uint64
}

func (id FileIdentity) Equal(other FileIdentity) bool {
	return id.Dev == other.Dev && id.Inode == other.Inode
}

type TailEvent struct {
	Line            string
	SourceFile      string
	CommittedOffset int64
	ReadAt          time.Time
}

type Follower struct {
	cfg    Config
	logger *log.Logger

	file     *os.File
	identity FileIdentity

	readOffset      int64
	committedOffset int64
	pending         []byte
}

func NewFollower(cfg Config, logger *log.Logger) *Follower {
	if logger == nil {
		logger = log.Default()
	}
	return &Follower{cfg: cfg, logger: logger}
}

func (f *Follower) Run(ctx context.Context, onLine func(TailEvent) error) error {
	if err := f.openFromCheckpoint(); err != nil {
		return err
	}
	defer f.closeCurrentFile()

	poll := time.NewTicker(time.Duration(f.cfg.PollIntervalMS) * time.Millisecond)
	defer poll.Stop()

	for {
		if err := f.readAvailable(onLine); err != nil {
			return err
		}
		if err := f.handleFileChanges(onLine); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-poll.C:
		}
	}
}

func (f *Follower) openFromCheckpoint() error {
	cp, err := LoadCheckpoint(f.cfg.CheckpointPath)
	if err != nil {
		return err
	}

	file, identity, size, err := openFileWithIdentity(f.cfg.SourceFile)
	if err != nil {
		return err
	}

	startOffset := int64(0)
	if cp.FilePath == f.cfg.SourceFile && cp.Offset >= 0 && cp.Offset <= size {
		if cp.Dev == identity.Dev && cp.Inode == identity.Inode {
			startOffset = cp.Offset
		}
	}

	if _, err := file.Seek(startOffset, io.SeekStart); err != nil {
		_ = file.Close()
		return fmt.Errorf("seek source file: %w", err)
	}

	f.file = file
	f.identity = identity
	f.readOffset = startOffset
	f.committedOffset = startOffset
	f.pending = nil

	f.logger.Printf("event=follower_open source_file=%q offset=%d inode=%d dev=%d", f.cfg.SourceFile, startOffset, identity.Inode, identity.Dev)
	return nil
}

func (f *Follower) readAvailable(onLine func(TailEvent) error) error {
	if f.file == nil {
		return errors.New("follower has no open file")
	}

	buffer := make([]byte, 64*1024)
	for {
		n, err := f.file.Read(buffer)
		if n > 0 {
			f.readOffset += int64(n)
			f.pending = append(f.pending, buffer[:n]...)

			for {
				idx := bytes.IndexByte(f.pending, '\n')
				if idx < 0 {
					break
				}

				line := string(f.pending[:idx])
				line = strings.TrimSuffix(line, "\r")
				f.pending = f.pending[idx+1:]
				f.committedOffset += int64(idx + 1)

				event := TailEvent{
					Line:            line,
					SourceFile:      f.cfg.SourceFile,
					CommittedOffset: f.committedOffset,
					ReadAt:          time.Now().UTC(),
				}
				if onLine != nil {
					if err := onLine(event); err != nil {
						return err
					}
				}
				if err := SaveCheckpoint(f.cfg.CheckpointPath, Checkpoint{
					FilePath: f.cfg.SourceFile,
					Offset:   f.committedOffset,
					Dev:      f.identity.Dev,
					Inode:    f.identity.Inode,
				}); err != nil {
					return err
				}
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read source file: %w", err)
		}
	}
}

func (f *Follower) handleFileChanges(onLine func(TailEvent) error) error {
	_, currentIdentity, size, err := statFileWithIdentity(f.cfg.SourceFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if currentIdentity.Equal(f.identity) {
		if size < f.readOffset {
			f.logger.Printf("event=file_truncated source_file=%q old_offset=%d new_size=%d", f.cfg.SourceFile, f.readOffset, size)
			if _, err := f.file.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("seek truncated file: %w", err)
			}
			f.readOffset = 0
			f.committedOffset = 0
			f.pending = nil
			if err := SaveCheckpoint(f.cfg.CheckpointPath, Checkpoint{
				FilePath: f.cfg.SourceFile,
				Offset:   0,
				Dev:      f.identity.Dev,
				Inode:    f.identity.Inode,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	f.logger.Printf("event=file_rotated source_file=%q old_inode=%d new_inode=%d", f.cfg.SourceFile, f.identity.Inode, currentIdentity.Inode)

	if err := f.readAvailable(onLine); err != nil {
		return err
	}

	f.closeCurrentFile()
	file, identity, _, err := openFileWithIdentity(f.cfg.SourceFile)
	if err != nil {
		return err
	}
	f.file = file
	f.identity = identity
	f.readOffset = 0
	f.committedOffset = 0
	f.pending = nil

	if err := SaveCheckpoint(f.cfg.CheckpointPath, Checkpoint{
		FilePath: f.cfg.SourceFile,
		Offset:   0,
		Dev:      f.identity.Dev,
		Inode:    f.identity.Inode,
	}); err != nil {
		return err
	}

	return nil
}

func (f *Follower) closeCurrentFile() {
	if f.file != nil {
		_ = f.file.Close()
		f.file = nil
	}
}

func openFileWithIdentity(path string) (*os.File, FileIdentity, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, FileIdentity{}, 0, fmt.Errorf("open source file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, 0, fmt.Errorf("stat source file: %w", err)
	}
	identity, err := fileIdentityFromInfo(info)
	if err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, 0, err
	}

	return file, identity, info.Size(), nil
}

func statFileWithIdentity(path string) (os.FileInfo, FileIdentity, int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, FileIdentity{}, 0, fmt.Errorf("stat source file: %w", err)
	}
	identity, err := fileIdentityFromInfo(info)
	if err != nil {
		return nil, FileIdentity{}, 0, err
	}
	return info, identity, info.Size(), nil
}

func fileIdentityFromInfo(info os.FileInfo) (FileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return FileIdentity{}, errors.New("file identity unavailable")
	}
	return FileIdentity{Dev: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}
