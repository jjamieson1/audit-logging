package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadCheckpointRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state", "checkpoint.json")
	input := Checkpoint{
		FilePath: "/tmp/app.log",
		Offset:   128,
		Dev:      7,
		Inode:    99,
	}

	if err := SaveCheckpoint(path, input); err != nil {
		t.Fatalf("SaveCheckpoint() error = %v", err)
	}

	loaded, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("LoadCheckpoint() error = %v", err)
	}

	if loaded.FilePath != input.FilePath || loaded.Offset != input.Offset || loaded.Dev != input.Dev || loaded.Inode != input.Inode {
		t.Fatalf("loaded checkpoint mismatch: got %+v want %+v", loaded, input)
	}
	if loaded.UpdatedAt == "" {
		t.Fatalf("expected UpdatedAt to be set")
	}
}

func TestLoadCheckpointNegativeOffsetClamped(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "checkpoint.json")
	content := []byte(`{"file_path":"/tmp/app.log","offset":-9,"dev":1,"inode":2}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	loaded, err := LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("LoadCheckpoint() error = %v", err)
	}
	if loaded.Offset != 0 {
		t.Fatalf("expected negative offset to clamp to 0, got %d", loaded.Offset)
	}
}

func TestLoadCheckpointInvalidJSON(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "checkpoint.json")
	if err := os.WriteFile(path, []byte(`{"offset":`), 0o644); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}

	if _, err := LoadCheckpoint(path); err == nil {
		t.Fatalf("expected decode error for invalid checkpoint JSON")
	}
}
