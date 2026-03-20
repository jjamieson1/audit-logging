package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFollowerReadsAndCheckpoints(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	sourcePath := filepath.Join(tmp, "app.log")
	checkpointPath := filepath.Join(tmp, "checkpoint.json")

	if err := os.WriteFile(sourcePath, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	cfg := Config{
		SourceFile:       sourcePath,
		CheckpointPath:   checkpointPath,
		PollIntervalMS:   20,
		ServerURL:        "http://localhost:3001/v1/logs",
		AuthBearerToken:  "token",
		AppName:          "app",
		TimestampField:   "timestamp",
		ParserMode:       "custom",
		BatchSize:        1,
		FlushIntervalMS:  1000,
		RetryMaxAttempts: 1,
	}

	follower := NewFollower(cfg, log.New(ioDiscard{}, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	lines := make([]string, 0, 4)

	errCh := make(chan error, 1)
	go func() {
		errCh <- follower.Run(ctx, func(event TailEvent) error {
			mu.Lock()
			lines = append(lines, event.Line)
			mu.Unlock()
			return nil
		})
	}()

	waitForLines(t, &mu, &lines, 2, 2*time.Second)

	file, err := os.OpenFile(sourcePath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open source file for append: %v", err)
	}
	if _, err := file.WriteString("c\n"); err != nil {
		file.Close()
		t.Fatalf("append source file: %v", err)
	}
	file.Close()

	waitForLines(t, &mu, &lines, 3, 2*time.Second)

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("follower.Run() error = %v", err)
	}

	cp, err := LoadCheckpoint(checkpointPath)
	if err != nil {
		t.Fatalf("LoadCheckpoint() error = %v", err)
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		t.Fatalf("stat source file: %v", err)
	}
	if cp.Offset != info.Size() {
		t.Fatalf("checkpoint offset mismatch: got %d want %d", cp.Offset, info.Size())
	}
}

func TestFollowerHandlesRenameRotation(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	sourcePath := filepath.Join(tmp, "app.log")
	rotatedPath := filepath.Join(tmp, "app.log.1")
	checkpointPath := filepath.Join(tmp, "checkpoint.json")

	if err := os.WriteFile(sourcePath, []byte("one\n"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	cfg := Config{
		SourceFile:       sourcePath,
		CheckpointPath:   checkpointPath,
		PollIntervalMS:   20,
		ServerURL:        "http://localhost:3001/v1/logs",
		AuthBearerToken:  "token",
		AppName:          "app",
		TimestampField:   "timestamp",
		ParserMode:       "custom",
		BatchSize:        1,
		FlushIntervalMS:  1000,
		RetryMaxAttempts: 1,
	}

	follower := NewFollower(cfg, log.New(ioDiscard{}, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	lines := make([]string, 0, 4)

	errCh := make(chan error, 1)
	go func() {
		errCh <- follower.Run(ctx, func(event TailEvent) error {
			mu.Lock()
			lines = append(lines, event.Line)
			mu.Unlock()
			return nil
		})
	}()

	waitForLines(t, &mu, &lines, 1, 2*time.Second)

	if err := os.Rename(sourcePath, rotatedPath); err != nil {
		t.Fatalf("rotate source file: %v", err)
	}
	if err := os.WriteFile(sourcePath, []byte("two\n"), 0o644); err != nil {
		t.Fatalf("create new source file: %v", err)
	}

	waitForLineValue(t, &mu, &lines, "two", 2*time.Second)

	cancel()
	if err := <-errCh; err != nil {
		t.Fatalf("follower.Run() error = %v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

func waitForLines(t *testing.T, mu *sync.Mutex, lines *[]string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(*lines)
		mu.Unlock()
		if count >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("timed out waiting for %d lines; got %v", want, *lines)
}

func waitForLineValue(t *testing.T, mu *sync.Mutex, lines *[]string, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, line := range *lines {
			if line == want {
				mu.Unlock()
				return
			}
		}
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("timed out waiting for line %q; got %v", want, *lines)
}
