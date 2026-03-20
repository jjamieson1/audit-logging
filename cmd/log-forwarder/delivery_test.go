package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComputeIdempotencyKeyDeterministic(t *testing.T) {
	t.Parallel()

	a := ComputeIdempotencyKey("app", "/tmp/app.log", 42, "line")
	b := ComputeIdempotencyKey("app", "/tmp/app.log", 42, "line")
	if a != b {
		t.Fatalf("expected deterministic key, got %q vs %q", a, b)
	}

	c := ComputeIdempotencyKey("app", "/tmp/app.log", 43, "line")
	if a == c {
		t.Fatalf("expected different key when offset changes")
	}
}

func TestWriteDeadLetter(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "deadletter.jsonl")

	payload := BuildPayload(NormalizedEvent{
		App:          "payments-api",
		Level:        "ERROR",
		Message:      "failed",
		ParserMode:   "plain",
		SourceFile:   "/tmp/app.log",
		SourceOffset: 12,
		RawLine:      "failed",
	}, "idem-1")

	if err := WriteDeadLetter(path, payload, "/tmp/app.log", 12, errSynthetic("send failed")); err != nil {
		t.Fatalf("WriteDeadLetter() error = %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read deadletter file: %v", err)
	}

	var entry DeadLetterEntry
	if err := json.Unmarshal(content[:len(content)-1], &entry); err != nil {
		t.Fatalf("decode deadletter entry: %v", err)
	}
	if entry.Error == "" || entry.Payload.App != "payments-api" {
		t.Fatalf("deadletter entry missing expected values: %+v", entry)
	}
}

type errSynthetic string

func (e errSynthetic) Error() string {
	return string(e)
}
