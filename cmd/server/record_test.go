package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A record exactly as the service wrote it before client attribution existed.
const legacyRecordJSON = `{"app":"payments-api","level":"INFO","message":"invoice created","metadata":{"invoiceId":"inv_123"}}`

func TestLegacyRecordRoundTripsToIdenticalBytes(t *testing.T) {
	// FileStore.verifyChainUnsafe re-marshals the parsed struct, so Go field
	// order and omitempty decide whether an old entry still hashes the same.
	var record LogRecord
	if err := json.Unmarshal([]byte(legacyRecordJSON), &record); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if record.ClientID != "" {
		t.Fatalf("ClientID = %q, want empty for a legacy record", record.ClientID)
	}

	remarshalled, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	if string(remarshalled) != legacyRecordJSON {
		t.Fatalf("round trip changed the bytes.\n got: %s\nwant: %s", remarshalled, legacyRecordJSON)
	}

	if sha256Hex(remarshalled) != sha256Hex([]byte(legacyRecordJSON)) {
		t.Fatal("payload hash changed for a legacy record")
	}
}

func TestLegacyChainStillVerifies(t *testing.T) {
	// Build a one-entry log the way the pre-attribution server would have,
	// hashing the raw legacy bytes, then open it with the current code.
	const timestamp = "2026-01-01T00:00:00Z"
	const prevHash = "GENESIS"

	payloadHash := sha256Hex([]byte(legacyRecordJSON))
	entryHash := sha256Hex([]byte(fmt.Sprintf("%d|%s|%s|%s", 1, timestamp, payloadHash, prevHash)))

	line := fmt.Sprintf(
		`{"index":1,"timestamp":%q,"prevHash":%q,"payloadHash":%q,"entryHash":%q,"record":%s}`+"\n",
		timestamp, prevHash, payloadHash, entryHash, legacyRecordJSON,
	)

	path := filepath.Join(t.TempDir(), "audit.log.jsonl")
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	// NewFileStore refuses to open an invalid chain, so this is itself a check.
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore() rejected a valid legacy chain: %v", err)
	}

	result, err := store.Verify()
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("legacy chain reported invalid at %v: %v", result.InvalidAt, result.Reason)
	}
	if result.TotalEntries != 1 {
		t.Fatalf("TotalEntries = %d, want 1", result.TotalEntries)
	}
}

func TestAttributedRecordIncludesClientIDInThePayload(t *testing.T) {
	record := LogRecord{
		ClientID: "a1b2c3d4e5f60718",
		App:      "payments-api",
		Level:    "INFO",
		Message:  "invoice created",
	}

	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	const want = `{"clientId":"a1b2c3d4e5f60718","app":"payments-api","level":"INFO","message":"invoice created"}`
	if string(encoded) != want {
		t.Fatalf("Marshal() = %s, want %s", encoded, want)
	}

	// The whole point: attribution changes the payload hash, so it is covered
	// by the chain and cannot be altered without detection.
	if sha256Hex(encoded) == sha256Hex([]byte(`{"app":"payments-api","level":"INFO","message":"invoice created"}`)) {
		t.Fatal("clientId did not affect the payload hash")
	}
}

func TestAppendedChainVerifiesWithClientID(t *testing.T) {
	store, err := NewFileStore(filepath.Join(t.TempDir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("NewFileStore() error: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := store.Append(LogRecord{
			ClientID: "a1b2c3d4e5f60718",
			App:      "payments-api",
			Level:    "INFO",
			Message:  "attributed entry",
		}); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	result, err := store.Verify()
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if !result.Valid {
		t.Fatalf("chain invalid at %v: %v", result.InvalidAt, result.Reason)
	}
}
