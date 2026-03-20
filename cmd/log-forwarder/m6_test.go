package main

import "testing"

func TestVerifyEndpointFromLogsEndpoint(t *testing.T) {
	t.Parallel()

	got, err := VerifyEndpointFromLogsEndpoint("http://localhost:3001/v1/logs")
	if err != nil {
		t.Fatalf("VerifyEndpointFromLogsEndpoint() error = %v", err)
	}
	want := "http://localhost:3001/v1/verify"
	if got != want {
		t.Fatalf("verify endpoint mismatch: got %q want %q", got, want)
	}
}

func TestRuntimeMetricsDuplicateDetection(t *testing.T) {
	t.Parallel()

	m := NewRuntimeMetrics()
	if dup := m.MarkIdempotencyKey("key-1"); dup {
		t.Fatalf("first key should not be duplicate")
	}
	if dup := m.MarkIdempotencyKey("key-1"); !dup {
		t.Fatalf("second key should be duplicate")
	}

	s := m.Snapshot()
	if s.DuplicateKeys != 1 {
		t.Fatalf("expected duplicate_keys=1, got %d", s.DuplicateKeys)
	}
}
