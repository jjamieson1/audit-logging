package main

import (
	"encoding/json"
	"testing"
)

// TestLogQueryResultJSONContract pins the wire contract that docs/querying.md
// and every paging client depend on: nextCursor is always present (null on
// the last page), while total and offset are absent unless the caller asked
// for them. Absent and null are different things on the wire, so this
// asserts key presence, not just value equality.
func TestLogQueryResultJSONContract(t *testing.T) {
	t.Run("unset fields: nextCursor is null, total and offset are absent", func(t *testing.T) {
		result := LogQueryResult{Items: []Entry{}, Limit: 50}

		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("json.Marshal() error: %v", err)
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("json.Unmarshal() error: %v", err)
		}

		cursorVal, ok := fields["nextCursor"]
		if !ok {
			t.Fatalf("nextCursor: got absent key, want present key with null value (%s)", raw)
		}
		if string(cursorVal) != "null" {
			t.Fatalf("nextCursor: got %s, want the JSON literal null", cursorVal)
		}

		if _, ok := fields["total"]; ok {
			t.Fatalf("total: got present key, want the key entirely absent when Total is nil (%s)", raw)
		}
		if _, ok := fields["offset"]; ok {
			t.Fatalf("offset: got present key, want the key entirely absent when Offset is nil (%s)", raw)
		}
	})

	t.Run("set fields: nextCursor, total and offset all carry values", func(t *testing.T) {
		cursor := "eyJpIjo0Mn0"
		total := 42
		offset := 10
		result := LogQueryResult{
			Items:      []Entry{},
			Limit:      50,
			NextCursor: &cursor,
			Total:      &total,
			Offset:     &offset,
		}

		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("json.Marshal() error: %v", err)
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("json.Unmarshal() error: %v", err)
		}

		if got, want := string(fields["nextCursor"]), `"eyJpIjo0Mn0"`; got != want {
			t.Fatalf("nextCursor: got %s, want %s", got, want)
		}
		if got, want := string(fields["total"]), "42"; got != want {
			t.Fatalf("total: got %s, want %s", got, want)
		}
		if got, want := string(fields["offset"]), "10"; got != want {
			t.Fatalf("offset: got %s, want %s", got, want)
		}
	})
}

// TestFileStoreQueryLogsOffsetZeroOmitsOffsetField pins a deliberate edge
// case: an explicit offset=0 is indistinguishable from "no offset supplied"
// in the response. FileStore.QueryLogs only sets result.Offset when
// query.Offset > 0 (see the comment on LogQueryResult.Offset), so a caller
// that explicitly asks for offset=0 gets no "offset" key back, same as a
// caller who never mentioned offset at all. This is not changed by this
// test; it only records the current, intended behaviour.
func TestFileStoreQueryLogsOffsetZeroOmitsOffsetField(t *testing.T) {
	store := newTestFileStore(t, 3)

	result, err := store.QueryLogs(LogQuery{Limit: 50, Offset: 0})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}

	if result.Offset != nil {
		t.Fatalf("Offset: got %d, want nil for an explicit offset=0 request", *result.Offset)
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if _, ok := fields["offset"]; ok {
		t.Fatalf("offset: got present key, want the key absent for an explicit offset=0 request (%s)", raw)
	}
}
