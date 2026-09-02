package main

import (
	"fmt"
	"path/filepath"
	"testing"
)

// newTestFileStore builds a FileStore in a temp directory seeded with count
// entries, whose indexes run 1..count.
func newTestFileStore(t *testing.T, count int) *FileStore {
	t.Helper()

	store, err := NewFileStore(filepath.Join(t.TempDir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("NewFileStore() error: %v", err)
	}

	for i := 1; i <= count; i++ {
		level := "INFO"
		if i%2 == 0 {
			level = "ERROR"
		}
		if _, err := store.Append(LogRecord{
			App:     "seed-app",
			Level:   level,
			Message: fmt.Sprintf("entry %d", i),
		}); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	return store
}

func TestFileStoreWalksEveryEntryOnceByCursor(t *testing.T) {
	store := newTestFileStore(t, 7)

	seen := make([]uint64, 0, 7)
	var afterIndex uint64
	for page := 0; page < 10; page++ {
		result, err := store.QueryLogs(LogQuery{Limit: 3, AfterIndex: afterIndex})
		if err != nil {
			t.Fatalf("QueryLogs() error: %v", err)
		}
		for _, item := range result.Items {
			seen = append(seen, item.Index)
		}
		if result.NextCursor == nil {
			break
		}
		next, err := decodeCursor(*result.NextCursor)
		if err != nil {
			t.Fatalf("decodeCursor() error: %v", err)
		}
		if next <= afterIndex {
			t.Fatalf("cursor did not advance: %d then %d", afterIndex, next)
		}
		afterIndex = next
	}

	want := []uint64{1, 2, 3, 4, 5, 6, 7}
	if len(seen) != len(want) {
		t.Fatalf("saw %d entries %v, want %d", len(seen), seen, len(want))
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen = %v, want %v", seen, want)
		}
	}
}

func TestFileStoreExactMultipleEndsWithoutEmptyPage(t *testing.T) {
	// 6 entries at 3 per page must finish in two pages, with the second
	// reporting no next cursor rather than handing out an empty third page.
	store := newTestFileStore(t, 6)

	first, err := store.QueryLogs(LogQuery{Limit: 3})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if len(first.Items) != 3 || first.NextCursor == nil {
		t.Fatalf("first page: %d items, nextCursor %v; want 3 items and a cursor", len(first.Items), first.NextCursor)
	}

	afterIndex, err := decodeCursor(*first.NextCursor)
	if err != nil {
		t.Fatalf("decodeCursor() error: %v", err)
	}

	second, err := store.QueryLogs(LogQuery{Limit: 3, AfterIndex: afterIndex})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if len(second.Items) != 3 {
		t.Fatalf("second page had %d items, want 3", len(second.Items))
	}
	if second.NextCursor != nil {
		t.Fatalf("second page returned cursor %q, want nil", *second.NextCursor)
	}
}

func TestFileStoreTotalIsOptIn(t *testing.T) {
	store := newTestFileStore(t, 7)

	without, err := store.QueryLogs(LogQuery{Limit: 2})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if without.Total != nil {
		t.Fatalf("Total = %d, want nil when WantTotal is false", *without.Total)
	}

	with, err := store.QueryLogs(LogQuery{Limit: 2, WantTotal: true})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if with.Total == nil {
		t.Fatal("Total = nil, want a value when WantTotal is true")
	}
	if *with.Total != 7 {
		t.Fatalf("Total = %d, want 7", *with.Total)
	}
}

func TestFileStoreTotalIgnoresCursorAndCountsWholeFilteredSet(t *testing.T) {
	store := newTestFileStore(t, 7)

	result, err := store.QueryLogs(LogQuery{Limit: 2, AfterIndex: 5, WantTotal: true})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if result.Total == nil {
		t.Fatal("Total = nil, want a value")
	}
	// Deep into the log, but Total is the size of the matching set, not the
	// number of entries left after the cursor.
	if *result.Total != 7 {
		t.Fatalf("Total = %d, want 7", *result.Total)
	}
	if len(result.Items) != 2 {
		t.Fatalf("Items = %d, want 2", len(result.Items))
	}
	if result.Items[0].Index != 6 {
		t.Fatalf("first item index = %d, want 6", result.Items[0].Index)
	}
}

func TestFileStoreCursorRespectsFilters(t *testing.T) {
	store := newTestFileStore(t, 7)

	// Even-numbered entries are ERROR: indexes 2, 4, 6.
	result, err := store.QueryLogs(LogQuery{Limit: 2, Level: "ERROR", WantTotal: true})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if *result.Total != 3 {
		t.Fatalf("Total = %d, want 3", *result.Total)
	}
	if len(result.Items) != 2 || result.Items[0].Index != 2 || result.Items[1].Index != 4 {
		t.Fatalf("unexpected page: %+v", result.Items)
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor = nil, want a cursor")
	}
}
