package main

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// TestPostgresStoreQueryLogs exercises PostgresStore.QueryLogs against a
// live, pre-existing database identified by TEST_DATABASE_URL.
//
// SAFETY: this test is strictly read-only against audit_log_entries. It must
// never INSERT, UPDATE, DELETE, TRUNCATE, or otherwise mutate that table.
// audit_log_entries is an append-only, tamper-evident hash chain; writing
// rows into it (or deleting them afterward) permanently corrupts the chain
// and makes GET /v1/verify report it invalid. There is no clean undo, so
// every query below is a SELECT via QueryLogs or store.db.QueryRow.
func TestPostgresStoreQueryLogs(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgresStore tests")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}

	store, err := NewPostgresStore(db)
	if err != nil {
		t.Fatalf("NewPostgresStore() error: %v", err)
	}

	var rowCount int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM audit_log_entries").Scan(&rowCount); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if rowCount < 10 {
		t.Skipf("audit_log_entries has only %d rows; need at least 10 for pagination coverage", rowCount)
	}

	// Read real filter values out of the table rather than hardcoding ones
	// that might match nothing.
	var level string
	if err := store.db.QueryRow(`
SELECT record_json::jsonb->>'level' FROM audit_log_entries
WHERE record_json::jsonb->>'level' IS NOT NULL AND record_json::jsonb->>'level' <> ''
LIMIT 1`).Scan(&level); err != nil {
		t.Fatalf("reading a sample level: %v", err)
	}

	var levelCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_log_entries WHERE record_json::jsonb->>'level' = $1`, level).Scan(&levelCount); err != nil {
		t.Fatalf("counting rows for level %q: %v", level, err)
	}
	if levelCount < 4 {
		t.Skipf("level %q only has %d rows; need at least 4 for pagination coverage", level, levelCount)
	}

	var message string
	if err := store.db.QueryRow(`
SELECT record_json::jsonb->>'message' FROM audit_log_entries
WHERE record_json::jsonb->>'message' IS NOT NULL AND record_json::jsonb->>'message' <> ''
LIMIT 1`).Scan(&message); err != nil {
		t.Fatalf("reading a sample message: %v", err)
	}
	text := message
	if len(text) > 6 {
		text = text[:6]
	}

	t.Run("cursor walk covers everything exactly once", func(t *testing.T) {
		seen := make(map[uint64]bool, rowCount)
		var last uint64
		var afterIndex uint64

		for iterations := 0; ; iterations++ {
			if iterations > 500 {
				t.Fatal("cursor walk exceeded 500 iterations; suspect a non-terminating cursor")
			}

			result, err := store.QueryLogs(LogQuery{Limit: 3, AfterIndex: afterIndex})
			if err != nil {
				t.Fatalf("QueryLogs() error: %v", err)
			}
			if len(result.Items) > 3 {
				t.Fatalf("page had %d items, want at most 3 (limit+1 lookahead leaked)", len(result.Items))
			}

			for _, item := range result.Items {
				if seen[item.Index] {
					t.Fatalf("index %d seen twice", item.Index)
				}
				seen[item.Index] = true
				if item.Index <= last {
					t.Fatalf("indexes not strictly ascending: %d after %d", item.Index, last)
				}
				last = item.Index
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

		if len(seen) != rowCount {
			t.Fatalf("walked %d entries, want %d", len(seen), rowCount)
		}
	})

	t.Run("total ignores the cursor", func(t *testing.T) {
		first, err := store.QueryLogs(LogQuery{Limit: 5, WantTotal: true})
		if err != nil {
			t.Fatalf("QueryLogs() error: %v", err)
		}
		if first.Total == nil {
			t.Fatal("Total = nil, want a value")
		}

		// Walk a few pages of cursor before asking for the total again.
		var afterIndex uint64
		for i := 0; i < 3; i++ {
			page, err := store.QueryLogs(LogQuery{Limit: 5, AfterIndex: afterIndex})
			if err != nil {
				t.Fatalf("QueryLogs() error: %v", err)
			}
			if page.NextCursor == nil {
				break
			}
			next, err := decodeCursor(*page.NextCursor)
			if err != nil {
				t.Fatalf("decodeCursor() error: %v", err)
			}
			afterIndex = next
		}
		if afterIndex == 0 {
			t.Fatal("cursor never advanced; need a non-zero AfterIndex to exercise this assertion")
		}

		second, err := store.QueryLogs(LogQuery{Limit: 5, AfterIndex: afterIndex, WantTotal: true})
		if err != nil {
			t.Fatalf("QueryLogs() error: %v", err)
		}
		if second.Total == nil {
			t.Fatal("Total = nil, want a value")
		}
		if *first.Total != *second.Total {
			t.Fatalf("Total changed with cursor: %d (no cursor) vs %d (AfterIndex=%d)", *first.Total, *second.Total, afterIndex)
		}
	})

	t.Run("placeholder numbering under combinations", func(t *testing.T) {
		cases := []struct {
			name  string
			query LogQuery
		}{
			{name: "no filters with cursor", query: LogQuery{Limit: 3, AfterIndex: 1}},
			{name: "level filter with cursor", query: LogQuery{Limit: 3, Level: level, AfterIndex: 1}},
			{name: "text filter with cursor", query: LogQuery{Limit: 3, Text: text, AfterIndex: 1}},
			{name: "level filter with offset", query: LogQuery{Limit: 3, Level: level, Offset: 1}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := store.QueryLogs(tc.query)
				if err != nil {
					t.Fatalf("QueryLogs() error: %v", err)
				}
				if len(result.Items) > tc.query.Limit {
					t.Fatalf("got %d items, want at most %d", len(result.Items), tc.query.Limit)
				}
			})
		}
	})

	t.Run("level filter actually filters", func(t *testing.T) {
		result, err := store.QueryLogs(LogQuery{Limit: 20, Level: level})
		if err != nil {
			t.Fatalf("QueryLogs() error: %v", err)
		}
		if len(result.Items) == 0 {
			t.Fatal("no items returned for a level known to exist")
		}
		for _, item := range result.Items {
			if !strings.EqualFold(item.Record.Level, level) {
				t.Fatalf("item has level %q, want %q", item.Record.Level, level)
			}
		}
	})

	t.Run("composite client index exists", func(t *testing.T) {
		// Asserting only indexname would pass for a single-column index too,
		// which is exactly the property the design insists on. indexdef
		// carries the real column list, so check both columns are in it.
		var indexDef string
		err := store.db.QueryRow(`
SELECT indexdef FROM pg_indexes
WHERE tablename = 'audit_log_entries' AND indexname = 'idx_audit_log_entries_client_index'`).Scan(&indexDef)
		if err != nil {
			t.Fatalf("idx_audit_log_entries_client_index not found: %v", err)
		}
		if !strings.Contains(indexDef, "clientId") {
			t.Fatalf("indexdef = %q, want it to reference clientId", indexDef)
		}
		if !strings.Contains(indexDef, "entry_index") {
			t.Fatalf("indexdef = %q, want it to reference entry_index — the index must be composite, not clientId alone", indexDef)
		}
	})

	t.Run("client-scoped query for an id that owns nothing returns zero items", func(t *testing.T) {
		result, err := store.QueryLogs(LogQuery{Limit: 20, ClientID: "no-such-client-id-plan-test"})
		if err != nil {
			t.Fatalf("QueryLogs() error: %v", err)
		}
		if len(result.Items) != 0 {
			t.Fatalf("got %d items for a client id that owns nothing, want 0", len(result.Items))
		}
	})

	t.Run("unscoped query returns rows including unattributed legacy entries", func(t *testing.T) {
		var legacyCount int
		if err := store.db.QueryRow(`
SELECT COUNT(*) FROM audit_log_entries
WHERE COALESCE(record_json::jsonb->>'clientId', '') = ''`).Scan(&legacyCount); err != nil {
			t.Fatalf("counting unattributed rows: %v", err)
		}
		if legacyCount == 0 {
			t.Skip("no unattributed legacy rows present; nothing to assert")
		}

		// Limit covers the whole table, so every legacy row is guaranteed to
		// be on this one page — no reliance on where legacy rows happen to
		// sort, and nothing here can skip past an unmet assertion.
		result, err := store.QueryLogs(LogQuery{Limit: rowCount, ClientID: ""})
		if err != nil {
			t.Fatalf("QueryLogs() error: %v", err)
		}
		if len(result.Items) != rowCount {
			t.Fatalf("unscoped query returned %d items, want all %d rows", len(result.Items), rowCount)
		}

		var seenLegacy int
		for _, item := range result.Items {
			if item.Record.ClientID == "" {
				seenLegacy++
			}
		}
		if seenLegacy != legacyCount {
			t.Fatalf("unscoped query saw %d unattributed entries, want %d", seenLegacy, legacyCount)
		}
	})
}
