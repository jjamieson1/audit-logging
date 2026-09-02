# API Authorization and Cursor Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every audit-logging client a token, bind each log entry to the client that wrote it, restrict reads to the caller's own entries, and make reads stay fast as the log grows.

**Architecture:** A PostgreSQL-backed client registry issues opaque tokens whose SHA-256 hashes are stored at rest. HTTP middleware resolves a bearer token into a `Principal`, the write handler stamps the caller's `clientId` into the hashed log record, and the read handlers force a `clientId` filter unless the caller has the `admin` role. Reads move from `OFFSET` to keyset pagination on the existing monotonic `entry_index`, served by a composite index, with the previously mandatory `COUNT(*)` becoming opt-in.

**Tech Stack:** Go 1.22, standard library only (`crypto/rand`, `crypto/subtle`, `encoding/base64`, `database/sql`, `net/http`, `net/http/httptest`), `github.com/lib/pq`, PostgreSQL 16.

**Spec:** `docs/superpowers/specs/2026-09-02-api-authorization-design.md`

## Global Constraints

- Go 1.22. **No new dependencies.** `go.mod` must not change. Everything here is standard library plus the existing `github.com/lib/pq`.
- Package is `main` in `cmd/server/`. All test files are `package main`.
- Existing helpers are reused, not reimplemented: `sha256Hex(input []byte) string`, `getEnv(key, fallback string) string`, `writeJSON(w, status, v)`, `withMethod(method, handler)`.
- Token literal prefix is exactly `alog`. Separator is `_`. Cursor version prefix is exactly `v1:`.
- Role values are exactly the lowercase strings `client` and `admin`. No others.
- Every authentication failure returns HTTP `401`, body `{"error":"unauthorized"}`, header `WWW-Authenticate: Bearer`. Missing, malformed, unknown and revoked tokens must be indistinguishable to the caller.
- `GET /v1/health` must remain reachable with no token. `deployment/deploy.sh:19` polls it as the post-deploy gate.
- Never log, print, or return a token secret except at the single moment of issue in the CLI. Never log a `token_hash`.
- Commit messages match this repo's existing style: a plain imperative sentence, no `feat:`/`fix:` prefix. Every commit ends with the trailer:

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

- Run `go build ./...` before every commit. Run `go test ./...` before every commit; it must pass with `TEST_DATABASE_URL` unset (Postgres suites skip themselves).

## Task Order Rationale

Tasks 1-3 are non-breaking groundwork: configurable limits, cursor pagination, and the new record field, each shippable on its own. Task 4 introduces the registry and makes `DATABASE_URL` mandatory. Task 5 is the breaking change that turns enforcement on. Tasks 6-10 add scoping, the CLI, the client-side integration, and the documentation.

## Deviations From the Spec's File List

Two files exist here that the spec's "Files touched" section does not name.
Both are deliberate; neither changes the design.

- `cmd/server/clientstore_postgres.go` — the spec listed
  `clientstore_postgres_test.go` but not the file under test. Adding it is the
  obvious reading, not a new decision.
- `cmd/server/router.go` — the spec put handler wiring in `main.go`. The
  handlers are currently closures inside `main()`, which no test can reach, so
  they have to move somewhere to be testable. `main.go` is already 800 lines,
  so they move to their own file rather than growing it further.

`parseLogQuery` also moves from `main.go` into `query.go`, where the rest of
query parsing now lives.

---

### Task 1: Configurable query limits and single-point normalization

Replaces the hardcoded `50` and `500` in `normalizeLogQuery` with env-driven values, and collapses the three normalization call sites into one. Also fixes `start_dev.sh`, which breaks the moment a second `.go` file joins `package main` in `cmd/server`.

**Files:**
- Create: `cmd/server/query.go`
- Create: `cmd/server/query_test.go`
- Modify: `cmd/server/main.go` — `Config` struct, `loadConfig`, **delete** `normalizeLogQuery` and `parseLogQuery` (both move to `query.go`), `FileStore.QueryLogs`, `PostgresStore.QueryLogs`, the two `/v1/logs` read handlers
- Modify: `start_dev.sh:8,31,37`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type QueryLimits struct { DefaultLimit, MaxLimit, MaxOffset int }`
  - `func defaultQueryLimits() QueryLimits`
  - `func normalizeLogQuery(query LogQuery, limits QueryLimits) LogQuery`
  - `func parseLogQuery(r *http.Request, limits QueryLimits) (LogQuery, error)`
  - `func envInt(key string, fallback int) int`
  - `Config.Query QueryLimits`

- [ ] **Step 1: Write the failing test**

Create `cmd/server/query_test.go`:

```go
package main

import "testing"

func TestNormalizeLogQueryAppliesLimits(t *testing.T) {
	limits := QueryLimits{DefaultLimit: 25, MaxLimit: 100, MaxOffset: 1000}

	tests := []struct {
		name       string
		in         LogQuery
		wantLimit  int
		wantOffset int
	}{
		{name: "absent limit takes the configured default", in: LogQuery{}, wantLimit: 25, wantOffset: 0},
		{name: "zero limit takes the configured default", in: LogQuery{Limit: 0}, wantLimit: 25, wantOffset: 0},
		{name: "negative limit takes the configured default", in: LogQuery{Limit: -5}, wantLimit: 25, wantOffset: 0},
		{name: "limit under the ceiling is preserved", in: LogQuery{Limit: 40}, wantLimit: 40, wantOffset: 0},
		{name: "limit over the ceiling is clamped not rejected", in: LogQuery{Limit: 5000}, wantLimit: 100, wantOffset: 0},
		{name: "negative offset floors at zero", in: LogQuery{Limit: 10, Offset: -3}, wantLimit: 10, wantOffset: 0},
		{name: "offset under the ceiling is preserved", in: LogQuery{Limit: 10, Offset: 900}, wantLimit: 10, wantOffset: 900},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeLogQuery(tc.in, limits)
			if got.Limit != tc.wantLimit {
				t.Errorf("Limit = %d, want %d", got.Limit, tc.wantLimit)
			}
			if got.Offset != tc.wantOffset {
				t.Errorf("Offset = %d, want %d", got.Offset, tc.wantOffset)
			}
		})
	}
}

func TestNormalizeLogQueryTrimsStrings(t *testing.T) {
	limits := QueryLimits{DefaultLimit: 50, MaxLimit: 500, MaxOffset: 10000}
	got := normalizeLogQuery(LogQuery{App: "  payments-api  ", Level: " ERROR ", Text: "  timeout "}, limits)

	if got.App != "payments-api" {
		t.Errorf("App = %q, want %q", got.App, "payments-api")
	}
	if got.Level != "ERROR" {
		t.Errorf("Level = %q, want %q", got.Level, "ERROR")
	}
	if got.Text != "timeout" {
		t.Errorf("Text = %q, want %q", got.Text, "timeout")
	}
}

func TestDefaultQueryLimits(t *testing.T) {
	got := defaultQueryLimits()
	want := QueryLimits{DefaultLimit: 50, MaxLimit: 500, MaxOffset: 10000}
	if got != want {
		t.Fatalf("defaultQueryLimits() = %+v, want %+v", got, want)
	}
}

func TestEnvIntFallsBackOnUnusableValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  int
	}{
		{name: "unset uses fallback", value: "", want: 7},
		{name: "non-numeric uses fallback", value: "banana", want: 7},
		{name: "zero uses fallback", value: "0", want: 7},
		{name: "negative uses fallback", value: "-1", want: 7},
		{name: "valid value is used", value: "123", want: 123},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_ENV_INT", tc.value)
			if got := envInt("TEST_ENV_INT", 7); got != tc.want {
				t.Fatalf("envInt() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestLoadConfigReadsQueryLimits(t *testing.T) {
	t.Setenv("DEFAULT_QUERY_LIMIT", "10")
	t.Setenv("MAX_QUERY_LIMIT", "20")
	t.Setenv("MAX_QUERY_OFFSET", "30")

	got := loadConfig().Query
	want := QueryLimits{DefaultLimit: 10, MaxLimit: 20, MaxOffset: 30}
	if got != want {
		t.Fatalf("loadConfig().Query = %+v, want %+v", got, want)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/server/ -run 'TestNormalizeLogQuery|TestDefaultQueryLimits|TestEnvInt|TestLoadConfigReadsQueryLimits' -v`

Expected: FAIL to build, with `undefined: QueryLimits`, `undefined: defaultQueryLimits`, `undefined: envInt`.

- [ ] **Step 3: Create `cmd/server/query.go`**

```go
package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// QueryLimits bounds how much of the log a single read may ask for. The values
// come from the environment so an operator can tune them per deployment.
type QueryLimits struct {
	DefaultLimit int
	MaxLimit     int
	MaxOffset    int
}

func defaultQueryLimits() QueryLimits {
	return QueryLimits{DefaultLimit: 50, MaxLimit: 500, MaxOffset: 10000}
}

// envInt reads a positive integer from the environment, falling back when the
// variable is unset, unparseable, or non-positive.
func envInt(key string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(getEnv(key, "")))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

// normalizeLogQuery is the single point where a query is bounded. Neither store
// implementation may call it; parseLogQuery is the only caller, so the limits
// exist in exactly one place.
func normalizeLogQuery(query LogQuery, limits QueryLimits) LogQuery {
	query.App = strings.TrimSpace(query.App)
	query.Level = strings.TrimSpace(query.Level)
	query.Text = strings.TrimSpace(query.Text)

	if query.Limit <= 0 {
		query.Limit = limits.DefaultLimit
	}
	if query.Limit > limits.MaxLimit {
		query.Limit = limits.MaxLimit
	}
	if query.Offset < 0 {
		query.Offset = 0
	}

	return query
}
```

- [ ] **Step 4: Delete the old `normalizeLogQuery` from `cmd/server/main.go`**

Delete this entire function from `main.go` — `query.go` now owns it:

```go
func normalizeLogQuery(query LogQuery) LogQuery {
	// ... delete the whole function
}
```

Then delete the line `query = normalizeLogQuery(query)` from **both** `FileStore.QueryLogs` and `PostgresStore.QueryLogs`. The stores now trust the query they are handed.

- [ ] **Step 5: Add `Query` to `Config` and populate it in `loadConfig`**

In the `Config` struct in `main.go`, add the field:

```go
type Config struct {
	Port            int
	BindAddr        string
	StorageBackend  string
	DatabaseURL     string
	LogFile         string
	MaxPayloadBytes int64
	Query           QueryLimits
}
```

In `loadConfig`, before the `return`, add:

```go
	defaults := defaultQueryLimits()
	queryLimits := QueryLimits{
		DefaultLimit: envInt("DEFAULT_QUERY_LIMIT", defaults.DefaultLimit),
		MaxLimit:     envInt("MAX_QUERY_LIMIT", defaults.MaxLimit),
		MaxOffset:    envInt("MAX_QUERY_OFFSET", defaults.MaxOffset),
	}
```

and add `Query: queryLimits,` to the returned `Config` literal.

- [ ] **Step 6: Move `parseLogQuery` into `query.go` and thread the limits through it**

`parseLogQuery` is query parsing, so it belongs beside the rest of it — and
Task 2 edits it there. **Delete** it from `main.go` and add this to `query.go`,
adding `"fmt"` and `"net/http"` to that file's imports:

```go
func parseLogQuery(r *http.Request, limits QueryLimits) (LogQuery, error) {
	values := r.URL.Query()

	// 0 means "caller did not say"; normalizeLogQuery substitutes the default.
	limit := 0
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return LogQuery{}, fmt.Errorf("invalid limit")
		}
		limit = parsed
	}

	offset := 0
	if raw := strings.TrimSpace(values.Get("offset")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return LogQuery{}, fmt.Errorf("invalid offset")
		}
		if parsed > limits.MaxOffset {
			return LogQuery{}, fmt.Errorf("offset exceeds maximum of %d; use cursor for deep pagination", limits.MaxOffset)
		}
		offset = parsed
	}

	text := strings.TrimSpace(values.Get("q"))
	if text == "" {
		text = strings.TrimSpace(values.Get("text"))
	}

	return normalizeLogQuery(LogQuery{
		App:    values.Get("app"),
		Level:  values.Get("level"),
		Text:   text,
		Limit:  limit,
		Offset: offset,
	}, limits), nil
}
```

- [ ] **Step 7: Update the three `parseLogQuery` call sites**

In `main()`, in the `GET` arm of the `/v1/logs` handler and in the `/v1/logs/search` handler, change `parseLogQuery(r)` to `parseLogQuery(r, cfg.Query)`. There are two call sites; `cfg` is already in scope in both via the closure.

- [ ] **Step 8: Run the tests to verify they pass**

Run: `go test ./cmd/server/ -v`

Expected: PASS, including the pre-existing `TestLoadConfigListenAddr`.

- [ ] **Step 9: Fix `start_dev.sh`**

`go run cmd/server/main.go` compiles that one file only and now fails with `undefined: QueryLimits`. Change three lines.

Line 8, replace:

```bash
BINARY_PATH="${BINARY_PATH:-$ROOT_DIR/cmd/server/main.go}"
```

with:

```bash
SERVER_PKG="${SERVER_PKG:-./cmd/server}"
```

Line 31, replace `echo "- binary:   $BINARY_PATH"` with:

```bash
echo "- package:  $SERVER_PKG"
```

Line 37, replace `nohup go run "$BINARY_PATH" >> "$RUNTIME_LOG" 2>&1 &` with:

```bash
nohup go run "$SERVER_PKG" >> "$RUNTIME_LOG" 2>&1 &
```

- [ ] **Step 10: Verify the script change compiles the whole package**

Run: `go run ./cmd/server -h 2>&1 | head -5 || true`

Expected: the binary builds. It will fail at runtime only if Postgres is unreachable, which is fine here — a compile error is what we are ruling out.

- [ ] **Step 11: Commit**

```bash
git add cmd/server/query.go cmd/server/query_test.go cmd/server/main.go start_dev.sh
git commit -m "$(cat <<'EOF'
Make query limits configurable and normalize in one place

DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT and MAX_QUERY_OFFSET replace the
constants hardcoded in normalizeLogQuery. The stores no longer normalize;
parseLogQuery is now the only caller, so the bounds live in one place.

start_dev.sh ran "go run cmd/server/main.go", which compiles a single file
and breaks as soon as the package has a second one.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Cursor pagination and opt-in totals

Replaces mandatory `OFFSET` + `COUNT(*)` with keyset pagination on `entry_index`. The count is the larger win: it currently runs on every read, scanning every matching row before `LIMIT` is applied.

**Files:**
- Modify: `cmd/server/query.go` — cursor codec, `parseLogQuery`
- Modify: `cmd/server/query_test.go` — cursor codec tests
- Create: `cmd/server/pagination_test.go`
- Modify: `cmd/server/main.go` — `LogQuery`, `LogQueryResult`, `FileStore.QueryLogs`, `PostgresStore.QueryLogs`

**Interfaces:**
- Consumes: `QueryLimits`, `normalizeLogQuery`, `parseLogQuery` from Task 1.
- Produces:
  - `func encodeCursor(index uint64) string`
  - `func decodeCursor(raw string) (uint64, error)`
  - `LogQuery.AfterIndex uint64` — 0 means no cursor; entry indexes start at 1
  - `LogQuery.WantTotal bool`
  - `LogQueryResult.NextCursor *string`, `LogQueryResult.Total *int`, `LogQueryResult.Offset *int`
  - `func newTestFileStore(t *testing.T, count int) *FileStore` (test helper)

- [ ] **Step 1: Write the failing cursor codec tests**

Append to `cmd/server/query_test.go`:

```go
func TestCursorRoundTrip(t *testing.T) {
	for _, index := range []uint64{1, 2, 50, 1427, 18446744073709551615} {
		encoded := encodeCursor(index)
		decoded, err := decodeCursor(encoded)
		if err != nil {
			t.Fatalf("decodeCursor(%q) returned error: %v", encoded, err)
		}
		if decoded != index {
			t.Fatalf("round trip gave %d, want %d", decoded, index)
		}
	}
}

func TestEncodeCursorIsOpaqueAndStable(t *testing.T) {
	// Locked in so a future format change is a deliberate, visible edit.
	if got, want := encodeCursor(1427), "djE6MTQyNw"; got != want {
		t.Fatalf("encodeCursor(1427) = %q, want %q", got, want)
	}
}

func TestDecodeCursorRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "not base64", in: "!!!!"},
		{name: "base64 but missing version prefix", in: "MTQyNw"},
		{name: "wrong version prefix", in: "djI6MTQyNw"},
		{name: "version prefix but non-numeric", in: "djE6YWJj"},
		{name: "negative index", in: "djE6LTE"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeCursor(tc.in); err == nil {
				t.Fatalf("decodeCursor(%q) succeeded, want error", tc.in)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/server/ -run 'TestCursor|TestEncodeCursor|TestDecodeCursor' -v`

Expected: FAIL to build with `undefined: encodeCursor`, `undefined: decodeCursor`.

- [ ] **Step 3: Add the cursor codec to `cmd/server/query.go`**

Add `encoding/base64` to the imports, then append:

```go
// cursorVersion prefixes the encoded payload so a future format change is
// detectable rather than silently misparsed.
const cursorVersion = "v1:"

// encodeCursor renders a keyset position opaquely. Callers must treat the
// result as a token, not as a number they can construct themselves.
func encodeCursor(index uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorVersion + strconv.FormatUint(index, 10)))
}

func decodeCursor(raw string) (uint64, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid cursor")
	}

	payload := string(decoded)
	if !strings.HasPrefix(payload, cursorVersion) {
		return 0, fmt.Errorf("invalid cursor")
	}

	index, err := strconv.ParseUint(strings.TrimPrefix(payload, cursorVersion), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cursor")
	}

	return index, nil
}
```

- [ ] **Step 4: Run to verify the codec tests pass**

Run: `go test ./cmd/server/ -run 'TestCursor|TestEncodeCursor|TestDecodeCursor' -v`

Expected: PASS.

- [ ] **Step 5: Write the failing pagination tests**

Create `cmd/server/pagination_test.go`:

```go
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
```

- [ ] **Step 6: Run to verify it fails**

Run: `go test ./cmd/server/ -run TestFileStore -v`

Expected: FAIL to build with `unknown field AfterIndex in struct literal` and `unknown field WantTotal`.

- [ ] **Step 7: Extend `LogQuery` and `LogQueryResult` in `cmd/server/main.go`**

Replace both struct definitions:

```go
type LogQuery struct {
	App    string
	Level  string
	Text   string
	Limit  int
	Offset int
	// AfterIndex is the keyset position. Zero means no cursor was supplied;
	// entry indexes start at 1, so zero is unambiguous.
	AfterIndex uint64
	// WantTotal opts in to the exact count, which costs a full scan of the
	// matching set. Off by default.
	WantTotal bool
}

type LogQueryResult struct {
	Items []Entry `json:"items"`
	Limit int     `json:"limit"`
	// NextCursor is always serialised; null means this was the last page.
	NextCursor *string `json:"nextCursor"`
	// Total and Offset are pointers so an absent value serialises as absent.
	// A plain int would emit "total": 0 on every uncounted response, which
	// reads as an empty result set.
	Total  *int `json:"total,omitempty"`
	Offset *int `json:"offset,omitempty"`
}
```

- [ ] **Step 8: Rewrite `FileStore.QueryLogs`**

Replace the whole method. Note it no longer reads to end of file unless a total was requested.

```go
// QueryLogs assumes query.Limit is positive; parseLogQuery guarantees it.
func (s *FileStore) QueryLogs(query LogQuery) (LogQueryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.path)
	if err != nil {
		return LogQueryResult{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	items := make([]Entry, 0, query.Limit)
	total := 0
	skipped := 0
	hasMore := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return LogQueryResult{}, err
		}

		if !matchesQuery(entry, query) {
			continue
		}

		// Counted before the cursor is applied: Total is the size of the
		// matching set, not of what remains after the cursor.
		total++

		if entry.Index <= query.AfterIndex {
			continue
		}
		if skipped < query.Offset {
			skipped++
			continue
		}

		if len(items) < query.Limit {
			items = append(items, entry)
			continue
		}

		// One past a full page proves there is a next page. Without a total to
		// finish, there is nothing left to learn from the rest of the file.
		hasMore = true
		if !query.WantTotal {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return LogQueryResult{}, err
	}

	result := LogQueryResult{Items: items, Limit: query.Limit}
	if query.WantTotal {
		result.Total = &total
	}
	if query.Offset > 0 {
		offset := query.Offset
		result.Offset = &offset
	}
	if hasMore && len(items) > 0 {
		cursor := encodeCursor(items[len(items)-1].Index)
		result.NextCursor = &cursor
	}

	return result, nil
}
```

- [ ] **Step 9: Run to verify the file store tests pass**

Run: `go test ./cmd/server/ -run TestFileStore -v`

Expected: PASS, all five.

- [ ] **Step 10: Rewrite `PostgresStore.QueryLogs`**

Replace the whole method. The filter clauses are built once and shared: the count uses them alone, the list adds the cursor on top.

```go
// QueryLogs assumes query.Limit is positive; parseLogQuery guarantees it.
func (s *PostgresStore) QueryLogs(query LogQuery) (LogQueryResult, error) {
	filters := make([]string, 0, 3)
	filterArgs := make([]any, 0, 4)

	if query.App != "" {
		filterArgs = append(filterArgs, query.App)
		filters = append(filters, fmt.Sprintf("record_json::jsonb->>'app' = $%d", len(filterArgs)))
	}
	if query.Level != "" {
		filterArgs = append(filterArgs, query.Level)
		filters = append(filters, fmt.Sprintf("record_json::jsonb->>'level' = $%d", len(filterArgs)))
	}
	if query.Text != "" {
		filterArgs = append(filterArgs, "%"+query.Text+"%")
		placeholder := fmt.Sprintf("$%d", len(filterArgs))
		filters = append(filters, "(record_json::jsonb->>'message' ILIKE "+placeholder+" OR record_json ILIKE "+placeholder+")")
	}

	filterWhere := ""
	if len(filters) > 0 {
		filterWhere = " WHERE " + strings.Join(filters, " AND ")
	}

	result := LogQueryResult{Limit: query.Limit}

	// Opt-in only: this scans every matching row.
	if query.WantTotal {
		var total int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM audit_log_entries"+filterWhere, filterArgs...).Scan(&total); err != nil {
			return LogQueryResult{}, err
		}
		result.Total = &total
	}

	listArgs := append([]any{}, filterArgs...)
	listWhere := filterWhere
	if query.AfterIndex > 0 {
		listArgs = append(listArgs, int64(query.AfterIndex))
		clause := fmt.Sprintf("entry_index > $%d", len(listArgs))
		if listWhere == "" {
			listWhere = " WHERE " + clause
		} else {
			listWhere += " AND " + clause
		}
	}

	// One extra row answers "is there another page" without a second query.
	listArgs = append(listArgs, query.Limit+1)
	limitClause := fmt.Sprintf(" LIMIT $%d", len(listArgs))

	offsetClause := ""
	if query.Offset > 0 {
		listArgs = append(listArgs, query.Offset)
		offsetClause = fmt.Sprintf(" OFFSET $%d", len(listArgs))
	}

	listQuery := "SELECT entry_index, ts, prev_hash, payload_hash, entry_hash, record_json FROM audit_log_entries" +
		listWhere + " ORDER BY entry_index ASC" + limitClause + offsetClause

	rows, err := s.db.Query(listQuery, listArgs...)
	if err != nil {
		return LogQueryResult{}, err
	}
	defer rows.Close()

	items := make([]Entry, 0, query.Limit)
	for rows.Next() {
		var dbIndex int64
		var timestamp, prevHash, payloadHash, entryHash, recordJSON string
		if err := rows.Scan(&dbIndex, &timestamp, &prevHash, &payloadHash, &entryHash, &recordJSON); err != nil {
			return LogQueryResult{}, err
		}

		var record LogRecord
		if err := json.Unmarshal([]byte(recordJSON), &record); err != nil {
			return LogQueryResult{}, err
		}

		items = append(items, Entry{
			Index:       uint64(dbIndex),
			Timestamp:   timestamp,
			PrevHash:    prevHash,
			PayloadHash: payloadHash,
			EntryHash:   entryHash,
			Record:      record,
		})
	}

	if err := rows.Err(); err != nil {
		return LogQueryResult{}, err
	}

	if len(items) > query.Limit {
		items = items[:query.Limit]
		cursor := encodeCursor(items[len(items)-1].Index)
		result.NextCursor = &cursor
	}

	result.Items = items
	if query.Offset > 0 {
		offset := query.Offset
		result.Offset = &offset
	}

	return result, nil
}
```

- [ ] **Step 11: Accept `cursor` and `count` in `parseLogQuery`**

In `cmd/server/query.go`, inside `parseLogQuery`, insert this block immediately after `values := r.URL.Query()`:

```go
	cursorRaw := strings.TrimSpace(values.Get("cursor"))
	if cursorRaw != "" && strings.TrimSpace(values.Get("offset")) != "" {
		return LogQuery{}, fmt.Errorf("cursor and offset cannot be combined")
	}

	var afterIndex uint64
	if cursorRaw != "" {
		decoded, err := decodeCursor(cursorRaw)
		if err != nil {
			return LogQuery{}, err
		}
		afterIndex = decoded
	}
```

Then add both new fields to the `LogQuery` literal in the `return`:

```go
		AfterIndex: afterIndex,
		WantTotal:  strings.EqualFold(strings.TrimSpace(values.Get("count")), "true"),
```

- [ ] **Step 12: Write the failing parse tests**

Append to `cmd/server/query_test.go`:

```go
func TestParseLogQueryPagination(t *testing.T) {
	limits := QueryLimits{DefaultLimit: 50, MaxLimit: 500, MaxOffset: 100}

	tests := []struct {
		name           string
		rawQuery       string
		wantErr        bool
		wantAfterIndex uint64
		wantTotal      bool
		wantLimit      int
	}{
		{name: "bare request takes the default limit", rawQuery: "", wantLimit: 50},
		{name: "cursor decodes to an index", rawQuery: "cursor=" + encodeCursor(42), wantAfterIndex: 42, wantLimit: 50},
		{name: "count=true opts into the total", rawQuery: "count=true", wantTotal: true, wantLimit: 50},
		{name: "count=TRUE is accepted", rawQuery: "count=TRUE", wantTotal: true, wantLimit: 50},
		{name: "count=false does not opt in", rawQuery: "count=false", wantTotal: false, wantLimit: 50},
		{name: "offset within the ceiling is accepted", rawQuery: "offset=99", wantLimit: 50},
		{name: "offset past the ceiling is rejected", rawQuery: "offset=101", wantErr: true},
		{name: "cursor with offset is rejected", rawQuery: "cursor=" + encodeCursor(1) + "&offset=10", wantErr: true},
		{name: "malformed cursor is rejected", rawQuery: "cursor=not-a-cursor", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/logs?"+tc.rawQuery, nil)
			got, err := parseLogQuery(req, limits)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseLogQuery() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseLogQuery() error: %v", err)
			}
			if got.AfterIndex != tc.wantAfterIndex {
				t.Errorf("AfterIndex = %d, want %d", got.AfterIndex, tc.wantAfterIndex)
			}
			if got.WantTotal != tc.wantTotal {
				t.Errorf("WantTotal = %v, want %v", got.WantTotal, tc.wantTotal)
			}
			if got.Limit != tc.wantLimit {
				t.Errorf("Limit = %d, want %d", got.Limit, tc.wantLimit)
			}
		})
	}
}
```

Add `"net/http"` and `"net/http/httptest"` to the imports of `query_test.go`.

- [ ] **Step 13: Run the full suite**

Run: `go build ./... && go test ./... `

Expected: PASS. `TestParseLogQueryPagination` and every earlier test are green.

- [ ] **Step 14: Commit**

```bash
git add cmd/server/query.go cmd/server/query_test.go cmd/server/pagination_test.go cmd/server/main.go
git commit -m "$(cat <<'EOF'
Page reads by cursor and make the total count opt-in

Reads keyset-paginate on entry_index, which is already a monotonic primary
key on an append-only table. Responses carry nextCursor, null on the last
page.

The bigger cost was the COUNT(*) that ran on every read to populate total,
scanning every matching row before LIMIT applied. It now runs only for
?count=true. The file store gains the same benefit: it no longer reads to
end of file once a page is full.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Add `clientId` to the hashed record without breaking the chain

Adds the field that carries client attribution. It goes *inside* `LogRecord`, so it is covered by `payloadHash` and therefore by the chain — attribution becomes tamper-evident rather than a mutable column. Nothing stamps it yet; this task only proves the existing chain survives the change.

**Files:**
- Modify: `cmd/server/main.go` — `LogRecord`, the `POST /v1/logs` handler
- Create: `cmd/server/record_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `LogRecord.ClientID string` with JSON tag `clientId,omitempty`, declared as the **first** field of the struct.

- [ ] **Step 1: Write the failing tests**

Create `cmd/server/record_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/server/ -run 'TestLegacy|TestAttributed|TestAppendedChain' -v`

Expected: FAIL to build with `unknown field ClientID in struct literal of type LogRecord`.

- [ ] **Step 3: Add the field to `LogRecord` in `cmd/server/main.go`**

`ClientID` must be **first**. Go marshals in declaration order, and `omitempty`
drops it for legacy records, so the remaining fields keep their existing order
and old entries re-marshal to identical bytes.

```go
type LogRecord struct {
	// ClientID is stamped by the server from the authenticated token. It lives
	// inside the record so it is covered by payloadHash and the chain, making
	// attribution tamper-evident. omitempty keeps pre-attribution entries
	// hashing exactly as they did.
	ClientID string         `json:"clientId,omitempty"`
	App      string         `json:"app"`
	Level    string         `json:"level"`
	Message  string         `json:"message"`
	Metadata map[string]any `json:"metadata,omitempty"`
}
```

- [ ] **Step 4: Reject caller-supplied attribution in the write handler**

Until Task 5 stamps the real value, a caller must not be able to set it. In the
`POST` arm of the `/v1/logs` handler in `main()`, immediately after the
`json.Unmarshal(body, &input)` error check, add:

```go
			// Attribution is server-assigned. Task 5 replaces this with the
			// authenticated client; until then nobody gets to self-attribute.
			input.ClientID = ""
```

- [ ] **Step 5: Run to verify the tests pass**

Run: `go test ./cmd/server/ -run 'TestLegacy|TestAttributed|TestAppendedChain' -v`

Expected: PASS, all four.

- [ ] **Step 6: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/server/main.go cmd/server/record_test.go
git commit -m "$(cat <<'EOF'
Add clientId to the hashed log record

The field sits inside LogRecord, so it is covered by payloadHash and the
hash chain: attribution cannot be altered without breaking verification.

Declared first with omitempty so pre-attribution entries re-marshal to
identical bytes and keep verifying. Tests pin that down by rebuilding a
legacy entry from raw bytes and re-opening it.

The write handler clears any caller-supplied clientId. Task 5 replaces
that with the authenticated value.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Client registry, opaque tokens, and a mandatory database

Introduces the registry that issues and verifies tokens. Nothing is enforced over HTTP yet — that is Task 5. This task also makes `DATABASE_URL` mandatory for every `STORAGE_BACKEND`, because the registry always lives in PostgreSQL, and refactors connection ownership so one pool serves both stores.

**Files:**
- Create: `cmd/server/auth.go`
- Create: `cmd/server/auth_test.go`
- Create: `cmd/server/clientstore_postgres.go`
- Create: `cmd/server/clientstore_postgres_test.go`
- Modify: `cmd/server/main.go` — `NewPostgresStore` signature, `main()` startup

**Interfaces:**
- Consumes: `sha256Hex` from `main.go`.
- Produces:
  - `const RoleClient = "client"`, `const RoleAdmin = "admin"`
  - `var ErrUnauthorized = errors.New("unauthorized")`
  - `type Principal struct { ClientID, Name, Role string }`
  - `type ClientSummary struct { ClientID, Name, Role string; CreatedAt time.Time; Revoked bool }`
  - `type ClientStore interface { Authenticate(token string) (Principal, error); Register(name, role string) (string, string, error); Rotate(clientID string) (string, error); Revoke(clientID string) error; List() ([]ClientSummary, error) }`
  - `func formatToken(clientID, secret string) string`
  - `func parseToken(token string) (clientID, secret string, err error)`
  - `func hashSecret(secret string) string`
  - `func newClientID() (string, error)`, `func newSecret() (string, error)`
  - `func validRole(role string) bool`
  - `func NewPostgresClientStore(db *sql.DB) (*PostgresClientStore, error)`
  - `func NewPostgresStore(db *sql.DB) (*PostgresStore, error)` — **signature changed**, no longer takes a URL

- [ ] **Step 1: Write the failing token tests**

Create `cmd/server/auth_test.go`:

```go
package main

import (
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	clientID, err := newClientID()
	if err != nil {
		t.Fatalf("newClientID() error: %v", err)
	}
	secret, err := newSecret()
	if err != nil {
		t.Fatalf("newSecret() error: %v", err)
	}

	token := formatToken(clientID, secret)
	if !strings.HasPrefix(token, "alog_") {
		t.Fatalf("token %q does not start with the alog_ prefix", token)
	}

	gotID, gotSecret, err := parseToken(token)
	if err != nil {
		t.Fatalf("parseToken() error: %v", err)
	}
	if gotID != clientID {
		t.Errorf("clientID = %q, want %q", gotID, clientID)
	}
	if gotSecret != secret {
		t.Errorf("secret = %q, want %q", gotSecret, secret)
	}
}

func TestParseTokenHandlesUnderscoresInTheSecret(t *testing.T) {
	// The base64url alphabet includes "_", so a secret can legitimately
	// contain the separator. Splitting on every underscore would reject
	// perfectly valid tokens, intermittently and confusingly.
	const clientID = "a1b2c3d4e5f60718"
	const secret = "ab_cd__ef_"

	gotID, gotSecret, err := parseToken(formatToken(clientID, secret))
	if err != nil {
		t.Fatalf("parseToken() error: %v", err)
	}
	if gotID != clientID {
		t.Errorf("clientID = %q, want %q", gotID, clientID)
	}
	if gotSecret != secret {
		t.Errorf("secret = %q, want %q", gotSecret, secret)
	}
}

func TestParseTokenRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "no separators", in: "alog"},
		{name: "only one separator", in: "alog_a1b2c3d4e5f60718"},
		{name: "wrong prefix", in: "bearer_a1b2c3d4e5f60718_secret"},
		{name: "prefix case must match", in: "ALOG_a1b2c3d4e5f60718_secret"},
		{name: "empty client id", in: "alog__secret"},
		{name: "empty secret", in: "alog_a1b2c3d4e5f60718_"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseToken(tc.in); err == nil {
				t.Fatalf("parseToken(%q) succeeded, want error", tc.in)
			}
		})
	}
}

func TestGeneratedValuesAreDistinctAndSized(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		clientID, err := newClientID()
		if err != nil {
			t.Fatalf("newClientID() error: %v", err)
		}
		if len(clientID) != 16 {
			t.Fatalf("clientID %q has length %d, want 16 hex characters", clientID, len(clientID))
		}
		if strings.Contains(clientID, "_") {
			t.Fatalf("clientID %q contains the token separator", clientID)
		}
		if seen[clientID] {
			t.Fatalf("newClientID() repeated %q within 100 draws", clientID)
		}
		seen[clientID] = true

		secret, err := newSecret()
		if err != nil {
			t.Fatalf("newSecret() error: %v", err)
		}
		if len(secret) != 43 {
			t.Fatalf("secret has length %d, want 43 (32 bytes, base64url unpadded)", len(secret))
		}
	}
}

func TestHashSecretIsStableAndDistinguishing(t *testing.T) {
	if hashSecret("abc") != hashSecret("abc") {
		t.Fatal("hashSecret is not deterministic")
	}
	if hashSecret("abc") == hashSecret("abd") {
		t.Fatal("hashSecret collided on different inputs")
	}
	if strings.Contains(hashSecret("abc"), "abc") {
		t.Fatal("hashSecret leaked its input")
	}
}

func TestValidRole(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{role: "client", want: true},
		{role: "admin", want: true},
		{role: "Admin", want: false},
		{role: "root", want: false},
		{role: "", want: false},
	}

	for _, tc := range tests {
		if got := validRole(tc.role); got != tc.want {
			t.Errorf("validRole(%q) = %v, want %v", tc.role, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/server/ -run 'TestToken|TestParseToken|TestGenerated|TestHashSecret|TestValidRole' -v`

Expected: FAIL to build with `undefined: newClientID`, `undefined: formatToken`, `undefined: parseToken`.

- [ ] **Step 3: Create `cmd/server/auth.go`**

```go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	RoleClient = "client"
	RoleAdmin  = "admin"
)

const (
	tokenPrefix    = "alog"
	tokenSeparator = "_"
	clientIDBytes  = 8  // 16 hex characters
	secretBytes    = 32 // 43 base64url characters
)

// ErrUnauthorized is the single failure returned for every authentication
// problem. Missing, malformed, unknown and revoked tokens must be
// indistinguishable so the endpoint cannot be used to probe for valid IDs.
var ErrUnauthorized = errors.New("unauthorized")

// Principal is the authenticated caller behind a request.
type Principal struct {
	ClientID string
	Name     string
	Role     string
}

func (p Principal) IsAdmin() bool { return p.Role == RoleAdmin }

// ClientSummary is the operator-facing view of a client. It deliberately
// carries no token and no hash.
type ClientSummary struct {
	ClientID  string
	Name      string
	Role      string
	CreatedAt time.Time
	Revoked   bool
}

type ClientStore interface {
	// Authenticate resolves a presented token, returning ErrUnauthorized for
	// any failure a caller is allowed to learn about.
	Authenticate(token string) (Principal, error)
	// Register creates a client and returns its id and its full token. The
	// token is the only time the secret exists outside the caller's hands.
	Register(name, role string) (clientID string, token string, err error)
	// Rotate issues a new secret for an existing client, keeping its id so
	// entries it has already written stay attributed to it.
	Rotate(clientID string) (token string, err error)
	Revoke(clientID string) error
	List() ([]ClientSummary, error)
}

func validRole(role string) bool {
	return role == RoleClient || role == RoleAdmin
}

func newClientID() (string, error) {
	buf := make([]byte, clientIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func newSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func formatToken(clientID, secret string) string {
	return tokenPrefix + tokenSeparator + clientID + tokenSeparator + secret
}

// parseToken splits a token into its client id and secret.
//
// It splits on the FIRST TWO separators only. The base64url alphabet includes
// "_", so a secret may contain separators of its own; splitting on all of them
// would reject valid tokens whenever a random secret happened to include one.
func parseToken(token string) (string, string, error) {
	parts := strings.SplitN(strings.TrimSpace(token), tokenSeparator, 3)
	if len(parts) != 3 || parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" {
		return "", "", ErrUnauthorized
	}
	return parts[1], parts[2], nil
}

func hashSecret(secret string) string {
	return sha256Hex([]byte(secret))
}
```

- [ ] **Step 4: Run to verify the token tests pass**

Run: `go test ./cmd/server/ -run 'TestToken|TestParseToken|TestGenerated|TestHashSecret|TestValidRole' -v`

Expected: PASS, all six.

- [ ] **Step 5: Create `cmd/server/clientstore_postgres.go`**

```go
package main

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type PostgresClientStore struct {
	db *sql.DB
}

func NewPostgresClientStore(db *sql.DB) (*PostgresClientStore, error) {
	if db == nil {
		return nil, errors.New("a database handle is required for the client registry")
	}

	store := &PostgresClientStore{db: db}
	if err := store.ensureSchema(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *PostgresClientStore) ensureSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS audit_clients (
    client_id  TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    role       TEXT NOT NULL DEFAULT 'client',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
`)
	return err
}

func (s *PostgresClientStore) Authenticate(token string) (Principal, error) {
	clientID, secret, err := parseToken(token)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}

	var name, role, storedHash string
	var revokedAt sql.NullTime

	err = s.db.QueryRow(`
SELECT name, role, token_hash, revoked_at FROM audit_clients WHERE client_id = $1
`, clientID).Scan(&name, &role, &storedHash, &revokedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return Principal{}, ErrUnauthorized
	}
	if err != nil {
		return Principal{}, err
	}
	if revokedAt.Valid {
		return Principal{}, ErrUnauthorized
	}

	if subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(storedHash)) != 1 {
		return Principal{}, ErrUnauthorized
	}

	return Principal{ClientID: clientID, Name: name, Role: role}, nil
}

func (s *PostgresClientStore) Register(name, role string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", errors.New("client name is required")
	}

	role = strings.TrimSpace(role)
	if role == "" {
		role = RoleClient
	}
	if !validRole(role) {
		return "", "", fmt.Errorf("invalid role %q: must be %q or %q", role, RoleClient, RoleAdmin)
	}

	clientID, err := newClientID()
	if err != nil {
		return "", "", err
	}
	secret, err := newSecret()
	if err != nil {
		return "", "", err
	}

	if _, err := s.db.Exec(`
INSERT INTO audit_clients(client_id, name, token_hash, role) VALUES ($1, $2, $3, $4)
`, clientID, name, hashSecret(secret), role); err != nil {
		return "", "", err
	}

	return clientID, formatToken(clientID, secret), nil
}

func (s *PostgresClientStore) Rotate(clientID string) (string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return "", errors.New("client id is required")
	}

	secret, err := newSecret()
	if err != nil {
		return "", err
	}

	// client_id is untouched, so entries already written stay attributed.
	result, err := s.db.Exec(`
UPDATE audit_clients SET token_hash = $1 WHERE client_id = $2 AND revoked_at IS NULL
`, hashSecret(secret), clientID)
	if err != nil {
		return "", err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if affected == 0 {
		return "", fmt.Errorf("no active client with id %q", clientID)
	}

	return formatToken(clientID, secret), nil
}

func (s *PostgresClientStore) Revoke(clientID string) error {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return errors.New("client id is required")
	}

	// The row is kept so historical entries stay attributable to a named client.
	result, err := s.db.Exec(`
UPDATE audit_clients SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL
`, clientID)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("no active client with id %q", clientID)
	}

	return nil
}

func (s *PostgresClientStore) List() ([]ClientSummary, error) {
	rows, err := s.db.Query(`
SELECT client_id, name, role, created_at, revoked_at
FROM audit_clients
ORDER BY created_at ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	summaries := make([]ClientSummary, 0)
	for rows.Next() {
		var summary ClientSummary
		var revokedAt sql.NullTime
		if err := rows.Scan(&summary.ClientID, &summary.Name, &summary.Role, &summary.CreatedAt, &revokedAt); err != nil {
			return nil, err
		}
		summary.Revoked = revokedAt.Valid
		summaries = append(summaries, summary)
	}

	return summaries, rows.Err()
}
```

- [ ] **Step 6: Verify the secret comparison is constant-time**

The spec calls for this, but a timing assertion is flaky under a test runner
and would fail on a loaded CI box, so verify it by inspection instead:

```bash
grep -n 'subtle.ConstantTimeCompare\|== storedHash\|!= storedHash' cmd/server/clientstore_postgres.go
```

Expected: exactly one hit, the `subtle.ConstantTimeCompare` line. Any `==` or
`!=` against `storedHash` is a defect — Go's string comparison returns early on
the first differing byte, which leaks how much of a guessed hash was correct.

- [ ] **Step 7: Write the gated PostgreSQL integration tests**

Create `cmd/server/clientstore_postgres_test.go`:

```go
package main

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

// Test clients are named with this prefix so cleanup can target them exactly.
// A blanket DELETE would be a foot-gun if TEST_DATABASE_URL ever pointed
// somewhere real.
const testClientNamePrefix = "plan-test-"

func newTestClientStore(t *testing.T) *PostgresClientStore {
	t.Helper()

	dsn := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping PostgreSQL integration tests")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open() error: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping() error: %v", err)
	}

	store, err := NewPostgresClientStore(db)
	if err != nil {
		t.Fatalf("NewPostgresClientStore() error: %v", err)
	}

	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM audit_clients WHERE name LIKE $1`, testClientNamePrefix+"%"); err != nil {
			t.Errorf("cleanup failed: %v", err)
		}
		db.Close()
	})

	return store
}

func TestPostgresClientStoreRegisterThenAuthenticate(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"payments", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	principal, err := store.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if principal.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", principal.ClientID, clientID)
	}
	if principal.Role != RoleClient {
		t.Errorf("Role = %q, want %q", principal.Role, RoleClient)
	}
	if principal.IsAdmin() {
		t.Error("IsAdmin() = true for a client-role principal")
	}
}

func TestPostgresClientStoreRejectsBadTokens(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"reject", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "malformed", in: "not-a-token"},
		{name: "unknown client id", in: formatToken("ffffffffffffffff", "whatever")},
		{name: "right client wrong secret", in: formatToken(clientID, "wrong-secret")},
		{name: "token with trailing junk", in: token + "x"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Authenticate(tc.in); err == nil {
				t.Fatalf("Authenticate(%q) succeeded, want failure", tc.in)
			}
		})
	}
}

func TestPostgresClientStoreRotateInvalidatesTheOldToken(t *testing.T) {
	store := newTestClientStore(t)

	clientID, oldToken, err := store.Register(testClientNamePrefix+"rotate", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	newToken, err := store.Rotate(clientID)
	if err != nil {
		t.Fatalf("Rotate() error: %v", err)
	}
	if newToken == oldToken {
		t.Fatal("Rotate() returned the same token")
	}

	// Rotation is a hard cutover: the old token stops working immediately.
	if _, err := store.Authenticate(oldToken); err == nil {
		t.Fatal("the pre-rotation token still authenticates")
	}

	principal, err := store.Authenticate(newToken)
	if err != nil {
		t.Fatalf("Authenticate(new) error: %v", err)
	}
	// The id survives, so entries already written stay attributed.
	if principal.ClientID != clientID {
		t.Fatalf("ClientID = %q, want %q", principal.ClientID, clientID)
	}
}

func TestPostgresClientStoreRevoke(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"revoke", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if err := store.Revoke(clientID); err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}
	if _, err := store.Authenticate(token); err == nil {
		t.Fatal("a revoked token still authenticates")
	}
	// Revoking twice is an error, not a silent success.
	if err := store.Revoke(clientID); err == nil {
		t.Fatal("Revoke() of an already-revoked client succeeded, want error")
	}
	// A revoked client cannot be rotated back into service.
	if _, err := store.Rotate(clientID); err == nil {
		t.Fatal("Rotate() of a revoked client succeeded, want error")
	}
}

func TestPostgresClientStoreRegisterValidation(t *testing.T) {
	store := newTestClientStore(t)

	if _, _, err := store.Register("   ", RoleClient); err == nil {
		t.Error("Register() with a blank name succeeded, want error")
	}
	if _, _, err := store.Register(testClientNamePrefix+"badrole", "root"); err == nil {
		t.Error("Register() with role \"root\" succeeded, want error")
	}

	// An empty role defaults to client rather than failing.
	_, token, err := store.Register(testClientNamePrefix+"defaultrole", "")
	if err != nil {
		t.Fatalf("Register() with empty role error: %v", err)
	}
	principal, err := store.Authenticate(token)
	if err != nil {
		t.Fatalf("Authenticate() error: %v", err)
	}
	if principal.Role != RoleClient {
		t.Fatalf("Role = %q, want %q", principal.Role, RoleClient)
	}
}

func TestPostgresClientStoreListOmitsSecrets(t *testing.T) {
	store := newTestClientStore(t)

	clientID, token, err := store.Register(testClientNamePrefix+"list", RoleAdmin)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	summaries, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	var found *ClientSummary
	for i := range summaries {
		if summaries[i].ClientID == clientID {
			found = &summaries[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("List() did not include %q", clientID)
	}
	if found.Role != RoleAdmin {
		t.Errorf("Role = %q, want %q", found.Role, RoleAdmin)
	}
	if found.Revoked {
		t.Error("Revoked = true for a fresh client")
	}
	if found.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}

	// Nothing in the summary may reconstruct the token.
	_, secret, err := parseToken(token)
	if err != nil {
		t.Fatalf("parseToken() error: %v", err)
	}
	if strings.Contains(found.Name, secret) || strings.Contains(found.ClientID, secret) {
		t.Error("List() leaked the token secret")
	}
}
```

- [ ] **Step 8: Run the gated tests both ways**

Run: `go test ./cmd/server/ -run TestPostgresClientStore -v`

Expected: all six report SKIP with "TEST_DATABASE_URL not set".

Then, with the compose database up (`docker compose up -d postgres`):

Run: `TEST_DATABASE_URL='postgres://audit:audit@localhost:5432/audit?sslmode=disable' go test ./cmd/server/ -run TestPostgresClientStore -v`

Expected: PASS, all six.

- [ ] **Step 9: Change `NewPostgresStore` to accept a connection**

One pool must serve both the log store and the registry. In `main.go`, replace the opening of `NewPostgresStore`:

```go
func NewPostgresStore(db *sql.DB) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("a database handle is required for the postgres backend")
	}

	store := &PostgresStore{db: db}
	if err := store.ensureSchema(); err != nil {
		return nil, err
	}

	verify, err := store.Verify()
	if err != nil {
		return nil, err
	}
	if !verify.Valid {
		return nil, fmt.Errorf("invalid chain at index %d", derefUint64(verify.InvalidAt))
	}

	return store, nil
}
```

The old body opened the connection, pinged it, and closed it on failure. Connection lifecycle now belongs to `main()`, so all of that is deleted — including every `_ = db.Close()` inside this function.

- [ ] **Step 10: Own the connection in `main()` and require `DATABASE_URL`**

In `main()`, replace the block from `cfg := loadConfig()` through the end of the `switch cfg.StorageBackend` with:

```go
	cfg := loadConfig()

	// The client registry always lives in PostgreSQL, so a database is
	// required even when log entries go to a file.
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		log.Fatal("DATABASE_URL is required: the client registry is always stored in PostgreSQL, whatever STORAGE_BACKEND is set to")
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to reach database: %v", err)
	}

	clientStore, err := NewPostgresClientStore(db)
	if err != nil {
		log.Fatalf("failed to initialize client registry: %v", err)
	}

	var store Store
	switch cfg.StorageBackend {
	case "postgres":
		store, err = NewPostgresStore(db)
		if err != nil {
			log.Fatalf("failed to initialize postgres store: %v", err)
		}
		log.Printf("storage backend: postgres")
	case "file", "":
		store, err = NewFileStore(cfg.LogFile)
		if err != nil {
			log.Fatalf("failed to initialize file store: %v", err)
		}
		log.Printf("storage backend: file")
		log.Printf("append-only file: %s", cfg.LogFile)
	default:
		log.Fatalf("invalid STORAGE_BACKEND: %s", cfg.StorageBackend)
	}
```

Delete the old `var ( store Store; err error )` declaration it replaces.

`clientStore` is unused until Task 5. To keep the build green in the meantime, add this line immediately after the switch — Task 5 deletes it:

```go
	_ = clientStore // wired into the handlers in Task 5
```

- [ ] **Step 11: Build and run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS. Postgres suites skip without `TEST_DATABASE_URL`.

- [ ] **Step 12: Commit**

```bash
git add cmd/server/auth.go cmd/server/auth_test.go cmd/server/clientstore_postgres.go cmd/server/clientstore_postgres_test.go cmd/server/main.go
git commit -m "$(cat <<'EOF'
Add the PostgreSQL client registry and opaque tokens

Tokens are alog_<clientId>_<secret>. Only the SHA-256 of the secret is
stored, so a database leak yields nothing usable, and verification is one
primary-key read plus a constant-time compare.

parseToken splits on the first two separators only: the base64url alphabet
includes "_", so secrets can contain them.

DATABASE_URL is now required for every STORAGE_BACKEND, because the
registry always lives in PostgreSQL. main() owns the connection and hands
it to both stores.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Extract the router and require a token

Turns enforcement on. The handlers currently live inside `main()` as closures, which no test can reach, so they move to `newRouter` first. After this task every log endpoint demands a valid token; scoping comes in Task 6.

**Files:**
- Create: `cmd/server/router.go`
- Create: `cmd/server/handlers_test.go`
- Modify: `cmd/server/auth.go` — bearer parsing, context plumbing, middleware
- Modify: `cmd/server/main.go` — delete the inline mux, call `newRouter`

**Interfaces:**
- Consumes: `Principal`, `ClientStore`, `ErrUnauthorized` from Task 4; `parseLogQuery` from Task 1.
- Produces:
  - `func newRouter(cfg Config, store Store, clients ClientStore) *http.ServeMux`
  - `func bearerToken(r *http.Request) string`
  - `func principalFrom(ctx context.Context) (Principal, bool)`
  - `func requireAuth(clients ClientStore, handler http.HandlerFunc) http.HandlerFunc`
  - `func writeUnauthorized(w http.ResponseWriter)`
  - `type fakeClientStore` and `func newTestServer(t *testing.T) (*httptest.Server, *FileStore, *fakeClientStore)` (test helpers)

- [ ] **Step 1: Add bearer parsing and middleware to `cmd/server/auth.go`**

Add `"context"` and `"net/http"` to the imports, then append:

```go
// contextKey is unexported so no other package can collide with it.
type contextKey struct{ name string }

var principalContextKey = &contextKey{name: "principal"}

// bearerToken pulls the credential out of an Authorization header. The scheme
// is compared case-insensitively; the token itself is not.
func bearerToken(r *http.Request) string {
	header := strings.TrimSpace(r.Header.Get("authorization"))
	const scheme = "bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

func principalFrom(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey).(Principal)
	return principal, ok
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}

// requireAuth resolves the bearer token and puts the Principal in the request
// context. Every credential problem produces an identical 401, so the endpoint
// cannot be used to probe for valid client ids. A registry outage is a 503
// instead: it says nothing about the token, and reporting it as 401 would send
// operators hunting for a credential bug during a database incident.
func requireAuth(clients ClientStore, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeUnauthorized(w)
			return
		}

		principal, err := clients.Authenticate(token)
		if errors.Is(err, ErrUnauthorized) {
			writeUnauthorized(w)
			return
		}
		if err != nil {
			log.Printf("client registry unavailable: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication unavailable"})
			return
		}

		handler(w, r.WithContext(context.WithValue(r.Context(), principalContextKey, principal)))
	}
}
```

Add `"log"` to the imports of `auth.go` as well.

- [ ] **Step 2: Create `cmd/server/router.go`**

This is the handler block moved out of `main()` verbatim, with `requireAuth` wrapped around every endpoint except health. `main.go` is already 800 lines; the routes get their own file rather than growing it further.

```go
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// newRouter builds the HTTP surface. It takes its collaborators as arguments
// so tests can drive the real routes with a temp-file store and a fake
// registry.
func newRouter(cfg Config, store Store, clients ClientStore) *http.ServeMux {
	mux := http.NewServeMux()

	// Unauthenticated on purpose: deployment/deploy.sh polls this as the
	// post-deploy gate, before any token exists.
	mux.HandleFunc("/v1/health", withMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	mux.HandleFunc("/v1/logs", requireAuth(clients, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleWriteLog(w, r, cfg, store)
		case http.MethodGet:
			handleReadLogs(w, r, cfg, store)
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	}))

	mux.HandleFunc("/v1/logs/search", requireAuth(clients, withMethod(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		handleReadLogs(w, r, cfg, store)
	})))

	// Authenticated because the response leaks chain-global information: the
	// total entry count and the head hash.
	mux.HandleFunc("/v1/verify", requireAuth(clients, withMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		result, err := store.Verify()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify chain"})
			return
		}

		if result.Valid {
			writeJSON(w, http.StatusOK, result)
			return
		}

		writeJSON(w, http.StatusConflict, result)
	})))

	return mux
}

func handleWriteLog(w http.ResponseWriter, r *http.Request, cfg Config, store Store) {
	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxPayloadBytes)
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "payload exceeds max size"})
		return
	}

	var input LogRecord
	if err := json.Unmarshal(body, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	// Attribution is server-assigned. Task 6 stamps the authenticated client;
	// until then nobody gets to self-attribute.
	input.ClientID = ""

	input.App = strings.TrimSpace(input.App)
	input.Level = strings.TrimSpace(input.Level)
	input.Message = strings.TrimSpace(input.Message)
	if input.App == "" || input.Level == "" || input.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "app, level, and message are required"})
		return
	}
	if input.Metadata == nil {
		input.Metadata = map[string]any{}
	}

	entry, err := store.Append(input)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to append log entry"})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"index":     entry.Index,
		"timestamp": entry.Timestamp,
		"entryHash": entry.EntryHash,
		"prevHash":  entry.PrevHash,
	})
}

func handleReadLogs(w http.ResponseWriter, r *http.Request, cfg Config, store Store) {
	query, err := parseLogQuery(r, cfg.Query)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	result, err := store.QueryLogs(query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query logs"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
```

- [ ] **Step 3: Replace the inline mux in `main()`**

In `main.go`, delete everything from `mux := http.NewServeMux()` down to and including the closing of the `/v1/verify` handler, and delete the `_ = clientStore` line added in Task 4. In their place:

```go
	mux := newRouter(cfg, store, clientStore)
```

The `addr := cfg.ListenAddr()` block below it is unchanged. Remove any imports from `main.go` that are now unused — `io` moved to `router.go`.

- [ ] **Step 4: Write the failing auth tests**

Create `cmd/server/handlers_test.go`:

```go
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClientStore resolves tokens from a map so handler tests need no database.
type fakeClientStore struct {
	byToken map[string]Principal
	failure error
}

func (f *fakeClientStore) Authenticate(token string) (Principal, error) {
	if f.failure != nil {
		return Principal{}, f.failure
	}
	principal, ok := f.byToken[token]
	if !ok {
		return Principal{}, ErrUnauthorized
	}
	return principal, nil
}

func (f *fakeClientStore) Register(string, string) (string, string, error) {
	return "", "", errors.New("not implemented in the fake")
}
func (f *fakeClientStore) Rotate(string) (string, error) {
	return "", errors.New("not implemented in the fake")
}
func (f *fakeClientStore) Revoke(string) error {
	return errors.New("not implemented in the fake")
}
func (f *fakeClientStore) List() ([]ClientSummary, error) {
	return nil, errors.New("not implemented in the fake")
}

const (
	tokenAlpha  = "alog_1111111111111111_alpha-secret"
	tokenBeta   = "alog_2222222222222222_beta-secret"
	tokenAdmin  = "alog_3333333333333333_admin-secret"
	clientAlpha = "1111111111111111"
	clientBeta  = "2222222222222222"
)

func newTestServer(t *testing.T) (*httptest.Server, *FileStore, *fakeClientStore) {
	t.Helper()

	store, err := NewFileStore(filepath.Join(t.TempDir(), "audit.log.jsonl"))
	if err != nil {
		t.Fatalf("NewFileStore() error: %v", err)
	}

	clients := &fakeClientStore{byToken: map[string]Principal{
		tokenAlpha: {ClientID: clientAlpha, Name: "alpha", Role: RoleClient},
		tokenBeta:  {ClientID: clientBeta, Name: "beta", Role: RoleClient},
		tokenAdmin: {ClientID: "3333333333333333", Name: "ops", Role: RoleAdmin},
	}}

	cfg := Config{MaxPayloadBytes: 32768, Query: defaultQueryLimits()}
	server := httptest.NewServer(newRouter(cfg, store, clients))
	t.Cleanup(server.Close)

	return server, store, clients
}

// do issues a request against the test server, setting a bearer token when one
// is given.
func do(t *testing.T, server *httptest.Server, method, path, token, body string) *http.Response {
	t.Helper()

	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	return resp
}

func decodeResult(t *testing.T, resp *http.Response) LogQueryResult {
	t.Helper()

	var result LogQueryResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return result
}

func TestHealthNeedsNoToken(t *testing.T) {
	server, _, _ := newTestServer(t)

	resp := do(t, server, http.MethodGet, "/v1/health", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestLogEndpointsRejectMissingAndBadTokens(t *testing.T) {
	server, _, _ := newTestServer(t)

	endpoints := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/v1/logs", body: `{"app":"a","level":"INFO","message":"m"}`},
		{method: http.MethodGet, path: "/v1/logs"},
		{method: http.MethodGet, path: "/v1/logs/search?q=x"},
		{method: http.MethodGet, path: "/v1/verify"},
	}

	credentials := []struct {
		name  string
		token string
	}{
		{name: "no token", token: ""},
		{name: "unknown token", token: "alog_9999999999999999_nope"},
		{name: "malformed token", token: "garbage"},
	}

	for _, endpoint := range endpoints {
		for _, credential := range credentials {
			t.Run(endpoint.method+" "+endpoint.path+" with "+credential.name, func(t *testing.T) {
				resp := do(t, server, endpoint.method, endpoint.path, credential.token, endpoint.body)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
				}
				if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
					t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
				}

				var payload map[string]string
				if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
					t.Fatalf("decoding body: %v", err)
				}
				// Identical for every failure, so the endpoint is not an oracle.
				if payload["error"] != "unauthorized" {
					t.Errorf("error = %q, want %q", payload["error"], "unauthorized")
				}
			})
		}
	}
}

func TestWrongAuthSchemeIsRejected(t *testing.T) {
	server, _, _ := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/logs", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("authorization", "Basic "+tokenAlpha)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	server, _, _ := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, server.URL+"/v1/logs", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}
	req.Header.Set("authorization", "bEaReR "+tokenAlpha)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestValidTokenReachesTheHandlers(t *testing.T) {
	server, _, _ := newTestServer(t)

	resp := do(t, server, http.MethodPost, "/v1/logs", tokenAlpha, `{"app":"payments","level":"INFO","message":"ok"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("write status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	resp = do(t, server, http.MethodGet, "/v1/verify", tokenAlpha, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestRegistryOutageIsNotReportedAsUnauthorized(t *testing.T) {
	server, _, clients := newTestServer(t)
	clients.failure = errors.New("connection refused")

	resp := do(t, server, http.MethodGet, "/v1/logs", tokenAlpha, "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}
```

- [ ] **Step 5: Run to verify it fails, then passes**

Run: `go test ./cmd/server/ -run 'TestHealth|TestLogEndpoints|TestWrongAuth|TestBearerScheme|TestValidToken|TestRegistryOutage' -v`

Expected before Steps 1-3 are in place: FAIL to build with `undefined: newRouter`. With them in place: PASS.

- [ ] **Step 6: Run the full suite**

Run: `go build ./... && go test ./...`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cmd/server/router.go cmd/server/handlers_test.go cmd/server/auth.go cmd/server/main.go
git commit -m "$(cat <<'EOF'
Require a bearer token on every log endpoint

The handlers were closures inside main(), unreachable from a test. They
move to newRouter, which takes its collaborators as arguments so tests can
drive the real routes with a temp-file store and a fake registry.

Every credential failure returns an identical 401 so the endpoint cannot be
used to probe for valid client ids. A registry outage returns 503 instead:
it says nothing about the token, and a 401 would send operators hunting a
credential bug during a database incident.

/v1/health stays open because deploy.sh polls it before any token exists.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Scope writes and reads to the authenticated client

Stamps the caller's id onto every entry and confines every read to it, with the `admin` role as the deliberate exception. Adds the composite index that makes a client-scoped page proportional to the page size rather than the table.

**Files:**
- Modify: `cmd/server/auth.go` — `scopeQuery`
- Modify: `cmd/server/router.go` — stamping, scoping
- Modify: `cmd/server/main.go` — `LogQuery.ClientID`, `matchesQuery`, `PostgresStore.QueryLogs`, `ensureSchema`
- Modify: `cmd/server/handlers_test.go` — isolation tests

**Interfaces:**
- Consumes: `Principal`, `principalFrom`, `newRouter` from Task 5; `LogQuery` from Task 2.
- Produces:
  - `LogQuery.ClientID string`
  - `func scopeQuery(query LogQuery, principal Principal, r *http.Request) LogQuery`

- [ ] **Step 1: Write the failing isolation tests**

Append to `cmd/server/handlers_test.go`:

```go
// seedTwoClientsAndLegacy writes entries for alpha, for beta, and one
// unattributed entry of the kind that existed before authorization.
func seedTwoClientsAndLegacy(t *testing.T, store *FileStore) {
	t.Helper()

	records := []LogRecord{
		{App: "legacy-app", Level: "INFO", Message: "written before auth existed"},
		{ClientID: clientAlpha, App: "payments", Level: "INFO", Message: "alpha one"},
		{ClientID: clientBeta, App: "billing", Level: "ERROR", Message: "beta one"},
		{ClientID: clientAlpha, App: "payments", Level: "ERROR", Message: "alpha two"},
		{ClientID: clientBeta, App: "billing", Level: "INFO", Message: "beta two"},
	}

	for _, record := range records {
		if _, err := store.Append(record); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}
}

func TestWriteStampsTheAuthenticatedClient(t *testing.T) {
	server, store, _ := newTestServer(t)

	resp := do(t, server, http.MethodPost, "/v1/logs", tokenAlpha, `{"app":"payments","level":"INFO","message":"stamped"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	result, err := store.QueryLogs(LogQuery{Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("stored %d entries, want 1", len(result.Items))
	}
	if got := result.Items[0].Record.ClientID; got != clientAlpha {
		t.Fatalf("stored clientId = %q, want %q", got, clientAlpha)
	}
}

func TestWriteOverwritesCallerSuppliedClientID(t *testing.T) {
	server, store, _ := newTestServer(t)

	// Alpha's token, but the body claims to be beta.
	body := `{"clientId":"` + clientBeta + `","app":"payments","level":"INFO","message":"forged"}`
	resp := do(t, server, http.MethodPost, "/v1/logs", tokenAlpha, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	result, err := store.QueryLogs(LogQuery{Limit: 10})
	if err != nil {
		t.Fatalf("QueryLogs() error: %v", err)
	}
	if got := result.Items[0].Record.ClientID; got != clientAlpha {
		t.Fatalf("stored clientId = %q, want %q — attribution was forgeable", got, clientAlpha)
	}
}

func TestReadsAreScopedToTheCallersClient(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50", tokenAlpha, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 2 {
		t.Fatalf("alpha saw %d entries, want 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Record.ClientID != clientAlpha {
			t.Fatalf("alpha saw an entry belonging to %q", item.Record.ClientID)
		}
	}
}

func TestSearchIsScopedToTheCallersClient(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	// "one" matches both "alpha one" and "beta one".
	resp := do(t, server, http.MethodGet, "/v1/logs/search?q=one&limit=50", tokenAlpha, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 1 {
		t.Fatalf("search returned %d entries, want 1", len(result.Items))
	}
	if result.Items[0].Record.ClientID != clientAlpha {
		t.Fatal("free-text search reached across clients")
	}
}

func TestNonAdminCannotWidenScopeWithClientIDParam(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	// Alpha asks for beta's entries. The parameter is ignored, not honoured,
	// and not an error.
	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50&clientId="+clientBeta, tokenAlpha, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	result := decodeResult(t, resp)
	if len(result.Items) != 2 {
		t.Fatalf("returned %d entries, want alpha's 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Record.ClientID != clientAlpha {
			t.Fatalf("clientId parameter widened scope to %q", item.Record.ClientID)
		}
	}
}

func TestAdminReadsEverythingIncludingLegacyEntries(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50", tokenAdmin, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 5 {
		t.Fatalf("admin saw %d entries, want all 5", len(result.Items))
	}

	var legacy int
	for _, item := range result.Items {
		if item.Record.ClientID == "" {
			legacy++
		}
	}
	if legacy != 1 {
		t.Fatalf("admin saw %d unattributed entries, want 1", legacy)
	}
}

func TestAdminCanScopeToOneClient(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	resp := do(t, server, http.MethodGet, "/v1/logs?limit=50&clientId="+clientBeta, tokenAdmin, "")
	result := decodeResult(t, resp)

	if len(result.Items) != 2 {
		t.Fatalf("admin scoped read returned %d entries, want 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.Record.ClientID != clientBeta {
			t.Fatalf("scoped read returned an entry for %q", item.Record.ClientID)
		}
	}
}

func TestScopedPaginationDoesNotLeakAcrossClients(t *testing.T) {
	server, store, _ := newTestServer(t)
	seedTwoClientsAndLegacy(t, store)

	// A page size of 1 forces a cursor walk through interleaved owners.
	seen := 0
	path := "/v1/logs?limit=1"
	for page := 0; page < 10; page++ {
		resp := do(t, server, http.MethodGet, path, tokenBeta, "")
		result := decodeResult(t, resp)

		for _, item := range result.Items {
			if item.Record.ClientID != clientBeta {
				t.Fatalf("page %d leaked an entry belonging to %q", page, item.Record.ClientID)
			}
			seen++
		}
		if result.NextCursor == nil {
			break
		}
		path = "/v1/logs?limit=1&cursor=" + *result.NextCursor
	}

	if seen != 2 {
		t.Fatalf("cursor walk saw %d of beta's entries, want 2", seen)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/server/ -run 'TestWriteStamps|TestWriteOverwrites|TestReadsAreScoped|TestSearchIsScoped|TestNonAdmin|TestAdmin|TestScopedPagination' -v`

Expected: FAIL. `TestWriteStampsTheAuthenticatedClient` fails with `stored clientId = "", want "1111111111111111"`; the scoping tests fail because every client currently sees all five entries.

- [ ] **Step 3: Add `ClientID` to `LogQuery` in `cmd/server/main.go`**

Add the field to the struct defined in Task 2:

```go
type LogQuery struct {
	// ClientID confines the result to one client. The handlers set it from the
	// authenticated principal; it is never taken from caller input except for
	// an admin.
	ClientID string
	App      string
	Level    string
	Text     string
	Limit    int
	Offset   int
	AfterIndex uint64
	WantTotal  bool
}
```

- [ ] **Step 4: Filter by client in `matchesQuery`**

In `main.go`, add this as the **first** check in `matchesQuery`, before the app and level checks:

```go
	// Exact comparison, unlike app and level: client ids are generated
	// identifiers, and a case-insensitive match on a security boundary is a
	// bug waiting to happen.
	if query.ClientID != "" && entry.Record.ClientID != query.ClientID {
		return false
	}
```

- [ ] **Step 5: Filter by client in `PostgresStore.QueryLogs`**

In the filter-building block written in Task 2, add this immediately before the `query.App` block so the client predicate is the first argument:

```go
	if query.ClientID != "" {
		filterArgs = append(filterArgs, query.ClientID)
		filters = append(filters, fmt.Sprintf("record_json::jsonb->>'clientId' = $%d", len(filterArgs)))
	}
```

- [ ] **Step 6: Add the composite index to `PostgresStore.ensureSchema`**

Append to the DDL string in `ensureSchema`:

```sql
CREATE INDEX IF NOT EXISTS idx_audit_log_entries_client_index
    ON audit_log_entries ((record_json::jsonb->>'clientId'), entry_index);
```

The index must be composite. `entry_index > cursor` alone walks the primary key
in order but then discards every row belonging to another client, so a client
holding a small share of a large log would still scan far. Both columns in one
index make a scoped page an index range scan.

It indexes the expression over `record_json` rather than a denormalised
`client_id` column on purpose: a denormalised column would sit outside the hash
chain, where a direct `UPDATE` could make one client's entries readable by
another with nothing to detect it.

- [ ] **Step 7: Add `scopeQuery` to `cmd/server/auth.go`**

```go
// scopeQuery confines a read to the caller. A non-admin is pinned to its own
// client id and the clientId parameter is ignored — ignored rather than
// rejected, so a caller cannot use the error to discover which ids exist.
//
// An admin with no clientId parameter sees everything, including the
// unattributed entries written before authorization existed.
func scopeQuery(query LogQuery, principal Principal, r *http.Request) LogQuery {
	if principal.IsAdmin() {
		query.ClientID = strings.TrimSpace(r.URL.Query().Get("clientId"))
		return query
	}

	query.ClientID = principal.ClientID
	return query
}
```

- [ ] **Step 8: Stamp and scope in `cmd/server/router.go`**

In `handleWriteLog`, replace the placeholder from Task 5:

```go
	// Attribution is server-assigned. Task 6 stamps the authenticated client;
	// until then nobody gets to self-attribute.
	input.ClientID = ""
```

with:

```go
	principal, ok := principalFrom(r.Context())
	if !ok {
		// Unreachable behind requireAuth; a 500 here means the route was wired
		// without the middleware.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "missing principal"})
		return
	}

	// Assigned from the token, overwriting whatever the caller sent, so
	// attribution cannot be forged.
	input.ClientID = principal.ClientID
```

In `handleReadLogs`, after the `parseLogQuery` error check, add:

```go
	principal, ok := principalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "missing principal"})
		return
	}
	query = scopeQuery(query, principal, r)
```

- [ ] **Step 9: Run the isolation tests**

Run: `go test ./cmd/server/ -run 'TestWriteStamps|TestWriteOverwrites|TestReadsAreScoped|TestSearchIsScoped|TestNonAdmin|TestAdmin|TestScopedPagination' -v`

Expected: PASS, all eight.

- [ ] **Step 10: Run the full suite, including against PostgreSQL**

Run: `go build ./... && go test ./...`

Expected: PASS.

With the compose database up:

Run: `TEST_DATABASE_URL='postgres://audit:audit@localhost:5432/audit?sslmode=disable' go test ./cmd/server/ -v`

Expected: PASS, with the Postgres suites running rather than skipping.

- [ ] **Step 11: Confirm the index is actually used**

With the compose database up and at least a few hundred rows present, run:

```bash
psql 'postgres://audit:audit@localhost:5432/audit?sslmode=disable' -c "
EXPLAIN SELECT entry_index FROM audit_log_entries
WHERE record_json::jsonb->>'clientId' = 'x' AND entry_index > 0
ORDER BY entry_index ASC LIMIT 51;"
```

Expected: the plan names `idx_audit_log_entries_client_index`. If it shows a
sequential scan, the row count is too low for the planner to bother — that is
fine, but confirm the index exists with `\d audit_log_entries`.

- [ ] **Step 12: Commit**

```bash
git add cmd/server/auth.go cmd/server/router.go cmd/server/main.go cmd/server/handlers_test.go
git commit -m "$(cat <<'EOF'
Scope writes and reads to the authenticated client

Writes are stamped with the caller's client id, overwriting anything the
body claimed, so attribution cannot be forged. Reads are pinned to that id;
the clientId parameter is ignored for a non-admin rather than rejected, so
the error cannot be used to discover which ids exist.

An admin reads across all clients, including the unattributed entries that
predate authorization, and can scope to one client on request.

The index is composite over (clientId, entry_index): a cursor alone walks
the primary key and then discards other clients' rows. It indexes the
expression over record_json rather than a denormalised column, which would
sit outside the hash chain where an UPDATE could re-point attribution
undetectably.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: The `clients` registration CLI

Adds registration, listing, rotation and revocation as argv subcommands of the existing server binary, so `deployment/deploy.sh` keeps shipping one artifact with nothing to keep in sync.

**Files:**
- Create: `cmd/server/clients_cli.go`
- Create: `cmd/server/clients_cli_test.go`
- Modify: `cmd/server/main.go` — argv dispatch at the top of `main()`

**Interfaces:**
- Consumes: `ClientStore`, `ClientSummary`, `RoleClient`, `RoleAdmin` from Task 4.
- Produces:
  - `func runClientsCLI(store ClientStore, args []string, out io.Writer) int`
  - `func runClientsCommand(args []string) int`

- [ ] **Step 1: Write the failing CLI tests**

Create `cmd/server/clients_cli_test.go`:

```go
package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// memoryClientStore is a working in-memory registry. The fake in
// handlers_test.go only needs Authenticate; the CLI exercises everything else.
type memoryClientStore struct {
	clients map[string]*ClientSummary
	secrets map[string]string
	nextID  int
}

func newMemoryClientStore() *memoryClientStore {
	return &memoryClientStore{
		clients: make(map[string]*ClientSummary),
		secrets: make(map[string]string),
	}
}

func (m *memoryClientStore) Authenticate(token string) (Principal, error) {
	clientID, secret, err := parseToken(token)
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	client, ok := m.clients[clientID]
	if !ok || client.Revoked || m.secrets[clientID] != secret {
		return Principal{}, ErrUnauthorized
	}
	return Principal{ClientID: clientID, Name: client.Name, Role: client.Role}, nil
}

func (m *memoryClientStore) Register(name, role string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", errors.New("client name is required")
	}
	if role == "" {
		role = RoleClient
	}
	if !validRole(role) {
		return "", "", fmt.Errorf("invalid role %q", role)
	}

	m.nextID++
	clientID := fmt.Sprintf("%016d", m.nextID)
	secret := fmt.Sprintf("secret-%d", m.nextID)

	m.clients[clientID] = &ClientSummary{
		ClientID:  clientID,
		Name:      name,
		Role:      role,
		CreatedAt: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
	}
	m.secrets[clientID] = secret

	return clientID, formatToken(clientID, secret), nil
}

func (m *memoryClientStore) Rotate(clientID string) (string, error) {
	client, ok := m.clients[clientID]
	if !ok || client.Revoked {
		return "", fmt.Errorf("no active client with id %q", clientID)
	}
	secret := "rotated-" + clientID
	m.secrets[clientID] = secret
	return formatToken(clientID, secret), nil
}

func (m *memoryClientStore) Revoke(clientID string) error {
	client, ok := m.clients[clientID]
	if !ok || client.Revoked {
		return fmt.Errorf("no active client with id %q", clientID)
	}
	client.Revoked = true
	return nil
}

func (m *memoryClientStore) List() ([]ClientSummary, error) {
	summaries := make([]ClientSummary, 0, len(m.clients))
	for _, client := range m.clients {
		summaries = append(summaries, *client)
	}
	return summaries, nil
}

func runCLI(t *testing.T, store ClientStore, args ...string) (string, int) {
	t.Helper()

	var out bytes.Buffer
	code := runClientsCLI(store, args, &out)
	return out.String(), code
}

func TestClientsRegisterPrintsTokenOnceWithAWarning(t *testing.T) {
	store := newMemoryClientStore()

	output, code := runCLI(t, store, "register", "--name", "payments-api")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0. output:\n%s", code, output)
	}

	if !strings.Contains(output, "0000000000000001") {
		t.Errorf("output does not contain the client id:\n%s", output)
	}
	if !strings.Contains(output, "alog_0000000000000001_secret-1") {
		t.Errorf("output does not contain the token:\n%s", output)
	}
	if strings.Count(output, "alog_0000000000000001_secret-1") != 1 {
		t.Errorf("token printed more than once:\n%s", output)
	}
	if !strings.Contains(strings.ToLower(output), "not recoverable") {
		t.Errorf("output does not warn that the token cannot be retrieved again:\n%s", output)
	}
}

func TestClientsRegisterRole(t *testing.T) {
	store := newMemoryClientStore()

	if _, code := runCLI(t, store, "register", "--name", "ops", "--role", "admin"); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	summaries, err := store.List()
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if summaries[0].Role != RoleAdmin {
		t.Fatalf("Role = %q, want %q", summaries[0].Role, RoleAdmin)
	}
}

func TestClientsRegisterRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing name", args: []string{"register"}},
		{name: "blank name", args: []string{"register", "--name", "   "}},
		{name: "invalid role", args: []string{"register", "--name", "x", "--role", "root"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, code := runCLI(t, newMemoryClientStore(), tc.args...)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero. output:\n%s", output)
			}
			if strings.Contains(output, "alog_") {
				t.Fatalf("a token was printed on a failed registration:\n%s", output)
			}
		})
	}
}

func TestClientsListShowsClientsWithoutSecrets(t *testing.T) {
	store := newMemoryClientStore()
	if _, _, err := store.Register("payments-api", RoleClient); err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	output, code := runCLI(t, store, "list")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(output, "payments-api") {
		t.Errorf("list output missing the client name:\n%s", output)
	}
	if !strings.Contains(output, "active") {
		t.Errorf("list output missing the status:\n%s", output)
	}
	// The one thing list must never do.
	if strings.Contains(output, "alog_") || strings.Contains(output, "secret-") {
		t.Errorf("list leaked a token or secret:\n%s", output)
	}
}

func TestClientsListMarksRevoked(t *testing.T) {
	store := newMemoryClientStore()
	clientID, _, err := store.Register("gone", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}
	if err := store.Revoke(clientID); err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}

	output, _ := runCLI(t, store, "list")
	if !strings.Contains(output, "revoked") {
		t.Errorf("list did not mark the revoked client:\n%s", output)
	}
}

func TestClientsRotate(t *testing.T) {
	store := newMemoryClientStore()
	clientID, oldToken, err := store.Register("payments-api", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	output, code := runCLI(t, store, "rotate", "--id", clientID)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0. output:\n%s", code, output)
	}
	if strings.Contains(output, oldToken) {
		t.Errorf("rotate printed the superseded token:\n%s", output)
	}
	if !strings.Contains(output, "alog_"+clientID+"_rotated-"+clientID) {
		t.Errorf("rotate did not print the new token:\n%s", output)
	}
}

func TestClientsRevoke(t *testing.T) {
	store := newMemoryClientStore()
	clientID, token, err := store.Register("payments-api", RoleClient)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	output, code := runCLI(t, store, "revoke", "--id", clientID)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0. output:\n%s", code, output)
	}
	if _, err := store.Authenticate(token); err == nil {
		t.Fatal("the token still authenticates after revoke")
	}

	// Revoking twice reports the failure rather than pretending to succeed.
	if _, code := runCLI(t, store, "revoke", "--id", clientID); code == 0 {
		t.Fatal("second revoke exited 0, want non-zero")
	}
}

func TestClientsUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "no subcommand", args: nil},
		{name: "unknown subcommand", args: []string{"delete"}},
		{name: "rotate without id", args: []string{"rotate"}},
		{name: "revoke without id", args: []string{"revoke"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, code := runCLI(t, newMemoryClientStore(), tc.args...)
			if code == 0 {
				t.Fatalf("exit code = 0, want non-zero. output:\n%s", output)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./cmd/server/ -run TestClients -v`

Expected: FAIL to build with `undefined: runClientsCLI`.

- [ ] **Step 3: Create `cmd/server/clients_cli.go`**

```go
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

const clientsUsage = `Usage: audit clients <command> [flags]

Commands:
  register --name <name> [--role client|admin]   Create a client and mint its token
  list                                           Show every client
  rotate --id <clientId>                         Issue a new token for a client
  revoke --id <clientId>                         Disable a client's token

DATABASE_URL must be set. The registry always lives in PostgreSQL.`

// runClientsCLI executes an admin subcommand against a registry. It takes the
// store and the output stream as arguments so it is testable without a
// database. The return value is the process exit code.
func runClientsCLI(store ClientStore, args []string, out io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(out, clientsUsage)
		return 2
	}

	switch args[0] {
	case "register":
		return clientsRegister(store, args[1:], out)
	case "list":
		return clientsList(store, out)
	case "rotate":
		return clientsRotate(store, args[1:], out)
	case "revoke":
		return clientsRevoke(store, args[1:], out)
	default:
		fmt.Fprintf(out, "unknown command %q\n\n%s\n", args[0], clientsUsage)
		return 2
	}
}

func clientsRegister(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients register", flag.ContinueOnError)
	flags.SetOutput(out)
	name := flags.String("name", "", "human-readable client name (required)")
	role := flags.String("role", RoleClient, "client or admin")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	clientID, token, err := store.Register(*name, *role)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "client id: %s\n", clientID)
	fmt.Fprintf(out, "token:     %s\n", token)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Give this token to the client now. Only its hash is stored, so the")
	fmt.Fprintln(out, "token is not recoverable. If it is lost, run: audit clients rotate")

	return 0
}

func clientsList(store ClientStore, out io.Writer) int {
	summaries, err := store.List()
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	if len(summaries) == 0 {
		fmt.Fprintln(out, "no clients registered")
		return 0
	}

	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(writer, "CLIENT ID\tNAME\tROLE\tCREATED\tSTATUS")
	for _, summary := range summaries {
		status := "active"
		if summary.Revoked {
			status = "revoked"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n",
			summary.ClientID, summary.Name, summary.Role,
			summary.CreatedAt.UTC().Format(time.RFC3339), status)
	}
	if err := writer.Flush(); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	return 0
}

func clientsRotate(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients rotate", flag.ContinueOnError)
	flags.SetOutput(out)
	clientID := flags.String("id", "", "client id to rotate (required)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*clientID) == "" {
		fmt.Fprintln(out, "error: --id is required")
		return 2
	}

	token, err := store.Rotate(*clientID)
	if err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "token: %s\n", token)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "The previous token stopped working the moment this one was issued.")
	fmt.Fprintln(out, "Update the client's configuration and restart it now.")

	return 0
}

func clientsRevoke(store ClientStore, args []string, out io.Writer) int {
	flags := flag.NewFlagSet("clients revoke", flag.ContinueOnError)
	flags.SetOutput(out)
	clientID := flags.String("id", "", "client id to revoke (required)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*clientID) == "" {
		fmt.Fprintln(out, "error: --id is required")
		return 2
	}

	if err := store.Revoke(*clientID); err != nil {
		fmt.Fprintf(out, "error: %v\n", err)
		return 1
	}

	fmt.Fprintf(out, "revoked %s\n", *clientID)
	fmt.Fprintln(out, "Entries it already wrote keep its attribution.")

	return 0
}

// runClientsCommand wires the CLI to a real registry. It never starts a
// listener.
func runClientsCommand(args []string) int {
	cfg := loadConfig()
	if strings.TrimSpace(cfg.DatabaseURL) == "" {
		fmt.Fprintln(os.Stderr, "error: DATABASE_URL is required")
		return 1
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open database: %v\n", err)
		return 1
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to reach database: %v\n", err)
		return 1
	}

	store, err := NewPostgresClientStore(db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to open client registry: %v\n", err)
		return 1
	}

	return runClientsCLI(store, args, os.Stdout)
}
```

- [ ] **Step 4: Dispatch on argv in `main()`**

Make this the **first** statement in `main()` in `main.go`:

```go
	// Admin subcommands run against the registry and exit without starting a
	// listener, so deployment ships one binary.
	if len(os.Args) > 1 && os.Args[1] == "clients" {
		os.Exit(runClientsCommand(os.Args[2:]))
	}
```

- [ ] **Step 5: Run the CLI tests**

Run: `go test ./cmd/server/ -run TestClients -v`

Expected: PASS, all eight.

- [ ] **Step 6: Exercise the CLI end to end**

With the compose database up:

```bash
export DATABASE_URL='postgres://audit:audit@localhost:5432/audit?sslmode=disable'
go run ./cmd/server clients register --name smoke-test
go run ./cmd/server clients list
```

Expected: `register` prints a client id, a token starting `alog_`, and the
warning. `list` shows the client as `active` and prints no token.

Then, using the token from `register`:

```bash
go run ./cmd/server &
curl -s -X POST http://localhost:8080/v1/logs \
  -H "authorization: Bearer <token from register>" \
  -H "content-type: application/json" \
  -d '{"app":"smoke","level":"INFO","message":"hello"}'
curl -s "http://localhost:8080/v1/logs?limit=5" -H "authorization: Bearer <token>"
```

Expected: the write returns `201`, and the read returns only that entry with
`"clientId"` set to the registered id.

Finally, confirm the cutover:

```bash
go run ./cmd/server clients rotate --id <client id>
curl -s -i "http://localhost:8080/v1/logs" -H "authorization: Bearer <old token>" | head -1
```

Expected: `HTTP/1.1 401 Unauthorized`.

- [ ] **Step 7: Run the full suite and commit**

Run: `go build ./... && go test ./...`

Expected: PASS.

```bash
git add cmd/server/clients_cli.go cmd/server/clients_cli_test.go cmd/server/main.go
git commit -m "$(cat <<'EOF'
Add the clients registration CLI

register, list, rotate and revoke run as argv subcommands of the server
binary, so deployment keeps shipping one artifact with nothing to keep in
sync. There is no HTTP registration endpoint by design.

register and rotate print the token exactly once with the warning that only
its hash is stored. list never prints a token or a hash.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Client-side integration — Node library and Postman

The Go library already has `AuthToken` (`clients/go-lib/client.go:33,126`) and the forwarder already sends it, so neither changes. The Node library has no auth support at all, and the Postman collection sends no token and pages by offset.

**Files:**
- Modify: `clients/node-lib/index.mjs` — `authToken` option
- Create: `clients/node-lib/index.test.mjs`
- Modify: `postman/Audit-Logging-API.postman_collection.json`
- Modify: `Makefile` — a `test-node` target

**Interfaces:**
- Consumes: the wire contract from Tasks 5-6.
- Produces: `new AuditLogger({ authToken })` sends `authorization: Bearer <token>`.

- [ ] **Step 1: Write the failing Node tests**

Node 18+ ships a test runner in `node:test`, so this needs no new dependency.

Create `clients/node-lib/index.test.mjs`:

```javascript
import test from "node:test";
import assert from "node:assert/strict";

import { AuditLogger } from "./index.mjs";

function stubFetch(captured, response = {}) {
  const { status = 201, body = '{"index":1}' } = response;
  return async (url, options) => {
    captured.push({ url, options });
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => body
    };
  };
}

test("sends a bearer token when one is configured", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured),
    authToken: "alog_1111111111111111_secret"
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal(captured.length, 1);
  assert.equal(
    captured[0].options.headers.authorization,
    "Bearer alog_1111111111111111_secret"
  );
});

test("omits the authorization header when no token is configured", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured)
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal("authorization" in captured[0].options.headers, false);
});

test("trims surrounding whitespace from the token", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured),
    authToken: "  alog_1111111111111111_secret  "
  });

  await logger.writeLog({ app: "a", level: "INFO", message: "m" });

  assert.equal(
    captured[0].options.headers.authorization,
    "Bearer alog_1111111111111111_secret"
  );
});

test("does not retry a 401 — a bad token will never become good", async () => {
  const captured = [];
  const logger = new AuditLogger({
    endpoint: "http://audit.test/v1/logs",
    fetchImpl: stubFetch(captured, { status: 401, body: '{"error":"unauthorized"}' }),
    authToken: "alog_1111111111111111_wrong",
    retry: { maxAttempts: 5, initialBackoffMs: 1 }
  });

  await assert.rejects(
    () => logger.writeLog({ app: "a", level: "INFO", message: "m" }),
    /401/
  );
  assert.equal(captured.length, 1, "a 401 must not be retried");
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test clients/node-lib/`

Expected: the first and third tests FAIL — the header is absent because the library has no `authToken` option. The second and fourth already pass (`shouldRetryStatus` covers only 429 and 5xx, so 401 is correctly not retried; the test locks that in).

- [ ] **Step 3: Add `authToken` to `clients/node-lib/index.mjs`**

In the constructor, add the option to the destructured parameters:

```javascript
  constructor({
    endpoint = "http://localhost:8080/v1/logs",
    fetchImpl = globalThis.fetch,
    authToken = "",
    retry = {}
  } = {}) {
```

and assign it alongside the other fields, immediately after `this.fetchImpl = fetchImpl;`:

```javascript
    this.authToken = String(authToken ?? "").trim();
```

In `writeLog`, replace the `headers` object in the `fetchImpl` call:

```javascript
          headers: {
            "content-type": "application/json"
          },
```

with:

```javascript
          headers: {
            "content-type": "application/json",
            // Spread so the header is absent, not empty, when unconfigured.
            ...(this.authToken ? { authorization: `Bearer ${this.authToken}` } : {})
          },
```

- [ ] **Step 4: Run the Node tests**

Run: `node --test clients/node-lib/`

Expected: PASS, all four.

- [ ] **Step 5: Add a `test-node` Makefile target**

In `Makefile`, add `test-node` to the `.PHONY` line, then add the target after the existing `test` target:

```make
test-node:
	node --test clients/node-lib/
```

- [ ] **Step 6: Add bearer auth to the Postman collection**

Edit `postman/Audit-Logging-API.postman_collection.json`.

Add an `authToken` entry to the top-level `variable` array, alongside the existing `baseUrl`, `appName`, `level` and `message`:

```json
    {
      "key": "authToken",
      "value": "alog_replace_me"
    },
    {
      "key": "nextCursor",
      "value": ""
    }
```

Add a collection-level `auth` block as a sibling of `item` and `variable`:

```json
  "auth": {
    "type": "bearer",
    "bearer": [
      { "key": "token", "value": "{{authToken}}", "type": "string" }
    ]
  }
```

On the **Health** request only, add a sibling of its `method` and `url` so it
does not inherit the token:

```json
        "auth": { "type": "noauth" }
```

- [ ] **Step 7: Rewrite the paginated request to use a cursor**

Replace the `List Logs (Paginated)` item's `url` with:

```json
          "url": {
            "raw": "{{baseUrl}}/v1/logs?limit=50&cursor={{nextCursor}}",
            "host": ["{{baseUrl}}"],
            "path": ["v1", "logs"],
            "query": [
              { "key": "limit", "value": "50" },
              { "key": "cursor", "value": "{{nextCursor}}" }
            ]
          }
```

and add an `event` array to that same item so re-sending walks the pages:

```json
          "event": [
            {
              "listen": "test",
              "script": {
                "type": "text/javascript",
                "exec": [
                  "const body = pm.response.json();",
                  "// Store the cursor so re-sending this request fetches the next page.",
                  "// A null cursor means the last page; clear it so the next send restarts.",
                  "pm.collectionVariables.set('nextCursor', body.nextCursor || '');",
                  "pm.test('request was authorized', () => pm.response.code !== 401);"
                ]
              }
            }
          ]
```

Also remove the `offset` query entry from the `Search Logs (q)` request, leaving
`q` and `limit`.

- [ ] **Step 8: Validate the collection is still well-formed JSON**

Run:

```bash
python3 -c "import json; d=json.load(open('postman/Audit-Logging-API.postman_collection.json')); print('ok', len(d['item']), 'requests,', len(d['variable']), 'variables')"
```

Expected: `ok 7 requests, 6 variables`.

- [ ] **Step 9: Commit**

```bash
git add clients/node-lib/index.mjs clients/node-lib/index.test.mjs postman/Audit-Logging-API.postman_collection.json Makefile
git commit -m "$(cat <<'EOF'
Add token support to the Node client and Postman collection

The Node library had no auth support at all; it now takes an authToken
option and sends it as a bearer header, omitting the header entirely when
unconfigured. Tests use the built-in node:test runner, so no new
dependency.

A 401 is not retried, and a test now locks that in: a rejected token will
not become valid on the next attempt.

The Postman collection gains a collection-level bearer variable, exempts
health from it, and pages by cursor instead of offset.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Integration guides

The two new documents users are pointed at. Both are written for someone integrating a service for the first time, not for someone who already read the spec.

**Files:**
- Create: `docs/authorization.md`
- Create: `docs/querying.md`

**Interfaces:**
- Consumes: the behaviour built in Tasks 1-8. Every command and response in these documents must be one you actually ran in Task 7 Step 6.

- [ ] **Step 1: Create `docs/authorization.md`**

Write this file exactly. The outer fence below is five backticks so the fenced
blocks inside survive; do not copy the outer fence into the file.

`````markdown
# Authorization

Every call that writes or reads log entries needs a token. This page covers
getting one, using it, and what happens when it goes wrong.

## The model

A **client** is a tenant. It is the unit of ownership and the unit of access:

- Every entry a client writes is stamped with that client's id by the server.
- Every read a client makes returns only that client's entries.

`app` is *not* the boundary. It stays a free-text label you can use however you
like — one client may write under many app names, and two clients may use the
same one without seeing each other's entries.

The `clientId` is stored inside the hashed record, so it is covered by the
tamper-evident hash chain. Attribution cannot be altered after the fact without
`GET /v1/verify` failing.

## Getting a token

Registration is deliberately local-only: there is no HTTP endpoint for it. An
operator runs this on the server, where `DATABASE_URL` is already set:

```bash
audit clients register --name payments-api
```

```
client id: a1b2c3d4e5f60718
token:     alog_a1b2c3d4e5f60718_x7Qk...

Give this token to the client now. Only its hash is stored, so the
token is not recoverable. If it is lost, run: audit clients rotate
```

**The token is shown once.** The service stores only its SHA-256 hash, so
nobody — including the operator — can read it back. If it is lost, rotate.

For a client that needs to read across all tenants (an operations dashboard, a
compliance export), register it as an admin instead:

```bash
audit clients register --name ops-dashboard --role admin
```

Treat an admin token as far more sensitive than a client token: it can read
every entry in the system.

## Making authenticated calls

Send the token as a bearer credential. The scheme is case-insensitive; the
token is not.

### Write an entry

```bash
curl -s -X POST http://localhost:8080/v1/logs \
  -H "authorization: Bearer $AUDIT_TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "app": "payments-api",
    "level": "INFO",
    "message": "invoice created",
    "metadata": {"invoiceId": "inv_123"}
  }'
```

You do not send `clientId`. If you do, the server overwrites it with the
identity behind your token — attribution is not something a caller can set.

### Read your entries

```bash
curl -s "http://localhost:8080/v1/logs?limit=20" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

### Search your entries

```bash
curl -s "http://localhost:8080/v1/logs/search?q=timeout&limit=10" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

### Verify the chain

```bash
curl -s http://localhost:8080/v1/verify \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

The chain is global, so the result covers every entry rather than only yours.
It needs a token because the response reveals the total entry count and the
head hash.

### Health

`GET /v1/health` takes no token. It is the only endpoint that does not.

## What you can and cannot see

| You are | You see |
| --- | --- |
| A `client` | Only entries your own token wrote. |
| An `admin` | Every entry, including entries written before authorization existed. Add `?clientId=<id>` to narrow to one client. |

Passing `?clientId=` as a non-admin does nothing. It is ignored rather than
rejected, so the response cannot be used to work out which client ids exist.

Entries written before this feature shipped have no `clientId`. They remain in
the chain and still verify, but only an admin can read them.

## Language clients

Go — `clients/go-lib`:

```go
client := auditclient.New("http://localhost:8080/v1/logs", nil)
client.AuthToken = os.Getenv("AUDIT_TOKEN")
```

Node — `clients/node-lib`:

```javascript
const logger = new AuditLogger({
  endpoint: "http://localhost:8080/v1/logs",
  authToken: process.env.AUDIT_TOKEN
});
```

Log forwarder — set `auth_bearer_token` in the forwarder's config file to the
registered token. See `cmd/log-forwarder/README.md`.

Both libraries retry on `429` and `5xx` only. A `401` is returned to you
immediately, because a rejected token will not become valid on a retry.

## Rotation

```bash
audit clients rotate --id a1b2c3d4e5f60718
```

**Rotation is a hard cutover.** A client row holds exactly one token hash, so
the previous token stops working the instant the new one is issued. There is no
overlap window.

The client id does not change, so entries the client has already written keep
their attribution.

To keep the gap small:

1. Schedule a brief window — writes during the gap will fail with `401`.
2. Run `rotate` and capture the new token.
3. Update the client's configuration.
4. Restart the client.

If the client buffers and retries on failure, the entries written during the gap
are not lost, but a `401` is not retried — they will land only if the client
re-sends after the restart. Check your producer's behaviour before assuming.

## Revocation

```bash
audit clients revoke --id a1b2c3d4e5f60718
```

The token stops working immediately. The client row is kept, so entries it
already wrote stay attributable to a named client. A revoked client cannot be
rotated back into service — register a new one.

## Errors

| Status | Body | What happened |
| --- | --- | --- |
| `401` | `{"error":"unauthorized"}` | No token, a malformed token, an unknown token, a wrong secret, or a revoked token. These are deliberately indistinguishable, so the endpoint cannot be used to probe for valid ids. |
| `400` | `{"error":"invalid cursor"}` | The `cursor` parameter was not one the server issued. See `docs/querying.md`. |
| `400` | `{"error":"offset exceeds maximum of N; use cursor for deep pagination"}` | Paging too deep with `offset`. See `docs/querying.md`. |
| `503` | `{"error":"authentication unavailable"}` | The client registry could not be reached. Your token is not the problem; the database is. Retry. |
| `409` | a `VerifyResult` with `"valid": false` | `/v1/verify` found a break in the chain. Escalate — this means entries were altered. |

A `401` always carries `WWW-Authenticate: Bearer`.

## Migrating an existing caller

Before this change every endpoint was open. To migrate a service that is
already writing:

1. Ask an operator to register it: `audit clients register --name <service>`.
2. Put the token in the service's secret store. Do not commit it.
3. Set `AuthToken` (Go), `authToken` (Node), or `auth_bearer_token` (forwarder).
4. Deploy. Writes now carry attribution.

Entries the service wrote *before* the migration keep an empty `clientId` and
will not appear in its reads. They are still in the chain and still verify, and
an admin can read them. They are not retroactively attributed — rewriting them
would break the hash chain, which is the whole point of the chain.
`````

- [ ] **Step 2: Create `docs/querying.md`**

`````markdown
# Reading and paging the log

## Page size

Every read is bounded. If you do not pass `limit`, the server applies its
configured default.

| Setting | Default | Effect |
| --- | --- | --- |
| `DEFAULT_QUERY_LIMIT` | `50` | Page size when you omit `limit`. |
| `MAX_QUERY_LIMIT` | `500` | Ceiling. A larger `limit` is silently clamped to this, not rejected. |
| `MAX_QUERY_OFFSET` | `10000` | Largest accepted `offset`. Past this you get a `400`. |

These are environment variables on the service, so the numbers above are
defaults, not guarantees — check with whoever operates your deployment.

## Paging with a cursor

Prefer `cursor` over `offset`. A cursor page costs the same whether it is the
first page or the ten-thousandth.

The first request omits `cursor`:

```bash
curl -s "http://localhost:8080/v1/logs?limit=50" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

```json
{
  "items": [],
  "limit": 50,
  "nextCursor": "djE6MTQyNw"
}
```

Each subsequent request passes back the `nextCursor` you were given:

```bash
curl -s "http://localhost:8080/v1/logs?limit=50&cursor=djE6MTQyNw" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

**`nextCursor` is `null` on the last page.** That is the stop condition — do not
keep requesting until you get an empty `items` array, because the last full page
already tells you it is the last.

Treat the cursor as opaque. It encodes a position, but the encoding is versioned
and may change; construct one yourself and it will be rejected.

```javascript
async function* readAllLogs(token, { baseUrl = "http://localhost:8080", limit = 50 } = {}) {
  let cursor = null;

  for (;;) {
    const url = new URL(`${baseUrl}/v1/logs`);
    url.searchParams.set("limit", String(limit));
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }

    const response = await fetch(url, {
      headers: { authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      throw new Error(`audit service returned ${response.status}`);
    }

    const page = await response.json();
    yield* page.items;

    // null means that was the last page.
    if (!page.nextCursor) {
      return;
    }
    cursor = page.nextCursor;
  }
}
```

## Counting

`total` is **not** returned by default. Ask for it explicitly:

```bash
curl -s "http://localhost:8080/v1/logs?limit=50&count=true" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

```json
{
  "items": [],
  "limit": 50,
  "nextCursor": "djE6MTQyNw",
  "total": 1427
}
```

`total` is the size of the whole matching set for your filters. It ignores
`cursor`, `offset` and `limit`, so it is not a count of what is left to read.

It is opt-in because producing it means counting every matching row. On a large
log that is the most expensive thing a read can do. Ask for it on the first page
of a UI if you need a count; do not ask for it on every page of a bulk export.

## Filters

| Parameter | Effect |
| --- | --- |
| `app` | Exact match on the app label. |
| `level` | Exact match on the level. |
| `q` or `text` | Free-text search across message and metadata. |
| `clientId` | **Admin only.** Narrows to one client. Ignored for everyone else. |

Filters combine with `AND`, and always apply within what you are allowed to see.

## If you are still using `offset`

`offset` still works, so nothing breaks today:

```bash
curl -s "http://localhost:8080/v1/logs?limit=50&offset=100" \
  -H "authorization: Bearer $AUDIT_TOKEN"
```

Two limits apply:

- Past `MAX_QUERY_OFFSET` you get `400 offset exceeds maximum of N; use cursor
  for deep pagination`.
- `cursor` and `offset` together is a `400`. Pick one.

When `offset` is used it is echoed back in the response, so an existing caller
sees the shape it expects plus the new fields.

## Performance, honestly

A cursor page scoped to your client is served by an index and costs about the
same regardless of how large the log has grown. Three things are not:

- **Free-text `q`** is a substring scan that no index serves. It is bounded by
  your own data, not the whole log, but it gets slower as your data grows.
- **A filter that matches almost nothing** — `level=ERROR` for a client with no
  errors — walks your entries looking for a full page before giving up.
- **`count=true`** counts every matching row, every time.

If a read feels slow, check for those three before assuming the cursor is at
fault.
`````

- [ ] **Step 3: Verify every command in the guides actually works**

These documents are the integration contract, so run them rather than trusting
them. With the service running and a token from Task 7:

```bash
export AUDIT_TOKEN='<token from clients register>'
curl -s -X POST http://localhost:8080/v1/logs -H "authorization: Bearer $AUDIT_TOKEN" -H "content-type: application/json" -d '{"app":"payments-api","level":"INFO","message":"invoice created","metadata":{"invoiceId":"inv_123"}}'
curl -s "http://localhost:8080/v1/logs?limit=20" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8080/v1/logs?limit=50&count=true" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8080/v1/logs/search?q=invoice&limit=10" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s http://localhost:8080/v1/verify -H "authorization: Bearer $AUDIT_TOKEN"
curl -s http://localhost:8080/v1/health
curl -s -i "http://localhost:8080/v1/logs?offset=999999" -H "authorization: Bearer $AUDIT_TOKEN" | head -1
curl -s -i "http://localhost:8080/v1/logs?cursor=nonsense" -H "authorization: Bearer $AUDIT_TOKEN" | head -1
```

Expected: `201`; a read showing your entry with `"nextCursor": null`; a counted
read including `"total"`; a search hit; a valid chain; health without a token;
and `400` for both the deep offset and the bad cursor.

Correct the documents to match what actually happened. The response bodies shown
in the guides must be real.

- [ ] **Step 4: Commit**

```bash
git add docs/authorization.md docs/querying.md
git commit -m "$(cat <<'EOF'
Document authorization and cursor paging for integrators

Two guides written for someone wiring up a service: getting and using a
token, what a client can and cannot see, rotation as a hard cutover, the
full error table, and migrating a caller that predates authorization.

The querying guide covers the cursor loop with its real stop condition,
why total is opt-in, and an honest note on what stays slow.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Update the existing documentation

Four documents describe a service with no authorization and offset paging. Left alone they are worse than no documentation, because a reader will follow them and get a `401`.

**Files:**
- Modify: `README.md`
- Modify: `clients/README.md`
- Modify: `cmd/log-forwarder/README.md`
- Modify: `deployment/README.md`

**Interfaces:**
- Consumes: `docs/authorization.md` and `docs/querying.md` from Task 9.

- [ ] **Step 1: Rewrite the API section of `README.md`**

Replace the `## API` heading and the endpoint list beneath it with:

`````markdown
## API

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /v1/health` | none | Liveness. The only unauthenticated endpoint. |
| `POST /v1/logs` | bearer token | Append an entry, stamped with the caller's client id. |
| `GET /v1/logs` | bearer token | Read your entries. |
| `GET /v1/logs/search` | bearer token | Free-text search over your entries. |
| `GET /v1/verify` | bearer token | Verify the chain. The result is global. |

All authenticated endpoints take `Authorization: Bearer <token>`. See
[docs/authorization.md](docs/authorization.md) for how to get a token, and
[docs/querying.md](docs/querying.md) for paging.
`````

- [ ] **Step 2: Rewrite the query-parameter list in `README.md`**

Replace the `### View/search logs` block — the "Query params" list and the three
`curl` examples under it — with:

`````markdown
### View/search logs

Query params:

- `app` exact app filter
- `level` exact level filter
- `q` or `text` free-text search over message/metadata
- `limit` page size (defaults to `DEFAULT_QUERY_LIMIT`, clamped to `MAX_QUERY_LIMIT`)
- `cursor` opaque page token from the previous response's `nextCursor`
- `count` set to `true` to include an exact `total` (expensive; off by default)
- `offset` still supported, but bounded by `MAX_QUERY_OFFSET`; prefer `cursor`
- `clientId` admin tokens only; narrows to one client

Responses carry `nextCursor`, which is `null` on the last page.

```bash
curl -s "http://localhost:8080/v1/logs?limit=20" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8080/v1/logs?app=payments-api&level=ERROR" -H "authorization: Bearer $AUDIT_TOKEN"
curl -s "http://localhost:8080/v1/logs/search?q=timeout&limit=10" -H "authorization: Bearer $AUDIT_TOKEN"
```

Full paging guide: [docs/querying.md](docs/querying.md).
`````

- [ ] **Step 3: Update the write, verify and run examples in `README.md`**

Add `-H "authorization: Bearer $AUDIT_TOKEN"` to the `### Example write` curl
and to the `## Verify chain` curl.

Replace the `## Run` section with:

`````markdown
## Run

The client registry always lives in PostgreSQL, so `DATABASE_URL` is required
even when log entries go to a file:

```bash
export DATABASE_URL='postgres://audit:audit@localhost:5432/audit?sslmode=disable'
go run ./cmd/server
```

Register a client to get a token:

```bash
go run ./cmd/server clients register --name my-service
```
`````

- [ ] **Step 4: Add an Authorization section to `README.md`**

Insert immediately after the `## API` section:

`````markdown
## Authorization

Every client is registered by an operator, which mints a token shown exactly
once. The client sends it as a bearer token; the server stamps the client's id
into each entry it writes and confines each read to that client's own entries.
An `admin` client reads across all of them.

```bash
audit clients register --name payments-api      # mint a token
audit clients list                              # who is registered
audit clients rotate --id <clientId>            # replace a token
audit clients revoke --id <clientId>            # disable a token
```

Registration is local-only — there is no HTTP endpoint for it.

Full guide: [docs/authorization.md](docs/authorization.md).
`````

- [ ] **Step 5: Update the Config section of `README.md`**

Replace the `## Config` list with:

`````markdown
## Config

- `PORT` (default `8080`)
- `BIND_ADDR` (default empty, listening on all interfaces; set `127.0.0.1` for loopback only)
- `DATABASE_URL` (**required**, always — the client registry lives in PostgreSQL whatever `STORAGE_BACKEND` is)
- `STORAGE_BACKEND` (default `file`; options: `file`, `postgres`) — where log *entries* go
- `DATA_DIR` (default `./data`)
- `LOG_FILE` (default `./data/audit.log.jsonl`)
- `MAX_PAYLOAD_BYTES` (default `32768`)
- `DEFAULT_QUERY_LIMIT` (default `50`) page size when a read omits `limit`
- `MAX_QUERY_LIMIT` (default `500`) ceiling; a larger `limit` is clamped
- `MAX_QUERY_OFFSET` (default `10000`) largest accepted `offset` before `400`
`````

Also add `test-node` to the `## Make targets` list.

- [ ] **Step 6: Update `clients/README.md`**

Add `client.AuthToken = os.Getenv("AUDIT_TOKEN")` to the Go example, directly
after the `auditclient.New(...)` line, and add `"os"` to that example's imports.

Add the same to the Node example's constructor options:
`authToken: process.env.AUDIT_TOKEN`.

Then add this section immediately after the `# Producer Clients` intro
paragraph:

`````markdown
## Authorization

Every producer needs a token. An operator mints one on the server with
`audit clients register --name <service>`; it is displayed once and only its
hash is stored.

- Go: set `client.AuthToken`
- Node: pass `authToken` to `AuditLogger`
- Forwarder: set `auth_bearer_token` in its config file

Keep the token in a secret store, not in source. Both libraries retry on `429`
and `5xx` only — a `401` is surfaced immediately, because a rejected token will
not become valid on a retry.

See [../docs/authorization.md](../docs/authorization.md).
`````

- [ ] **Step 7: Update `cmd/log-forwarder/README.md`**

Find the description of `auth_bearer_token` and replace it with:

`````markdown
- `auth_bearer_token`: the forwarder's registered client token. An operator
  mints it on the audit host with `audit clients register --name <forwarder>`;
  it is shown once. Every entry the forwarder delivers is attributed to that
  client, and the forwarder's `/v1/verify` integrity checks use the same token.
  A rotation is a hard cutover: update this value and restart the forwarder.
  See [../../docs/authorization.md](../../docs/authorization.md).
`````

- [ ] **Step 8: Add a client-management section to `deployment/README.md`**

Insert before the existing `## Operations` section:

`````markdown
## Managing clients

Client registration runs on the server, against the local database. The admin
commands are subcommands of the same binary that runs the service, so there is
nothing extra to deploy.

```bash
ssh muni-demo
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) /app/audit/audit clients list
```

Register a new client and hand over the token:

```bash
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) \
  /app/audit/audit clients register --name payments-api
```

The token is printed once and only its hash is stored. Deliver it over a
channel you would use for any other credential — never over the same ticket or
chat thread you would use for its client id alone.

Rotate a leaked token:

```bash
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) \
  /app/audit/audit clients rotate --id <clientId>
```

Rotation is a hard cutover: the old token stops working immediately, so update
and restart the client promptly. The client id is unchanged, so entries it has
already written keep their attribution.

Decommission a client:

```bash
sudo -u audit env $(grep -v '^#' /etc/audit/audit.env | xargs) \
  /app/audit/audit clients revoke --id <clientId>
```

The row is kept so historical entries stay attributable. A revoked client
cannot be rotated back into service — register a new one.

An `admin`-role client can read every tenant's entries. Register one only when
something genuinely needs a cross-tenant view, and treat its token accordingly.
`````

- [ ] **Step 9: Check every internal link resolves**

Run:

```bash
grep -oh '](\.\.\?/[^)]*\|](docs/[^)]*' README.md clients/README.md cmd/log-forwarder/README.md deployment/README.md docs/authorization.md docs/querying.md \
  | sed 's/^](//' | sort -u
```

Then confirm each printed path exists relative to the file that references it.
`docs/authorization.md` and `docs/querying.md` must both resolve from the repo
root, `../docs/authorization.md` from `clients/`, and
`../../docs/authorization.md` from `cmd/log-forwarder/`.

- [ ] **Step 10: Final full verification**

Run:

```bash
go build ./...
go test ./...
node --test clients/node-lib/
```

Expected: all green. Then with the compose database up:

```bash
TEST_DATABASE_URL='postgres://audit:audit@localhost:5432/audit?sslmode=disable' go test ./cmd/server/ -v
```

Expected: PASS, with the PostgreSQL suites running rather than skipping.

- [ ] **Step 11: Commit**

```bash
git add README.md clients/README.md cmd/log-forwarder/README.md deployment/README.md
git commit -m "$(cat <<'EOF'
Update the existing docs for authorization and cursor paging

Four documents described an open API paged by offset. A reader following
them would have got a 401.

The root README gains an auth column, the new read parameters, the three
query-limit variables, and the fact that DATABASE_URL is now required for
every storage backend. The deployment README gains the client-management
runbook.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```
