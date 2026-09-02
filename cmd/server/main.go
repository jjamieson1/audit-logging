package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type Config struct {
	Port            int
	BindAddr        string
	StorageBackend  string
	DatabaseURL     string
	LogFile         string
	MaxPayloadBytes int64
	Query           QueryLimits
}

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

type Entry struct {
	Index       uint64    `json:"index"`
	Timestamp   string    `json:"timestamp"`
	PrevHash    string    `json:"prevHash"`
	PayloadHash string    `json:"payloadHash"`
	EntryHash   string    `json:"entryHash"`
	Record      LogRecord `json:"record"`
}

type VerifyResult struct {
	Valid        bool    `json:"valid"`
	TotalEntries uint64  `json:"totalEntries"`
	LastHash     string  `json:"lastHash"`
	InvalidAt    *uint64 `json:"invalidAt"`
	Reason       *string `json:"reason"`
}

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
	Total *int `json:"total,omitempty"`
	// Offset is populated only when query.Offset > 0 (see FileStore.QueryLogs
	// and PostgresStore.QueryLogs), so an explicit offset=0 request gets no
	// "offset" field back, same as no offset at all. This is deliberate: an
	// offset of zero is indistinguishable from "unset" for echo purposes, and
	// pinned by TestFileStoreQueryLogsOffsetZeroOmitsOffsetField.
	Offset *int `json:"offset,omitempty"`
}

type Store interface {
	Append(record LogRecord) (Entry, error)
	Verify() (VerifyResult, error)
	QueryLogs(query LogQuery) (LogQueryResult, error)
}

type FileStore struct {
	path      string
	mu        sync.Mutex
	lastHash  string
	lastIndex uint64
}

type PostgresStore struct {
	db *sql.DB
}

func loadConfig() Config {
	dataDir := getEnv("DATA_DIR", "data")
	logFile := getEnv("LOG_FILE", filepath.Join(dataDir, "audit.log.jsonl"))
	storageBackend := strings.ToLower(getEnv("STORAGE_BACKEND", "file"))
	databaseURL := getEnv("DATABASE_URL", "")

	bindAddr := getEnv("BIND_ADDR", "")

	port, _ := strconv.Atoi(getEnv("PORT", "8080"))
	if port <= 0 {
		port = 8080
	}

	maxPayloadBytes, _ := strconv.ParseInt(getEnv("MAX_PAYLOAD_BYTES", "32768"), 10, 64)
	if maxPayloadBytes <= 0 {
		maxPayloadBytes = 32768
	}

	defaults := defaultQueryLimits()
	queryLimits := QueryLimits{
		DefaultLimit: envInt("DEFAULT_QUERY_LIMIT", defaults.DefaultLimit),
		MaxLimit:     envInt("MAX_QUERY_LIMIT", defaults.MaxLimit),
		MaxOffset:    envInt("MAX_QUERY_OFFSET", defaults.MaxOffset),
	}

	return Config{
		Port:            port,
		BindAddr:        bindAddr,
		StorageBackend:  storageBackend,
		DatabaseURL:     databaseURL,
		LogFile:         logFile,
		MaxPayloadBytes: maxPayloadBytes,
		Query:           queryLimits,
	}
}

// ListenAddr is the address the HTTP server binds to. An empty BIND_ADDR
// listens on all interfaces; set it to 127.0.0.1 to accept loopback only.
func (c Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.BindAddr, c.Port)
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func NewFileStore(path string) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}

	store := &FileStore{path: path, lastHash: "GENESIS", lastIndex: 0}
	verify, err := store.verifyChainUnsafe()
	if err != nil {
		return nil, err
	}
	if !verify.Valid {
		return nil, fmt.Errorf("invalid chain at index %d", derefUint64(verify.InvalidAt))
	}

	store.lastHash = verify.LastHash
	store.lastIndex = verify.TotalEntries
	return store, nil
}

func (s *FileStore) Append(record LogRecord) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index := s.lastIndex + 1
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	payloadBytes, err := json.Marshal(record)
	if err != nil {
		return Entry{}, err
	}

	payloadHash := sha256Hex(payloadBytes)
	prevHash := s.lastHash
	entryHash := sha256Hex([]byte(fmt.Sprintf("%d|%s|%s|%s", index, timestamp, payloadHash, prevHash)))

	entry := Entry{
		Index:       index,
		Timestamp:   timestamp,
		PrevHash:    prevHash,
		PayloadHash: payloadHash,
		EntryHash:   entryHash,
		Record:      record,
	}

	lineBytes, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, err
	}

	file, err := os.OpenFile(s.path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return Entry{}, err
	}
	defer file.Close()

	if _, err := file.Write(append(lineBytes, '\n')); err != nil {
		return Entry{}, err
	}

	s.lastIndex = index
	s.lastHash = entryHash
	return entry, nil
}

func (s *FileStore) Verify() (VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyChainUnsafe()
}

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
	// offset=0 deliberately omits the field; see the Offset comment on
	// LogQueryResult.
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

func (s *FileStore) verifyChainUnsafe() (VerifyResult, error) {
	file, err := os.Open(s.path)
	if err != nil {
		return VerifyResult{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var expectedIndex uint64 = 1
	previousHash := "GENESIS"
	var total uint64

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			reason := "invalid JSON line"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}

		payloadBytes, err := json.Marshal(entry.Record)
		if err != nil {
			reason := "payload marshal failed"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}

		expectedPayloadHash := sha256Hex(payloadBytes)
		expectedEntryHash := sha256Hex([]byte(fmt.Sprintf("%d|%s|%s|%s", entry.Index, entry.Timestamp, expectedPayloadHash, entry.PrevHash)))

		if entry.Index != expectedIndex {
			reason := "index sequence broken"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}
		if entry.PrevHash != previousHash {
			reason := "previous hash mismatch"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}
		if entry.PayloadHash != expectedPayloadHash {
			reason := "payload hash mismatch"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}
		if entry.EntryHash != expectedEntryHash {
			reason := "entry hash mismatch"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}

		total++
		expectedIndex++
		previousHash = entry.EntryHash
	}

	if err := scanner.Err(); err != nil {
		return VerifyResult{}, err
	}

	return VerifyResult{Valid: true, TotalEntries: total, LastHash: previousHash}, nil
}

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

func (s *PostgresStore) ensureSchema() error {
	query := `
CREATE TABLE IF NOT EXISTS audit_log_entries (
    entry_index BIGINT PRIMARY KEY,
    ts TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_entries_index ON audit_log_entries(entry_index);
CREATE INDEX IF NOT EXISTS idx_audit_log_entries_client_index
    ON audit_log_entries ((record_json::jsonb->>'clientId'), entry_index);
`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) Append(record LogRecord) (Entry, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Entry{}, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(987654321)`); err != nil {
		return Entry{}, err
	}

	var lastIndex int64
	var prevHash string
	if err := tx.QueryRow(`
SELECT
  COALESCE(MAX(entry_index), 0) AS last_index,
  COALESCE((SELECT entry_hash FROM audit_log_entries ORDER BY entry_index DESC LIMIT 1), 'GENESIS') AS last_hash
FROM audit_log_entries
`).Scan(&lastIndex, &prevHash); err != nil {
		return Entry{}, err
	}

	nextIndex := lastIndex + 1
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)

	payloadBytes, err := json.Marshal(record)
	if err != nil {
		return Entry{}, err
	}

	payloadHash := sha256Hex(payloadBytes)
	entryHash := sha256Hex([]byte(fmt.Sprintf("%d|%s|%s|%s", nextIndex, timestamp, payloadHash, prevHash)))

	_, err = tx.Exec(`
INSERT INTO audit_log_entries(entry_index, ts, prev_hash, payload_hash, entry_hash, record_json)
VALUES ($1, $2, $3, $4, $5, $6)
`, nextIndex, timestamp, prevHash, payloadHash, entryHash, string(payloadBytes))
	if err != nil {
		return Entry{}, err
	}

	if err := tx.Commit(); err != nil {
		return Entry{}, err
	}

	return Entry{
		Index:       uint64(nextIndex),
		Timestamp:   timestamp,
		PrevHash:    prevHash,
		PayloadHash: payloadHash,
		EntryHash:   entryHash,
		Record:      record,
	}, nil
}

func (s *PostgresStore) Verify() (VerifyResult, error) {
	rows, err := s.db.Query(`
SELECT entry_index, ts, prev_hash, payload_hash, entry_hash, record_json
FROM audit_log_entries
ORDER BY entry_index ASC
`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()

	var expectedIndex uint64 = 1
	previousHash := "GENESIS"
	var total uint64

	for rows.Next() {
		var dbIndex int64
		var timestamp, prevHash, payloadHash, entryHash, recordJSON string
		if err := rows.Scan(&dbIndex, &timestamp, &prevHash, &payloadHash, &entryHash, &recordJSON); err != nil {
			return VerifyResult{}, err
		}
		if dbIndex <= 0 {
			reason := "index sequence broken"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}

		index := uint64(dbIndex)
		expectedPayloadHash := sha256Hex([]byte(recordJSON))
		expectedEntryHash := sha256Hex([]byte(fmt.Sprintf("%d|%s|%s|%s", index, timestamp, expectedPayloadHash, prevHash)))

		if index != expectedIndex {
			reason := "index sequence broken"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}
		if prevHash != previousHash {
			reason := "previous hash mismatch"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}
		if payloadHash != expectedPayloadHash {
			reason := "payload hash mismatch"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}
		if entryHash != expectedEntryHash {
			reason := "entry hash mismatch"
			invalidAt := expectedIndex
			return VerifyResult{Valid: false, TotalEntries: total, LastHash: previousHash, InvalidAt: &invalidAt, Reason: &reason}, nil
		}

		total++
		expectedIndex++
		previousHash = entryHash
	}

	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}

	return VerifyResult{Valid: true, TotalEntries: total, LastHash: previousHash}, nil
}

// QueryLogs assumes query.Limit is positive; parseLogQuery guarantees it.
func (s *PostgresStore) QueryLogs(query LogQuery) (LogQueryResult, error) {
	filters := make([]string, 0, 4)
	filterArgs := make([]any, 0, 5)

	if query.ClientID != "" {
		filterArgs = append(filterArgs, query.ClientID)
		filters = append(filters, fmt.Sprintf("record_json::jsonb->>'clientId' = $%d", len(filterArgs)))
	}
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

func sha256Hex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func matchesQuery(entry Entry, query LogQuery) bool {
	// Exact comparison, unlike app and level: client ids are generated
	// identifiers, and a case-insensitive match on a security boundary is a
	// bug waiting to happen.
	if query.ClientID != "" && entry.Record.ClientID != query.ClientID {
		return false
	}
	if query.App != "" && !strings.EqualFold(entry.Record.App, query.App) {
		return false
	}
	if query.Level != "" && !strings.EqualFold(entry.Record.Level, query.Level) {
		return false
	}

	if query.Text == "" {
		return true
	}

	metadataJSON, _ := json.Marshal(entry.Record.Metadata)
	haystack := strings.ToLower(strings.Join([]string{
		entry.Record.App,
		entry.Record.Level,
		entry.Record.Message,
		string(metadataJSON),
		entry.EntryHash,
	}, " "))

	return strings.Contains(haystack, strings.ToLower(query.Text))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withMethod(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		handler(w, r)
	}
}

func main() {
	// Admin subcommands run against the registry and exit without starting a
	// listener, so deployment ships one binary.
	if len(os.Args) > 1 && os.Args[1] == "clients" {
		os.Exit(runClientsCommand(os.Args[2:]))
	}

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

	mux := newRouter(cfg, store, clientStore)

	addr := cfg.ListenAddr()
	log.Printf("audit-logging listening on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func derefUint64(v *uint64) uint64 {
	if v == nil {
		return 0
	}
	return *v
}
