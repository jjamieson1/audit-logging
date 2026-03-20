package main

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	StorageBackend  string
	DatabaseURL     string
	LogFile         string
	MaxPayloadBytes int64
}

type LogRecord struct {
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
	App    string
	Level  string
	Text   string
	Limit  int
	Offset int
}

type LogQueryResult struct {
	Items  []Entry `json:"items"`
	Total  int     `json:"total"`
	Limit  int     `json:"limit"`
	Offset int     `json:"offset"`
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

	port, _ := strconv.Atoi(getEnv("PORT", "3001"))
	if port <= 0 {
		port = 3001
	}

	maxPayloadBytes, _ := strconv.ParseInt(getEnv("MAX_PAYLOAD_BYTES", "32768"), 10, 64)
	if maxPayloadBytes <= 0 {
		maxPayloadBytes = 32768
	}

	return Config{
		Port:            port,
		StorageBackend:  storageBackend,
		DatabaseURL:     databaseURL,
		LogFile:         logFile,
		MaxPayloadBytes: maxPayloadBytes,
	}
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

func (s *FileStore) QueryLogs(query LogQuery) (LogQueryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query = normalizeLogQuery(query)

	file, err := os.Open(s.path)
	if err != nil {
		return LogQueryResult{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	items := make([]Entry, 0, query.Limit)
	matched := 0

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

		if matched >= query.Offset && len(items) < query.Limit {
			items = append(items, entry)
		}
		matched++
	}

	if err := scanner.Err(); err != nil {
		return LogQueryResult{}, err
	}

	return LogQueryResult{
		Items:  items,
		Total:  matched,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
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

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, errors.New("DATABASE_URL is required for postgres backend")
	}

	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}

	store := &PostgresStore{db: db}
	if err := store.ensureSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	verify, err := store.Verify()
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if !verify.Valid {
		_ = db.Close()
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

func (s *PostgresStore) QueryLogs(query LogQuery) (LogQueryResult, error) {
	query = normalizeLogQuery(query)

	clauses := make([]string, 0)
	args := make([]any, 0)

	if query.App != "" {
		args = append(args, query.App)
		clauses = append(clauses, fmt.Sprintf("record_json::jsonb->>'app' = $%d", len(args)))
	}
	if query.Level != "" {
		args = append(args, query.Level)
		clauses = append(clauses, fmt.Sprintf("record_json::jsonb->>'level' = $%d", len(args)))
	}
	if query.Text != "" {
		args = append(args, "%"+query.Text+"%")
		placeholder := fmt.Sprintf("$%d", len(args))
		clauses = append(clauses, "(record_json::jsonb->>'message' ILIKE "+placeholder+" OR record_json ILIKE "+placeholder+")")
	}

	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM audit_log_entries" + where
	var total int
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return LogQueryResult{}, err
	}

	args = append(args, query.Limit, query.Offset)
	listQuery := "SELECT entry_index, ts, prev_hash, payload_hash, entry_hash, record_json FROM audit_log_entries" +
		where + fmt.Sprintf(" ORDER BY entry_index ASC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.db.Query(listQuery, args...)
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

	return LogQueryResult{
		Items:  items,
		Total:  total,
		Limit:  query.Limit,
		Offset: query.Offset,
	}, nil
}

func sha256Hex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

func normalizeLogQuery(query LogQuery) LogQuery {
	query.App = strings.TrimSpace(query.App)
	query.Level = strings.TrimSpace(query.Level)
	query.Text = strings.TrimSpace(query.Text)

	if query.Limit <= 0 {
		query.Limit = 50
	}
	if query.Limit > 500 {
		query.Limit = 500
	}
	if query.Offset < 0 {
		query.Offset = 0
	}

	return query
}

func matchesQuery(entry Entry, query LogQuery) bool {
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

func parseLogQuery(r *http.Request) (LogQuery, error) {
	values := r.URL.Query()

	limit := 50
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
		offset = parsed
	}

	text := strings.TrimSpace(values.Get("q"))
	if text == "" {
		text = strings.TrimSpace(values.Get("text"))
	}

	query := normalizeLogQuery(LogQuery{
		App:    values.Get("app"),
		Level:  values.Get("level"),
		Text:   text,
		Limit:  limit,
		Offset: offset,
	})

	return query, nil
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
	cfg := loadConfig()

	var (
		store Store
		err   error
	)

	switch cfg.StorageBackend {
	case "postgres":
		store, err = NewPostgresStore(cfg.DatabaseURL)
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

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/health", withMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	mux.HandleFunc("/v1/logs", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
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
		case http.MethodGet:
			query, err := parseLogQuery(r)
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
		default:
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
	})

	mux.HandleFunc("/v1/logs/search", withMethod(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		query, err := parseLogQuery(r)
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
	}))

	mux.HandleFunc("/v1/verify", withMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
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
	}))

	addr := fmt.Sprintf(":%d", cfg.Port)
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
