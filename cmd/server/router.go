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

	principal, ok := principalFrom(r.Context())
	if !ok {
		// Unreachable behind requireAuth; a 500 here means the route was wired
		// without the middleware.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "missing principal"})
		return
	}
	if principal.ClientID == "" {
		// Fail closed: stamping an empty client id would store an entry
		// indistinguishable from a pre-authorization legacy row. Not reachable
		// through PostgresClientStore today, but this is the one line whose
		// entire job is attribution, so it must not trust a zero-value
		// Principal from any future ClientStore.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "principal missing client id"})
		return
	}

	// Assigned from the token, overwriting whatever the caller sent, so
	// attribution cannot be forged.
	input.ClientID = principal.ClientID

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

	principal, ok := principalFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "missing principal"})
		return
	}
	if principal.ClientID == "" {
		// Fail closed on the principal's own id being empty — every real
		// principal has one. This is distinct from scopeQuery ever setting
		// query.ClientID to "" for an admin with no clientId parameter, which
		// legitimately means "everything" and must keep working: this check
		// runs before scopeQuery and never looks at query.ClientID.
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "principal missing client id"})
		return
	}
	query = scopeQuery(query, principal, r)

	result, err := store.QueryLogs(query)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query logs"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
