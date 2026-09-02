package main

import (
	"encoding/base64"
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

func parseLogQuery(r *http.Request, limits QueryLimits) (LogQuery, error) {
	values := r.URL.Query()

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
		App:        values.Get("app"),
		Level:      values.Get("level"),
		Text:       text,
		Limit:      limit,
		Offset:     offset,
		AfterIndex: afterIndex,
		WantTotal:  strings.EqualFold(strings.TrimSpace(values.Get("count")), "true"),
	}, limits), nil
}

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
