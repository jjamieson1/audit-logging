package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	auditclient "audit-logging/clients/go-lib"
)

type DeadLetterEntry struct {
	CreatedAt    string                 `json:"created_at"`
	Error        string                 `json:"error"`
	SourceFile   string                 `json:"source_file"`
	SourceOffset int64                  `json:"source_offset"`
	Payload      auditclient.LogRequest `json:"payload"`
}

func BuildPayload(parsed NormalizedEvent, idempotencyKey string) auditclient.LogRequest {
	payload := auditclient.LogRequest{
		App:     parsed.App,
		Level:   parsed.Level,
		Message: parsed.Message,
		Metadata: map[string]any{
			"source_file":          parsed.SourceFile,
			"source_offset":        parsed.SourceOffset,
			"source_timestamp_raw": parsed.TimestampRaw,
			"parser_mode":          parsed.ParserMode,
			"raw_line":             parsed.RawLine,
			"idempotency_key":      idempotencyKey,
		},
	}
	for key, value := range parsed.AdditionalFields {
		payload.Metadata[key] = value
	}
	return payload
}

func ComputeIdempotencyKey(appName, sourceFile string, sourceOffset int64, rawLine string) string {
	normalized := strings.TrimSpace(rawLine)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s", appName, sourceFile, sourceOffset, normalized)))
	return hex.EncodeToString(sum[:])
}

func WriteDeadLetter(path string, payload auditclient.LogRequest, sourceFile string, sourceOffset int64, deliveryErr error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir dead-letter dir: %w", err)
	}

	entry := DeadLetterEntry{
		CreatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Error:        deliveryErr.Error(),
		SourceFile:   sourceFile,
		SourceOffset: sourceOffset,
		Payload:      payload,
	}

	bytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal dead-letter entry: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open dead-letter file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(append(bytes, '\n')); err != nil {
		return fmt.Errorf("append dead-letter entry: %w", err)
	}

	return nil
}

func DeliverParsedEvent(ctx context.Context, cfg Config, client *auditclient.Client, parsed NormalizedEvent) (auditclient.LogResponse, error) {
	idempotencyKey := ComputeIdempotencyKey(parsed.App, parsed.SourceFile, parsed.SourceOffset, parsed.RawLine)
	payload := BuildPayload(parsed, idempotencyKey)

	client.Headers = map[string]string{"x-idempotency-key": idempotencyKey}
	requestCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.RequestTimeoutMS)*time.Millisecond)
	defer cancel()

	return client.WriteLog(requestCtx, payload)
}
