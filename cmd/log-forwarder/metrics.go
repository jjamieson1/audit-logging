package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type MetricsSnapshot struct {
	LinesRead        uint64 `json:"lines_read"`
	ParsedOK         uint64 `json:"parsed_ok"`
	ParseFailed      uint64 `json:"parse_failed"`
	DeliverySuccess  uint64 `json:"delivery_success"`
	DeliveryFailed   uint64 `json:"delivery_failed"`
	DeadLetterWrites uint64 `json:"dead_letter_writes"`
	Retries          uint64 `json:"retries"`
	DuplicateKeys    uint64 `json:"duplicate_keys"`
}

type RuntimeMetrics struct {
	linesRead        atomic.Uint64
	parsedOK         atomic.Uint64
	parseFailed      atomic.Uint64
	deliverySuccess  atomic.Uint64
	deliveryFailed   atomic.Uint64
	deadLetterWrites atomic.Uint64
	retries          atomic.Uint64
	duplicateKeys    atomic.Uint64

	seenMu sync.Mutex
	seen   map[string]struct{}
}

func NewRuntimeMetrics() *RuntimeMetrics {
	return &RuntimeMetrics{seen: map[string]struct{}{}}
}

func (m *RuntimeMetrics) IncLinesRead()        { m.linesRead.Add(1) }
func (m *RuntimeMetrics) IncParsedOK()         { m.parsedOK.Add(1) }
func (m *RuntimeMetrics) IncParseFailed()      { m.parseFailed.Add(1) }
func (m *RuntimeMetrics) IncDeliverySuccess()  { m.deliverySuccess.Add(1) }
func (m *RuntimeMetrics) IncDeliveryFailed()   { m.deliveryFailed.Add(1) }
func (m *RuntimeMetrics) IncDeadLetterWrites() { m.deadLetterWrites.Add(1) }
func (m *RuntimeMetrics) IncRetries()          { m.retries.Add(1) }

func (m *RuntimeMetrics) MarkIdempotencyKey(key string) bool {
	m.seenMu.Lock()
	defer m.seenMu.Unlock()
	if _, exists := m.seen[key]; exists {
		m.duplicateKeys.Add(1)
		return true
	}
	m.seen[key] = struct{}{}
	return false
}

func (m *RuntimeMetrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		LinesRead:        m.linesRead.Load(),
		ParsedOK:         m.parsedOK.Load(),
		ParseFailed:      m.parseFailed.Load(),
		DeliverySuccess:  m.deliverySuccess.Load(),
		DeliveryFailed:   m.deliveryFailed.Load(),
		DeadLetterWrites: m.deadLetterWrites.Load(),
		Retries:          m.retries.Load(),
		DuplicateKeys:    m.duplicateKeys.Load(),
	}
}

func StartMetricsReporter(ctx context.Context, logger *log.Logger, interval time.Duration, metrics *RuntimeMetrics) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s := metrics.Snapshot()
			logger.Printf("event=metrics lines_read=%d parsed_ok=%d parse_failed=%d delivery_success=%d delivery_failed=%d deadletter_writes=%d retries=%d duplicate_keys=%d",
				s.LinesRead,
				s.ParsedOK,
				s.ParseFailed,
				s.DeliverySuccess,
				s.DeliveryFailed,
				s.DeadLetterWrites,
				s.Retries,
				s.DuplicateKeys,
			)
		}
	}
}

func StartMetricsServer(ctx context.Context, logger *log.Logger, port int, metrics *RuntimeMetrics) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"metrics": metrics.Snapshot(),
		})
	})

	server := &http.Server{Addr: fmt.Sprintf(":%d", port), Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Printf("event=metrics_server_failed err=%q", err)
		}
	}()
}
