package main

import (
	"testing"
)

func TestParserJSONMode(t *testing.T) {
	t.Parallel()

	cfg := Config{
		AppName:         "payments-api",
		TimestampField:  "timestamp",
		ParserMode:      "json",
		DefaultLevel:    "INFO",
		RegexPattern:    "",
		SourceFile:      "./app.log",
		CheckpointPath:  "./checkpoint.json",
		AuthBearerToken: "token",
		ServerURL:       "http://localhost:3001/v1/logs",
	}

	parser, err := NewLineParser(cfg)
	if err != nil {
		t.Fatalf("NewLineParser() error = %v", err)
	}

	event := TailEvent{Line: `{"timestamp":"2026-03-18T10:00:00Z","level":"warn","message":"timeout","trace":"abc"}`, SourceFile: "/tmp/app.log", CommittedOffset: 42}
	parsed, err := parser.Parse(event)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.Level != "WARN" {
		t.Fatalf("expected level WARN, got %q", parsed.Level)
	}
	if parsed.Message != "timeout" {
		t.Fatalf("expected message timeout, got %q", parsed.Message)
	}
	if parsed.TimestampRaw != "2026-03-18T10:00:00Z" {
		t.Fatalf("expected timestamp extracted, got %q", parsed.TimestampRaw)
	}
	if parsed.ParserMode != "json" {
		t.Fatalf("expected parser mode json, got %q", parsed.ParserMode)
	}
	if parsed.AdditionalFields["trace"] != "abc" {
		t.Fatalf("expected trace field in metadata")
	}
}

func TestParserRegexMode(t *testing.T) {
	t.Parallel()

	cfg := Config{
		AppName:         "payments-api",
		TimestampField:  "ts",
		ParserMode:      "regex",
		RegexPattern:    `^(?P<ts>\S+) (?P<level>\w+) (?P<message>.*)$`,
		DefaultLevel:    "INFO",
		SourceFile:      "./app.log",
		CheckpointPath:  "./checkpoint.json",
		AuthBearerToken: "token",
		ServerURL:       "http://localhost:3001/v1/logs",
	}

	parser, err := NewLineParser(cfg)
	if err != nil {
		t.Fatalf("NewLineParser() error = %v", err)
	}

	event := TailEvent{Line: "2026-03-18T10:01:00Z error disk-full", SourceFile: "/tmp/app.log", CommittedOffset: 100}
	parsed, err := parser.Parse(event)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.Level != "ERROR" {
		t.Fatalf("expected level ERROR, got %q", parsed.Level)
	}
	if parsed.Message != "disk-full" {
		t.Fatalf("expected message disk-full, got %q", parsed.Message)
	}
	if parsed.TimestampRaw != "2026-03-18T10:01:00Z" {
		t.Fatalf("expected timestamp extracted, got %q", parsed.TimestampRaw)
	}
	if parsed.ParserMode != "regex" {
		t.Fatalf("expected parser mode regex, got %q", parsed.ParserMode)
	}
}

func TestParserCustomFallbackPlain(t *testing.T) {
	t.Parallel()

	cfg := Config{
		AppName:         "payments-api",
		TimestampField:  "timestamp",
		ParserMode:      "custom",
		RegexPattern:    `^(?P<level>INFO|WARN|ERROR): (?P<message>.*)$`,
		DefaultLevel:    "INFO",
		SourceFile:      "./app.log",
		CheckpointPath:  "./checkpoint.json",
		AuthBearerToken: "token",
		ServerURL:       "http://localhost:3001/v1/logs",
	}

	parser, err := NewLineParser(cfg)
	if err != nil {
		t.Fatalf("NewLineParser() error = %v", err)
	}

	event := TailEvent{Line: "plain text line", SourceFile: "/tmp/app.log", CommittedOffset: 9}
	parsed, err := parser.Parse(event)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.ParserMode != "plain" {
		t.Fatalf("expected parser mode plain, got %q", parsed.ParserMode)
	}
	if parsed.Message != "plain text line" {
		t.Fatalf("expected plain message passthrough, got %q", parsed.Message)
	}
	if parsed.Level != "INFO" {
		t.Fatalf("expected default level INFO, got %q", parsed.Level)
	}
}
