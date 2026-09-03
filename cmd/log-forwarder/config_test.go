package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigValid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	sourceFile := filepath.Join(tmp, "app.log")
	if err := os.WriteFile(sourceFile, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	configPath := filepath.Join(tmp, "config.json")
	configJSON := `{
  "server_url": "http://localhost:8090/v1/logs",
  "auth_bearer_token": "secret-token",
  "source_file": "` + sourceFile + `",
  "app_name": "payments-api",
  "timestamp_field": "timestamp",
  "parser_mode": "custom"
}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.AppName != "payments-api" {
		t.Fatalf("expected app_name to be preserved, got %q", cfg.AppName)
	}
	if cfg.PollIntervalMS <= 0 {
		t.Fatalf("expected defaults to be applied for poll_interval_ms")
	}
}

func TestLoadConfigInvalid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	configJSON := `{
  "server_url": "not-a-url",
  "auth_bearer_token": "",
  "source_file": "` + filepath.Join(tmp, "missing.log") + `",
  "app_name": "",
  "timestamp_field": "",
  "parser_mode": "invalid"
}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("expected config validation error, got nil")
	}

	msg := err.Error()
	for _, expected := range []string{
		"server_url must be a valid absolute URL",
		"auth_bearer_token is required",
		"app_name is required",
		"timestamp_field is required",
		"parser_mode must be one of: json, regex, custom",
		"source_file is not accessible",
	} {
		if !strings.Contains(msg, expected) {
			t.Fatalf("expected error to contain %q, got %q", expected, msg)
		}
	}
}
