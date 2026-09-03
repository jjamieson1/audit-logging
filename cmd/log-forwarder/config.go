package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Config struct {
	ServerURL               string `json:"server_url"`
	AuthBearerToken         string `json:"auth_bearer_token"`
	SourceFile              string `json:"source_file"`
	AppName                 string `json:"app_name"`
	TimestampField          string `json:"timestamp_field"`
	ParserMode              string `json:"parser_mode"`
	RegexPattern            string `json:"regex_pattern"`
	DefaultLevel            string `json:"default_level"`
	PollIntervalMS          int    `json:"poll_interval_ms"`
	BatchSize               int    `json:"batch_size"`
	FlushIntervalMS         int    `json:"flush_interval_ms"`
	CheckpointPath          string `json:"checkpoint_path"`
	RetryMaxAttempts        int    `json:"retry_max_attempts"`
	RetryInitialBackoffMS   int    `json:"retry_initial_backoff_ms"`
	RetryMaxBackoffMS       int    `json:"retry_max_backoff_ms"`
	RequestTimeoutMS        int    `json:"request_timeout_ms"`
	DeadLetterPath          string `json:"dead_letter_path"`
	MetricsPort             int    `json:"metrics_port"`
	MetricsReportIntervalMS int    `json:"metrics_report_interval_ms"`
	VerifyIntervalMS        int    `json:"verify_interval_ms"`
}

func LoadConfig(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("config path is required")
	}

	// #nosec G304 -- the config path comes from this process's own -config
	// flag. A forwarder that cannot read an operator-chosen config is useless.
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	if err := cfg.applyDefaults(path); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) applyDefaults(configPath string) error {
	configDir := filepath.Dir(configPath)

	c.ServerURL = strings.TrimSpace(c.ServerURL)
	c.AuthBearerToken = strings.TrimSpace(c.AuthBearerToken)
	c.SourceFile = strings.TrimSpace(c.SourceFile)
	c.AppName = strings.TrimSpace(c.AppName)
	c.TimestampField = strings.TrimSpace(c.TimestampField)
	c.ParserMode = strings.ToLower(strings.TrimSpace(c.ParserMode))
	c.RegexPattern = strings.TrimSpace(c.RegexPattern)
	c.DefaultLevel = strings.ToUpper(strings.TrimSpace(c.DefaultLevel))
	c.CheckpointPath = strings.TrimSpace(c.CheckpointPath)
	c.DeadLetterPath = strings.TrimSpace(c.DeadLetterPath)

	if c.ParserMode == "" {
		c.ParserMode = "custom"
	}
	if c.DefaultLevel == "" {
		c.DefaultLevel = "INFO"
	}
	if c.PollIntervalMS <= 0 {
		c.PollIntervalMS = 250
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 1
	}
	if c.FlushIntervalMS <= 0 {
		c.FlushIntervalMS = 1000
	}
	if c.CheckpointPath == "" {
		c.CheckpointPath = filepath.Join(configDir, "log-forwarder.checkpoint.json")
	}
	if c.DeadLetterPath == "" {
		c.DeadLetterPath = filepath.Join(configDir, "log-forwarder.deadletter.jsonl")
	}
	if c.RetryMaxAttempts <= 0 {
		c.RetryMaxAttempts = 5
	}
	if c.RetryInitialBackoffMS <= 0 {
		c.RetryInitialBackoffMS = 200
	}
	if c.RetryMaxBackoffMS <= 0 {
		c.RetryMaxBackoffMS = 5000
	}
	if c.RequestTimeoutMS <= 0 {
		c.RequestTimeoutMS = 10000
	}
	if c.MetricsReportIntervalMS <= 0 {
		c.MetricsReportIntervalMS = 30000
	}
	if c.VerifyIntervalMS <= 0 {
		c.VerifyIntervalMS = 60000
	}

	if c.SourceFile != "" {
		absSourceFile, err := filepath.Abs(c.SourceFile)
		if err != nil {
			return fmt.Errorf("resolve source_file path: %w", err)
		}
		c.SourceFile = absSourceFile
	}

	absCheckpoint, err := filepath.Abs(c.CheckpointPath)
	if err != nil {
		return fmt.Errorf("resolve checkpoint_path: %w", err)
	}
	c.CheckpointPath = absCheckpoint

	absDeadLetter, err := filepath.Abs(c.DeadLetterPath)
	if err != nil {
		return fmt.Errorf("resolve dead_letter_path: %w", err)
	}
	c.DeadLetterPath = absDeadLetter

	return nil
}

func (c Config) Validate() error {
	var problems []string

	if c.ServerURL == "" {
		problems = append(problems, "server_url is required")
	} else {
		u, err := url.Parse(c.ServerURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			problems = append(problems, "server_url must be a valid absolute URL")
		}
	}

	if c.AuthBearerToken == "" {
		problems = append(problems, "auth_bearer_token is required")
	}
	if c.SourceFile == "" {
		problems = append(problems, "source_file is required")
	}
	if c.AppName == "" {
		problems = append(problems, "app_name is required")
	}
	if c.TimestampField == "" {
		problems = append(problems, "timestamp_field is required")
	}
	if c.PollIntervalMS <= 0 {
		problems = append(problems, "poll_interval_ms must be > 0")
	}
	if c.BatchSize <= 0 {
		problems = append(problems, "batch_size must be > 0")
	}
	if c.FlushIntervalMS <= 0 {
		problems = append(problems, "flush_interval_ms must be > 0")
	}
	if c.RetryMaxAttempts <= 0 {
		problems = append(problems, "retry_max_attempts must be > 0")
	}
	if c.RetryInitialBackoffMS <= 0 {
		problems = append(problems, "retry_initial_backoff_ms must be > 0")
	}
	if c.RetryMaxBackoffMS < c.RetryInitialBackoffMS {
		problems = append(problems, "retry_max_backoff_ms must be >= retry_initial_backoff_ms")
	}
	if c.RequestTimeoutMS <= 0 {
		problems = append(problems, "request_timeout_ms must be > 0")
	}
	if c.MetricsPort < 0 || c.MetricsPort > 65535 {
		problems = append(problems, "metrics_port must be between 0 and 65535")
	}
	if c.MetricsReportIntervalMS <= 0 {
		problems = append(problems, "metrics_report_interval_ms must be > 0")
	}
	if c.VerifyIntervalMS <= 0 {
		problems = append(problems, "verify_interval_ms must be > 0")
	}

	switch c.ParserMode {
	case "json", "regex", "custom":
	default:
		problems = append(problems, "parser_mode must be one of: json, regex, custom")
	}

	if c.ParserMode == "regex" {
		if c.RegexPattern == "" {
			problems = append(problems, "regex_pattern is required when parser_mode=regex")
		} else if _, err := regexp.Compile(c.RegexPattern); err != nil {
			problems = append(problems, "regex_pattern is invalid: "+err.Error())
		}
	}

	if c.SourceFile != "" {
		info, err := os.Stat(c.SourceFile)
		if err != nil {
			problems = append(problems, "source_file is not accessible: "+err.Error())
		} else if info.IsDir() {
			problems = append(problems, "source_file must be a file, not a directory")
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(problems, "; "))
	}

	return nil
}
