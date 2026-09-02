package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
		{name: "limit exactly at the ceiling is preserved", in: LogQuery{Limit: 100}, wantLimit: 100, wantOffset: 0},
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

func TestParseLogQueryOffsetCeiling(t *testing.T) {
	limits := QueryLimits{DefaultLimit: 25, MaxLimit: 100, MaxOffset: 1000}

	t.Run("offset exactly at the ceiling is accepted", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/logs?offset=1000", nil)
		got, err := parseLogQuery(r, limits)
		if err != nil {
			t.Fatalf("parseLogQuery() error = %v, want nil", err)
		}
		if got.Offset != 1000 {
			t.Errorf("Offset = %d, want %d", got.Offset, 1000)
		}
	})

	t.Run("offset one past the ceiling is rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/logs?offset=1001", nil)
		_, err := parseLogQuery(r, limits)
		if err == nil {
			t.Fatal("parseLogQuery() error = nil, want an error")
		}
		if !strings.Contains(err.Error(), "cursor") {
			t.Errorf("error = %q, want it to mention %q", err.Error(), "cursor")
		}
	})

	t.Run("no limit parameter takes the configured default", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/logs", nil)
		got, err := parseLogQuery(r, limits)
		if err != nil {
			t.Fatalf("parseLogQuery() error = %v, want nil", err)
		}
		if got.Limit != limits.DefaultLimit {
			t.Errorf("Limit = %d, want %d", got.Limit, limits.DefaultLimit)
		}
	})
}

func TestParseLogQueryRejectsMalformedNumbers(t *testing.T) {
	limits := QueryLimits{DefaultLimit: 25, MaxLimit: 100, MaxOffset: 1000}

	t.Run("non-numeric limit is rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/logs?limit=abc", nil)
		_, err := parseLogQuery(r, limits)
		if err == nil {
			t.Fatal("parseLogQuery() error = nil, want an error")
		}
	})

	t.Run("non-numeric offset is rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/v1/logs?offset=abc", nil)
		_, err := parseLogQuery(r, limits)
		if err == nil {
			t.Fatal("parseLogQuery() error = nil, want an error")
		}
	})
}
