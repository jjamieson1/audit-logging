package main

import "testing"

// The bug this guards: semgrep writes its JSON document to stdout and a progress
// banner to stderr. While both were captured into one buffer the document did
// not parse, countJSONArray returned 0, and the dashboard reported
// "pass — 0 findings" for a scan that had actually found 42.
const semgrepBanner = "\n\n┌─────────────┐\n│ Scan Status │\n└─────────────┘\n  Scanning 415 files\n"

func TestJSONParsersReadStdoutNotTheBanner(t *testing.T) {
	semgrepJSON := `{"results":[{"check_id":"a"},{"check_id":"b"},{"check_id":"c"}],"errors":[]}`
	gosecJSON := `{"Issues":[{"rule_id":"G101"}],"Stats":{}}`
	npmJSON := `{"metadata":{"vulnerabilities":{"critical":2,"high":1,"total":3}}}`

	tests := []struct {
		name, parser, stdout, stderr string
		wantStatus                   string
		wantFindings                 int
	}{
		{
			name:   "semgrep findings survive a stderr banner",
			parser: "semgrep-json", stdout: semgrepJSON, stderr: semgrepBanner,
			wantStatus: "warn", wantFindings: 3,
		},
		{
			name:   "gosec findings survive a stderr banner",
			parser: "gosec-json", stdout: gosecJSON, stderr: "[gosec] loading...\n",
			wantStatus: "warn", wantFindings: 1,
		},
		{
			name:   "npm audit counts survive a stderr notice",
			parser: "npm-audit", stdout: npmJSON, stderr: "npm notice New major version\n",
			wantStatus: "fail", wantFindings: 3,
		},
		{
			// A genuinely clean scan still reads as a pass.
			name:   "clean semgrep scan passes",
			parser: "semgrep-json", stdout: `{"results":[],"errors":[]}`, stderr: semgrepBanner,
			wantStatus: "pass", wantFindings: 0,
		},
		{
			// Tools omit the key entirely when they find nothing; that is a real
			// zero, not a parse failure.
			name:   "missing key is a legitimate zero",
			parser: "gosec-json", stdout: `{"Stats":{}}`, stderr: "",
			wantStatus: "pass", wantFindings: 0,
		},
		{
			// The failure mode that must never read as a pass.
			name:   "unparseable output is an error",
			parser: "semgrep-json", stdout: "", stderr: "semgrep: command not found\n",
			wantStatus: "error",
		},
		{
			name:   "truncated JSON is an error",
			parser: "gosec-json", stdout: `{"Issues":[{"rule_`, stderr: "",
			wantStatus: "error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &CheckResult{CheckDef: CheckDef{Parser: tc.parser}}
			parseResult(res, tc.stdout, tc.stderr+tc.stdout, 0)
			if res.Status != tc.wantStatus {
				t.Errorf("status = %q (%q), want %q", res.Status, res.Summary, tc.wantStatus)
			}
			if tc.wantStatus != "error" && res.Findings != tc.wantFindings {
				t.Errorf("findings = %d, want %d", res.Findings, tc.wantFindings)
			}
		})
	}
}

// gitleaks writes its entire report to stderr and nothing to stdout, so the text
// parsers must keep reading the combined stream.
func TestTextParsersStillReadStderr(t *testing.T) {
	tests := []struct {
		name, parser, stderr, wantStatus string
		wantFindings                     int
	}{
		{"gitleaks clean on stderr", "gitleaks", "INF no leaks found\n", "pass", 0},
		{"gitleaks findings on stderr", "gitleaks", "WRN leaks found: 3\n", "fail", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &CheckResult{CheckDef: CheckDef{Parser: tc.parser}}
			// stdout empty, everything on stderr — gitleaks' real shape.
			parseResult(res, "", tc.stderr, 0)
			if res.Status != tc.wantStatus {
				t.Errorf("status = %q (%q), want %q", res.Status, res.Summary, tc.wantStatus)
			}
			if res.Findings != tc.wantFindings {
				t.Errorf("findings = %d, want %d", res.Findings, tc.wantFindings)
			}
		})
	}
}

func TestCountJSONArrayReportsParseFailure(t *testing.T) {
	if _, ok := countJSONArray("not json", "results"); ok {
		t.Error("countJSONArray reported ok on non-JSON input")
	}
	if _, ok := countJSONArray(`{"Stats":{}}`, "Issues"); !ok {
		t.Error("countJSONArray reported failure for a valid document missing the key")
	}
	n, ok := countJSONArray(`{"results":[1,2]}`, "results")
	if !ok || n != 2 {
		t.Errorf("countJSONArray = (%d, %v), want (2, true)", n, ok)
	}
}
