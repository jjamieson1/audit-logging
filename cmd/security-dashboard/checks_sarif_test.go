package main

import "testing"

// A CodeQL-shaped log: severity lives on a rule under tool.extensions, which is
// where query packs put it, and results reference those rules by id.
const codeqlSARIF = `{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {"name": "CodeQL"},
      "extensions": [{"rules": [
        {"id": "go/sql-injection",  "properties": {"security-severity": "8.8"}},
        {"id": "go/clear-text-log", "properties": {"security-severity": "5.3"}}
      ]}]
    },
    "results": [
      {"ruleId": "go/sql-injection",  "level": "error"},
      {"ruleId": "go/clear-text-log", "level": "warning"},
      {"ruleId": "go/clear-text-log", "level": "warning"}
    ]
  }]
}`

func TestSARIFCounts(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		total, high int
		ok          bool
	}{
		{"codeql severities", codeqlSARIF, 3, 1, true},
		{
			// No security-severity property, so grading falls back to SARIF level.
			name:  "level fallback",
			in:    `{"runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"a","level":"error"},{"ruleId":"b","level":"note"}]}]}`,
			total: 2, high: 1, ok: true,
		},
		{
			// Severity on the driver rather than an extension.
			name:  "driver rules",
			in:    `{"runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"a","properties":{"security-severity":"9.1"}}]}},"results":[{"ruleId":"a","level":"warning"}]}]}`,
			total: 1, high: 1, ok: true,
		},
		{
			// A real, clean scan: runs present, results empty.
			name: "clean scan", in: `{"runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`,
			total: 0, high: 0, ok: true,
		},
		{"multiple runs", `{"runs":[
			{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"a","level":"error"}]},
			{"tool":{"driver":{"name":"y"}},"results":[{"ruleId":"b","level":"note"}]}]}`, 2, 1, true},
		{"7.0 is high", `{"runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"a","properties":{"security-severity":"7.0"}}]}},"results":[{"ruleId":"a"}]}]}`, 1, 1, true},
		{"6.9 is not high", `{"runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"a","properties":{"security-severity":"6.9"}}]}},"results":[{"ruleId":"a"}]}]}`, 1, 0, true},

		// Everything below must report ok=false so the caller raises an error
		// rather than silently recording a pass.
		{"empty output", "", 0, 0, false},
		{"not json", "codeql: command not found", 0, 0, false},
		{"json without runs", `{"results":[]}`, 0, 0, false},
		{"null runs", `{"runs":null}`, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			total, high, ok := sarifCounts(tc.in, nil)
			if ok != tc.ok || total != tc.total || high != tc.high {
				t.Errorf("sarifCounts() = (%d, %d, %v), want (%d, %d, %v)",
					total, high, ok, tc.total, tc.high, tc.ok)
			}
		})
	}
}

func TestSARIFParserStatus(t *testing.T) {
	tests := []struct {
		name, in, want string
		exit           int
	}{
		{name: "high severity fails", in: codeqlSARIF, want: "fail"},
		{name: "findings without high warn", exit: 0, want: "warn",
			in: `{"runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"a","level":"note"}]}]}`},
		{name: "clean scan passes", want: "pass",
			in: `{"runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`},

		// The regression this parser exists to prevent: a missing tool exits
		// non-zero with no SARIF, and must never read as a pass.
		{name: "missing tool errors", in: "sh: codeql: command not found", exit: 127, want: "error"},
		{name: "empty output errors", in: "", exit: 0, want: "error"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := &CheckResult{CheckDef: CheckDef{Parser: "sarif"}}
			parseResult(res, tc.in, tc.in, tc.exit)
			if res.Status != tc.want {
				t.Errorf("status = %q (%q), want %q", res.Status, res.Summary, tc.want)
			}
		})
	}
}

// Manifest suppressions exist because the CodeQL CLI emits no `suppressions`
// field — an in-code `// codeql[rule-id]` comment cannot clear a finding here.
func TestSARIFManifestSuppressions(t *testing.T) {
	const doc = `{"runs":[{"tool":{"driver":{"name":"CodeQL","rules":[
	  {"id":"go/log-injection","properties":{"security-severity":"6.1"}},
	  {"id":"go/request-forgery","properties":{"security-severity":"9.1"}}]}},
	 "results":[
	  {"ruleId":"go/log-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"sdk/trustnode/node.go"}}}]},
	  {"ruleId":"go/request-forgery","locations":[{"physicalLocation":{"artifactLocation":{"uri":"internal/trustnode/discovery.go"}}}]},
	  {"ruleId":"go/log-injection","locations":[{"physicalLocation":{"artifactLocation":{"uri":"internal/other/thing.go"}}}]}]}]}`

	tests := []struct {
		name        string
		suppress    []Suppression
		total, high int
	}{
		{"none suppressed", nil, 3, 1},
		{
			name:     "rule+path match removes one",
			suppress: []Suppression{{Rule: "go/log-injection", Path: "sdk/trustnode/node.go"}},
			total:    2, high: 1,
		},
		{
			// The high-severity one is dismissed; the count must drop too.
			name:     "suppressing the high finding clears high",
			suppress: []Suppression{{Rule: "go/request-forgery", Path: "internal/trustnode/discovery.go"}},
			total:    2, high: 0,
		},
		{
			// A dismissal must not leak to another file with the same rule.
			name:     "path must match, not just rule",
			suppress: []Suppression{{Rule: "go/log-injection", Path: "sdk/trustnode/node.go"}},
			total:    2, high: 1,
		},
		{
			name:     "wrong rule on the right path does nothing",
			suppress: []Suppression{{Rule: "go/sql-injection", Path: "sdk/trustnode/node.go"}},
			total:    3, high: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			total, high, ok := sarifCounts(doc, tc.suppress)
			if !ok {
				t.Fatal("sarifCounts reported the fixture as unparseable")
			}
			if total != tc.total || high != tc.high {
				t.Errorf("= (%d total, %d high), want (%d, %d)", total, high, tc.total, tc.high)
			}
		})
	}
}
