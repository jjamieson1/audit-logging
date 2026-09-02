package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// performScan runs every configured check, captures its output as a raw report,
// classifies the result, and assembles a Run. A check whose tool isn't installed
// is recorded as "skipped" (with an install hint) rather than failing the scan —
// so the dashboard honestly shows both what ran and what's available to enable.
func performScan(cfg Config, dir, trigger string) Run {
	now := time.Now()
	run := Run{
		ID:        newRunID(now),
		StartedAt: now.UTC().Format(time.RFC3339),
		GitSHA:    gitOut("rev-parse", "--short", "HEAD"),
		GitBranch: gitOut("rev-parse", "--abbrev-ref", "HEAD"),
		Trigger:   trigger,
	}
	runDir := filepath.Join(dir, "runs", run.ID)
	_ = os.MkdirAll(runDir, 0o755)

	for _, def := range cfg.Checks {
		if def.Disabled {
			continue
		}
		fmt.Printf("  · %-28s ", def.Key)
		res := runCheck(def, runDir)
		run.Checks = append(run.Checks, res)
		fmt.Printf("%s%s\n", statusGlyph(res.Status), func() string {
			if res.Summary != "" {
				return " — " + res.Summary
			}
			return ""
		}())
	}
	run.Totals = tally(run.Checks)
	return run
}

func runCheck(def CheckDef, runDir string) CheckResult {
	res := CheckResult{CheckDef: def}

	// Resolve the tool binary and skip cleanly if it's absent. An explicit Probe
	// wins, and is the only way to resolve the tool behind a command that uses
	// shell syntax: such a command's first word isn't a resolvable binary
	// (`sh`, `set`, a redirect), so the inference below has to let it through.
	if def.Probe != "" {
		if _, err := exec.LookPath(def.Probe); err != nil {
			res.Status = "skipped"
			res.Summary = "not installed"
			return res
		}
	} else if bin := firstWord(def.Command); bin != "go" && bin != "npm" && !strings.ContainsAny(def.Command, ";|&$`") {
		if _, err := exec.LookPath(bin); err != nil {
			res.Status = "skipped"
			res.Summary = "not installed"
			return res
		}
	}
	if def.Dir != "" {
		if _, err := os.Stat(def.Dir); err != nil {
			res.Status = "skipped"
			res.Summary = def.Dir + " not present"
			return res
		}
	}

	start := time.Now()
	cmd := exec.Command("sh", "-c", def.Command)
	cmd.Dir = def.Dir
	// Captured apart because the two streams serve different parsers. Tools that
	// emit a JSON document put it on stdout and interleave progress and warnings
	// on stderr, where a single byte of banner makes the document unparseable —
	// but gitleaks writes its entire report to stderr, so text parsers still need
	// both. See parseResult.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	res.DurationMs = time.Since(start).Milliseconds()

	// Persist the raw report next to the run manifest and link it relatively. It
	// keeps both streams, labelled, so a failed check can still be diagnosed.
	var report bytes.Buffer
	if stderr.Len() > 0 {
		report.WriteString("=== stderr ===\n")
		report.Write(stderr.Bytes())
		report.WriteString("\n=== stdout ===\n")
	}
	report.Write(stdout.Bytes())
	reportName := def.Key + ".txt"
	_ = os.WriteFile(filepath.Join(runDir, reportName), report.Bytes(), 0o644)
	// Linked relative to security/ so the dashboard opens reports locally.
	res.ReportFile = filepath.Join("runs", filepath.Base(runDir), reportName)

	exit := exitCode(runErr)
	parseResult(&res, stdout.String(), stderr.String()+stdout.String(), exit)
	return res
}

// parseResult applies the check's named parser to turn raw output + exit code
// into a status and finding count. Parsers are intentionally forgiving: if a
// tool's format shifts, we fall back to the exit code rather than crash.
// structured is the stream a JSON parser should read: stdout, falling back to
// the combined output for a tool that writes its document to stderr.
func structured(stdout, combined string) string {
	if strings.TrimSpace(stdout) != "" {
		return stdout
	}
	return combined
}

// unparseable marks a check whose tool produced output the parser could not
// read. It is never a pass: reporting "0 findings" because the document failed
// to parse is how a scanner that is finding real problems comes out green.
func unparseable(res *CheckResult, what string, exit int) {
	res.Status = "error"
	res.Summary = fmt.Sprintf("could not parse %s output (exit %d)", what, exit)
}

func parseResult(res *CheckResult, stdout, combined string, exit int) {
	// Text parsers read the combined stream; the tools they cover put their
	// report on either stream and are line-oriented, so extra banner is harmless.
	output := combined
	switch res.Parser {
	case "govulncheck":
		// Prefer govulncheck's authoritative summary ("Your code is affected by N
		// vulnerabilities"); fall back to counting entries. Only *affecting* vulns
		// (ones your code calls) count as failures.
		n := 0
		if m := reAffected.FindStringSubmatch(output); len(m) == 2 {
			n = atoi(m[1])
		} else if strings.Contains(output, "No vulnerabilities found") {
			n = 0
		} else {
			n = len(reVuln.FindAllString(output, -1))
		}
		res.Findings = n
		if n > 0 {
			res.Status = "fail"
			res.Summary = plural(n, "vulnerability your code calls", "vulnerabilities your code calls")
		} else {
			res.Status = "pass"
			res.Summary = "no known vulnerable dependencies called"
		}
	case "gosec-json":
		n, ok := countJSONArray(structured(stdout, combined), "Issues")
		if !ok {
			unparseable(res, "gosec JSON", exit)
			return
		}
		res.Findings = n
		gradeFindings(res, "issue", "issues")
	case "semgrep-json":
		n, ok := countJSONArray(structured(stdout, combined), "results")
		if !ok {
			unparseable(res, "Semgrep JSON", exit)
			return
		}
		res.Findings = n
		gradeFindings(res, "finding", "findings")
	case "gitleaks":
		if m := reLeaks.FindStringSubmatch(output); len(m) == 2 {
			res.Findings = atoi(m[1])
		} else if exit != 0 {
			res.Findings = 1
		}
		if res.Findings > 0 {
			res.Status = "fail"
			res.Summary = plural(res.Findings, "secret leaked", "secrets leaked")
		} else {
			res.Status = "pass"
			res.Summary = "no secrets detected"
		}
	case "npm-audit":
		crit, high, ok := npmAuditCounts(structured(stdout, combined))
		if !ok {
			unparseable(res, "npm audit JSON", exit)
			return
		}
		res.Findings = crit + high
		if crit > 0 {
			res.Status = "fail"
		} else if high > 0 {
			res.Status = "warn"
		} else {
			res.Status = "pass"
		}
		res.Summary = fmt.Sprintf("%d critical, %d high", crit, high)
	case "sarif":
		// SARIF is the lingua franca of code scanners (CodeQL, Scorecard, semgrep
		// --sarif), so this parser is deliberately tool-agnostic: it grades on
		// severity, not on which tool produced the file.
		total, high, ok := sarifCounts(structured(stdout, combined), res.Suppress)
		if !ok {
			// No parseable SARIF. Never call that a pass — the tool crashed, wrote
			// its report elsewhere, or emitted a format we don't understand, and
			// silently reporting green would be worse than reporting nothing.
			res.Status = "error"
			if exit != 0 {
				res.Summary = fmt.Sprintf("no SARIF output (exit %d)", exit)
			} else {
				res.Summary = "no SARIF output"
			}
			return
		}
		res.Findings = total
		switch {
		case high > 0:
			res.Status = "fail"
			res.Summary = fmt.Sprintf("%s, %d high or critical", plural(total, "finding", "findings"), high)
		case total > 0:
			res.Status = "warn"
			res.Summary = plural(total, "finding", "findings")
		default:
			res.Status = "pass"
			res.Summary = "no findings"
		}
	case "eslint-json":
		// ESLint's JSON report is a top-level array of files, not an object, so
		// countJSONArray does not apply.
		errs, warns, ok := eslintCounts(structured(stdout, combined))
		if !ok {
			unparseable(res, "ESLint JSON", exit)
			return
		}
		res.Findings = errs + warns
		switch {
		case errs > 0:
			res.Status = "fail"
		case warns > 0:
			res.Status = "warn"
		default:
			res.Status = "pass"
		}
		res.Summary = fmt.Sprintf("%d error(s), %d warning(s)", errs, warns)
	case "vitest-json":
		total, failed, ok := vitestCounts(structured(stdout, combined))
		if !ok {
			unparseable(res, "Vitest JSON", exit)
			return
		}
		res.Findings = failed
		if failed > 0 {
			res.Status = "fail"
			res.Summary = fmt.Sprintf("%d of %d tests failing", failed, total)
		} else {
			res.Status = "pass"
			res.Summary = plural(total, "test passed", "tests passed")
		}
	case "gotest":
		if exit == 0 {
			res.Status = "pass"
			if m := reTestOK.FindStringSubmatch(output); len(m) == 2 {
				res.Summary = "package tests passed"
			} else {
				res.Summary = "passed"
			}
		} else {
			res.Status = "fail"
			res.Findings = len(reTestFail.FindAllString(output, -1))
			res.Summary = plural(res.Findings, "test failed", "tests failed")
		}
	default: // "exit"
		if exit == 0 {
			res.Status = "pass"
			res.Summary = "passed"
		} else {
			res.Status = "fail"
			res.Summary = "non-zero exit"
		}
	}
}

// gradeFindings sets pass/warn from a raw finding count for advisory scanners.
func gradeFindings(res *CheckResult, one, many string) {
	if res.Findings > 0 {
		res.Status = "warn"
	} else {
		res.Status = "pass"
	}
	res.Summary = plural(res.Findings, one, many)
}

// ---- small parser helpers --------------------------------------------------

var (
	reVuln     = regexp.MustCompile(`Vulnerability #\d+`)
	reAffected = regexp.MustCompile(`affected by (\d+) vulnerabilit`)
	reLeaks    = regexp.MustCompile(`(?i)leaks found:?\s*(\d+)`)
	reTestOK   = regexp.MustCompile(`(?m)^ok\s+\S+`)
	reTestFail = regexp.MustCompile(`(?m)^--- FAIL`)
)

// countJSONArray parses output as JSON and returns len() of the named top-level
// array field. ok is false when the document does not parse, which the caller
// must surface as an error — a missing field, by contrast, is a legitimate zero
// (tools omit the key when they find nothing).
func countJSONArray(output, field string) (n int, ok bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(output), &m) != nil {
		return 0, false
	}
	raw, present := m[field]
	if !present {
		return 0, true
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return 0, false
	}
	return len(arr), true
}

// sarifCounts reports the number of results in a SARIF log and how many of them
// are high severity. ok is false when the input isn't SARIF at all, which the
// caller must treat as an error rather than an empty (clean) result.
//
// Severity is read from the rule's `security-severity` property — a CVSS-style
// 0-10 score, the convention CodeQL and GitHub code scanning use, where >= 7.0
// is high or critical. Tools that set no such property fall back to the SARIF
// `level`, where "error" is the high band.
func sarifCounts(output string, suppress []Suppression) (total, high int, ok bool) {
	type rule struct {
		ID         string `json:"id"`
		Properties struct {
			SecuritySeverity string `json:"security-severity"`
		} `json:"properties"`
	}
	var doc struct {
		Runs *[]struct {
			Tool struct {
				Driver struct {
					Rules []rule `json:"rules"`
				} `json:"driver"`
				Extensions []struct {
					Rules []rule `json:"rules"`
				} `json:"extensions"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				// A result the analysis itself marked suppressed — CodeQL populates
				// this from a `// codeql[rule-id]` comment at the alert. Counting
				// these would make an in-code dismissal impossible to act on.
				Suppressions []struct {
					Kind string `json:"kind"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	// A pointer distinguishes "runs was absent" (not SARIF) from "runs was []"
	// (a real, clean scan).
	if json.Unmarshal([]byte(output), &doc) != nil || doc.Runs == nil {
		return 0, 0, false
	}

	for _, r := range *doc.Runs {
		// Rules live on the driver, or on extensions when the scan pulled in query
		// packs — CodeQL uses the latter, so both have to be indexed.
		severity := map[string]float64{}
		index := func(rules []rule) {
			for _, rl := range rules {
				if s, err := strconv.ParseFloat(rl.Properties.SecuritySeverity, 64); err == nil {
					severity[rl.ID] = s
				}
			}
		}
		index(r.Tool.Driver.Rules)
		for _, ext := range r.Tool.Extensions {
			index(ext.Rules)
		}

		for _, res := range r.Results {
			// Honour a suppression the analysis itself recorded. The CodeQL CLI
			// never sets this, but other SARIF producers do, and ignoring it would
			// re-report something a tool was told to dismiss.
			if len(res.Suppressions) > 0 {
				continue
			}
			var path string
			if len(res.Locations) > 0 {
				path = res.Locations[0].PhysicalLocation.ArtifactLocation.URI
			}
			if suppressed(suppress, res.RuleID, path) {
				continue
			}
			total++
			if s, found := severity[res.RuleID]; found {
				if s >= 7.0 {
					high++
				}
				continue
			}
			if res.Level == "error" {
				high++
			}
		}
	}
	return total, high, true
}

// suppressed reports whether a finding was dismissed in the manifest. Both the
// rule and the path must match: a rule-only dismissal would silently cover new
// call sites as the code grows, which is how a suppression stops meaning
// "reviewed" and starts meaning "ignored".
func suppressed(list []Suppression, rule, path string) bool {
	for _, s := range list {
		if s.Rule == rule && s.Path == path {
			return true
		}
	}
	return false
}

// eslintCounts totals errors and warnings across ESLint's per-file report.
func eslintCounts(output string) (errs, warns int, ok bool) {
	var files []struct {
		ErrorCount   int `json:"errorCount"`
		WarningCount int `json:"warningCount"`
	}
	if json.Unmarshal([]byte(output), &files) != nil {
		return 0, 0, false
	}
	for _, f := range files {
		errs += f.ErrorCount
		warns += f.WarningCount
	}
	return errs, warns, true
}

// vitestCounts reads the run totals from `vitest run --reporter=json`.
func vitestCounts(output string) (total, failed int, ok bool) {
	var doc struct {
		Total  *int `json:"numTotalTests"`
		Failed int  `json:"numFailedTests"`
	}
	// numTotalTests is a pointer so a JSON document that simply lacks it (any
	// other tool's output) is rejected rather than read as "0 tests, all passing".
	if json.Unmarshal([]byte(output), &doc) != nil || doc.Total == nil {
		return 0, 0, false
	}
	return *doc.Total, doc.Failed, true
}

// npmAuditCounts pulls critical/high counts from `npm audit --json`. ok is false
// when the document does not parse.
func npmAuditCounts(output string) (crit, high int, ok bool) {
	var doc struct {
		Metadata struct {
			Vulnerabilities struct {
				Critical int `json:"critical"`
				High     int `json:"high"`
			} `json:"vulnerabilities"`
		} `json:"metadata"`
	}
	if json.Unmarshal([]byte(output), &doc) != nil {
		return 0, 0, false
	}
	return doc.Metadata.Vulnerabilities.Critical, doc.Metadata.Vulnerabilities.High, true
}

func tally(checks []CheckResult) Totals {
	var t Totals
	for _, c := range checks {
		switch c.Status {
		case "pass":
			t.Pass++
		case "fail", "error":
			t.Fail++
			if c.Gating {
				t.GatingFail++
			}
		case "warn":
			t.Warn++
		case "skipped":
			t.Skipped++
		}
	}
	return t
}

// ---- misc ------------------------------------------------------------------

func gitOut(args ...string) string {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if bytes.Contains([]byte(err.Error()), []byte("executable file not found")) {
		return 127
	}
	if asExit(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}

func asExit(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func firstWord(s string) string {
	first, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	return first
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func statusGlyph(status string) string {
	switch status {
	case "pass":
		return "✓ pass"
	case "fail", "error":
		return "✗ FAIL"
	case "warn":
		return "! warn"
	case "skipped":
		return "– skipped"
	}
	return status
}
