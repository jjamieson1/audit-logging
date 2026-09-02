// Command security-dashboard turns the project's security + quality scans into a
// single, self-contained, shareable HTML dashboard — evidence that the app is
// tested with rigor, for developers and customers alike.
//
//	go run ./cmd/security-dashboard init      # scan the project, write/refresh security/config.json
//	go run ./cmd/security-dashboard init --check   # CI gate: fail on stack drift, warn on gaps
//	go run ./cmd/security-dashboard scan     # run all configured checks, record a run, re-render
//	go run ./cmd/security-dashboard render    # re-render dashboard.html from existing runs
//
// It is deliberately manifest-driven and language-agnostic: `scan` writes a JSON
// run manifest (+ raw reports) under security/runs/, and `render` builds the page
// from those manifests. Any project — Go or not — gets the same dashboard by
// dropping in a security/config.json describing its checks. That makes it a
// reusable piece of C2 for every client application (permitting, facility
// booking, …).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---- data model (the security/ manifest schema) ---------------------------

type Config struct {
	App struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Repo        string `json:"repo"`
		Team        string `json:"team"`
		Contact     string `json:"contact"`
	} `json:"app"`
	ManualDoc      string          `json:"manualDoc"`
	Standards      []Standard      `json:"standards"`
	ComplianceDocs []ComplianceDoc `json:"complianceDocs,omitempty"`
	ASVS           *ASVS           `json:"asvs,omitempty"`
	Conformance    []Conformance   `json:"conformance,omitempty"`
	Checks         []CheckDef      `json:"checks"`
}

// Conformance is a formal conformance/certification test result (e.g. the
// OpenID Foundation OIDC suite) shown as compliance evidence.
type Conformance struct {
	Name    string `json:"name"`
	Suite   string `json:"suite,omitempty"`
	Status  string `json:"status"` // passed | issues | pending
	Summary string `json:"summary,omitempty"`
	LastRun string `json:"lastRun,omitempty"`
	Report  string `json:"report,omitempty"`
}

// ASVS captures the OWASP ASVS level the app targets and the evidence for each
// control family — persuasive for enterprise/gov buyers.
type ASVS struct {
	TargetLevel  string        `json:"targetLevel"`
	Note         string        `json:"note"`
	Requirements []ASVSReqItem `json:"requirements"`
}

type ASVSReqItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Coverage string `json:"coverage"` // automated | partial | manual
	Evidence string `json:"evidence"`
}

type Standard struct {
	Name string `json:"name"`
	Note string `json:"note"`
	// Framework links this entry to a compliance doc in security/compliance/, so
	// `init --check` can tell a regime that is mapped from one merely in scope.
	Framework string `json:"framework,omitempty"`
}

// ComplianceDoc is a framework document (HIPAA, GDPR, PCI-DSS …) dropped into
// security/compliance/ by the project's initialization skill. `init` records
// what is in scope; authoring the controls it implies is the agent's job.
type ComplianceDoc struct {
	ID    string `json:"id"`    // slug from the filename
	Title string `json:"title"` // the doc's first H1
	Path  string `json:"path"`
}

// CheckDef is a configured scan. Adding a check is a JSON edit, no code change:
// give it a command and one of the built-in parsers (see checks.go).
type CheckDef struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Tool        string `json:"tool"`
	Gating      bool   `json:"gating"`
	Command     string `json:"command"`
	Parser      string `json:"parser"`
	Dir         string `json:"dir,omitempty"`
	InstallHint string `json:"installHint,omitempty"`
	// Probe names the binary whose absence means "skip". Needed when Command uses
	// shell syntax, because the first word is then `sh`/`set`/a redirect rather
	// than the tool — without it a missing tool runs, exits 127, and a lenient
	// parser can read the empty output as a pass.
	Probe string `json:"probe,omitempty"`
	// Suppress lists findings dismissed after review. It exists because CodeQL's
	// in-code `// codeql[rule-id]` comments are a GitHub code-scanning feature
	// applied server-side: the CLI emits no `suppressions` in its SARIF, so an
	// annotation in the source cannot clear a finding here. Keeping the dismissals
	// in the manifest also puts every reason in one reviewable place.
	Suppress []Suppression `json:"suppress,omitempty"`

	// Source records who authored this check: "detected" (written by `init`) or
	// empty, which means hand-authored — `init` never rewrites or removes those.
	Source string `json:"source,omitempty"`
	// Disabled is the deliberate opt-out. `scan` skips it and `init` treats the
	// signal as covered, so it is not resurrected on the next run.
	Disabled bool   `json:"disabled,omitempty"`
	Reason   string `json:"reason,omitempty"` // why it is disabled
}

// Suppression dismisses one reviewed finding. Rule and Path must both match,
// so a dismissal cannot silently widen to another call site, and Reason is
// required — an unexplained suppression is indistinguishable from hiding a bug.
type Suppression struct {
	Rule   string `json:"rule"`   // tool rule id, e.g. "go/log-injection"
	Path   string `json:"path"`   // file the finding sits in
	Reason string `json:"reason"` // why it was dismissed
}

// CheckResult is the outcome of running a CheckDef.
type CheckResult struct {
	CheckDef
	Status     string `json:"status"` // pass | fail | warn | skipped | error
	Summary    string `json:"summary"`
	Findings   int    `json:"findings"`
	ReportFile string `json:"reportFile,omitempty"` // relative to security/
	DurationMs int64  `json:"durationMs"`
}

// Run is one comprehensive scan.
type Run struct {
	ID        string        `json:"id"` // e.g. 20260825T101500Z
	StartedAt string        `json:"startedAt"`
	GitSHA    string        `json:"gitSha"`
	GitBranch string        `json:"gitBranch"`
	Trigger   string        `json:"trigger"` // manual | ci | nightly
	Checks    []CheckResult `json:"checks"`
	Totals    Totals        `json:"totals"`
}

type Totals struct {
	Pass, Fail, Warn, Skipped, GatingFail int
}

type Tasks struct {
	Tasks []Task `json:"tasks"`
}

type Task struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Category  string `json:"category"`
	Cadence   string `json:"cadence"`
	Owner     string `json:"owner"`
	Status    string `json:"status"`
	LastRun   string `json:"lastRun"`
	NextDue   string `json:"nextDue"`
	DocAnchor string `json:"docAnchor"`
	Notes     string `json:"notes"`
	// LastNote is what the last run of this task found — the evidence a reader
	// wants next to the date. Notes above stays the method description.
	LastNote string `json:"lastNote,omitempty"`
	// IntervalDays opts a task into time-based tracking that its cadence text
	// cannot express (an event-driven "Every release" that should also not go
	// stale, or a bespoke interval). Overrides the cadence-derived interval.
	IntervalDays int    `json:"intervalDays,omitempty"`
	Source       string `json:"source,omitempty"` // "baseline" when seeded by `init`
}

// ---- entrypoint ------------------------------------------------------------

func main() {
	dir := "security"
	trigger := "manual"
	args := os.Args[1:]
	cmd := "render"
	if len(args) > 0 && (args[0] == "scan" || args[0] == "render" || args[0] == "bundle" || args[0] == "init" || args[0] == "task") {
		cmd = args[0]
		args = args[1:]
	}

	var opts initOpts
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			opts.dryRun = true
		case "--check":
			opts.check = true
		case "--force":
			opts.force = true
		case "--dir":
			i++
			if i < len(args) {
				dir = args[i]
			}
		case "--trigger":
			i++
			if i < len(args) {
				trigger = args[i]
			}
		}
	}

	// `init` generates the manifest, so it must run before anything tries to load
	// one.
	if cmd == "init" {
		if err := runInit(dir, opts); err != nil {
			fatal(err)
		}
		return
	}

	// `task` records and reports the manual programme; it touches only
	// tasks.json, so it needs no config.
	if cmd == "task" {
		if err := runTask(dir, args); err != nil {
			fatal(err)
		}
		return
	}

	cfg, err := loadConfig(dir)
	if err != nil {
		fatal(err)
	}

	// `bundle` emits a full health bundle (security + compliance) to stdout, ready
	// to upload to C2's admin Health dashboard for this application. Availability
	// is left for the caller/monitoring to add.
	if cmd == "bundle" {
		b, err := buildBundle(dir, cfg)
		if err != nil {
			fatal(err)
		}
		_, _ = os.Stdout.Write(append(b, '\n'))
		return
	}

	if cmd == "scan" {
		run := performScan(cfg, dir, trigger)
		if err := saveRun(dir, run); err != nil {
			fatal(err)
		}
		fmt.Printf("security-dashboard: recorded run %s (%d pass, %d fail, %d warn, %d skipped)\n",
			run.ID, run.Totals.Pass, run.Totals.Fail, run.Totals.Warn, run.Totals.Skipped)
	}

	if err := render(dir, cfg); err != nil {
		fatal(err)
	}
	fmt.Printf("security-dashboard: wrote %s\n", filepath.Join(dir, "dashboard.html"))
	// Surface the manual programme in the same output as the scan, so a lapsed
	// schedule is visible in CI logs and not only on the page.
	fmt.Printf("security-dashboard: manual tasks — %s\n", summarizeTasks(loadTasks(dir).Tasks, time.Now()).Line)
}

// runTask handles the `task` subcommand:
//
//	task list                 show the schedule in the terminal
//	task done <id> [flags]    stamp a manual task as performed today
//
// Flags: --date YYYY-MM-DD (default today), --owner <name>, --note <text>.
func runTask(dir string, args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		printTaskSchedule(dir, os.Stdout)
		return nil
	case "done":
	default:
		return fmt.Errorf("unknown task command %q (want: list, done)", sub)
	}

	id := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		id = args[0]
		args = args[1:]
	}
	if id == "" {
		return fmt.Errorf("usage: task done <id> [--date YYYY-MM-DD] [--owner <name>] [--note <text>]")
	}

	date := time.Now().Format("2006-01-02")
	owner, note := "", ""
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if i+1 >= len(args) {
			return fmt.Errorf("%s needs a value", flag)
		}
		i++
		switch flag {
		case "--date":
			date = args[i]
		case "--owner":
			owner = args[i]
		case "--note":
			note = args[i]
		case "--dir":
			// Already applied by the caller; consume its value so it is not read
			// as another flag.
		default:
			return fmt.Errorf("unknown flag %q", flag)
		}
	}

	if err := markTaskDone(dir, id, date, owner, note); err != nil {
		return err
	}
	fmt.Printf("security-dashboard: recorded %s as done on %s\n", id, date)

	// Re-render so the page and the manifest never disagree.
	cfg, err := loadConfig(dir)
	if err != nil {
		return err
	}
	if err := render(dir, cfg); err != nil {
		return err
	}
	fmt.Printf("security-dashboard: wrote %s\n", filepath.Join(dir, "dashboard.html"))
	return nil
}

// buildBundle assembles a health bundle for upload to C2: the latest security
// run plus the compliance evidence from config. Shape matches the admin Health
// upload contract ({security, compliance}).
func buildBundle(dir string, cfg Config) ([]byte, error) {
	runs := loadRuns(dir)
	if len(runs) == 0 {
		return nil, fmt.Errorf("no runs found in %s/runs — run `scan` first", dir)
	}
	compliance := map[string]any{
		"standards":   cfg.Standards,
		"conformance": cfg.Conformance,
	}
	if cfg.ASVS != nil {
		compliance["asvsLevel"] = cfg.ASVS.TargetLevel
		compliance["note"] = cfg.ASVS.Note
		compliance["requirements"] = cfg.ASVS.Requirements
	}
	bundle := map[string]any{
		"app":        map[string]string{"name": cfg.App.Name, "description": cfg.App.Description},
		"security":   runs[0],
		"compliance": compliance,
	}
	return json.MarshalIndent(bundle, "", "  ")
}

// ---- manifest IO -----------------------------------------------------------

func loadConfig(dir string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func loadTasks(dir string) Tasks {
	var t Tasks
	if b, err := os.ReadFile(filepath.Join(dir, "tasks.json")); err == nil {
		_ = json.Unmarshal(b, &t)
	}
	return t
}

func saveRun(dir string, run Run) error {
	runsDir := filepath.Join(dir, "runs")
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runsDir, run.ID+".json"), append(b, '\n'), 0o644)
}

// loadRuns returns every recorded run, newest first.
func loadRuns(dir string) []Run {
	var runs []Run
	matches, _ := filepath.Glob(filepath.Join(dir, "runs", "*.json"))
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		var r Run
		if json.Unmarshal(b, &r) == nil && r.ID != "" {
			runs = append(runs, r)
		}
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].ID > runs[j].ID })
	return runs
}

func newRunID(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "security-dashboard:", err)
	os.Exit(1)
}
