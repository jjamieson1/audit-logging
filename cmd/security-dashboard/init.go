package main

// `init` writes security/config.json (and a tasks.json skeleton) by scanning the
// project, and is safe to re-run so the manifest stays honest as the stack moves.
//
// The split is the whole design. Three kinds of content live in config.json:
//
//  1. Derivable from the filesystem — app identity and the `checks` array. init
//     owns this: it detects each stack signal (a Go module, a package.json, a
//     Dockerfile) and proposes the checks that cover it.
//  2. Derivable only from stated intent — which compliance regimes apply. That
//     arrives as markdown dropped into security/compliance/ by the project's
//     initialization skill. init records those docs so a regime can't sit in
//     scope while silently unmapped, but it does not interpret them.
//  3. Derivable only by reading the code — the `evidence` strings in the
//     standards / ASVS tables. init NEVER writes these. A generated compliance
//     table full of invented evidence is worse than no table at all, because the
//     compliance section is exactly what a customer reads as an assertion. init
//     leaves them to the agent and reports which ones are still missing.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type initOpts struct {
	dryRun bool
	check  bool
	force  bool
}

// A stack signal and a check that covers it. `covered` asks whether the existing
// config already does this job — matched on what a check *does* (its parser,
// tool, directory, command) rather than on its key, so a hand-written check with
// its own name and a narrower command still counts and init stays quiet. That is
// what lets init be introduced to a repo whose config was written by hand.
type proposal struct {
	signal   string
	required bool // absent ⇒ a real coverage hole (fails --check); else a suggestion
	def      CheckDef
	covered  func(CheckDef) bool
}

// A finding from --check. Drift (the config no longer matches the stack) fails;
// a gap (a tool not installed, a regime not yet mapped) warns — adopting a new
// framework must not red-build every app until every control is written up.
type finding struct {
	level string // fail | warn
	msg   string
}

// ---- entrypoint ------------------------------------------------------------

func runInit(dir string, opts initOpts) error {
	root := filepath.Dir(dir)
	if root == "" {
		root = "."
	}
	cfgPath := filepath.Join(dir, "config.json")

	raw := map[string]json.RawMessage{}
	existing := Config{}
	if b, err := os.ReadFile(cfgPath); err == nil {
		if opts.force {
			fmt.Printf("security-dashboard init: --force — rebuilding %s from scratch\n", cfgPath)
		} else {
			if err := json.Unmarshal(b, &raw); err != nil {
				return fmt.Errorf("parse %s: %w", cfgPath, err)
			}
			if err := json.Unmarshal(b, &existing); err != nil {
				return fmt.Errorf("parse %s: %w", cfgPath, err)
			}
		}
	} else if opts.check {
		return fmt.Errorf("%s does not exist — run `init` first", cfgPath)
	}

	st := detectStack(root)
	props := proposalsFor(st)
	docs := detectComplianceDocs(root, dir)

	fmt.Printf("security-dashboard init: scanned %s\n", must(filepath.Abs(root)))
	for _, line := range st.summary() {
		fmt.Printf("  · %s\n", line)
	}

	// Split the proposals against what the config already covers.
	var add []proposal
	for _, p := range props {
		if !slices.ContainsFunc(existing.Checks, p.covered) {
			add = append(add, p)
		}
	}

	// --check and --dry-run report the config as it stands; a write run reports
	// what is left once the additions have landed.
	if opts.check {
		return reportCheck(auditConfig(root, existing, add, docs))
	}

	// Merge. Existing entries are never rewritten or dropped: a check with no
	// `source` is hand-authored by definition (it predates init), and one the
	// citizen deliberately turned off carries disabled:true, which `covered`
	// still matches so init won't resurrect it.
	checks := append([]CheckDef{}, existing.Checks...)
	for _, p := range add {
		d := p.def
		d.Source = "detected"
		checks = append(checks, d)
	}

	app := existing.App
	if app.Name == "" {
		app.Name = st.appName
	}
	if app.Repo == "" {
		app.Repo = st.repo
	}

	manualDoc := existing.ManualDoc
	if manualDoc == "" {
		manualDoc = st.manualDoc
	}

	setJSON(raw, "app", app)
	setJSON(raw, "checks", checks)
	if manualDoc != "" {
		setJSON(raw, "manualDoc", manualDoc)
	}
	if len(docs) > 0 {
		setJSON(raw, "complianceDocs", docs)
	}
	// Only seed the compliance scaffolding on a genuinely new config, and only as
	// empty structure — never invented content (see the file comment).
	if _, ok := raw["standards"]; !ok {
		setJSON(raw, "standards", []Standard{})
	}

	fmt.Println()
	if len(add) == 0 {
		fmt.Printf("config.json: no new checks — %d already cover this stack\n", len(existing.Checks))
	} else {
		fmt.Printf("config.json: +%d check(s), %d preserved\n", len(add), len(existing.Checks))
		for _, p := range add {
			fmt.Printf("  + %-24s %s\n", p.def.Key, p.signal)
		}
	}

	tasksPath := filepath.Join(dir, "tasks.json")
	_, tasksErr := os.Stat(tasksPath)
	writeTasks := os.IsNotExist(tasksErr)

	if opts.dryRun {
		fmt.Println("\n--dry-run: nothing written")
		if writeTasks {
			fmt.Printf("would create %s with %d baseline manual tasks\n", tasksPath, len(baselineTasks()))
		}
		printFindings(auditConfig(root, existing, add, docs))
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeOrderedJSON(cfgPath, raw, configKeyOrder); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", cfgPath)

	if writeTasks {
		b, err := json.MarshalIndent(Tasks{Tasks: baselineTasks()}, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(tasksPath, append(b, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d baseline manual tasks)\n", tasksPath, len(baselineTasks()))
	}

	merged := existing
	merged.Checks = checks
	merged.ComplianceDocs = docs
	printFindings(auditConfig(root, merged, nil, docs))
	fmt.Printf("\nnext: go run ./cmd/security-dashboard scan\n")
	return nil
}

// ---- detection -------------------------------------------------------------

type nodeProject struct {
	dir string // relative to the repo root; "" is the root itself
	pm  string // npm | yarn | pnpm
}

type stack struct {
	goMod     bool
	node      []nodeProject
	python    bool
	php       bool
	ruby      bool
	rust      bool
	jvm       bool
	docker    bool
	terraform bool
	manualDoc string
	appName   string
	repo      string
}

func (s stack) summary() []string {
	var out []string
	if s.goMod {
		out = append(out, "Go module (go.mod)")
	}
	for _, n := range s.node {
		where := n.dir
		if where == "" {
			where = "."
		}
		out = append(out, fmt.Sprintf("Node project at %s (%s)", where, n.pm))
	}
	for _, c := range []struct {
		on bool
		s  string
	}{
		{s.python, "Python project"},
		{s.php, "PHP project (composer)"},
		{s.ruby, "Ruby project (Gemfile)"},
		{s.rust, "Rust crate (Cargo.toml)"},
		{s.jvm, "JVM project (maven/gradle)"},
		{s.docker, "Dockerfile"},
		{s.terraform, "Terraform"},
	} {
		if c.on {
			out = append(out, c.s)
		}
	}
	if len(out) == 0 {
		out = append(out, "no language stack recognised — only universal checks apply")
	}
	return out
}

// Directories that never hold a project we should scan — build output, vendored
// code and caches. Walking into node_modules in particular would find hundreds
// of package.json files.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "dist": true, "build": true, "out": true,
	"target": true, "coverage": true, "__pycache__": true, "venv": true,
	".venv": true, "tmp": true, "testdata": true,
}

func detectStack(root string) stack {
	s := stack{}
	seen := map[string]bool{}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			//nolint:nilerr // WalkDir reports per-entry errors here; returning nil
			// skips the unreadable entry and continues the walk, which is what a
			// best-effort stack scan wants. Returning err would abort the whole walk.
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			//nolint:nilerr // a path outside root cannot be classified; skip it and
			// keep walking rather than abandoning the scan.
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if rel != "." && (skipDirs[name] || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		relDir := filepath.Dir(rel)
		if relDir == "." {
			relDir = ""
		}
		switch d.Name() {
		case "go.mod":
			s.goMod = true
			if relDir == "" && s.appName == "" {
				s.appName = moduleName(path)
			}
		case "package.json":
			if !seen["node:"+relDir] {
				seen["node:"+relDir] = true
				s.node = append(s.node, nodeProject{dir: relDir, pm: packageManager(filepath.Dir(path))})
			}
		case "pyproject.toml", "requirements.txt", "Pipfile":
			s.python = true
		case "composer.json":
			s.php = true
		case "Gemfile":
			s.ruby = true
		case "Cargo.toml":
			s.rust = true
		case "pom.xml", "build.gradle", "build.gradle.kts":
			s.jvm = true
		}
		if strings.HasPrefix(d.Name(), "Dockerfile") {
			s.docker = true
		}
		if strings.HasSuffix(d.Name(), ".tf") {
			s.terraform = true
		}
		return nil
	})

	sort.Slice(s.node, func(i, j int) bool { return s.node[i].dir < s.node[j].dir })

	for _, p := range []string{
		filepath.Join("docs", "security-testing-manual.md"),
		filepath.Join("docs", "security.md"),
		"SECURITY.md",
	} {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			s.manualDoc = filepath.ToSlash(p)
			break
		}
	}

	if s.appName == "" {
		for _, n := range s.node {
			if n.dir == "" {
				s.appName = jsonField(filepath.Join(root, "package.json"), "name")
			}
		}
	}
	if s.appName == "" {
		if abs, err := filepath.Abs(root); err == nil {
			s.appName = filepath.Base(abs)
		}
	}
	s.repo = strings.TrimSpace(gitOut("remote", "get-url", "origin"))
	return s
}

// moduleName reads the module path from a go.mod and returns its last element.
func moduleName(goMod string) string {
	b, err := os.ReadFile(goMod)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			parts := strings.Split(strings.TrimSpace(rest), "/")
			return parts[len(parts)-1]
		}
	}
	return ""
}

func packageManager(dir string) string {
	for _, c := range []struct{ file, pm string }{
		{"pnpm-lock.yaml", "pnpm"},
		{"yarn.lock", "yarn"},
		{"package-lock.json", "npm"},
	} {
		if _, err := os.Stat(filepath.Join(dir, c.file)); err == nil {
			return c.pm
		}
	}
	return "npm"
}

func jsonField(path, field string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m[field].(string)
	return s
}

// detectComplianceDocs lists the framework docs the project's initialization
// skill dropped into security/compliance/. init records them; mapping them to
// controls is the agent's job (see the file comment).
func detectComplianceDocs(root, dir string) []ComplianceDoc {
	matches, _ := filepath.Glob(filepath.Join(dir, "compliance", "*.md"))
	sort.Strings(matches)
	var out []ComplianceDoc
	for _, m := range matches {
		id := strings.TrimSuffix(filepath.Base(m), ".md")
		path := m
		if rel, err := filepath.Rel(root, m); err == nil {
			path = rel
		}
		out = append(out, ComplianceDoc{ID: id, Title: markdownTitle(m, id), Path: filepath.ToSlash(path)})
	}
	return out
}

// markdownTitle returns the document's first H1, falling back to the slug.
func markdownTitle(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	if len(b) > 4096 {
		b = b[:4096]
	}
	for _, line := range strings.Split(string(b), "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(line), "# "); ok {
			return strings.TrimSpace(t)
		}
	}
	return fallback
}

// ---- proposals -------------------------------------------------------------

func cmdHas(sub string) func(CheckDef) bool {
	return func(c CheckDef) bool { return strings.Contains(c.Command, sub) }
}

func parserIs(p string) func(CheckDef) bool {
	return func(c CheckDef) bool { return c.Parser == p }
}

func toolOrCmd(tool string) func(CheckDef) bool {
	return func(c CheckDef) bool {
		return c.Tool == tool || strings.Contains(c.Command, tool)
	}
}

func proposalsFor(s stack) []proposal {
	var p []proposal

	if s.goMod {
		p = append(p,
			proposal{"Go module", true, CheckDef{Key: "build", Name: "Compile", Category: "Quality", Tool: "go", Gating: true, Command: "go build ./...", Parser: "exit"}, cmdHas("go build")},
			proposal{"Go module", true, CheckDef{Key: "vet", Name: "go vet", Category: "Quality", Tool: "go", Gating: true, Command: "go vet ./...", Parser: "exit"}, cmdHas("go vet")},
			proposal{"Go module", true, CheckDef{Key: "tests", Name: "Test suite", Category: "Quality", Tool: "go test", Gating: true, Command: "go test ./...", Parser: "gotest"}, cmdHas("go test")},
			proposal{"Go module", true, CheckDef{Key: "govulncheck", Name: "Known vulnerabilities (Go)", Category: "Dependencies", Tool: "govulncheck", Gating: true, Command: "govulncheck ./...", Parser: "govulncheck", InstallHint: "go install golang.org/x/vuln/cmd/govulncheck@latest"}, toolOrCmd("govulncheck")},
			proposal{"Go module", false, CheckDef{Key: "gosec", Name: "Static analysis (Go)", Category: "SAST", Tool: "gosec", Command: "gosec -fmt=json -quiet ./...", Parser: "gosec-json", InstallHint: "go install github.com/securego/gosec/v2/cmd/gosec@latest"}, parserIs("gosec-json")},
		)
	}

	for _, n := range s.node {
		key := "npm-audit"
		where := "."
		if n.dir != "" {
			key = "npm-audit-" + strings.ReplaceAll(n.dir, string(filepath.Separator), "-")
			where = n.dir
		}
		cmd := map[string]string{
			"npm":  "npm audit --json",
			"yarn": "yarn npm audit --json",
			"pnpm": "pnpm audit --json",
		}[n.pm]
		hint := map[string]string{"yarn": "npm i -g yarn", "pnpm": "npm i -g pnpm"}[n.pm]
		dir := n.dir
		p = append(p, proposal{
			signal:   fmt.Sprintf("Node project at %s", where),
			required: true,
			def:      CheckDef{Key: key, Name: "Dependency audit (" + where + ")", Category: "Dependencies", Tool: n.pm, Command: cmd, Parser: "npm-audit", Dir: dir, InstallHint: hint},
			covered: func(c CheckDef) bool {
				return c.Dir == dir && (c.Parser == "npm-audit" || strings.Contains(c.Command, "audit"))
			},
		})
	}

	if s.python {
		p = append(p,
			proposal{"Python project", true, CheckDef{Key: "pip-audit", Name: "Known vulnerabilities (Python)", Category: "Dependencies", Tool: "pip-audit", Gating: true, Command: "pip-audit --strict", Parser: "exit", InstallHint: "pipx install pip-audit"}, toolOrCmd("pip-audit")},
			proposal{"Python project", false, CheckDef{Key: "bandit", Name: "Static analysis (Python)", Category: "SAST", Tool: "bandit", Command: "bandit -r . -q", Parser: "exit", InstallHint: "pipx install bandit"}, toolOrCmd("bandit")},
		)
	}
	if s.php {
		p = append(p, proposal{"PHP project", true, CheckDef{Key: "composer-audit", Name: "Known vulnerabilities (PHP)", Category: "Dependencies", Tool: "composer", Gating: true, Command: "composer audit", Parser: "exit"}, toolOrCmd("composer")})
	}
	if s.ruby {
		p = append(p, proposal{"Ruby project", true, CheckDef{Key: "bundler-audit", Name: "Known vulnerabilities (Ruby)", Category: "Dependencies", Tool: "bundler-audit", Gating: true, Command: "bundler-audit check --update", Parser: "exit", InstallHint: "gem install bundler-audit"}, toolOrCmd("bundler-audit")})
	}
	if s.rust {
		p = append(p, proposal{"Rust crate", true, CheckDef{Key: "cargo-audit", Name: "Known vulnerabilities (Rust)", Category: "Dependencies", Tool: "cargo", Gating: true, Command: "cargo audit", Parser: "exit", InstallHint: "cargo install cargo-audit"}, cmdHas("cargo audit")})
	}
	if s.jvm {
		p = append(p, proposal{"JVM project", true, CheckDef{Key: "osv-scanner", Name: "Known vulnerabilities (OSV)", Category: "Dependencies", Tool: "osv-scanner", Gating: true, Command: "osv-scanner -r .", Parser: "exit", InstallHint: "brew install osv-scanner"}, toolOrCmd("osv-scanner")})
	}

	// Universal — secret scanning has no stack excuse, so it is required. The
	// rest are recommendations: valuable, but their absence is not drift.
	p = append(p,
		proposal{"any repository", true, CheckDef{Key: "gitleaks", Name: "Secret scan", Category: "Secrets", Tool: "gitleaks", Command: "gitleaks detect --no-banner --redact", Parser: "gitleaks", InstallHint: "brew install gitleaks"}, parserIs("gitleaks")},
		proposal{"any repository", false, CheckDef{Key: "semgrep", Name: "Static analysis (OWASP Top 10)", Category: "SAST", Tool: "semgrep", Command: "semgrep --config p/owasp-top-ten --json --quiet", Parser: "semgrep-json", InstallHint: "pipx install semgrep"}, parserIs("semgrep-json")},
		proposal{"any repository", false, CheckDef{Key: "sbom", Name: "Software bill of materials", Category: "Supply chain", Tool: "syft", Command: "syft . -o cyclonedx-json", Parser: "exit", InstallHint: "brew install syft"}, toolOrCmd("syft")},
	)

	if s.docker {
		p = append(p, proposal{"Dockerfile", false, CheckDef{Key: "trivy-fs", Name: "Image & config scan", Category: "Infrastructure", Tool: "trivy", Command: "trivy fs --scanners vuln,secret,misconfig --quiet .", Parser: "exit", InstallHint: "brew install trivy"}, toolOrCmd("trivy")})
	}
	if s.terraform {
		p = append(p, proposal{"Terraform", false, CheckDef{Key: "checkov", Name: "IaC misconfiguration", Category: "Infrastructure", Tool: "checkov", Command: "checkov -d . --compact --quiet", Parser: "exit", InstallHint: "pipx install checkov"}, toolOrCmd("checkov")})
	}

	return p
}

// ---- audit (--check) -------------------------------------------------------

func auditConfig(root string, cfg Config, missing []proposal, docs []ComplianceDoc) []finding {
	var f []finding

	for _, p := range missing {
		lvl := "warn"
		verb := "no check for"
		if p.required {
			lvl = "fail"
			verb = "not covered:"
		}
		f = append(f, finding{lvl, fmt.Sprintf("%s %s (%s) — suggested check %q", verb, p.signal, p.def.Name, p.def.Key)})
	}

	// A check pinned to a directory that no longer exists can only ever error.
	for _, c := range cfg.Checks {
		if c.Disabled || c.Dir == "" {
			continue
		}
		if st, err := os.Stat(filepath.Join(root, c.Dir)); err != nil || !st.IsDir() {
			f = append(f, finding{"fail", fmt.Sprintf("check %q runs in %q, which does not exist", c.Key, c.Dir)})
		}
	}

	// Tool availability is a gap, not drift: scan already records an absent tool
	// as "not run" with its install hint.
	for _, c := range cfg.Checks {
		if c.Disabled {
			continue
		}
		bin := firstWord(c.Command)
		if bin == "" || strings.ContainsAny(c.Command, ";|&$`") {
			continue
		}
		if _, err := exec.LookPath(bin); err != nil {
			msg := fmt.Sprintf("check %q needs %q, not installed", c.Key, bin)
			if c.InstallHint != "" {
				msg += " — " + c.InstallHint
			}
			f = append(f, finding{"warn", msg})
		}
	}

	// A regime in scope with nothing authored against it. This is the handoff
	// point to the agent, and the reason the docs are recorded at all.
	for _, d := range docs {
		mapped := slices.ContainsFunc(cfg.Standards, func(s Standard) bool {
			return s.Framework == d.ID || strings.EqualFold(s.Name, d.Title)
		})
		if !mapped {
			f = append(f, finding{"warn", fmt.Sprintf("compliance doc %s is in scope but has no authored standard/controls", d.Path)})
		}
	}

	if cfg.ASVS != nil {
		var blank int
		for _, r := range cfg.ASVS.Requirements {
			if strings.TrimSpace(r.Evidence) == "" || r.Coverage == "pending" {
				blank++
			}
		}
		if blank > 0 {
			f = append(f, finding{"warn", fmt.Sprintf("%d of %d ASVS controls have no evidence yet", blank, len(cfg.ASVS.Requirements))})
		}
	}

	return f
}

func printFindings(f []finding) {
	if len(f) == 0 {
		return
	}
	fmt.Println()
	for _, x := range f {
		fmt.Printf("%-5s %s\n", strings.ToUpper(x.level), x.msg)
	}
}

func reportCheck(f []finding) error {
	fails := 0
	for _, x := range f {
		if x.level == "fail" {
			fails++
		}
	}
	printFindings(f)
	fmt.Println()
	if fails > 0 {
		fmt.Printf("security-dashboard init --check: %d drift failure(s), %d warning(s)\n", fails, len(f)-fails)
		os.Exit(1)
	}
	fmt.Printf("security-dashboard init --check: no drift, %d warning(s)\n", len(f))
	return nil
}

// ---- baseline manual tasks -------------------------------------------------

// The manual work no scanner covers. Cadence and owner are placeholders for the
// team to set; docAnchor is left for whoever writes the playbook section.
func baselineTasks() []Task {
	mk := func(id, title, category, cadence, notes string) Task {
		return Task{ID: id, Title: title, Category: category, Cadence: cadence, Status: "pending", Notes: notes, Source: "baseline"}
	}
	return []Task{
		mk("threat-model-review", "Threat-model review", "Design", "Every release", "Re-review trust boundaries when a new integration lands."),
		mk("access-review", "User & role access review", "Access control", "Quarterly", "Confirm every operator role still needs its permissions."),
		mk("dependency-review", "Dependency review", "Dependencies", "Monthly", "Triage advisories the automated audit reports as accepted risk."),
		mk("pen-test", "External penetration test", "Dynamic", "Annually", "Independent test against a staging environment."),
		mk("backup-restore-test", "Backup restore test", "Infrastructure", "Quarterly", "Prove a restore actually works, not just that backups run."),
		mk("incident-response-drill", "Incident-response drill", "Operations", "Annually", "Walk a breach scenario end to end, including notification duties."),
	}
}

// ---- ordered JSON write ----------------------------------------------------

var configKeyOrder = []string{"app", "manualDoc", "standards", "asvs", "conformance", "complianceDocs", "checks"}

func setJSON(raw map[string]json.RawMessage, key string, v any) {
	// A config file is not a web page: keep &, < and > literal rather than letting
	// the default encoder escape them into \u00XX.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return
	}
	raw[key] = bytes.TrimSpace(buf.Bytes())
}

// writeOrderedJSON rewrites the manifest through a generic map, so a key this
// binary doesn't know about (a newer schema, a per-app extension) survives the
// merge instead of being silently dropped — and emits the known keys in schema
// order so a regenerated file stays readable and diffs stay small.
func writeOrderedJSON(path string, raw map[string]json.RawMessage, order []string) error {
	keys := make([]string, 0, len(raw))
	for _, k := range order {
		if _, ok := raw[k]; ok {
			keys = append(keys, k)
		}
	}
	extra := make([]string, 0, len(raw))
	for k := range raw {
		if !slices.Contains(order, k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	keys = append(keys, extra...)

	var buf bytes.Buffer
	buf.WriteString("{\n")
	for i, k := range keys {
		var v bytes.Buffer
		if err := json.Indent(&v, raw[k], "  ", "  "); err != nil {
			v.Reset()
			v.Write(raw[k])
		}
		fmt.Fprintf(&buf, "  %q: %s", k, v.String())
		if i < len(keys)-1 {
			buf.WriteString(",")
		}
		buf.WriteString("\n")
	}
	buf.WriteString("}\n")
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func must(s string, err error) string {
	if err != nil {
		return "."
	}
	return s
}
