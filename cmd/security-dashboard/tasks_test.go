package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The bug this guards: nothing ever tracked the manual programme. `lastRun` was
// hand-typed prose, `nextDue` was declared and never computed, and every task
// rendered the literal word "pending" forever — so a quarterly review last done
// a year ago was indistinguishable from one done this morning.

func TestCadenceDays(t *testing.T) {
	tests := []struct {
		cadence string
		want    int
	}{
		{"Quarterly", 90},
		{"Quarterly + on federation changes", 90},
		{"quarterly", 90},
		{"Monthly", 30},
		{"Weekly", 7},
		{"Annually", 365},
		{"Yearly", 365},
		// "semi-annual" contains "annual"; the more specific match must win.
		{"Semi-annual", 182},
		{"Every 6 months", 182},
		// Event-driven cadences are real but are not a clock: no interval.
		{"Every release", 0},
		{"Every PR", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := cadenceDays(tt.cadence); got != tt.want {
			t.Errorf("cadenceDays(%q) = %d, want %d", tt.cadence, got, tt.want)
		}
	}
}

func TestTaskStateFromLastRun(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		task      Task
		wantState string
		wantClass string
		wantDue   string
	}{
		{
			name:      "quarterly done recently is current",
			task:      Task{Cadence: "Quarterly", LastRun: "2026-08-03"},
			wantState: "current", wantClass: "ok", wantDue: "2026-11-01",
		},
		{
			name:      "quarterly done four months ago is overdue",
			task:      Task{Cadence: "Quarterly", LastRun: "2026-04-20"},
			wantState: "overdue", wantClass: "bad", wantDue: "2026-07-19",
		},
		{
			name:      "inside the two-week window is due soon",
			task:      Task{Cadence: "Quarterly", LastRun: "2026-06-01"},
			wantState: "due-soon", wantClass: "warn", wantDue: "2026-08-30",
		},
		{
			name:      "never recorded is never, not current",
			task:      Task{Cadence: "Quarterly", LastRun: ""},
			wantState: "never", wantClass: "bad", wantDue: "",
		},
		{
			name:      "event-driven with a record claims no due date",
			task:      Task{Cadence: "Every release", LastRun: "2026-08-03"},
			wantState: "event", wantClass: "muted", wantDue: "",
		},
		{
			name:      "event-driven never recorded is still never",
			task:      Task{Cadence: "Every release", LastRun: ""},
			wantState: "never", wantClass: "bad", wantDue: "",
		},
		{
			name:      "explicit intervalDays overrides the cadence text",
			task:      Task{Cadence: "Every release", LastRun: "2026-08-03", IntervalDays: 7},
			wantState: "overdue", wantClass: "bad", wantDue: "2026-08-10",
		},
		{
			name:      "explicit nextDue overrides the computed date",
			task:      Task{Cadence: "Quarterly", LastRun: "2026-08-03", NextDue: "2026-09-01"},
			wantState: "due-soon", wantClass: "warn", wantDue: "2026-09-01",
		},
		{
			name:      "waived is neither green nor overdue",
			task:      Task{Cadence: "Quarterly", Status: "waived"},
			wantState: "waived", wantClass: "muted", wantDue: "",
		},
		{
			name:      "an unparseable date is reported, not silently treated as never",
			task:      Task{Cadence: "Quarterly", LastRun: "last spring"},
			wantState: "unknown", wantClass: "warn", wantDue: "",
		},
		{
			name:      "RFC3339 timestamps are accepted",
			task:      Task{Cadence: "Quarterly", LastRun: "2026-08-03T09:30:00Z"},
			wantState: "current", wantClass: "ok", wantDue: "2026-11-01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := taskStatus(tt.task, now)
			if got.State != tt.wantState {
				t.Errorf("State = %q, want %q", got.State, tt.wantState)
			}
			if got.Class != tt.wantClass {
				t.Errorf("Class = %q, want %q", got.Class, tt.wantClass)
			}
			if got.Due != tt.wantDue {
				t.Errorf("Due = %q, want %q", got.Due, tt.wantDue)
			}
			if got.StateLabel == "" {
				t.Error("StateLabel is empty; the pill would render blank")
			}
			if got.DueLabel == "" {
				t.Error("DueLabel is empty; the cell would render blank")
			}
		})
	}
}

func TestTaskSummaryCounts(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	tasks := []Task{
		{ID: "a", Cadence: "Quarterly", LastRun: "2026-08-03"}, // current
		{ID: "b", Cadence: "Quarterly", LastRun: "2026-01-01"}, // overdue
		{ID: "c", Cadence: "Quarterly", LastRun: ""},           // never
		{ID: "d", Cadence: "Quarterly", LastRun: ""},           // never
		{ID: "e", Cadence: "Quarterly", Status: "waived"},      // waived
	}
	got := summarizeTasks(tasks, now)
	if got.Overdue != 1 {
		t.Errorf("Overdue = %d, want 1", got.Overdue)
	}
	if got.Never != 2 {
		t.Errorf("Never = %d, want 2", got.Never)
	}
	if got.Total != 5 {
		t.Errorf("Total = %d, want 5", got.Total)
	}
	if got.Tracked != 4 {
		t.Errorf("Tracked = %d, want 4 (waived tasks are not part of the schedule)", got.Tracked)
	}
	if got.Line == "" {
		t.Error("Line is empty; the page would show no schedule summary")
	}
}

func TestMarkTaskDoneStampsTheFile(t *testing.T) {
	dir := t.TempDir()
	seed := `{
  "tasks": [
    {
      "id": "jwt-attacks",
      "title": "JWT attacks",
      "category": "Federation",
      "cadence": "Quarterly",
      "owner": "",
      "status": "pending",
      "lastRun": "",
      "nextDue": "",
      "docAnchor": "b-fed",
      "notes": "jwt_tool against issued tokens."
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "tasks.json"), []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := markTaskDone(dir, "jwt-attacks", "2026-08-29", "jamie", "no findings"); err != nil {
		t.Fatalf("markTaskDone: %v", err)
	}

	got := loadTasks(dir)
	if len(got.Tasks) != 1 {
		t.Fatalf("got %d tasks, want 1", len(got.Tasks))
	}
	tk := got.Tasks[0]
	if tk.LastRun != "2026-08-29" {
		t.Errorf("LastRun = %q, want 2026-08-29", tk.LastRun)
	}
	if tk.Owner != "jamie" {
		t.Errorf("Owner = %q, want jamie", tk.Owner)
	}
	if tk.LastNote != "no findings" {
		t.Errorf("LastNote = %q, want %q", tk.LastNote, "no findings")
	}
	// "pending" is the stale placeholder; completing the task must clear it or
	// the derived state stays hidden behind a manual override.
	if tk.Status != "" {
		t.Errorf("Status = %q, want it cleared", tk.Status)
	}
	// The method notes are the playbook pointer, not a log — they must survive.
	if tk.Notes != "jwt_tool against issued tokens." {
		t.Errorf("Notes = %q, want them preserved", tk.Notes)
	}

	// The file must stay valid, hand-editable JSON.
	b, err := os.ReadFile(filepath.Join(dir, "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var round Tasks
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatalf("rewritten tasks.json does not parse: %v", err)
	}
	if b[len(b)-1] != '\n' {
		t.Error("rewritten tasks.json has no trailing newline")
	}
}

func TestMarkTaskDoneRejectsUnknownIDAndBadDate(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tasks.json"), []byte(`{"tasks":[{"id":"a","cadence":"Quarterly"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := markTaskDone(dir, "nope", "2026-08-29", "", ""); err == nil {
		t.Error("want an error for an unknown task id, got nil")
	}
	if err := markTaskDone(dir, "a", "29/08/2026", "", ""); err == nil {
		t.Error("want an error for a malformed date, got nil")
	}
}
