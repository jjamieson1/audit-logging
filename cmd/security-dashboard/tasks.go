package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manual tasks are the part of the programme no scanner covers — and until the
// page can say whether that programme is being kept, the section is decoration.
// Previously nothing wrote `lastRun`, `nextDue` was declared but never computed,
// and every row rendered the literal word "pending" forever, so a quarterly
// review last done a year ago looked exactly like one done this morning.
//
// These helpers turn cadence + lastRun into a due date and a freshness state, so
// an overdue review is as visible on the dashboard as a failing check.

// dueSoonDays is how far ahead a task starts warning. Two weeks is enough notice
// to schedule a quarterly review without the row sitting amber for a month.
const dueSoonDays = 14

// cadenceDays maps the free-text cadence to a review interval in days.
//
// A 0 means event-driven ("Every release", "Every PR"): a real cadence, but not
// a clock. No due date is invented for those, because a date derived from a
// guess about release frequency would be evidence of nothing. Set `intervalDays`
// on the task to opt one into time-based tracking anyway.
func cadenceDays(cadence string) int {
	c := strings.ToLower(cadence)
	switch {
	case strings.Contains(c, "weekly"):
		return 7
	// Checked before "annual": "semi-annual" contains it.
	case strings.Contains(c, "semi-annual"), strings.Contains(c, "semiannual"),
		strings.Contains(c, "biannual"), strings.Contains(c, "6 months"),
		strings.Contains(c, "six months"):
		return 182
	case strings.Contains(c, "monthly"):
		return 30
	case strings.Contains(c, "quarterly"):
		return 90
	case strings.Contains(c, "annual"), strings.Contains(c, "yearly"):
		return 365
	}
	return 0
}

// taskView is a Task plus everything derived from the calendar.
type taskView struct {
	Task
	Due        string // YYYY-MM-DD; empty when no due date can be claimed
	DueLabel   string // what the "Next due" cell shows
	State      string // current | due-soon | overdue | never | event | waived | blocked | unknown
	StateLabel string // pill text
	Class      string // pill class: ok | warn | bad | muted
}

// taskStatus derives a task's freshness. The `status` field stays a manual
// override for the two states a calendar cannot know — waived and blocked —
// and is otherwise ignored in favour of the recorded dates.
func taskStatus(t Task, now time.Time) taskView {
	v := taskView{Task: t}
	today := now.Truncate(24 * time.Hour)

	switch strings.ToLower(strings.TrimSpace(t.Status)) {
	case "automated":
		// The task still exists, but a check in checks[] now performs it on every
		// run. It leaves the human schedule rather than sitting permanently green.
		v.State, v.StateLabel, v.Class = "automated", "automated", "ok"
		v.DueLabel = "every scan"
		return v
	case "waived", "n/a", "na", "not applicable":
		v.State, v.StateLabel, v.Class = "waived", "waived", "muted"
		v.DueLabel = "—"
		return v
	case "blocked":
		v.State, v.StateLabel, v.Class = "blocked", "blocked", "bad"
		v.DueLabel = "—"
		return v
	}

	if strings.TrimSpace(t.LastRun) == "" {
		v.State, v.StateLabel, v.Class = "never", "never run", "bad"
		v.DueLabel = "—"
		return v
	}

	last, ok := parseTaskDate(t.LastRun)
	if !ok {
		v.State, v.StateLabel, v.Class = "unknown", "date unreadable", "warn"
		v.DueLabel = "—"
		return v
	}

	interval := t.IntervalDays
	if interval <= 0 {
		interval = cadenceDays(t.Cadence)
	}

	var due time.Time
	switch {
	case strings.TrimSpace(t.NextDue) != "":
		// An explicitly agreed date wins over the computed one.
		d, ok := parseTaskDate(t.NextDue)
		if !ok {
			v.State, v.StateLabel, v.Class = "unknown", "date unreadable", "warn"
			v.DueLabel = "—"
			return v
		}
		due = d
	case interval > 0:
		due = last.AddDate(0, 0, interval)
	default:
		// Event-driven and on record: honest about having no deadline.
		v.State, v.StateLabel, v.Class = "event", eventLabel(t.Cadence), "muted"
		v.DueLabel = eventDueLabel(t.Cadence)
		return v
	}

	v.Due = due.Format("2006-01-02")
	days := int(due.Sub(today).Hours() / 24)
	switch {
	case days < 0:
		v.State, v.Class = "overdue", "bad"
		v.StateLabel = fmt.Sprintf("overdue %s", plural(-days, "day", "days"))
		v.DueLabel = v.Due
	case days <= dueSoonDays:
		v.State, v.Class = "due-soon", "warn"
		v.StateLabel = "due soon"
		v.DueLabel = fmt.Sprintf("%s (%s)", v.Due, inDays(days))
	default:
		v.State, v.Class = "current", "ok"
		v.StateLabel = "current"
		v.DueLabel = v.Due
	}
	return v
}

func inDays(d int) string {
	if d == 0 {
		return "today"
	}
	return "in " + plural(d, "day", "days")
}

func eventLabel(cadence string) string {
	if strings.Contains(strings.ToLower(cadence), "pr") {
		return "per PR"
	}
	return "per release"
}

func eventDueLabel(cadence string) string {
	if strings.Contains(strings.ToLower(cadence), "pr") {
		return "each PR"
	}
	return "each release"
}

// parseTaskDate accepts the plain dates a human types and the RFC3339 stamps a
// tool might write.
func parseTaskDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Truncate(24 * time.Hour), true
		}
	}
	return time.Time{}, false
}

// taskSummary is the one-line verdict on the manual programme.
type taskSummary struct {
	Total   int
	Tracked int // excludes waived tasks — they are not part of the schedule
	Current int
	DueSoon int
	Overdue int
	Never   int
	Line    string
	Class   string // ok | warn | bad
}

func summarizeTasks(tasks []Task, now time.Time) taskSummary {
	s := taskSummary{Total: len(tasks)}
	for _, t := range tasks {
		v := taskStatus(t, now)
		if v.State != "waived" && v.State != "automated" {
			s.Tracked++
		}
		switch v.State {
		case "current", "event", "automated":
			s.Current++
		case "due-soon":
			s.DueSoon++
		case "overdue", "blocked":
			s.Overdue++
		case "never":
			s.Never++
		}
	}

	var parts []string
	if s.Overdue > 0 {
		parts = append(parts, fmt.Sprintf("%d overdue", s.Overdue))
	}
	if s.Never > 0 {
		parts = append(parts, fmt.Sprintf("%d never recorded", s.Never))
	}
	if s.DueSoon > 0 {
		parts = append(parts, fmt.Sprintf("%d due soon", s.DueSoon))
	}
	switch {
	case s.Overdue > 0 || s.Never > 0:
		s.Class = "bad"
	case s.DueSoon > 0:
		s.Class = "warn"
	default:
		s.Class = "ok"
	}
	if len(parts) == 0 {
		s.Line = fmt.Sprintf("%s on schedule", plural(s.Tracked, "task", "tasks"))
	} else {
		s.Line = fmt.Sprintf("%s of %d tracked tasks — run them, automate them, or waive them",
			strings.Join(parts, " · "), s.Tracked)
	}
	return s
}

// ---- recording completion --------------------------------------------------

// markTaskDone stamps a task as performed. Completion becomes a committed edit
// to tasks.json, so git history — not memory — is the audit trail for when a
// manual control was last exercised, and by whom.
func markTaskDone(dir, id, date, owner, note string) error {
	if _, ok := parseTaskDate(date); !ok {
		return fmt.Errorf("date %q is not YYYY-MM-DD", date)
	}
	path := filepath.Join(dir, "tasks.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var tasks Tasks
	if err := json.Unmarshal(b, &tasks); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	found := false
	for i := range tasks.Tasks {
		if tasks.Tasks[i].ID != id {
			continue
		}
		found = true
		tasks.Tasks[i].LastRun = date
		// "pending" is the stale placeholder every task shipped with; leaving it
		// set would keep the manual override in front of the derived state.
		if isPlaceholderStatus(tasks.Tasks[i].Status) {
			tasks.Tasks[i].Status = ""
		}
		if owner != "" {
			tasks.Tasks[i].Owner = owner
		}
		tasks.Tasks[i].LastNote = note
		// A computed due date replaces any one-off date that has now been met.
		tasks.Tasks[i].NextDue = ""
	}
	if !found {
		return fmt.Errorf("no task with id %q in %s", id, path)
	}

	out, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func isPlaceholderStatus(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "pending", "in-progress", "in progress":
		return true
	}
	return false
}

// printTaskSchedule is the terminal view of the same table the dashboard shows,
// so the schedule is checkable without opening the HTML.
func printTaskSchedule(dir string, w *os.File) {
	tasks := loadTasks(dir).Tasks
	now := time.Now()
	_, _ = fmt.Fprintf(w, "%-26s %-16s %-12s %-12s %s\n", "ID", "STATE", "LAST DONE", "NEXT DUE", "CADENCE")
	for _, t := range tasks {
		v := taskStatus(t, now)
		_, _ = fmt.Fprintf(w, "%-26s %-16s %-12s %-12s %s\n",
			t.ID, v.StateLabel, dashIfEmpty(t.LastRun), dashIfEmpty(v.Due), t.Cadence)
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", summarizeTasks(tasks, now).Line)
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
