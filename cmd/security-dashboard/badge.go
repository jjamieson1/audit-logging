package main

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
)

// writeBadge emits a self-contained, shields-style SVG badge reflecting the
// latest run's posture. Commit it and embed with
// `![Security](security/badge.svg)` in any README — it updates on every render.
func writeBadge(dir string, latest *Run) error {
	label := "security & quality"
	msg, color := "no scans", "#6a737d"
	if latest != nil {
		switch code, _, _ := posture(*latest); code {
		case "green":
			msg, color = "passing", "#2ea44f"
		case "amber":
			msg, color = fmt.Sprintf("%d advisories", latest.Totals.Warn+latest.Totals.Fail), "#dbab09"
		case "red":
			msg, color = "action required", "#d73a49"
		}
	}

	lw := textWidth(label) + 20
	mw := textWidth(msg) + 20
	total := lw + mw

	// Escape for XML/SVG (the label contains "&"); width was measured on raw text.
	label, msg = html.EscapeString(label), html.EscapeString(msg)

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="%s: %s">
  <title>%s: %s</title>
  <linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="%d" height="20" fill="#555"/>
    <rect x="%d" width="%d" height="20" fill="%s"/>
    <rect width="%d" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
    <text x="%d" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%d" y="14">%s</text>
  </g>
</svg>
`,
		total, label, msg, label, msg,
		total,
		lw,
		lw, mw, color,
		total,
		lw/2, label,
		lw/2, label,
		lw+mw/2, msg,
		lw+mw/2, msg,
	)
	return os.WriteFile(filepath.Join(dir, "badge.svg"), []byte(svg), 0o644)
}

// textWidth approximates rendered width at 11px Verdana (~6.6px/char average).
func textWidth(s string) int {
	w := 0
	for _, c := range s {
		switch c {
		case 'i', 'l', 'j', '.', ' ':
			w += 3
		case 'm', 'w':
			w += 9
		default:
			w += 7
		}
	}
	return w
}
