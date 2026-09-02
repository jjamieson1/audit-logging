package main

// dashboardHTML is the self-contained page: all CSS + JS inline, no external
// requests, theme-aware (light/dark). Server-side rendered so it reads correctly
// even with JS disabled; JS only adds filter/search.
const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{.Cfg.App.Name}} — Security &amp; Quality</title>
<style>
  :root{
    --bg:#f6f7f9; --panel:#ffffff; --ink:#14181f; --muted:#5b6572; --line:#e4e7ec;
    --ok:#137a4b; --ok-bg:#e7f4ec; --warn:#8a5a00; --warn-bg:#fbf1dc;
    --bad:#a5261a; --bad-bg:#fbe9e7; --accent:#1f5fbf; --accent-bg:#e8f0fc;
    --shadow:0 1px 2px rgba(0,0,0,.04),0 1px 3px rgba(0,0,0,.06);
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#0e1116; --panel:#161a21; --ink:#e7ebf0; --muted:#9aa4b2; --line:#262c36;
      --ok:#4ec98a; --ok-bg:#12271d; --warn:#e6b455; --warn-bg:#2a2113;
      --bad:#f0857a; --bad-bg:#2b1512; --accent:#6ea8fe; --accent-bg:#12203a;
      --shadow:none;
    }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline}
  .wrap{max-width:1060px;margin:0 auto;padding:32px 20px 64px}
  h1,h2,h3{margin:0;font-weight:650;letter-spacing:-.01em}
  h2{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:36px 0 14px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:var(--shadow)}
  .muted{color:var(--muted)}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em}

  /* hero */
  .hero{display:flex;gap:24px;align-items:center;padding:24px 26px}
  .badge{flex:none;width:104px;height:104px;border-radius:14px;display:flex;flex-direction:column;
    align-items:center;justify-content:center;font-weight:750;text-align:center;line-height:1.1}
  .badge .dot{font-size:30px}
  .badge.green{background:var(--ok-bg);color:var(--ok)}
  .badge.amber{background:var(--warn-bg);color:var(--warn)}
  .badge.red{background:var(--bad-bg);color:var(--bad)}
  .badge.none{background:var(--accent-bg);color:var(--accent)}
  .hero .meta{flex:1;min-width:0}
  .hero h1{font-size:23px}
  .hero .sub{color:var(--muted);margin-top:3px}
  .facts{display:flex;flex-wrap:wrap;gap:6px 22px;margin-top:12px;font-size:13.5px;color:var(--muted)}
  .facts b{color:var(--ink);font-weight:600}

  /* stat tiles */
  .tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}
  .tile{padding:14px 16px;border-radius:10px;border:1px solid var(--line);background:var(--panel)}
  .tile .n{font-size:26px;font-weight:720;line-height:1}
  .tile .l{font-size:12.5px;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.04em}
  .tile.ok .n{color:var(--ok)} .tile.warn .n{color:var(--warn)}
  .tile.bad .n{color:var(--bad)} .tile.muted .n{color:var(--muted)}

  /* composition bar */
  .bar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin-top:14px;border:1px solid var(--line)}
  .bar span{display:block}
  .bar .ok{background:var(--ok)} .bar .warn{background:var(--warn)}
  .bar .bad{background:var(--bad)} .bar .muted{background:var(--line)}

  /* trend chart (status composition over time) */
  .trendwrap{padding:18px 20px 14px}
  .trend{display:flex;gap:7px;align-items:stretch;height:96px}
  .tcol{flex:1;min-width:10px;display:flex;flex-direction:column;gap:2px;cursor:default}
  .tcol span{display:block;border-radius:2px}
  .tcol .ok{background:var(--ok)} .tcol .warn{background:var(--warn)}
  .tcol .bad{background:var(--bad)} .tcol .muted{background:var(--line)}
  .tlabels{display:flex;gap:7px;margin-top:6px}
  .tlabels div{flex:1;min-width:10px;text-align:center;font-size:10.5px;color:var(--muted);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:12px;font-size:12.5px;color:var(--muted)}
  .legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}

  /* ASVS evidence */
  .asvs-head{display:flex;align-items:center;gap:12px;margin:-4px 0 12px}
  .asvs-level{font-weight:750;color:var(--accent);background:var(--accent-bg);border:1px solid var(--accent);
    border-radius:8px;padding:4px 12px;font-size:14px}
  .cov{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;padding:3px 9px;border-radius:999px;white-space:nowrap}
  .cov.automated{background:var(--ok-bg);color:var(--ok)}
  .cov.partial{background:var(--warn-bg);color:var(--warn)}
  .cov.manual{background:var(--accent-bg);color:var(--accent)}

  /* export button */
  .toolbar{display:flex;justify-content:flex-end;margin:-8px 0 -8px}
  .export{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:8px;
    padding:7px 14px;font-size:13px;cursor:pointer}
  .export:hover{border-color:var(--accent);color:var(--accent)}

  /* filter chips */
  .chips{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
  .chip{border:1px solid var(--line);background:var(--panel);color:var(--muted);border-radius:999px;
    padding:5px 13px;font-size:13px;cursor:pointer}
  .chip.active{background:var(--ink);color:var(--bg);border-color:var(--ink)}

  /* check rows */
  .cat{padding:6px 2px 2px}
  .cat h3{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:16px 0 8px}
  .rows{border:1px solid var(--line);border-radius:10px;overflow:hidden;background:var(--panel)}
  .row{display:flex;align-items:center;gap:14px;padding:12px 16px;border-top:1px solid var(--line)}
  .row:first-child{border-top:none}
  .row .name{font-weight:600}
  .row .grow{flex:1;min-width:0}
  .row .sum{color:var(--muted);font-size:14px;margin-top:1px}
  .pill{flex:none;font-size:11.5px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
    padding:3px 9px;border-radius:999px;white-space:nowrap}
  .pill.ok{background:var(--ok-bg);color:var(--ok)}
  .pill.warn{background:var(--warn-bg);color:var(--warn)}
  .pill.bad{background:var(--bad-bg);color:var(--bad)}
  .pill.muted{background:var(--line);color:var(--muted)}
  .tool{flex:none;font-size:12px;color:var(--muted);background:var(--bg);border:1px solid var(--line);
    padding:2px 8px;border-radius:6px}
  .gate{flex:none;font-size:10.5px;color:var(--accent);border:1px solid var(--accent);border-radius:5px;padding:1px 5px}

  table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
  th,td{text-align:left;padding:11px 14px;border-top:1px solid var(--line);font-size:14px;vertical-align:top}
  th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);border-top:none;background:var(--bg)}
  .minibar{display:inline-flex;height:7px;width:120px;border-radius:4px;overflow:hidden;border:1px solid var(--line);vertical-align:middle}
  .minibar span{display:block;height:100%}

  .stds{display:flex;flex-wrap:wrap;gap:10px}
  .std{border:1px solid var(--line);background:var(--panel);border-radius:8px;padding:10px 14px;font-size:13px}
  .std b{display:block;margin-bottom:2px}
  .foot{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
  @media(max-width:720px){.tiles{grid-template-columns:repeat(2,1fr)}.hero{flex-direction:column;text-align:center}}

  /* print / PDF export: clean, ink-friendly, no interactive chrome */
  @media print{
    :root{--bg:#fff;--panel:#fff;--ink:#111;--muted:#555;--line:#ccc;--shadow:none}
    body{font-size:12px}
    .wrap{max-width:none;padding:0}
    .chips,.export,.toolbar,#chips{display:none !important}
    .panel,.rows,table,.std{box-shadow:none}
    .row,tr,.cat,.std{break-inside:avoid}
    h2{break-after:avoid}
    a[href^="runs/"]{display:none} /* report links are local-only */
  }
</style>
</head>
<body>
<div class="wrap">

  <!-- HERO -->
  <div class="panel hero">
    <div class="badge {{.Posture}}"><span class="dot">{{if eq .Posture "green"}}●{{else if eq .Posture "amber"}}▲{{else if eq .Posture "red"}}■{{else}}○{{end}}</span></div>
    <div class="meta">
      <h1>{{.Cfg.App.Name}}</h1>
      <div class="sub">{{.Cfg.App.Description}}</div>
      <div class="facts">
        <span><b>{{.PostureLabel}}</b> — {{.PostureNote}}</span>
      </div>
      {{if .Latest}}
      <div class="facts">
        <span>Last comprehensive scan <b>{{.Latest.When}}</b></span>
        <span>Trigger <b>{{.Latest.Trigger}}</b></span>
        {{if .Latest.GitSHA}}<span>Commit <b class="mono">{{.Latest.GitSHA}}</b>{{if .Latest.GitBranch}} ({{.Latest.GitBranch}}){{end}}</span>{{end}}
      </div>
      {{end}}
    </div>
  </div>

  {{if .Latest}}
  <!-- STAT TILES -->
  <div class="tiles">
    <div class="tile ok"><div class="n">{{.Latest.Totals.Pass}}</div><div class="l">Passing</div></div>
    <div class="tile warn"><div class="n">{{.Latest.Totals.Warn}}</div><div class="l">Advisories</div></div>
    <div class="tile bad"><div class="n">{{.Latest.Totals.Fail}}</div><div class="l">Failing</div></div>
    <div class="tile muted"><div class="n">{{.Latest.Totals.Skipped}}</div><div class="l">Not run</div></div>
  </div>
  <div class="bar">
    {{if .Latest.Totals.Pass}}<span class="ok" style="flex:{{.Latest.Totals.Pass}}"></span>{{end}}
    {{if .Latest.Totals.Warn}}<span class="warn" style="flex:{{.Latest.Totals.Warn}}"></span>{{end}}
    {{if .Latest.Totals.Fail}}<span class="bad" style="flex:{{.Latest.Totals.Fail}}"></span>{{end}}
    {{if .Latest.Totals.Skipped}}<span class="muted" style="flex:{{.Latest.Totals.Skipped}}"></span>{{end}}
  </div>

  <div class="toolbar"><button class="export" onclick="window.print()">⧉ Export / Save as PDF</button></div>
  {{end}}

  <!-- TREND -->
  {{if .Trend}}
  <h2>Results over time</h2>
  <div class="panel trendwrap">
    <div class="trend">
      {{range .Trend}}
      <div class="tcol" title="{{.When}} — {{.Totals.Pass}} pass, {{.Totals.Warn}} advisory, {{.Totals.Fail}} fail, {{.Totals.Skipped}} not run">
        {{if .Totals.Fail}}<span class="bad" style="flex:{{.Totals.Fail}}"></span>{{end}}
        {{if .Totals.Warn}}<span class="warn" style="flex:{{.Totals.Warn}}"></span>{{end}}
        {{if .Totals.Skipped}}<span class="muted" style="flex:{{.Totals.Skipped}}"></span>{{end}}
        {{if .Totals.Pass}}<span class="ok" style="flex:{{.Totals.Pass}}"></span>{{end}}
      </div>
      {{end}}
    </div>
    <div class="tlabels">
      {{range .Trend}}<div>{{.GitSHA}}</div>{{end}}
    </div>
    <div class="legend">
      <span><i style="background:var(--ok)"></i>Passing</span>
      <span><i style="background:var(--warn)"></i>Advisories</span>
      <span><i style="background:var(--bad)"></i>Failing</span>
      <span><i style="background:var(--line)"></i>Not run</span>
    </div>
  </div>
  {{end}}

  {{if .Latest}}
  <!-- LATEST SCAN -->
  <h2>Latest scan results</h2>
  <div class="chips" id="chips">
    <div class="chip active" data-f="all">All</div>
    <div class="chip" data-f="bad">Failing</div>
    <div class="chip" data-f="warn">Advisories</div>
    <div class="chip" data-f="muted">Not run</div>
  </div>
  {{range .Categories}}
  <div class="cat">
    <h3>{{.Name}}</h3>
    <div class="rows">
      {{range .Checks}}
      <div class="row" data-status="{{statusClass .Status}}">
        <span class="pill {{.StatusClass}}">{{.StatusLabel}}</span>
        <div class="grow">
          <div class="name">{{.Name}}</div>
          <div class="sum">{{.Summary}}{{if .InstallHint}}{{if eq .Status "skipped"}} · <span class="mono">{{.InstallHint}}</span>{{end}}{{end}}</div>
        </div>
        {{if .Gating}}<span class="gate">GATING</span>{{end}}
        <span class="tool">{{.Tool}}</span>
        {{if .ReportFile}}<a href="{{.ReportFile}}">View report →</a>{{end}}
      </div>
      {{end}}
    </div>
  </div>
  {{end}}
  {{end}}

  <!-- HISTORY -->
  {{if .History}}
  <h2>Scan history</h2>
  <table>
    <thead><tr><th>When</th><th>Trigger</th><th>Commit</th><th>Composition</th><th>Result</th></tr></thead>
    <tbody>
    {{range .History}}
      <tr>
        <td>{{.When}}</td>
        <td>{{.Trigger}}</td>
        <td class="mono">{{if .GitSHA}}{{.GitSHA}}{{else}}—{{end}}</td>
        <td>
          <span class="minibar">
            {{if .Totals.Pass}}<span class="ok" style="width:{{.Totals.Pass}}0px" title="{{.Totals.Pass}} pass"></span>{{end}}
            {{if .Totals.Warn}}<span class="warn" style="width:{{.Totals.Warn}}0px"></span>{{end}}
            {{if .Totals.Fail}}<span class="bad" style="width:{{.Totals.Fail}}0px"></span>{{end}}
            {{if .Totals.Skipped}}<span class="muted" style="width:{{.Totals.Skipped}}0px"></span>{{end}}
          </span>
        </td>
        <td>{{if .Totals.GatingFail}}<span class="pill bad">{{.Totals.GatingFail}} gating fail</span>{{else}}<span class="pill ok">gates green</span>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <!-- CONFORMANCE -->
  {{if .Conformance}}
  <h2>Conformance</h2>
  <table>
    <thead><tr><th>Profile</th><th>Status</th><th>Result</th><th>Last run</th></tr></thead>
    <tbody>
    {{range .Conformance}}
      <tr>
        <td><b>{{.Name}}</b>{{if .Suite}}<div class="muted" style="font-size:13px">{{.Suite}}</div>{{end}}{{if .Report}}<div class="mono" style="font-size:12px">{{.Report}}</div>{{end}}</td>
        <td><span class="cov {{if eq .Status "passed"}}automated{{else if eq .Status "pending"}}manual{{else}}partial{{end}}">{{.Status}}</span></td>
        <td>{{if .Summary}}{{.Summary}}{{else}}—{{end}}</td>
        <td>{{if .LastRun}}{{.LastRun}}{{else}}—{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <!-- ASVS -->
  {{if .ASVS}}
  <h2>ASVS compliance evidence</h2>
  <div class="asvs-head">
    <span class="asvs-level">Target: ASVS {{.ASVS.TargetLevel}}</span>
    <span class="muted">{{.ASVS.Note}}</span>
  </div>
  <table>
    <thead><tr><th>Control family</th><th>Coverage</th><th>Evidence</th></tr></thead>
    <tbody>
    {{range .ASVS.Requirements}}
      <tr>
        <td><b>{{.ID}}</b><div class="muted" style="font-size:13px">{{.Name}}</div></td>
        <td><span class="cov {{.Coverage}}">{{.Coverage}}</span></td>
        <td>{{.Evidence}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>
  {{end}}

  <!-- MANUAL TASKS -->
  {{if .TaskGroups}}
  <h2>Manual security tasks</h2>
  <p class="muted" style="margin:-6px 0 10px">Scans automate what they can. These require a human and a schedule — full method in the <a href="{{.ManualHref}}">security testing playbook</a>.</p>
  <p style="margin:0 0 14px"><span class="pill {{.TaskSummary.Class}}">schedule</span> <span class="muted">{{.TaskSummary.Line}}</span></p>
  <table>
    <thead><tr><th>Task</th><th>Cadence</th><th>Last done</th><th>Next due</th><th>Owner</th><th>Status</th><th></th></tr></thead>
    <tbody>
    {{range .TaskGroups}}
      {{range .Tasks}}
      <tr>
        <td><b>{{.Title}}</b><div class="muted" style="font-size:13px">{{.Notes}}</div></td>
        <td>{{.Cadence}}</td>
        <td>{{dash .LastRun}}{{if .LastNote}}<div class="muted" style="font-size:13px">{{.LastNote}}</div>{{end}}</td>
        <td>{{.DueLabel}}</td>
        <td>{{dash .Owner}}</td>
        <td><span class="pill {{.Class}}">{{.StateLabel}}</span></td>
        <td>{{if $.ManualHref}}<a href="{{$.ManualHref}}#{{.DocAnchor}}">How →</a>{{end}}</td>
      </tr>
      {{end}}
    {{end}}
    </tbody>
  </table>
  <p class="muted" style="margin:10px 0 0;font-size:13px">Record a completed task with
    <span class="mono">go run ./cmd/security-dashboard task done &lt;id&gt; --owner &lt;name&gt;</span> — the stamp lands in
    <span class="mono">security/tasks.json</span>, so git history is the audit trail.</p>
  {{end}}

  <!-- FRAMEWORKS IN SCOPE -->
  {{if .Frameworks}}
  <h2>Frameworks in scope</h2>
  <div class="stds">
    {{range .Frameworks}}
    <div class="std">
      <b>{{if .Href}}<a href="{{.Href}}">{{.Title}}</a>{{else}}{{.Title}}{{end}}</b>
      <span class="muted">{{if .Mapped}}controls mapped below{{else}}evidence pending — no controls authored yet{{end}}</span>
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- STANDARDS -->
  {{if .Cfg.Standards}}
  <h2>Standards &amp; frameworks</h2>
  <div class="stds">
    {{range .Cfg.Standards}}<div class="std"><b>{{.Name}}</b><span class="muted">{{.Note}}</span></div>{{end}}
  </div>
  {{end}}

  <div class="foot">
    Generated {{.GeneratedAt}} · <span class="mono">go run ./cmd/security-dashboard scan</span> to refresh ·
    {{if .Cfg.App.Contact}}Contact <a href="mailto:{{.Cfg.App.Contact}}">{{.Cfg.App.Contact}}</a> · {{end}}
    {{.Cfg.App.Team}}
  </div>
</div>

<script>
  // Client-side filter of check rows by status.
  var chips = document.querySelectorAll('#chips .chip');
  chips.forEach(function(chip){
    chip.addEventListener('click', function(){
      chips.forEach(function(c){c.classList.remove('active')});
      chip.classList.add('active');
      var f = chip.getAttribute('data-f');
      document.querySelectorAll('.row').forEach(function(row){
        row.style.display = (f==='all' || row.getAttribute('data-status')===f) ? '' : 'none';
      });
      // Hide category groups that end up empty.
      document.querySelectorAll('.cat').forEach(function(cat){
        var any = Array.prototype.some.call(cat.querySelectorAll('.row'),function(r){return r.style.display!=='none'});
        cat.style.display = any ? '' : 'none';
      });
    });
  });
</script>
</body>
</html>`
