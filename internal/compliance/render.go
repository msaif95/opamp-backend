package compliance

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxHTMLCollectors keeps the printable report a reasonable size; the CSV and JSON hold every collector.
const maxHTMLCollectors = 2000

const stamp = "2006-01-02 15:04 UTC"

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func health(c Collector) string {
	switch {
	case !c.Connected:
		return "offline"
	case c.Paused:
		return "paused"
	case c.Healthy == nil:
		return "connected"
	case *c.Healthy:
		return "healthy"
	}
	return "unhealthy"
}

func configOf(c Collector) string {
	if c.Config == "" {
		return "–"
	}
	return c.Config + " v" + strconv.Itoa(*c.ConfigVersion)
}

func details(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, _ := json.Marshal(m[k])
		parts = append(parts, k+"="+strings.Trim(string(v), `"`))
	}
	return strings.Join(parts, ", ")
}

func pct(n, of int) string {
	if of == 0 {
		return "–"
	}
	return strconv.Itoa(int(float64(n)/float64(of)*100+0.5)) + "%"
}

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"time":    func(t time.Time) string { return t.UTC().Format(stamp) },
	"date":    func(t time.Time) string { return t.UTC().Format("2 Jan 2006") },
	"yesNo":   yesNo,
	"health":  health,
	"config":  configOf,
	"details": details,
	"pct":     pct,
	"short":   func(s string) string { return s[:min(len(s), 16)] },
	"inCategory": func(events []Event, category string) []Event {
		var out []Event
		for _, e := range events {
			if e.Category == category {
				out = append(out, e)
			}
		}
		return out
	},
	"categories": func() []string { return Categories },
	"dict": func(pairs ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(pairs); i += 2 {
			m[pairs[i].(string)] = pairs[i+1]
		}
		return m
	},
	"first": func(c []Collector) []Collector { return c[:min(len(c), maxHTMLCollectors)] },
	"more":  func(c []Collector) int { return max(0, len(c)-maxHTMLCollectors) },
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Name}}</title>
<style>
  body { font: 13px/1.45 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #1a1d29; margin: 2rem auto; max-width: 68rem; padding: 0 1.5rem; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
  h2 { font-size: 1.1rem; margin: 2rem 0 .5rem; border-bottom: 2px solid #1a1d29; padding-bottom: .2rem; }
  h3 { font-size: .95rem; margin: 1.25rem 0 .4rem; }
  p.meta, .muted { color: #555b6e; }
  table { border-collapse: collapse; width: 100%; margin: .4rem 0 1rem; }
  th, td { text-align: left; padding: .28rem .5rem; border-bottom: 1px solid #dfe2ec; vertical-align: top; }
  th { font-weight: 600; background: #f3f4f9; }
  td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
  .cards { display: flex; flex-wrap: wrap; gap: .6rem; margin: .8rem 0; }
  .card { border: 1px solid #dfe2ec; border-radius: 6px; padding: .5rem .8rem; min-width: 8.5rem; }
  .card b { display: block; font-size: 1.35rem; }
  .ok { color: #116a3c; } .bad { color: #b91c28; }
  .box { border: 1px solid #dfe2ec; border-left: 4px solid #116a3c; padding: .6rem .9rem; margin: .6rem 0; }
  .box.bad { border-left-color: #b91c28; color: inherit; }
  code, .mono { font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  @media print { body { margin: 0; max-width: none; font-size: 10.5px; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
</style>
</head>
<body>
<h1>{{.Name}}</h1>
<p class="meta">Compliance report for {{time .PeriodFrom}} to {{time .PeriodTo}}.
Generated {{time .GeneratedAt}} by {{.GeneratedBy}}. Report ID <span class="mono">{{.ID}}</span>.</p>

<h2>1. Summary</h2>
<div class="cards">
  <div class="card"><b>{{.Summary.Collectors}}</b>collectors</div>
  <div class="card"><b>{{.Summary.Connected}}</b>connected ({{pct .Summary.Connected .Summary.Collectors}})</div>
  <div class="card"><b>{{.Summary.InSync}}</b>running their assigned config ({{pct .Summary.InSync .Summary.WithConfig}} of {{.Summary.WithConfig}} assigned)</div>
  <div class="card"><b{{if .Summary.ConfigFailed}} class="bad"{{end}}>{{.Summary.ConfigFailed}}</b>failed to apply a config</div>
  <div class="card"><b>{{.Summary.Changes}}</b>changes in the period</div>
  <div class="card"><b{{if .Summary.FailedSignIns}} class="bad"{{end}}>{{.Summary.FailedSignIns}}</b>failed sign-ins</div>
</div>
{{with .Audit}}
<div class="box{{if not .Intact}} bad{{end}}">
  {{if .Intact}}<b class="ok">Audit log intact.</b> Every one of its {{.TotalEvents}} events carries a hash that follows from the event before it, and all of them verified when this report was made.
  {{else}}<b class="bad">Audit log NOT intact.</b> Verification failed at event {{.FirstBrokenEventID}}: that event or one before it was altered, inserted or removed outside the application.{{end}}
  {{if .HeadHash}}<br>Newest event when this report was made: #{{.HeadEventID}}, hash <span class="mono">{{.HeadHash}}</span>. If the log is unaltered, event #{{.HeadEventID}} still has this hash.{{end}}
</div>
{{end}}

<h2>2. Fleet state at {{time .GeneratedAt}}</h2>
<p class="muted">The state of every collector at the moment the report was made (not over the period).</p>
{{define "groups"}}
<table><tr><th>{{.Title}}</th><th class="n">Collectors</th><th class="n">Connected</th><th class="n">Healthy</th><th class="n">With a config</th><th class="n">Running it</th><th class="n">Config failed</th></tr>
{{range .Rows}}<tr><td>{{.Name}}</td><td class="n">{{.Collectors}}</td><td class="n">{{.Connected}}</td><td class="n">{{.Healthy}}</td><td class="n">{{.WithConfig}}</td><td class="n">{{.InSync}}</td><td class="n">{{.ConfigFailed}}</td></tr>
{{else}}<tr><td colspan="7" class="muted">No collectors.</td></tr>{{end}}</table>
{{end}}
<h3>By project</h3>{{template "groups" (dict "Title" "Project" "Rows" .ByProject)}}
<h3>By collector version</h3>{{template "groups" (dict "Title" "Version" "Rows" .ByVersion)}}
<h3>By assigned config</h3>{{template "groups" (dict "Title" "Config" "Rows" .ByConfig)}}

<h3>Config inventory</h3>
<table><tr><th>Config</th><th>Project</th><th>Source</th><th class="n">Latest version</th><th class="n">Collectors assigned</th></tr>
{{range .Configs}}<tr><td>{{.Name}}</td><td>{{or .Project "–"}}</td><td>{{.Origin}}</td><td class="n">{{.LatestVersion}}</td><td class="n">{{.Assigned}}</td></tr>
{{else}}<tr><td colspan="5" class="muted">No configs.</td></tr>{{end}}</table>

<h2>3. Changes from {{date .PeriodFrom}} to {{date .PeriodTo}}</h2>
<p class="muted">Taken from the audit log. {{with .Audit}}{{.EventsInPeriod}} events in the period{{if .LeftOut}}; the first {{len $.Events}} are listed, {{.LeftOut}} more are in the audit log itself{{end}}.{{end}}</p>
<table><tr><th>Kind of change</th><th class="n">Events</th></tr>
{{range .ByCategory}}<tr><td>{{.Name}}</td><td class="n">{{.N}}</td></tr>{{else}}<tr><td colspan="2" class="muted">Nothing was recorded in this period.</td></tr>{{end}}</table>
{{if .ByActor}}<h3>Who made changes</h3>
<table><tr><th>Person or token</th><th class="n">Changes</th></tr>
{{range .ByActor}}<tr><td>{{.Name}}</td><td class="n">{{.N}}</td></tr>{{end}}</table>{{end}}

{{range $cat := categories}}{{$events := inCategory $.Events $cat}}{{if $events}}
<h3>{{$cat}}</h3>
<table><tr><th>When (UTC)</th><th>Who</th><th>Action</th><th>On</th><th>Details</th></tr>
{{range $events}}<tr><td>{{time .OccurredAt}}</td><td>{{.Actor}}<br><span class="muted">{{.ActorAuth}}</span></td><td class="mono">{{.Action}}</td><td>{{.TargetType}}{{if .TargetID}}<br><span class="mono">{{.TargetID}}</span>{{end}}</td><td class="mono">{{details .Details}}</td></tr>
{{end}}</table>{{end}}{{end}}

<h3>Collectors removed from the fleet</h3>
<table><tr><th>When (UTC)</th><th>Host</th><th>Project</th><th>Removed by</th><th>Instance</th></tr>
{{range .Removed}}<tr><td>{{time .DeletedAt}}</td><td>{{.Host}}</td><td>{{or .Project "–"}}</td><td>{{.DeletedBy}}</td><td class="mono">{{.InstanceUID}}</td></tr>
{{else}}<tr><td colspan="5" class="muted">None in this period.</td></tr>{{end}}</table>

<h2>4. Appendix: every collector</h2>
<table><tr><th>Host</th><th>Project</th><th>Version</th><th>State</th><th>Assigned config</th><th>Running it</th><th>Sign-in</th><th>Last seen (UTC)</th></tr>
{{range first .Collectors}}<tr><td>{{or .Host (short (print .InstanceUID))}}</td><td>{{or .Project "–"}}</td><td>{{or .Version "–"}}</td><td>{{health .}}</td><td>{{config .}}</td><td>{{if .Config}}{{yesNo .InSync}}{{else}}–{{end}}</td><td>{{.AuthMode}}</td><td>{{time .LastSeen}}</td></tr>
{{else}}<tr><td colspan="8" class="muted">No collectors.</td></tr>{{end}}</table>
{{if or (more .Collectors) .CollectorsLeftOut}}<p class="muted">This printable report lists the first {{len (first .Collectors)}} collectors. The CSV and JSON exports of this report hold more.</p>{{end}}
</body>
</html>
`))

// WriteHTML writes the report as a self-contained, printable page.
func (r *Report) WriteHTML(w io.Writer) error { return page.Execute(w, r) }

// csvCell neutralises values a spreadsheet would run as a formula.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func writeCSV(w io.Writer, header []string, rows [][]string) error {
	out := csv.NewWriter(w)
	if err := out.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		for i := range row {
			row[i] = csvCell(row[i])
		}
		if err := out.Write(row); err != nil {
			return err
		}
	}
	out.Flush()
	return out.Error()
}

// WriteCollectorsCSV writes the fleet snapshot, one collector per row.
func (r *Report) WriteCollectorsCSV(w io.Writer) error {
	rows := make([][]string, 0, len(r.Collectors))
	for _, c := range r.Collectors {
		version := ""
		if c.ConfigVersion != nil {
			version = strconv.Itoa(*c.ConfigVersion)
		}
		rows = append(rows, []string{c.InstanceUID.String(), c.Host, c.Project, c.Version, c.Connector, c.AuthMode, health(c),
			yesNo(c.Connected), c.Config, version, c.ConfigStatus, yesNo(c.InSync), details(labelsOf(c)), c.FirstSeen.UTC().Format(time.RFC3339), c.LastSeen.UTC().Format(time.RFC3339)})
	}
	return writeCSV(w, []string{"instance_uid", "host", "project", "collector_version", "connector", "sign_in", "state", "connected",
		"assigned_config", "assigned_config_version", "config_status", "running_assigned_config", "labels", "first_seen", "last_seen"}, rows)
}

func labelsOf(c Collector) map[string]any {
	m := make(map[string]any, len(c.Labels))
	for k, v := range c.Labels {
		m[k] = v
	}
	return m
}

// WriteChangesCSV writes the period's audit events, oldest first.
func (r *Report) WriteChangesCSV(w io.Writer) error {
	rows := make([][]string, 0, len(r.Events))
	for _, e := range r.Events {
		d, _ := json.Marshal(e.Details)
		rows = append(rows, []string{strconv.FormatInt(e.ID, 10), e.OccurredAt.UTC().Format(time.RFC3339), e.Category, e.Actor, e.ActorAuth, e.Action, e.TargetType, e.TargetID, string(d)})
	}
	return writeCSV(w, []string{"event_id", "occurred_at", "category", "actor", "signed_in_via", "action", "target_type", "target_id", "details"}, rows)
}

// FileName is a download name for the report in the given format.
func (r *Report) FileName(suffix string) string {
	name := strings.Map(func(c rune) rune {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			return c
		case c >= 'A' && c <= 'Z':
			return c + 32
		}
		return '-'
	}, r.Name)
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return fmt.Sprintf("compliance-%s-%s.%s", strings.Trim(name, "-"), r.GeneratedAt.UTC().Format("20060102"), suffix)
}
