package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// exportLimit caps one download. Larger fleets should narrow the filter.
const exportLimit = 100_000

// download sets the headers for a file download in the requested format and reports whether it is CSV.
func download(w http.ResponseWriter, r *http.Request, name string) (asCSV bool, ok bool) {
	format := r.URL.Query().Get("format")
	switch format {
	case "", "csv":
		format, asCSV = "csv", true
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	case "json":
		w.Header().Set("Content-Type", "application/json")
	default:
		writeError(w, http.StatusBadRequest, "format must be csv or json")
		return false, false
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.%s"`, name, time.Now().UTC().Format("20060102-150405"), format))
	return asCSV, true
}

// csvCell neutralises values a spreadsheet would run as a formula.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// exportAgents downloads the agents matching the fleet filters as CSV or JSON.
func (s *Server) exportAgents(w http.ResponseWriter, r *http.Request) {
	f, ok, none := s.agentFilter(w, r)
	if !ok {
		return
	}
	asCSV, ok := download(w, r, "collectors")
	if !ok {
		return
	}
	var all []registry.Agent
	for f.Limit, f.Offset = 1000, 0; !none && len(all) < exportLimit; f.Offset += f.Limit {
		page, _, err := s.Registry.List(r.Context(), f)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		all = append(all, page...)
		if len(page) < f.Limit {
			break
		}
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "agents.export", "agents", "", map[string]any{"rows": len(all), "query": r.URL.RawQuery})
	if !asCSV {
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": nonNil(all)})
		return
	}
	// One column per attribute any exported agent reports, after the fixed columns.
	keys := map[string]bool{}
	for _, a := range all {
		for k := range a.Attributes {
			keys[k] = true
		}
	}
	attrs := make([]string, 0, len(keys))
	for k := range keys {
		attrs = append(attrs, k)
	}
	sort.Strings(attrs)
	out := csv.NewWriter(w)
	_ = out.Write(append([]string{"instance_uid", "project_id", "connected", "healthy", "health_status", "collector_version",
		"config", "config_version", "config_status", "config_error", "paused", "auth", "first_seen", "last_seen"}, attrs...))
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, a := range all {
		project, healthy, config, version := "", "", "", ""
		if a.ProjectID != nil {
			project = a.ProjectID.String()
		}
		if a.Healthy != nil {
			healthy = strconv.FormatBool(*a.Healthy)
		}
		if a.DesiredConfig != nil {
			config, version = a.DesiredConfig.TemplateName, strconv.Itoa(a.DesiredConfig.Version)
		}
		row := []string{a.InstanceUID.String(), project, strconv.FormatBool(a.Connected), healthy, deref(a.HealthStatus), deref(a.AgentVersion),
			config, version, a.RemoteConfigStatus, deref(a.RemoteConfigError), strconv.FormatBool(a.Paused), a.AuthMode,
			a.FirstSeen.UTC().Format(time.RFC3339), a.LastSeen.UTC().Format(time.RFC3339)}
		for _, k := range attrs {
			row = append(row, a.Attributes[k])
		}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		_ = out.Write(row)
	}
	out.Flush()
}

// exportAudit downloads the audit log (optionally filtered by ?q=, ?from= and ?to= as RFC 3339 times) as CSV or JSON.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var from, to *time.Time
	for name, dst := range map[string]**time.Time{"from": &from, "to": &to} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, http.StatusBadRequest, name+" must be a time such as 2026-01-31T00:00:00Z")
				return
			}
			*dst = &t
		}
	}
	rows, err := s.DB.Query(r.Context(), `
SELECT id, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), actor, actor_auth, action, target_type, target_id, details
FROM audit_events
WHERE ($1 = '' OR action ILIKE '%' || $1 || '%' OR actor ILIKE '%' || $1 || '%' OR target_id ILIKE '%' || $1 || '%')
  AND ($2::timestamptz IS NULL OR occurred_at >= $2) AND ($3::timestamptz IS NULL OR occurred_at < $3)
ORDER BY id DESC LIMIT $4`, q.Get("q"), from, to, exportLimit)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Actor, &e.ActorAuth, &e.Action, &e.TargetType, &e.TargetID, &e.Details); err != nil {
			s.internal(w, r, err)
			return
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, r, err)
		return
	}
	asCSV, ok := download(w, r, "audit-log")
	if !ok {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "audit.export", "audit", "", map[string]any{"rows": len(events), "query": r.URL.RawQuery})
	if !asCSV {
		_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
		return
	}
	out := csv.NewWriter(w)
	_ = out.Write([]string{"id", "occurred_at", "actor", "signed_in_via", "action", "target_type", "target_id", "details"})
	for _, e := range events {
		details, _ := json.Marshal(e.Details)
		target := ""
		if e.TargetID != nil {
			target = *e.TargetID
		}
		_ = out.Write([]string{strconv.FormatInt(e.ID, 10), e.OccurredAt, csvCell(e.Actor), e.ActorAuth, csvCell(e.Action), csvCell(e.TargetType),
			csvCell(target), csvCell(string(details))})
	}
	out.Flush()
}

// agentBreakdown counts agents by one or two attributes: ?by=region&by=dc.
func (s *Server) agentBreakdown(w http.ResponseWriter, r *http.Request) {
	project, ok := projectFilter(w, r)
	if !ok {
		return
	}
	keys := r.URL.Query()["by"]
	if len(keys) == 0 || len(keys) > 2 {
		writeError(w, http.StatusBadRequest, "give one or two attributes: ?by=region&by=dc")
		return
	}
	rows, err := s.Registry.Breakdown(r.Context(), scopeOf(r.Context()), project, keys)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"by": keys, "rows": nonNil(rows)})
}

// summaryHistory returns the fleet counts over the last ?hours= (default 24, at most 48).
func (s *Server) summaryHistory(w http.ResponseWriter, r *http.Request) {
	project, ok := projectFilter(w, r)
	if !ok {
		return
	}
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	points, err := s.Registry.FleetTrend(r.Context(), scopeOf(r.Context()), project, hours)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": nonNil(points)})
}

// rolloutBatches returns a rollout's batches with their timings, for the timeline.
func (s *Server) rolloutBatches(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	ro, err := s.Rollouts.Get(r.Context(), id)
	if err != nil {
		s.rolloutError(w, r, err)
		return
	}
	if !s.allow(w, r, ro.ProjectID, auth.RoleViewer) {
		return
	}
	batches, err := s.Rollouts.Batches(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"batches": nonNil(batches)})
}

// secretNames lists the names (never the values) of a project's secrets, so
// the config editor can offer them to anyone who may edit configs there.
func (s *Server) secretNames(w http.ResponseWriter, r *http.Request) {
	project, ok := projectFilter(w, r)
	if !ok {
		return
	}
	target := registry.ProjectRef{}
	if project != nil {
		target = *project
	}
	if !s.allow(w, r, target.ID, auth.RoleOperator) {
		return
	}
	names, err := s.Secrets.Names(r.Context(), target.ID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": nonNil(names)})
}
