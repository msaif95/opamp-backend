package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/access"
	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/api"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/ownlogs"
	"github.com/msaif95/opamp-backend/internal/owntraces"
	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/ratelimit"
	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/secrets"
	"github.com/msaif95/opamp-backend/internal/settings"
	"github.com/msaif95/opamp-backend/internal/targeting"
	"github.com/msaif95/opamp-backend/internal/testdb"
	"github.com/msaif95/opamp-backend/internal/throughput"
)

const collectorYAML = "receivers:\n  otlp:\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"

type harness struct {
	t        *testing.T
	srv      *httptest.Server
	sessions *auth.Sessions
}

// call makes an API request as the given token and returns the status and decoded body.
func (h *harness) call(token, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.srv.URL+"/api/v1"+path, reader)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// raw returns a response body as text, for downloads.
func (h *harness) raw(token, path string) string {
	h.t.Helper()
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/v1"+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func (h *harness) session(subject string, role auth.Role) string {
	tok, err := h.sessions.Issue(auth.User{Subject: subject, Provider: "okta", Role: role})
	if err != nil {
		h.t.Fatal(err)
	}
	return tok
}

func (h *harness) expect(name string, got, want int) {
	h.t.Helper()
	if got != want {
		h.t.Errorf("%s: HTTP %d, want %d", name, got, want)
	}
}

func names(body map[string]any, list, field string) []string {
	var out []string
	items, _ := body[list].([]any)
	for _, it := range items {
		m := it.(map[string]any)
		if attrs, ok := m["attributes"].(map[string]any); ok && field == "host" {
			out = append(out, attrs["host.name"].(string))
		} else {
			out = append(out, m[field].(string))
		}
	}
	return out
}

func TestProjectAccess(t *testing.T) {
	db, rdb := testdb.Open(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := registry.New(db, rdb, "replica-a", time.Minute)
	configs := agentconfig.NewService(db)
	agents := auth.NewAgentAuthenticator(db)
	projects := access.NewProjects(db)
	tokens := auth.NewTokens(db)
	sessions := auth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "")
	sessions.APITokens = tokens.Authenticate
	sessions.Store = auth.NewRedisSessions(rdb)
	switches, err := settings.New(ctx, db, rdb, map[string]settings.Definition{settings.SecondApprover: {Available: true}}, log)
	if err != nil {
		t.Fatal(err)
	}
	secretStore, err := secrets.New(db, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, sessions: sessions}
	h.srv = httptest.NewServer((&api.Server{
		DB: db, Registry: reg, Configs: configs, Library: pipeline.NewLibrary(db), Rollouts: rollout.NewService(db, reg, log),
		Agents: agents, Sessions: sessions, Groups: targeting.NewGroups(db), Events: http.NotFoundHandler(), Log: log,
		Tokens: tokens, Projects: projects, Secrets: secretStore, Settings: switches, Logins: auth.NewLoginLimiter(rdb),
		// No deployment-wide budget: only tokens given their own are limited.
		Limits:     ratelimit.New(rdb, 0, 0, log),
		Throughput: func(context.Context, uuid.UUID) (*throughputSample, error) { return nil, nil },
		History:    func(context.Context, uuid.UUID) ([]throughputPoint, error) { return nil, nil },
		AllMetrics: func(context.Context, uuid.UUID) ([]throughput.Series, []throughput.MetricSample, error) {
			return nil, nil, nil
		},
		Traces: func(context.Context, uuid.UUID) ([]owntraces.Span, error) { return nil, nil },
		Logs: func(context.Context, uuid.UUID, int) ([]ownlogs.Line, error) {
			return []ownlogs.Line{{Message: "hello"}}, nil
		},
		Ready: func(context.Context) error { return nil },
	}).Router())
	defer h.srv.Close()

	admin := h.session("root", auth.RoleAdmin)
	alice := h.session("Alice@Example.com", auth.RoleNone) // operator in A, viewer in B; case differs from the stored subject
	bob := h.session("bob@example.com", auth.RoleViewer)   // no project, global viewer
	carol := h.session("carol@example.com", auth.RoleNone) // nothing at all

	// Projects and members.
	_, pa := h.call(admin, "POST", "/projects", map[string]string{"name": "A"})
	_, pb := h.call(admin, "POST", "/projects", map[string]string{"name": "B"})
	A, B := pa["id"].(string), pb["id"].(string)
	h.expect("add alice to A", first(h.call(admin, "PUT", "/projects/"+A+"/members", map[string]string{"subject": "alice@example.com", "role": "operator"})), 204)
	h.expect("add alice to B", first(h.call(admin, "PUT", "/projects/"+B+"/members", map[string]string{"subject": "alice@example.com", "role": "viewer"})), 204)
	h.expect("non-admin cannot create projects", first(h.call(alice, "POST", "/projects", map[string]string{"name": "X"})), 403)
	h.expect("non-admin cannot manage members", first(h.call(alice, "PUT", "/projects/"+A+"/members", map[string]string{"subject": "eve", "role": "admin"})), 403)

	// One collector per project plus an unassigned one. A collector joins the project of its API key.
	connect := func(host string, project *string) string {
		var pid *uuid.UUID
		if project != nil {
			id := uuid.MustParse(*project)
			pid = &id
		}
		key, err := agents.IssueAPIKey(ctx, host+"-key", pid, "root", nil)
		if err != nil {
			t.Fatal(err)
		}
		uid := uuid.New()
		_, err = reg.Report(ctx, uid, registry.Identity{AuthMode: "api_key", CredentialID: &key.ID}, &protobufs.AgentToServer{
			Capabilities: uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig),
			AgentDescription: &protobufs.AgentDescription{NonIdentifyingAttributes: []*protobufs.KeyValue{
				{Key: "host.name", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: host}}},
				{Key: "env", Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "prod"}}},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return uid.String()
	}
	a1, b1, u1 := connect("a1", &A), connect("b1", &B), connect("u1", nil)

	// Configs: one per project, and one outside any project. The API no longer creates those, but data from
	// before projects were mandatory can exist and must stay invisible to project members.
	mk := func(name string, project *string) (string, string) {
		body := map[string]any{"name": name, "body": collectorYAML}
		if project != nil {
			body["project_id"] = *project
		}
		code, out := h.call(admin, "POST", "/configs", body)
		h.expect("admin creates "+name, code, 201)
		return out["config"].(map[string]any)["id"].(string), out["version"].(map[string]any)["id"].(string)
	}
	cA, vA := mk("cfg-a", &A)
	cB, vB := mk("cfg-b", &B)
	legacy, _, err := configs.Create(ctx, nil, "cfg-u", "", collectorYAML, "root", nil)
	if err != nil {
		t.Fatal(err)
	}
	cU := legacy.ID.String()
	h.expect("admin creates a config without a project", first(h.call(admin, "POST", "/configs", map[string]any{"name": "x", "body": collectorYAML})), 400)
	h.expect("admin issues an API key without a project", first(h.call(admin, "POST", "/credentials/api-keys", map[string]any{"name": "x"})), 400)
	h.expect("admin creates a group without a project", first(h.call(admin, "POST", "/groups", map[string]any{"name": "x", "selector": map[string][]string{"env": {"prod"}}})), 400)
	h.expect("admin creates an operator token without a project", first(h.call(admin, "POST", "/auth/tokens", map[string]any{"name": "x", "role": "operator"})), 400)
	h.expect("admin creates a global admin token", first(h.call(admin, "POST", "/auth/tokens", map[string]any{"name": "global", "role": "admin"})), 201)

	// --- What each person sees.
	for who, tc := range map[string]struct {
		token          string
		agents, config []string
	}{
		"admin": {admin, []string{"a1", "b1", "u1"}, []string{"cfg-a", "cfg-b", "cfg-u"}},
		"alice": {alice, []string{"a1", "b1"}, []string{"cfg-a", "cfg-b"}},
		"bob":   {bob, []string{"u1"}, []string{"cfg-u"}},
		"carol": {carol, nil, nil},
	} {
		_, out := h.call(tc.token, "GET", "/agents", nil)
		if got := names(out, "agents", "host"); !equal(got, tc.agents) {
			t.Errorf("%s sees agents %v, want %v", who, got, tc.agents)
		}
		_, out = h.call(tc.token, "GET", "/configs", nil)
		if got := names(out, "configs", "name"); !equal(got, tc.config) {
			t.Errorf("%s sees configs %v, want %v", who, got, tc.config)
		}
		_, sum := h.call(tc.token, "GET", "/summary", nil)
		if int(sum["total"].(float64)) != len(tc.agents) {
			t.Errorf("%s summary total %v, want %d", who, sum["total"], len(tc.agents))
		}
	}
	_, me := h.call(alice, "GET", "/auth/me", nil)
	if len(me["projects"].([]any)) != 2 || me["admin"] != false {
		t.Errorf("alice /auth/me = %v", me)
	}

	// --- Reading by ID outside your projects looks like it does not exist.
	h.expect("alice reads unassigned agent", first(h.call(alice, "GET", "/agents/"+u1, nil)), 404)
	h.expect("alice reads agent in B", first(h.call(alice, "GET", "/agents/"+b1, nil)), 200)
	h.expect("alice reads unassigned config", first(h.call(alice, "GET", "/configs/"+cU, nil)), 404)
	h.expect("bob reads project config", first(h.call(bob, "GET", "/configs/"+cA+"/versions/1", nil)), 404)
	h.expect("carol reads agent metrics", first(h.call(carol, "GET", "/agents/"+a1+"/metrics", nil)), 404)
	h.expect("carol reads agent traces", first(h.call(carol, "GET", "/agents/"+a1+"/traces", nil)), 404)
	h.expect("carol reads all agent metrics", first(h.call(carol, "GET", "/agents/"+a1+"/metrics/all", nil)), 404)
	h.expect("alice reads traces of an agent in B", first(h.call(alice, "GET", "/agents/"+b1+"/traces", nil)), 200)
	h.expect("carol lists a bridge's collectors", first(h.call(carol, "GET", "/agents/"+a1+"/collectors", nil)), 404)
	h.expect("viewer sets a bridge collector config in B", first(h.call(alice, "PUT", "/agents/"+b1+"/collectors/config", map[string]any{"collector": "x/y"})), 403)
	h.expect("collectors of an ordinary agent", first(h.call(alice, "GET", "/agents/"+a1+"/collectors", nil)), 404)
	h.expect("carol reads agent logs", first(h.call(carol, "GET", "/agents/"+a1+"/logs", nil)), 404)
	h.expect("alice reads logs of an agent in B", first(h.call(alice, "GET", "/agents/"+b1+"/logs", nil)), 200)

	// --- Changes need the operator role in that project.
	h.expect("alice creates config in A", first(h.call(alice, "POST", "/configs", map[string]any{"name": "mine", "body": collectorYAML, "project_id": A})), 201)
	h.expect("alice creates config in B (viewer)", first(h.call(alice, "POST", "/configs", map[string]any{"name": "mine", "body": collectorYAML, "project_id": B})), 403)
	h.expect("alice creates config outside a project", first(h.call(alice, "POST", "/configs", map[string]any{"name": "mine", "body": collectorYAML})), 400)
	h.expect("alice edits config in B", first(h.call(alice, "POST", "/configs/"+cB+"/versions", map[string]any{"body": collectorYAML + "# x\n"})), 403)
	h.expect("alice deletes unassigned config", first(h.call(alice, "DELETE", "/configs/"+cU, nil)), 404)
	h.expect("bob (global viewer) creates unassigned config", first(h.call(bob, "POST", "/configs", map[string]any{"name": "b", "body": collectorYAML})), 400)
	h.expect("alice stops collector in B (viewer)", first(h.call(alice, "POST", "/agents/"+b1+"/pause", nil)), 403)
	h.expect("alice restarts unassigned collector", first(h.call(alice, "POST", "/agents/"+u1+"/restart", nil)), 404)
	h.expect("alice assigns A config to A collector", first(h.call(alice, "PUT", "/agents/"+a1+"/config", map[string]any{"config_version_id": vA})), 204)
	h.expect("alice assigns B config to A collector", first(h.call(alice, "PUT", "/agents/"+a1+"/config", map[string]any{"config_version_id": vB})), 409)
	h.expect("alice assigns A config to B collector", first(h.call(alice, "PUT", "/agents/"+b1+"/config", map[string]any{"config_version_id": vA})), 403)

	// --- Bulk actions judge every collector as the single endpoints do, and one refusal does not stop the rest.
	a2, b2 := connect("a2", &A), connect("b2", &B)
	bulk := func(token, action string, uids ...string) (map[string]int, float64) {
		code, out := h.call(token, "POST", "/agents/bulk", map[string]any{"action": action, "instance_uids": uids})
		h.expect("bulk "+action, code, 200)
		got := map[string]int{}
		for _, r := range out["results"].([]any) {
			m := r.(map[string]any)
			got[m["instance_uid"].(string)] = int(m["status"].(float64))
		}
		return got, out["succeeded"].(float64)
	}
	if got, _ := bulk(alice, "pause", a2, b2, u1); got[a2] != 409 || got[b2] != 403 || got[u1] != 404 {
		t.Errorf("alice bulk pause (no config, viewer, invisible) = %v", got)
	}
	if got, _ := bulk(alice, "restart", a2, b2, u1); got[a2] != 409 || got[b2] != 403 || got[u1] != 404 {
		t.Errorf("alice bulk restart = %v", got)
	}
	h.expect("bulk with an unknown action", first(h.call(alice, "POST", "/agents/bulk", map[string]any{"action": "explode", "instance_uids": []string{a2}})), 400)
	h.expect("bulk with no collectors", first(h.call(alice, "POST", "/agents/bulk", map[string]any{"action": "pause", "instance_uids": []string{}})), 400)
	// Labels: operators in the collector's project, one at a time or in bulk; a label then selects like an attribute.
	h.expect("alice labels a collector in A", first(h.call(alice, "PUT", "/agents/"+a2+"/labels", map[string]any{"labels": map[string]string{"owner": "alice"}})), 204)
	h.expect("alice labels a collector in B (viewer)", first(h.call(alice, "PUT", "/agents/"+b2+"/labels", map[string]any{"labels": map[string]string{"owner": "alice"}})), 403)
	h.expect("alice labels an unassigned collector", first(h.call(alice, "PUT", "/agents/"+u1+"/labels", map[string]any{"labels": map[string]string{"owner": "alice"}})), 404)
	h.expect("a label key with a space", first(h.call(alice, "PUT", "/agents/"+a2+"/labels", map[string]any{"labels": map[string]string{"my key": "x"}})), 400)
	lcode, lout := h.call(alice, "POST", "/agents/bulk", map[string]any{"action": "label", "instance_uids": []string{a2, b2, u1},
		"labels": map[string]any{"set": map[string]string{"canary": "true"}}})
	h.expect("alice bulk labels", lcode, 200)
	if lout["succeeded"].(float64) != 1 {
		t.Errorf("bulk label = %v, want only a2 to succeed", lout)
	}
	h.expect("bulk label with nothing to change", first(h.call(alice, "POST", "/agents/bulk", map[string]any{"action": "label", "instance_uids": []string{a2}})), 400)
	_, labelled := h.call(alice, "GET", "/agents?attr=label.canary=true", nil)
	if got := names(labelled, "agents", "host"); !equal(got, []string{"a2"}) {
		t.Errorf("fleet filtered by label = %v, want [a2]", got)
	}
	_, one := h.call(alice, "GET", "/agents/"+a2, nil)
	if l, _ := one["labels"].(map[string]any); l["owner"] != "alice" || l["canary"] != "true" {
		t.Errorf("a2 labels = %v", one["labels"])
	}

	h.expect("alice removes a connected collector", first(h.call(alice, "DELETE", "/agents/"+a2, nil)), 409)
	for _, uid := range []string{a2, b2} {
		if err := reg.Disconnected(ctx, uuid.MustParse(uid)); err != nil {
			t.Fatal(err)
		}
	}
	if got, ok := bulk(alice, "delete", a2, b2, u1, a2); got[a2] != 204 || got[b2] != 403 || got[u1] != 404 || ok != 1 || len(got) != 3 {
		t.Errorf("alice bulk delete = %v, %v succeeded", got, ok)
	}
	h.expect("the removed collector is gone", first(h.call(admin, "GET", "/agents/"+a2, nil)), 404)
	h.expect("carol removes a collector she cannot see", first(h.call(carol, "DELETE", "/agents/"+b2, nil)), 404)
	h.expect("admin removes B's offline collector", first(h.call(admin, "DELETE", "/agents/"+b2, nil)), 204)
	// Removing keeps a record, visible by project like everything else.
	for who, tc := range map[string]struct {
		token string
		want  []string
	}{"admin": {admin, []string{"b2", "a2"}}, "alice": {alice, []string{"b2", "a2"}}, "bob": {bob, nil}, "carol": {carol, nil}} {
		_, out := h.call(tc.token, "GET", "/agents/deleted", nil)
		if got := names(out, "agents", "host_name"); !equal(got, tc.want) {
			t.Errorf("%s sees removed collectors %v, want %v", who, got, tc.want)
		}
	}
	_, removed := h.call(admin, "GET", "/agents/deleted", nil)
	if m := removed["agents"].([]any)[1].(map[string]any); m["deleted_by"] != "alice@example.com" && m["deleted_by"] != "Alice@Example.com" {
		t.Errorf("a2 removed by %v, want alice", m["deleted_by"])
	}
	recA := strconv.Itoa(int(removed["agents"].([]any)[1].(map[string]any)["id"].(float64)))
	code, rec := h.call(alice, "GET", "/agents/deleted/"+recA, nil)
	h.expect("alice reads a2's record", code, 200)
	if hist, _ := rec["history"].([]any); rec["host_name"] != "a2" || len(hist) < 2 || hist[0].(map[string]any)["kind"] != "first_seen" {
		t.Errorf("a2's record = %v", rec)
	}
	h.expect("bob reads a2's record", first(h.call(bob, "GET", "/agents/deleted/"+recA, nil)), 404)
	h.expect("a record that does not exist", first(h.call(admin, "GET", "/agents/deleted/999999", nil)), 404)

	// --- Preview works on what the caller sends, so anyone signed in may use it; nothing is stored.
	pcode, pv := h.call(carol, "POST", "/configs/preview", map[string]any{"body": collectorYAML})
	h.expect("carol previews a config", pcode, 200)
	if pv["signal"] != "logs" || pv["in"].(float64) != 8 || pv["out"].(float64) != 8 || pv["exact"] != true {
		t.Errorf("preview = %v", pv)
	}
	h.expect("preview of a signal the config lacks", first(h.call(carol, "POST", "/configs/preview", map[string]any{"body": collectorYAML, "signal": "traces"})), 400)
	h.expect("preview of a builder pipeline with errors", first(h.call(alice, "POST", "/configs/preview", map[string]any{"builder": map[string]any{"sources": []any{}}})), 422)
	bcode, bv := h.call(alice, "POST", "/configs/preview", map[string]any{"builder": map[string]any{
		"sources":      []any{map[string]any{"type": "otlp"}},
		"processors":   []any{map[string]any{"type": "drop_low_severity_logs", "params": map[string]any{"min_severity": "ERROR"}}},
		"destinations": []any{map[string]any{"type": "debug"}},
	}})
	h.expect("alice previews a builder pipeline", bcode, 200)
	if bv["out"].(float64) != 3 {
		t.Errorf("builder preview keeps %v records, want 3 (two errors and one with no severity)", bv["out"])
	}
	_, smp := h.call(carol, "GET", "/configs/preview/samples", nil)
	if s, _ := smp["traces"].(string); !strings.Contains(s, "resourceSpans") {
		t.Errorf("samples = %.80v", smp)
	}

	// --- Groups and pushes stay inside their project, even with a selector that matches everywhere.
	code, grp := h.call(alice, "POST", "/groups", map[string]any{"name": "prod", "project_id": A, "selector": map[string][]string{"env": {"prod"}}})
	h.expect("alice creates group in A", code, 201)
	_, groups := h.call(alice, "GET", "/groups", nil)
	if g := groups["groups"].([]any)[0].(map[string]any); g["members"].(float64) != 1 {
		t.Errorf("group in A counts %v members, want 1 (only A's collector)", g["members"])
	}
	_, list := h.call(alice, "GET", "/agents?group_id="+grp["id"].(string), nil)
	if got := names(list, "agents", "host"); !equal(got, []string{"a1"}) {
		t.Errorf("fleet filtered by A's group = %v", got)
	}
	// The project and group filters narrow together: a group from one project filtered by another matches nothing.
	_, list = h.call(admin, "GET", "/agents?group_id="+grp["id"].(string)+"&project_id="+A, nil)
	if got := names(list, "agents", "host"); !equal(got, []string{"a1"}) {
		t.Errorf("A's group within project A = %v", got)
	}
	// The summary cards follow the group as well.
	_, sum := h.call(admin, "GET", "/summary?group_id="+grp["id"].(string), nil)
	if sum["total"].(float64) != 1 {
		t.Errorf("summary for A's group counts %v agents, want 1", sum["total"])
	}
	for _, other := range []string{B, "none"} {
		_, list = h.call(admin, "GET", "/agents?group_id="+grp["id"].(string)+"&project_id="+other, nil)
		if list["total"].(float64) != 0 {
			t.Errorf("A's group filtered by project %s matched %v agents, want 0", other, list["total"])
		}
	}
	code, ro := h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vA, "project_id": A, "all_agents": true, "selector": map[string]any{}})
	h.expect("alice pushes to all of A", code, 201)
	if ro["total_agents"].(float64) != 1 {
		t.Errorf("push to all of A targets %v agents, want 1", ro["total_agents"])
	}
	h.expect("alice pushes in B (viewer)", first(h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vB, "project_id": B, "all_agents": true, "selector": map[string]any{}})), 403)
	h.expect("alice pushes to unassigned agents", first(h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vA, "all_agents": true, "selector": map[string]any{}})), 400)
	h.expect("alice pushes B's config into A", first(h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vB, "project_id": A, "all_agents": true, "selector": map[string]any{}})), 409)
	h.expect("bob reads A's push", first(h.call(bob, "GET", "/rollouts/"+ro["id"].(string), nil)), 404)
	h.expect("bob aborts A's push", first(h.call(bob, "POST", "/rollouts/"+ro["id"].(string)+"/abort", nil)), 404)
	_, preview := h.call(bob, "POST", "/rollouts/preview", map[string]any{"project_id": A, "selector": map[string]any{}})
	if preview["total"].(float64) != 0 {
		t.Errorf("bob previews %v agents in A, want 0", preview["total"])
	}

	// --- API tokens: a project token acts only in its project.
	code, tok := h.call(admin, "POST", "/auth/tokens", map[string]any{"name": "ci-a", "role": "operator", "project_id": A})
	h.expect("admin creates project token", code, 201)
	_, out := h.call(tok["secret"].(string), "GET", "/agents", nil)
	if got := names(out, "agents", "host"); !equal(got, []string{"a1"}) {
		t.Errorf("project token sees %v, want [a1]", got)
	}
	h.expect("project token changes B", first(h.call(tok["secret"].(string), "POST", "/configs/"+cB+"/versions", map[string]any{"body": collectorYAML + "# y\n"})), 404)
	// A token's own rate limits are set by administrators and apply to that token only.
	limitsOf := "/auth/tokens/" + tok["id"].(string) + "/limits"
	h.expect("non-admin sets a token's limits", first(h.call(alice, "PUT", limitsOf, map[string]any{"write_limit_per_minute": 1})), 403)
	h.expect("a negative limit", first(h.call(admin, "PUT", limitsOf, map[string]any{"write_limit_per_minute": -1})), 400)
	h.expect("limits of an unknown token", first(h.call(admin, "PUT", "/auth/tokens/"+uuid.NewString()+"/limits", map[string]any{})), 404)
	lcode, limited := h.call(admin, "PUT", limitsOf, map[string]any{"write_limit_per_minute": 1})
	h.expect("admin sets a token's limits", lcode, 200)
	if limited["write_limit_per_minute"].(float64) != 1 || limited["rate_limit_per_minute"] != nil {
		t.Errorf("limits after change = %v", limited)
	}
	validate := map[string]any{"body": collectorYAML}
	h.expect("the token's first change", first(h.call(tok["secret"].(string), "POST", "/configs/validate", validate)), 200)
	h.expect("the token's second change in a minute", first(h.call(tok["secret"].(string), "POST", "/configs/validate", validate)), 429)
	h.expect("the token still reads", first(h.call(tok["secret"].(string), "GET", "/agents", nil)), 200)
	h.expect("someone else is not affected", first(h.call(alice, "POST", "/configs/validate", validate)), 200)
	h.expect("admin clears the token's limits", first(h.call(admin, "PUT", limitsOf, map[string]any{})), 200)
	h.expect("the token changes things again", first(h.call(tok["secret"].(string), "POST", "/configs/validate", validate)), 200)
	h.expect("admin token cannot be project-bound", first(h.call(admin, "POST", "/auth/tokens", map[string]any{"name": "x", "role": "admin", "project_id": A})), 400)

	// --- The Users page: people who signed in, and people added ahead of their first sign-in.
	if err := projects.RecordSignIn(ctx, "okta", "00u1", "Alice@Example.com", "Alice A", auth.RoleNone); err != nil {
		t.Fatal(err)
	}
	h.expect("non-admin lists users", first(h.call(alice, "GET", "/users", nil)), 403)
	_, users := h.call(admin, "GET", "/users", nil)
	byName := map[string]map[string]any{}
	for _, u := range users["users"].([]any) {
		byName[u.(map[string]any)["subject"].(string)] = u.(map[string]any)
	}
	if a := byName["alice@example.com"]; a == nil || a["name"] != "Alice A" || a["provider"] != "okta" || len(a["projects"].([]any)) != 2 {
		t.Errorf("alice on the users page = %v", a)
	}
	h.expect("add someone who never signed in", first(h.call(admin, "PUT", "/projects/"+B+"/members", map[string]string{"subject": "new@example.com", "role": "viewer"})), 204)
	_, users = h.call(admin, "GET", "/users", nil)
	found := false
	for _, u := range users["users"].([]any) {
		m := u.(map[string]any)
		found = found || (m["subject"] == "new@example.com" && m["provider"] == "" && len(m["projects"].([]any)) == 1)
	}
	if !found {
		t.Error("a person added before signing in is missing from the users page")
	}

	// --- Search, export, breakdown and trend all respect projects.
	_, searched := h.call(alice, "GET", "/agents?q=1", nil) // every host name contains "1"
	if got := names(searched, "agents", "host"); !equal(got, []string{"a1", "b1"}) {
		t.Errorf("alice searching finds %v", got)
	}
	if csv := h.raw(alice, "/agents/export?format=csv"); !strings.Contains(csv, "a1") || !strings.Contains(csv, "b1") || strings.Contains(csv, "u1") {
		t.Errorf("alice's export:\n%s", csv)
	}
	if csv := h.raw(carol, "/agents/export"); strings.Count(csv, "\n") != 1 {
		t.Errorf("carol's export should be a header only:\n%s", csv)
	}
	_, bd := h.call(alice, "GET", "/agents/breakdown?by=env", nil)
	if rows := bd["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["total"].(float64) != 2 {
		t.Errorf("alice's breakdown = %v", bd)
	}
	if err := reg.SampleFleet(ctx); err != nil {
		t.Fatal(err)
	}
	_, trend := h.call(alice, "GET", "/summary/history?hours=1", nil)
	if pts := trend["points"].([]any); len(pts) != 1 || pts[0].(map[string]any)["total"].(float64) != 2 {
		t.Errorf("alice's trend = %v", trend)
	}
	h.expect("non-admin exports the audit log", first(h.call(alice, "GET", "/audit/export", nil)), 403)
	if csv := h.raw(admin, "/audit/export?format=csv"); !strings.HasPrefix(csv, "id,occurred_at,actor") || !strings.Contains(csv, "project.create") {
		t.Errorf("audit export:\n%.300s", csv)
	}
	h.expect("bob reads A's push timeline", first(h.call(bob, "GET", "/rollouts/"+ro["id"].(string)+"/batches", nil)), 404)
	_, tl := h.call(alice, "GET", "/rollouts/"+ro["id"].(string)+"/batches", nil)
	if b := tl["batches"].([]any); len(b) != 1 || b[0].(map[string]any)["agents"].(float64) != 1 {
		t.Errorf("timeline = %v", tl)
	}

	// --- Secrets: admins only, and the value never comes back out.
	h.expect("admin sets a secret", first(h.call(admin, "PUT", "/secrets", map[string]any{"name": "vendor_key", "value": "s3cr3t-value", "project_id": A})), 204)
	h.expect("operator sets a secret", first(h.call(alice, "PUT", "/secrets", map[string]any{"name": "x", "value": "s3cr3t-value", "project_id": A})), 403)
	h.expect("operator lists secrets", first(h.call(alice, "GET", "/secrets", nil)), 403)
	// Operators may see which names exist in their project (for the editor), never values, and not other projects' names.
	_, nm := h.call(alice, "GET", "/secrets/names?project_id="+A, nil)
	if got := nm["names"].([]any); len(got) != 1 || got[0] != "vendor_key" {
		t.Errorf("secret names for alice = %v", nm)
	}
	h.expect("viewer lists secret names in B", first(h.call(alice, "GET", "/secrets/names?project_id="+B, nil)), 403)
	h.expect("alice lists unassigned secret names", first(h.call(alice, "GET", "/secrets/names?project_id=none", nil)), 404)
	_, listed := h.call(admin, "GET", "/secrets", nil)
	if raw, _ := json.Marshal(listed); len(listed["secrets"].([]any)) != 1 || bytes.Contains(raw, []byte("s3cr3t")) {
		t.Errorf("secret list = %s", raw)
	}

	// --- Signing out ends the session on the server; an admin can end someone else's.
	dave := h.session("dave@example.com", auth.RoleViewer)
	h.expect("dave before sign-out", first(h.call(dave, "GET", "/auth/me", nil)), 200)
	h.expect("dave signs out", first(h.call(dave, "POST", "/auth/logout", nil)), 204)
	h.expect("dave's token after sign-out", first(h.call(dave, "GET", "/auth/me", nil)), 401)
	erin := h.session("erin@example.com", auth.RoleViewer)
	h.expect("non-admin ends sessions", first(h.call(alice, "DELETE", "/users/erin@example.com/sessions", nil)), 403)
	h.expect("admin ends erin's sessions", first(h.call(admin, "DELETE", "/users/Erin@example.com/sessions", nil)), 200)
	h.expect("erin's token afterwards", first(h.call(erin, "GET", "/auth/me", nil)), 401)

	// --- Second approver: with the switch on, whoever started a push cannot continue it.
	code, ro2 := h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vA, "project_id": A, "all_agents": true, "selector": map[string]any{}, "manual_approval": true})
	h.expect("alice starts a push", code, 201)
	h.expect("alice pauses it", first(h.call(alice, "POST", "/rollouts/"+ro2["id"].(string)+"/pause", nil)), 204)
	if err := switches.Set(ctx, settings.SecondApprover, true, "root"); err != nil {
		t.Fatal(err)
	}
	h.expect("alice resumes her own push", first(h.call(alice, "POST", "/rollouts/"+ro2["id"].(string)+"/resume", nil)), 403)
	h.expect("alice can still abort it", first(h.call(alice, "POST", "/rollouts/"+ro2["id"].(string)+"/abort", nil)), 204)

	// --- Admin-only housekeeping.
	h.expect("remove alice from A", first(h.call(admin, "DELETE", "/projects/"+A+"/members/alice@example.com", nil)), 204)
	h.expect("alice loses A at once", first(h.call(alice, "GET", "/agents/"+a1, nil)), 404)

	// --- Deleting a project keeps it as a record, revokes its keys and tokens, and takes away access.
	keyB, err := agents.IssueAPIKey(ctx, "b-live", func() *uuid.UUID { id := uuid.MustParse(B); return &id }(), "root", nil)
	if err != nil {
		t.Fatal(err)
	}
	code, gone := h.call(admin, "DELETE", "/projects/"+B, nil)
	h.expect("admin deletes B", code, 200)
	if gone["api_keys_revoked"].(float64) < 1 || gone["collectors"].(float64) != 1 {
		t.Errorf("delete result = %v", gone)
	}
	probe := httptest.NewRequest("GET", "/v1/opamp", nil)
	probe.Header.Set("Authorization", "Bearer "+keyB.Secret)
	if _, err := agents.Authenticate(ctx, probe); err == nil {
		t.Error("an API key of a deleted project still authenticates")
	}
	h.expect("alice no longer sees B's collector", first(h.call(alice, "GET", "/agents/"+b1, nil)), 404)
	h.expect("nothing can be created in a deleted project", first(h.call(admin, "POST", "/configs", map[string]any{"name": "late", "body": collectorYAML, "project_id": B})), 400)
	h.expect("deleting it again", first(h.call(admin, "DELETE", "/projects/"+B, nil)), 404)
	_, active := h.call(admin, "GET", "/projects", nil)
	_, all := h.call(admin, "GET", "/projects?include_deleted=true", nil)
	if len(all["projects"].([]any)) != len(active["projects"].([]any))+1 {
		t.Errorf("deleted project not kept as a record: %d active, %d with deleted", len(active["projects"].([]any)), len(all["projects"].([]any)))
	}
	// Its collector and config are still on record for administrators, and its name is free again.
	h.expect("admin still reads B's collector", first(h.call(admin, "GET", "/agents/"+b1, nil)), 200)
	h.expect("admin still reads B's config", first(h.call(admin, "GET", "/configs/"+cB, nil)), 200)
	h.expect("the name can be reused", first(h.call(admin, "POST", "/projects", map[string]string{"name": "B"})), 201)
}

func first(code int, _ map[string]any) int { return code }

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
