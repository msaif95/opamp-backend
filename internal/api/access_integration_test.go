package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/access"
	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/api"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/settings"
	"github.com/msaif95/opamp-backend/internal/targeting"
	"github.com/msaif95/opamp-backend/internal/testdb"
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
	switches, err := settings.New(ctx, db, rdb, map[string]settings.Definition{}, log)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, sessions: sessions}
	h.srv = httptest.NewServer((&api.Server{
		DB: db, Registry: reg, Configs: configs, Library: pipeline.NewLibrary(db), Rollouts: rollout.NewService(db, reg, log),
		Agents: agents, Sessions: sessions, Groups: targeting.NewGroups(db), Events: http.NotFoundHandler(), Log: log,
		Tokens: tokens, Projects: projects, Settings: switches, Logins: auth.NewLoginLimiter(rdb),
		Throughput: func(context.Context, uuid.UUID) (*throughputSample, error) { return nil, nil },
		History:    func(context.Context, uuid.UUID) ([]throughputPoint, error) { return nil, nil },
		Ready:      func(context.Context) error { return nil },
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

	// Configs: one per project and one unassigned.
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
	cU, _ := mk("cfg-u", nil)

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

	// --- Changes need the operator role in that project.
	h.expect("alice creates config in A", first(h.call(alice, "POST", "/configs", map[string]any{"name": "mine", "body": collectorYAML, "project_id": A})), 201)
	h.expect("alice creates config in B (viewer)", first(h.call(alice, "POST", "/configs", map[string]any{"name": "mine", "body": collectorYAML, "project_id": B})), 403)
	h.expect("alice creates config outside a project", first(h.call(alice, "POST", "/configs", map[string]any{"name": "mine", "body": collectorYAML})), 403)
	h.expect("alice edits config in B", first(h.call(alice, "POST", "/configs/"+cB+"/versions", map[string]any{"body": collectorYAML + "# x\n"})), 403)
	h.expect("alice deletes unassigned config", first(h.call(alice, "DELETE", "/configs/"+cU, nil)), 404)
	h.expect("bob (global viewer) creates unassigned config", first(h.call(bob, "POST", "/configs", map[string]any{"name": "b", "body": collectorYAML})), 403)
	h.expect("alice stops collector in B (viewer)", first(h.call(alice, "POST", "/agents/"+b1+"/pause", nil)), 403)
	h.expect("alice restarts unassigned collector", first(h.call(alice, "POST", "/agents/"+u1+"/restart", nil)), 404)
	h.expect("alice assigns A config to A collector", first(h.call(alice, "PUT", "/agents/"+a1+"/config", map[string]any{"config_version_id": vA})), 204)
	h.expect("alice assigns B config to A collector", first(h.call(alice, "PUT", "/agents/"+a1+"/config", map[string]any{"config_version_id": vB})), 409)
	h.expect("alice assigns A config to B collector", first(h.call(alice, "PUT", "/agents/"+b1+"/config", map[string]any{"config_version_id": vA})), 403)

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
	code, ro := h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vA, "project_id": A, "all_agents": true, "selector": map[string]any{}})
	h.expect("alice pushes to all of A", code, 201)
	if ro["total_agents"].(float64) != 1 {
		t.Errorf("push to all of A targets %v agents, want 1", ro["total_agents"])
	}
	h.expect("alice pushes in B (viewer)", first(h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vB, "project_id": B, "all_agents": true, "selector": map[string]any{}})), 403)
	h.expect("alice pushes to unassigned agents", first(h.call(alice, "POST", "/rollouts", map[string]any{"config_version_id": vA, "all_agents": true, "selector": map[string]any{}})), 403)
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
	h.expect("admin token cannot be project-bound", first(h.call(admin, "POST", "/auth/tokens", map[string]any{"name": "x", "role": "admin", "project_id": A})), 400)

	// --- Admin-only housekeeping.
	h.expect("delete a project that owns things", first(h.call(admin, "DELETE", "/projects/"+A, nil)), 409)
	h.expect("remove alice from A", first(h.call(admin, "DELETE", "/projects/"+A+"/members/alice@example.com", nil)), 204)
	h.expect("alice loses A at once", first(h.call(alice, "GET", "/agents/"+a1, nil)), 404)
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
