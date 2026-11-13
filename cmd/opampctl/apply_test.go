package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAPI is just enough of the console API for apply.
type fakeAPI struct {
	configs  map[string][]string // name → version bodies
	groups   map[string]group
	requests []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.URL.Path != "/api/v1/configs/validate" {
		f.requests = append(f.requests, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api/v1"))
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	str := func(k string) string { s, _ := body[k].(string); return s }
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case r.Method == "GET" && path == "/configs":
		var list []configSummary
		for name, versions := range f.configs {
			list = append(list, configSummary{ID: "id-" + name, Name: name, LatestVersion: len(versions)})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"configs": list})
	case r.Method == "GET" && strings.HasPrefix(path, "/configs/id-"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/configs/id-"), "/versions/"+path[strings.LastIndex(path, "/")+1:])
		versions := f.configs[name]
		_ = json.NewEncoder(w).Encode(configVersion{Version: len(versions), Body: versions[len(versions)-1]})
	case path == "/configs/validate":
		issues := []issue{}
		if strings.Contains(str("body"), "BROKEN") {
			issues = append(issues, issue{Severity: "error", Path: "service", Message: "broken"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issues": issues})
	case r.Method == "POST" && path == "/configs":
		f.configs[str("name")] = []string{str("body")}
		w.WriteHeader(201)
	case r.Method == "POST" && strings.HasSuffix(path, "/versions"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/configs/id-"), "/versions")
		f.configs[name] = append(f.configs[name], str("body"))
		_ = json.NewEncoder(w).Encode(configVersion{Version: len(f.configs[name])})
	case r.Method == "GET" && path == "/groups":
		var list []group
		for _, g := range f.groups {
			list = append(list, g)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"groups": list})
	case (r.Method == "POST" && path == "/groups") || (r.Method == "PUT" && strings.HasPrefix(path, "/groups/")):
		raw, _ := json.Marshal(body)
		var g group
		_ = json.Unmarshal(raw, &g)
		g.ID = "gid-" + g.Name
		f.groups[g.Name] = g
	default:
		w.WriteHeader(404)
	}
}

func TestApplyIsIdempotentAndOnlyChangesWhatDiffers(t *testing.T) {
	api := &fakeAPI{configs: map[string][]string{"existing": {"old body\n"}}, groups: map[string]group{}}
	srv := httptest.NewServer(api)
	defer srv.Close()
	c := newClient(srv.URL, "t")

	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("hosts.collector.yaml", "receivers: {}\n") // not a resource: no kind
	write("resources.yaml", `kind: Config
name: hosts
bodyFile: hosts.collector.yaml
---
kind: Config
name: existing
description: updated
body: |
  new body
---
kind: Group
name: prod-sre
selector:
  team: [sre]
  env: [prod]
`)
	resources, err := loadResources(dir)
	if err != nil || len(resources) != 3 {
		t.Fatalf("load: %v, %d resources", err, len(resources))
	}

	// Dry run reports but writes nothing.
	var out bytes.Buffer
	changed, err := apply(c, resources, true, &out)
	if err != nil || changed != 3 || len(api.requests) != 0 {
		t.Fatalf("dry run: changed %d, err %v, wrote %v\n%s", changed, err, api.requests, out.String())
	}
	for _, want := range []string{`config "hosts": would be created`, `config "existing": would get a new version (v2)`, `group "prod-sre": would be created`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("dry run output lacks %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if changed, err = apply(c, resources, false, &out); err != nil || changed != 3 {
		t.Fatalf("apply: changed %d, err %v", changed, err)
	}
	if got := strings.Join(api.requests, "; "); got != "POST /configs; POST /configs/id-existing/versions; POST /groups" {
		t.Fatalf("requests = %s", got)
	}
	if api.configs["hosts"][0] != "receivers: {}\n" || api.configs["existing"][1] != "new body\n" {
		t.Fatalf("configs = %v", api.configs)
	}

	// A second run changes nothing.
	api.requests, out = nil, bytes.Buffer{}
	if changed, err = apply(c, resources, false, &out); err != nil || changed != 0 || len(api.requests) != 0 {
		t.Fatalf("second apply: changed %d, err %v, wrote %v\n%s", changed, err, api.requests, out.String())
	}

	// Reordering a group's selector values is not a change; changing them is.
	resources[2].Selector = map[string][]string{"env": {"prod"}, "team": {"sre"}}
	if changed, _ = apply(c, resources, false, &out); changed != 0 {
		t.Fatal("selector order treated as a change")
	}
	resources[2].Selector["team"] = []string{"sre", "platform"}
	if changed, _ = apply(c, resources, false, &out); changed != 1 || api.requests[0] != "PUT /groups/gid-prod-sre" {
		t.Fatalf("group update: changed %d, requests %v", changed, api.requests)
	}

	// An invalid config stops the run before it is saved.
	api.requests = nil
	_, err = apply(c, []resource{{Kind: "Config", Name: "bad", Body: "BROKEN"}}, false, &out)
	if err == nil || !strings.Contains(err.Error(), "not valid") || len(api.requests) != 0 {
		t.Fatalf("invalid config: err %v, wrote %v", err, api.requests)
	}
}

func TestLoadResourcesRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct{ content, want string }{
		"nokind.yaml":  {"name: x\n", "missing kind"},
		"noname.yaml":  {"kind: Config\nbody: x\n", "has no name"},
		"nobody.yaml":  {"kind: Config\nname: x\n", "exactly one of body or bodyFile"},
		"both.yaml":    {"kind: Config\nname: x\nbody: a\nbodyFile: b\n", "exactly one of body or bodyFile"},
		"nosel.yaml":   {"kind: Group\nname: g\n", "needs a selector"},
		"unknown.yaml": {"kind: Rollout\nname: r\n", "unknown kind"},
		"badfile.yaml": {"kind: Config\nname: x\nbodyFile: missing.yaml\n", "no such file"},
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadResources(path); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one containing %q", name, err, tc.want)
		}
	}
}

func TestParseSelector(t *testing.T) {
	sel, err := parseSelector("env=prod, region=us-east-1,region=eu-west-1")
	if err != nil || len(sel["region"]) != 2 || sel["env"][0] != "prod" {
		t.Fatalf("sel = %v, err %v", sel, err)
	}
	if _, err := parseSelector("env"); err == nil {
		t.Fatal("selector without a value accepted")
	}
}
