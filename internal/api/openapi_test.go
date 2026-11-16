package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/msaif95/opamp-backend/internal/auth"
)

// The API reference must list exactly the endpoints the router serves.
func TestAPIReferenceMatchesTheRouter(t *testing.T) {
	s := &Server{Sessions: auth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), ""), Events: http.NotFoundHandler()}
	served := map[string]bool{}
	_ = chi.Walk(s.Router().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if path, ok := strings.CutPrefix(route, "/api/v1"); ok {
			served[method+" "+path] = true
		}
		return nil
	})
	documented := map[string]bool{}
	for _, d := range routeDocs {
		key := d.Method + " " + d.Path
		if documented[key] {
			t.Errorf("%s is documented twice", key)
		}
		documented[key] = true
		if d.Summary == "" || d.Tag == "" || d.Needs == "" {
			t.Errorf("%s lacks a summary, tag or who may call it", key)
		}
		if d.Body != "" && !json.Valid([]byte(d.Body)) {
			t.Errorf("%s: example body is not valid JSON", key)
		}
		if (d.Body != "") != (d.Method == "POST" || d.Method == "PUT") && d.Body != "" {
			t.Errorf("%s: a %s with a request body", key, d.Method)
		}
	}
	var missing, stale []string
	for k := range served {
		if !documented[k] {
			missing = append(missing, k)
		}
	}
	for k := range documented {
		if !served[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("served but not in the API reference (add them to routeDocs in openapi.go):\n  %s", strings.Join(missing, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("in the API reference but not served:\n  %s", strings.Join(stale, "\n  "))
	}
}

func TestOpenAPIDocument(t *testing.T) {
	raw, err := json.Marshal(buildOpenAPI("1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		OpenAPI string
		Info    struct{ Version string }
		Paths   map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Security    *[]any
			Parameters  []struct{ Name, In string }
			RequestBody *struct {
				Content map[string]struct{ Example any }
			} `json:"requestBody"`
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.0.3" || doc.Info.Version != "1.2.3" {
		t.Errorf("header = %s %s", doc.OpenAPI, doc.Info.Version)
	}
	ids, ops := map[string]bool{}, 0
	for _, item := range doc.Paths {
		for _, op := range item {
			ops++
			if ids[op.OperationID] {
				t.Errorf("operationId %q is used twice", op.OperationID)
			}
			ids[op.OperationID] = true
		}
	}
	if ops != len(routeDocs) {
		t.Errorf("%d operations for %d documented routes", ops, len(routeDocs))
	}
	if login := doc.Paths["/auth/login"]["post"]; login.Security == nil || len(*login.Security) != 0 || login.RequestBody == nil {
		t.Errorf("login = %+v, want no security and a request body", login)
	}
	list := doc.Paths["/agents"]["get"]
	if list.Security != nil || len(list.Parameters) != 11 || list.Parameters[5].Name != "attr" || list.Parameters[5].In != "query" {
		t.Errorf("list collectors = %+v", list)
	}
	if p := doc.Paths["/configs/{id}/versions/{version}"]["get"].Parameters; len(p) != 2 || p[0].Name != "id" || p[1].Name != "version" || p[0].In != "path" {
		t.Errorf("path parameters = %+v", p)
	}
	if ex, _ := doc.Paths["/agents/bulk"]["post"].RequestBody.Content["application/json"].Example.(map[string]any); ex["action"] != "label" {
		t.Errorf("bulk example = %v", ex)
	}
}
