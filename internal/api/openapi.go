package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// routeDoc documents one endpoint for the API reference. The table below is
// the single source: the OpenAPI document served to the console is built
// from it, and a test fails when it and the router disagree, so an endpoint
// cannot be added, removed or renamed without its entry.
type routeDoc struct {
	Method, Path string
	Tag, Summary string
	// Needs says who may call it, in words.
	Needs string
	// Query lists query parameters as "name: what it does".
	Query []string
	// Body is an example JSON request body; empty when the endpoint takes none.
	Body string
}

const (
	anyone   = "No sign-in needed."
	signedIn = "Any signed-in user."
	viewer   = "Viewer in the resource's project. Results are limited to the caller's projects."
	operator = "Operator in the resource's project."
	admin    = "Global administrator."

	tagSession = "Session"
	tagAgents  = "Collectors"
	tagConfigs = "Configs"
	tagGroups  = "Groups"
	tagPushes  = "Bulk pushes"
	tagAccess  = "Projects and users"
	tagCreds   = "Credentials and tokens"
	tagAudit   = "Audit and compliance"
	tagSystem  = "System"
	tagConsole = "Console"
)

var fleetFilters = []string{
	"limit: page size (default 50, at most 1000)", "offset: rows to skip", "connected: true or false", "healthy: true or false",
	"config_status: unset, applied, applying or failed", "attr: attribute filter key=value; repeat for several (labels are label.<name>=value)",
	"q: free text matched against the UID and every attribute", "group_id: only collectors in this group", "project_id: a project ID, or none",
	"sort: name or last_seen", "order: asc or desc",
}

var routeDocs = []routeDoc{
	{"POST", "/auth/login", tagSession, "Sign in as the local administrator", anyone, nil, `{"username": "admin", "password": "..."}`},
	{"GET", "/auth/config", tagSession, "Which sign-in methods are available", anyone, nil, ""},
	{"GET", "/auth/okta/login", tagSession, "Start single sign-on (redirects to the identity provider)", anyone, nil, ""},
	{"GET", "/auth/okta/callback", tagSession, "Finish single sign-on (called by the identity provider)", anyone, []string{"code: authorization code", "state: value from the login redirect"}, ""},
	{"GET", "/auth/me", tagSession, "The caller: role, projects and session settings", signedIn, nil, ""},
	{"POST", "/auth/logout", tagSession, "End the caller's session", signedIn, nil, ""},
	{"GET", "/auth/me/settings/{key}", tagConsole, "One of the caller's own console settings (fleet_views, overview_cards)", signedIn, nil, ""},
	{"PUT", "/auth/me/settings/{key}", tagConsole, "Replace one of the caller's own console settings", signedIn, nil, `{"value": [{"id": "1", "name": "Prod", "query": "attr=env%3Dprod"}]}`},
	{"GET", "/events", tagConsole, "Server-sent events: a cue that something changed (carries no detail)", signedIn, []string{"access_token: session token, since EventSource cannot send headers"}, ""},
	{"GET", "/openapi.json", tagConsole, "This API reference as an OpenAPI 3 document", signedIn, nil, ""},
	{"GET", "/downloads/opampctl", tagConsole, "The opampctl command-line tool: version, usage text and the platforms available to download", signedIn, nil, ""},
	{"GET", "/downloads/opampctl/{platform}", tagConsole, "Download opampctl for a platform such as linux_amd64 or darwin_arm64", signedIn, nil, ""},

	{"GET", "/summary", tagAgents, "Fleet counts: total, connected, healthy, unhealthy, config failed", viewer, []string{"project_id: a project ID, or none", "group_id: only collectors in this group"}, ""},
	{"GET", "/summary/history", tagAgents, "Fleet counts over time, for trend lines", viewer, []string{"hours: how far back (default 24)", "project_id: a project ID, or none"}, ""},
	{"GET", "/agents", tagAgents, "List collectors", viewer, fleetFilters, ""},
	{"GET", "/agents/facets", tagAgents, "Low-cardinality attributes and their values, for building selectors", viewer, []string{"project_id: a project ID, or none"}, ""},
	{"GET", "/agents/export", tagAgents, "Download the collectors matching the fleet filters", viewer, append([]string{"format: csv (default) or json"}, fleetFilters[2:9]...), ""},
	{"GET", "/agents/breakdown", tagAgents, "Count collectors by one or two attributes", viewer, []string{"by: attribute name; repeat for a second"}, ""},
	{"GET", "/agents/deleted", tagAgents, "Records of collectors removed from the fleet", viewer, nil, ""},
	{"GET", "/agents/deleted/{id}", tagAgents, "One removed collector's record, with its history and last reported config", viewer, nil, ""},
	{"POST", "/agents/bulk", tagAgents, "Apply one action to up to 500 collectors; the answer reports each", operator, nil, `{"action": "label", "instance_uids": ["581e3c22-fc8a-5394-9354-edab70db7668"], "labels": {"set": {"owner": "platform"}, "remove": ["old"]}}`},
	{"POST", "/agents/install-command", tagAgents, "Issue an agent API key and return an install script for it", admin, nil, `{"platform": "linux_amd64", "version": "0.164.0", "key_name": "edge-hosts", "expires_days": 90, "project_id": "<project id>", "labels": {"env": "prod"}, "transport": "websocket"}`},
	{"GET", "/agents/{uid}", tagAgents, "One collector, with its effective config and throughput", viewer, nil, ""},
	{"DELETE", "/agents/{uid}", tagAgents, "Remove an offline collector from the fleet (a record is kept)", operator, nil, ""},
	{"PUT", "/agents/{uid}/config", tagAgents, "Assign a config version to a collector and push it", operator, nil, `{"config_version_id": "<version id>"}`},
	{"PUT", "/agents/{uid}/labels", tagAgents, "Replace a collector's labels", operator, nil, `{"labels": {"owner": "alice"}}`},
	{"PUT", "/agents/{uid}/project", tagAgents, "Move a certificate-authenticated collector to a project", admin, nil, `{"project_id": "<project id>"}`},
	{"POST", "/agents/{uid}/restart", tagAgents, "Ask the collector to restart (needs the restart capability)", operator, nil, ""},
	{"POST", "/agents/{uid}/pause", tagAgents, "Stop collection: the collector runs an empty pipeline until resumed", operator, nil, ""},
	{"POST", "/agents/{uid}/resume", tagAgents, "Resume collection with the assigned config", operator, nil, ""},
	{"GET", "/agents/{uid}/events", tagAgents, "The collector's history, newest first", viewer, []string{"before: event ID to continue from", "limit: page size (default 100)"}, ""},
	{"GET", "/agents/{uid}/metrics", tagAgents, "Recent CPU, memory and throughput samples", viewer, nil, ""},
	{"GET", "/agents/{uid}/metrics/all", tagAgents, "Every metric series the collector reports about itself", viewer, nil, ""},
	{"GET", "/agents/{uid}/logs", tagAgents, "The collector's most recent own log lines", viewer, nil, ""},
	{"GET", "/agents/{uid}/traces", tagAgents, "The collector's most recent own spans", viewer, nil, ""},
	{"GET", "/agents/{uid}/collectors", tagAgents, "For a Kubernetes OpAMP Bridge: the collectors it manages", viewer, nil, ""},
	{"PUT", "/agents/{uid}/collectors/config", tagAgents, "For a Kubernetes OpAMP Bridge: assign a config to one of its collectors", operator, nil, `{"collector": "namespace/name", "config_version_id": "<version id>"}`},

	{"GET", "/configs", tagConfigs, "List configs", viewer, nil, ""},
	{"POST", "/configs", tagConfigs, "Create a config from YAML (body), a builder pipeline (builder) or a base config (base_id + overrides)", operator, nil, `{"name": "linux-hosts", "description": "", "project_id": "<project id>", "body": "receivers:\n  otlp:\nexporters:\n  debug:\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"}`},
	{"POST", "/configs/validate", tagConfigs, "Check collector YAML without saving it", signedIn, nil, `{"body": "receivers: {}"}`},
	{"POST", "/configs/preview", tagConfigs, "Show what a config's processors would do to sample telemetry", signedIn, nil, `{"body": "<collector yaml>", "signal": "logs", "sample": ""}`},
	{"GET", "/configs/preview/samples", tagConfigs, "The built-in sample telemetry as OTLP JSON", signedIn, nil, ""},
	{"POST", "/configs/merge", tagConfigs, "Show what a base config with the given overrides would be", viewer, nil, `{"base_id": "<config id>", "overrides": "processors:\n  batch:\n    timeout: 10s\n"}`},
	{"GET", "/configs/builder/catalog", tagConfigs, "The sources, processors and destinations the builder offers", signedIn, nil, ""},
	{"POST", "/configs/builder/render", tagConfigs, "Render a builder pipeline to collector YAML without saving it", signedIn, nil, `{"sources": [{"type": "otlp", "params": {}}], "processors": [{"type": "batch", "params": {}}], "destinations": [{"type": "debug", "params": {}}]}`},
	{"GET", "/configs/builder/library", tagConfigs, "Saved builder components", viewer, nil, ""},
	{"POST", "/configs/builder/library", tagConfigs, "Save a builder component for reuse", operator, nil, `{"kind": "destination", "name": "prod-gateway", "type": "otlp_grpc", "params": {"endpoint": "gateway.example.com:4317"}, "project_id": "<project id>"}`},
	{"PUT", "/configs/builder/library/{id}", tagConfigs, "Change a saved builder component", operator, nil, `{"kind": "destination", "name": "prod-gateway", "type": "otlp_grpc", "params": {"endpoint": "gateway.example.com:4317"}}`},
	{"DELETE", "/configs/builder/library/{id}", tagConfigs, "Delete a saved builder component", operator, nil, ""},
	{"GET", "/configs/{id}", tagConfigs, "A config with its version list and, for a base, its derived configs", viewer, nil, ""},
	{"DELETE", "/configs/{id}", tagConfigs, "Delete a config that is not assigned and has no derived configs", operator, nil, ""},
	{"POST", "/configs/{id}/versions", tagConfigs, "Add a version: body or builder for an ordinary config; overrides (or nothing, to rebuild from the base) for a derived one", operator, nil, `{"body": "<collector yaml>", "description": "what changed"}`},
	{"GET", "/configs/{id}/versions/{version}", tagConfigs, "One version, with its body", viewer, nil, ""},
	{"POST", "/configs/{id}/derived/update", tagConfigs, "Bring every config derived from this base up to date with its latest version", operator, nil, ""},
	{"GET", "/secrets/names", tagConfigs, "Names of the secrets a project's configs may refer to", operator, []string{"project_id: a project ID, or none"}, ""},
	{"GET", "/secrets", tagConfigs, "List config secrets (never their values)", admin, nil, ""},
	{"PUT", "/secrets", tagConfigs, "Set a config secret", admin, nil, `{"name": "vendor_key", "value": "...", "project_id": "<project id>"}`},
	{"DELETE", "/secrets/{id}", tagConfigs, "Delete a config secret", admin, nil, ""},

	{"GET", "/groups", tagGroups, "List groups with their live member counts", viewer, nil, ""},
	{"POST", "/groups", tagGroups, "Create a group from an attribute selector", operator, nil, `{"name": "prod-sre", "description": "", "project_id": "<project id>", "selector": {"env": ["prod"], "team": ["sre"]}}`},
	{"PUT", "/groups/{id}", tagGroups, "Change a group", operator, nil, `{"name": "prod-sre", "description": "", "selector": {"env": ["prod"]}}`},
	{"DELETE", "/groups/{id}", tagGroups, "Delete a group", operator, nil, ""},
	{"PUT", "/groups/{id}/config", tagGroups, "Set the group's config: starts a push to its members and gives it to new members", operator, nil, `{"config_version_id": "<version id>", "batch_size": 50, "max_failure_pct": 10}`},
	{"DELETE", "/groups/{id}/config", tagGroups, "Stop giving the group's config to new members", operator, nil, ""},

	{"GET", "/rollouts", tagPushes, "List bulk pushes", viewer, nil, ""},
	{"POST", "/rollouts", tagPushes, "Start a bulk push to a group, a selector or every collector in a project", operator, nil, `{"config_version_id": "<version id>", "project_id": "<project id>", "group_id": null, "selector": {"env": ["prod"]}, "all_agents": false, "batch_size": 50, "canary_steps_pct": null, "max_failure_pct": 10, "auto_rollback": false, "manual_approval": false}`},
	{"POST", "/rollouts/preview", tagPushes, "Count the collectors a push would target", viewer, nil, `{"project_id": "<project id>", "selector": {"env": ["prod"]}}`},
	{"GET", "/rollouts/{id}", tagPushes, "One bulk push with its progress and problems", viewer, nil, ""},
	{"GET", "/rollouts/{id}/batches", tagPushes, "The push's batches with their timings", viewer, nil, ""},
	{"POST", "/rollouts/{id}/pause", tagPushes, "Pause a running push", operator, nil, ""},
	{"POST", "/rollouts/{id}/resume", tagPushes, "Resume a paused push, or approve its next batch", operator, nil, ""},
	{"POST", "/rollouts/{id}/abort", tagPushes, "Stop a push where it is", operator, nil, ""},
	{"POST", "/rollouts/{id}/rollback", tagPushes, "Put the previous config back on the collectors a push changed", operator, nil, ""},

	{"GET", "/projects", tagAccess, "List the projects the caller can see", signedIn, []string{"include_deleted: true to include deleted projects (administrators)"}, ""},
	{"POST", "/projects", tagAccess, "Create a project", admin, nil, `{"name": "payments", "description": ""}`},
	{"DELETE", "/projects/{id}", tagAccess, "Delete a project: it is kept as a record, its keys and tokens are revoked", admin, nil, ""},
	{"GET", "/projects/{id}/members", tagAccess, "A project's members and their roles", admin, nil, ""},
	{"PUT", "/projects/{id}/members", tagAccess, "Add someone to a project or change their role", admin, nil, `{"subject": "ana@example.com", "role": "operator"}`},
	{"DELETE", "/projects/{id}/members/{subject}", tagAccess, "Remove someone from a project", admin, nil, ""},
	{"GET", "/users", tagAccess, "Everyone who has signed in or been added to a project", admin, nil, ""},
	{"DELETE", "/users/{subject}/sessions", tagAccess, "Sign someone out everywhere", admin, nil, ""},

	{"GET", "/credentials/api-keys", tagCreds, "List agent API keys (collectors connect with these)", admin, nil, ""},
	{"POST", "/credentials/api-keys", tagCreds, "Issue an agent API key; the secret is returned once", admin, nil, `{"name": "edge-hosts", "project_id": "<project id>", "expires_at": null}`},
	{"PUT", "/credentials/api-keys/{id}/project", tagCreds, "Move an agent API key to a project", admin, nil, `{"project_id": "<project id>"}`},
	{"DELETE", "/credentials/{id}", tagCreds, "Revoke an agent credential; collectors using it are disconnected", admin, nil, ""},
	{"GET", "/credentials/revoked-certs", tagCreds, "List revoked client certificates", admin, nil, ""},
	{"POST", "/credentials/revoked-certs", tagCreds, "Revoke a client certificate by its PEM", admin, nil, `{"name": "decommissioned host", "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."}`},
	{"GET", "/auth/tokens", tagCreds, "List console API tokens (for opampctl and automation)", admin, nil, ""},
	{"POST", "/auth/tokens", tagCreds, "Create a console API token; the secret is returned once", admin, nil, `{"name": "ci-pipeline", "role": "operator", "project_id": "<project id>", "expires_days": 90, "rate_limit_per_minute": null, "write_limit_per_minute": null}`},
	{"DELETE", "/auth/tokens/{id}", tagCreds, "Revoke a console API token", admin, nil, ""},
	{"PUT", "/auth/tokens/{id}/limits", tagCreds, "Set a token's own rate limits (null: the default, 0: no limit)", admin, nil, `{"rate_limit_per_minute": 300, "write_limit_per_minute": null}`},

	{"GET", "/audit", tagAudit, "The audit log, newest first", admin, []string{"q: matches action, actor or target", "before: event ID to continue from", "limit: page size (default 100, at most 500)"}, ""},
	{"GET", "/audit/export", tagAudit, "Download the audit log", admin, []string{"format: csv (default) or json", "q: matches action, actor or target", "from: RFC 3339 time", "to: RFC 3339 time"}, ""},
	{"GET", "/audit/verify", tagAudit, "Check the audit log's hash chain", admin, nil, ""},
	{"GET", "/reports", tagAudit, "List compliance reports", admin, nil, ""},
	{"POST", "/reports", tagAudit, "Generate a compliance report covering the last N days", admin, nil, `{"name": "Q4 audit preparation", "days": 30}`},
	{"GET", "/reports/schedules", tagAudit, "List report schedules", admin, nil, ""},
	{"POST", "/reports/schedules", tagAudit, "Create a report schedule (daily, weekly or monthly, in UTC)", admin, nil, `{"name": "Monthly compliance review", "frequency": "monthly"}`},
	{"PUT", "/reports/schedules/{id}", tagAudit, "Pause or resume a report schedule", admin, nil, `{"enabled": false}`},
	{"DELETE", "/reports/schedules/{id}", tagAudit, "Delete a report schedule (its reports are kept)", admin, nil, ""},
	{"POST", "/reports/schedules/{id}/run", tagAudit, "Make a schedule's report for the last whole period now", admin, nil, ""},
	{"GET", "/reports/{id}", tagAudit, "One compliance report in full", admin, nil, ""},
	{"GET", "/reports/{id}/download", tagAudit, "Download a report", admin, []string{"format: html, json, collectors or changes"}, ""},
	{"DELETE", "/reports/{id}", tagAudit, "Delete a compliance report", admin, nil, ""},

	{"GET", "/system", tagSystem, "Deployment status, protections, live replicas and recent alerts", admin, nil, ""},
	{"PUT", "/system/settings/{key}", tagSystem, "Switch a protection on or off for every replica", admin, nil, `{"enabled": true}`},
}

var pathParam = regexp.MustCompile(`\{([a-z_]+)\}`)

// buildOpenAPI turns the route table into an OpenAPI 3 document.
func buildOpenAPI(version string) map[string]any {
	errorResponse := map[string]any{"description": "Refused or failed. The body says why.",
		"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/Error"}}}}
	paths := map[string]any{}
	for _, d := range routeDocs {
		op := map[string]any{
			"tags": []string{d.Tag}, "summary": d.Summary, "description": "**Who may call it:** " + d.Needs,
			"operationId": strings.ToLower(d.Method) + strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_").Replace(d.Path),
			"responses": map[string]any{
				"2XX":     map[string]any{"description": "Success. Most endpoints answer with JSON; a few with 204 and no body, or a file download."},
				"default": errorResponse,
			},
		}
		if d.Needs == anyone {
			op["security"] = []any{}
		}
		var params []any
		for _, m := range pathParam.FindAllStringSubmatch(d.Path, -1) {
			params = append(params, map[string]any{"name": m[1], "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
		}
		for _, q := range d.Query {
			name, what, _ := strings.Cut(q, ": ")
			params = append(params, map[string]any{"name": name, "in": "query", "description": what, "schema": map[string]any{"type": "string"}})
		}
		if params != nil {
			op["parameters"] = params
		}
		if d.Body != "" {
			var example any
			_ = json.Unmarshal([]byte(d.Body), &example)
			op["requestBody"] = map[string]any{"required": true,
				"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "object"}, "example": example}}}
		}
		item, _ := paths[d.Path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[d.Path] = item
		}
		item[strings.ToLower(d.Method)] = op
	}
	var tags []any
	for _, t := range []string{tagAgents, tagConfigs, tagGroups, tagPushes, tagAccess, tagCreds, tagAudit, tagSystem, tagSession, tagConsole} {
		tags = append(tags, map[string]any{"name": t})
	}
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title": "OpAMP Fleet console API", "version": version,
			"description": "The API behind the console and `opampctl`. Send a console API token (created under Agent credentials → API tokens) " +
				"or a session token as `Authorization: Bearer <token>`.\n\n" +
				"Access is by project: something the caller may not see answers 404, not 403. Errors are `{\"error\": \"...\"}`; a config that fails " +
				"validation also carries `issues`. Each caller has a request budget per minute; beyond it the API answers 429 with `Retry-After`.\n\n" +
				"This reference lists every endpoint with its parameters, who may call it and an example request. It does not describe response " +
				"bodies field by field: use Try it out, or `opampctl ... -o json`, to see them.",
		},
		"servers":  []any{map[string]any{"url": "/api/v1"}},
		"tags":     tags,
		"security": []any{map[string]any{"bearer": []any{}}},
		"paths":    paths,
		"components": map[string]any{
			"securitySchemes": map[string]any{"bearer": map[string]any{"type": "http", "scheme": "bearer"}},
			"schemas": map[string]any{"Error": map[string]any{"type": "object", "properties": map[string]any{
				"error":  map[string]any{"type": "string"},
				"issues": map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			}}},
		},
	}
}

// openAPI serves the API reference as an OpenAPI 3 document.
func (s *Server) openAPI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, buildOpenAPI(s.Status.Version))
}
