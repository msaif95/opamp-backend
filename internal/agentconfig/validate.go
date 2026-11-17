package agentconfig

import (
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Severity of a validation issue. Errors block saving; warnings do not.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Issue is one validation finding.
type Issue struct {
	Severity string `json:"severity"`
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

// componentSections maps a pipeline role to the top-level sections that may
// define a component used in that role. Connectors act as both receivers
// and exporters.
var componentSections = map[string][]string{
	"receivers":  {"receivers", "connectors"},
	"processors": {"processors"},
	"exporters":  {"exporters", "connectors"},
}

var knownTopLevel = map[string]bool{
	"receivers": true, "processors": true, "exporters": true,
	"extensions": true, "connectors": true, "service": true,
}

// Validate lints a collector config. It checks YAML syntax and the
// structural rules the collector itself enforces at startup: every
// component referenced by a pipeline or service.extensions must be defined.
// When policy is non-nil it also enforces the component allowlist.
func Validate(body string, policy *ComponentPolicy) []Issue {
	if strings.TrimSpace(body) == "" {
		return []Issue{{Severity: SeverityError, Message: "config is empty"}}
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(body), &root); err != nil {
		return []Issue{{Severity: SeverityError, Message: "invalid YAML: " + err.Error()}}
	}
	if len(root) == 0 {
		return []Issue{{Severity: SeverityError, Message: "config must be a non-empty YAML mapping"}}
	}

	var issues []Issue
	add := func(sev, path, format string, args ...any) {
		issues = append(issues, Issue{Severity: sev, Path: path, Message: fmt.Sprintf(format, args...)})
	}

	for _, k := range sortedKeys(root) {
		if !knownTopLevel[k] {
			add(SeverityWarning, k, "unknown top-level section %q", k)
		} else if _, ok := root[k].(map[string]any); !ok && root[k] != nil {
			add(SeverityError, k, "%q must be a mapping", k)
		}
	}

	issues = append(issues, policy.Check(root)...)
	if HasErrors(issues) {
		return issues
	}

	service, _ := root["service"].(map[string]any)
	if service == nil {
		add(SeverityWarning, "service", "no service section: the config defines no pipelines")
		return issues
	}

	defined := func(sections []string, id string) bool {
		for _, s := range sections {
			if m, ok := root[s].(map[string]any); ok {
				if _, ok := m[id]; ok {
					return true
				}
			}
		}
		return false
	}

	if exts, ok := service["extensions"]; ok {
		for _, id := range stringList(exts) {
			if !defined([]string{"extensions"}, id) {
				add(SeverityError, "service.extensions", "extension %q is not defined in extensions", id)
			}
		}
	}

	pipelines, _ := service["pipelines"].(map[string]any)
	if len(pipelines) == 0 {
		add(SeverityWarning, "service.pipelines", "no pipelines defined")
	}
	for _, name := range sortedKeys(pipelines) {
		path := "service.pipelines." + name
		p, ok := pipelines[name].(map[string]any)
		if !ok {
			add(SeverityError, path, "pipeline must be a mapping")
			continue
		}
		for _, role := range []string{"receivers", "processors", "exporters"} {
			ids := stringList(p[role])
			if len(ids) == 0 && role != "processors" {
				add(SeverityError, path+"."+role, "pipeline must have at least one %s", strings.TrimSuffix(role, "s"))
			}
			for _, id := range ids {
				if !defined(componentSections[role], id) {
					add(SeverityError, path+"."+role, "%s %q is not defined in %s",
						strings.TrimSuffix(role, "s"), id, strings.Join(componentSections[role], " or "))
				}
			}
		}
	}
	return issues
}

// HasErrors reports whether any issue is an error.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if i.Severity == SeverityError {
			return true
		}
	}
	return false
}

func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
