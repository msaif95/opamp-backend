package agentconfig

import (
	"fmt"
	"strings"
)

// ComponentPolicy controls which OTel Collector component types are allowed
// in a config. A nil policy skips all component checking.
type ComponentPolicy struct {
	Receivers  map[string]bool
	Processors map[string]bool
	Exporters  map[string]bool
	Extensions map[string]bool
	Blocked    map[string]bool
}

// Check inspects every component defined in the parsed config and returns
// errors for blocked or unknown types. Connectors are checked against both
// the receiver and exporter allowlists.
func (p *ComponentPolicy) Check(root map[string]any) []Issue {
	if p == nil {
		return nil
	}
	var issues []Issue
	for section, allowed := range map[string]map[string]bool{
		"receivers":  p.Receivers,
		"processors": p.Processors,
		"exporters":  p.Exporters,
		"extensions": p.Extensions,
	} {
		m, _ := root[section].(map[string]any)
		for key := range m {
			ct := componentType(key)
			if p.Blocked[ct] {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Path:     section + "." + key,
					Message:  fmt.Sprintf("%s %q is blocked for security reasons", strings.TrimSuffix(section, "s"), key),
				})
			} else if !allowed[ct] {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Path:     section + "." + key,
					Message:  fmt.Sprintf("%s type %q is not in the allowed component list", strings.TrimSuffix(section, "s"), ct),
				})
			}
		}
	}
	m, _ := root["connectors"].(map[string]any)
	for key := range m {
		ct := componentType(key)
		if p.Blocked[ct] {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Path:     "connectors." + key,
				Message:  fmt.Sprintf("connector %q is blocked for security reasons", key),
			})
		} else if !p.Receivers[ct] && !p.Exporters[ct] {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Path:     "connectors." + key,
				Message:  fmt.Sprintf("connector type %q is not in the allowed component list", ct),
			})
		}
	}
	return issues
}

// componentType extracts the type from a component ID like "otlp/grpc" → "otlp".
func componentType(id string) string {
	if i := strings.IndexByte(id, '/'); i >= 0 {
		return id[:i]
	}
	return id
}
