package pipeline

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
)

// Component is one source, processor or destination in a built pipeline.
type Component struct {
	Type   string         `json:"type"`
	Params map[string]any `json:"params"`
	// Library, if set, is the ID of a saved library item whose type and
	// settings replace Type and Params (see Library.Resolve).
	Library *uuid.UUID `json:"library,omitempty"`
}

// Spec is a pipeline as built in the console. Processors run in the order given.
type Spec struct {
	Sources      []Component `json:"sources"`
	Processors   []Component `json:"processors"`
	Destinations []Component `json:"destinations"`
}

const maxComponents = 100

// params are a component's settings with catalog defaults filled in.
type params map[string]any

func (p params) str(k string) string {
	s, _ := p[k].(string)
	return strings.TrimSpace(s)
}
func (p params) number(k string) float64 { f, _ := p[k].(float64); return f }
func (p params) int(k string) int        { return int(p.number(k)) }
func (p params) bool(k string) bool      { b, _ := p[k].(bool); return b }
func (p params) list(k string) []string  { l, _ := p[k].([]string); return l }
func (p params) kv(k string) map[string]any {
	out := map[string]any{}
	for _, pair := range p.pairs(k) {
		out[pair[0]] = pair[1]
	}
	return out
}

// pairs returns a map field as key/value pairs sorted by key.
func (p params) pairs(k string) [][2]string {
	m, _ := p[k].(map[string]string)
	out := make([][2]string, 0, len(m))
	for key, v := range m {
		out = append(out, [2]string{key, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// normalize checks raw settings against the type's fields, applies
// defaults and converts values to the Go types the builders expect.
func normalize(t *Type, raw map[string]any, path string) (params, []agentconfig.Issue) {
	p := params{}
	var issues []agentconfig.Issue
	bad := func(f Field, msg string) {
		issues = append(issues, agentconfig.Issue{Severity: agentconfig.SeverityError, Path: path + "." + f.Key, Message: f.Label + ": " + msg})
	}
	for _, f := range t.Fields {
		v, set := raw[f.Key]
		if !set || v == nil {
			v = f.Default
		}
		switch f.Type {
		case FieldString, FieldEnum:
			s, ok := v.(string)
			if v != nil && !ok {
				bad(f, "must be text")
				continue
			}
			s = strings.TrimSpace(s)
			if f.Required && s == "" {
				bad(f, "is required")
			} else if f.Type == FieldEnum && s != "" && !slices.Contains(f.Options, s) {
				bad(f, "must be one of "+strings.Join(f.Options, ", "))
			}
			p[f.Key] = s
		case FieldInt, FieldNumber:
			var n float64
			switch x := v.(type) {
			case float64:
				n = x
			case int:
				n = float64(x)
			case nil:
				if f.Required {
					bad(f, "is required")
				}
				continue
			default:
				bad(f, "must be a number")
				continue
			}
			if n < 0 || (f.Type == FieldInt && n != float64(int(n))) {
				bad(f, "must be a whole number, 0 or more")
			}
			p[f.Key] = n
		case FieldBool:
			b, ok := v.(bool)
			if v != nil && !ok {
				bad(f, "must be on or off")
			}
			p[f.Key] = b
		case FieldList, FieldMulti:
			var list []string
			switch x := v.(type) {
			case []string:
				list = x
			case []any:
				for _, e := range x {
					s, ok := e.(string)
					if !ok {
						bad(f, "must be a list of text values")
						break
					}
					if s = strings.TrimSpace(s); s != "" {
						list = append(list, s)
					}
				}
			case nil:
			default:
				bad(f, "must be a list")
			}
			if f.Required && len(list) == 0 {
				bad(f, "needs at least one value")
			}
			if f.Type == FieldMulti {
				for _, s := range list {
					if !slices.Contains(f.Options, s) {
						bad(f, fmt.Sprintf("%q is not one of %s", s, strings.Join(f.Options, ", ")))
					}
				}
			}
			p[f.Key] = list
		case FieldMap:
			m := map[string]string{}
			switch x := v.(type) {
			case map[string]any:
				for k, e := range x {
					s, ok := e.(string)
					if !ok || strings.TrimSpace(k) == "" {
						bad(f, "must be key/value text pairs")
						break
					}
					m[strings.TrimSpace(k)] = s
				}
			case nil:
			default:
				bad(f, "must be key/value pairs")
			}
			if f.Required && len(m) == 0 {
				bad(f, "needs at least one entry")
			}
			p[f.Key] = m
		}
	}
	return p, issues
}

type rendered struct {
	id      string
	signals []string
	used    bool
	label   string
}

// Render turns a spec into collector YAML. It returns the YAML and any
// issues; if an issue is an error the YAML is empty.
//
// One pipeline is generated per signal (logs, metrics, traces) that at
// least one source collects and at least one destination accepts; the
// processors that support that signal run in the order given.
func Render(spec Spec) (string, []agentconfig.Issue) {
	var issues []agentconfig.Issue
	fail := func(path, format string, args ...any) {
		issues = append(issues, agentconfig.Issue{Severity: agentconfig.SeverityError, Path: path, Message: fmt.Sprintf(format, args...)})
	}
	if len(spec.Sources)+len(spec.Processors)+len(spec.Destinations) > maxComponents {
		fail("", "a pipeline can hold at most %d components", maxComponents)
		return "", issues
	}
	if len(spec.Sources) == 0 {
		fail("sources", "add at least one source")
	}
	if len(spec.Destinations) == 0 {
		fail("destinations", "add at least one destination")
	}

	sections := map[string]map[string]any{"receivers": {}, "processors": {}, "exporters": {}}
	build := func(kind, section, group string, comps []Component) []rendered {
		var out []rendered
		seen := map[string]int{}
		for i, c := range comps {
			path := fmt.Sprintf("%s[%d]", group, i)
			idx := slices.IndexFunc(catalog, func(t Type) bool { return t.Kind == kind && t.Type == c.Type })
			if idx < 0 {
				fail(path, "unknown %s type %q", kind, c.Type)
				continue
			}
			t := &catalog[idx]
			p, errs := normalize(t, c.Params, path)
			issues = append(issues, errs...)
			if len(errs) > 0 {
				continue
			}
			// The first instance of a collector component keeps its bare name; later ones are numbered.
			seen[t.component]++
			id := t.component
			if n := seen[t.component]; n > 1 {
				id = fmt.Sprintf("%s/%d", t.component, n)
			}
			sections[section][id] = t.build(p)
			out = append(out, rendered{id: id, signals: t.Signals, label: t.Label})
		}
		return out
	}
	sources := build(KindSource, "receivers", "sources", spec.Sources)
	processors := build(KindProcessor, "processors", "processors", spec.Processors)
	destinations := build(KindDestination, "exporters", "destinations", spec.Destinations)
	if agentconfig.HasErrors(issues) {
		return "", issues
	}

	ids := func(comps []rendered, signal string) []any {
		var out []any
		for i := range comps {
			if slices.Contains(comps[i].signals, signal) {
				comps[i].used = true
				out = append(out, comps[i].id)
			}
		}
		return out
	}
	pipelines := map[string]any{}
	for _, signal := range allSignals {
		// Check both ends before marking anything used.
		collects := slices.ContainsFunc(sources, func(r rendered) bool { return slices.Contains(r.signals, signal) })
		accepts := slices.ContainsFunc(destinations, func(r rendered) bool { return slices.Contains(r.signals, signal) })
		if !collects || !accepts {
			continue
		}
		p := map[string]any{"receivers": ids(sources, signal), "exporters": ids(destinations, signal)}
		if procs := ids(processors, signal); len(procs) > 0 {
			p["processors"] = procs
		}
		pipelines[signal] = p
	}
	if len(pipelines) == 0 {
		fail("", "nothing would flow: no destination accepts what the sources collect (for example a metrics source with a logs-only destination)")
		return "", issues
	}

	// Components that ended up in no pipeline are left out of the YAML and reported.
	for section, group := range map[string][]rendered{"receivers": sources, "processors": processors, "exporters": destinations} {
		for _, r := range group {
			if !r.used {
				delete(sections[section], r.id)
				issues = append(issues, agentconfig.Issue{Severity: agentconfig.SeverityWarning, Path: r.id,
					Message: fmt.Sprintf("%s is not used: nothing in this pipeline carries %s through it", r.label, strings.Join(r.signals, "/"))})
			}
		}
	}

	doc := map[string]any{"receivers": sections["receivers"], "exporters": sections["exporters"], "service": map[string]any{"pipelines": pipelines}}
	if len(sections["processors"]) > 0 {
		doc["processors"] = sections["processors"]
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		fail("", "could not render the config: %v", err)
		return "", issues
	}
	body := "# Generated by the OpAMP Fleet config builder. Edit it in the builder, or as YAML to take over by hand.\n" + string(out)
	return body, append(issues, agentconfig.Validate(body, nil)...)
}
