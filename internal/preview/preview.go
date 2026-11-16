// Package preview shows what a config's processors would do to telemetry,
// before the config is pushed. It does not run a collector: it applies its
// own model of the common processors to a sample (built in, or supplied as
// OTLP JSON) and says plainly which processors it cannot model.
package preview

import (
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Signals in the order they are offered.
var Signals = []string{"logs", "traces", "metrics"}

// Step statuses.
const (
	// StatusApplied: the processor's effect is modelled.
	StatusApplied = "applied"
	// StatusApproximate: the size of the effect is right, the detail illustrative (sampling).
	StatusApproximate = "approximate"
	// StatusPassthrough: the processor does not change telemetry by design (batch, memory_limiter).
	StatusPassthrough = "passthrough"
	// StatusNotPreviewed: not modelled; records pass through unchanged here, which may not be what the collector does.
	StatusNotPreviewed = "not_previewed"
)

// Step is one processor of the pipeline, in order, and what it did to the sample.
type Step struct {
	// ID is the processor's name in the config ("attributes/2"); Component its type ("attributes").
	ID        string `json:"id"`
	Component string `json:"component"`
	Status    string `json:"status"`
	Note      string `json:"note"`
	In        int    `json:"in"`
	Out       int    `json:"out"`
	Dropped   int    `json:"dropped"`
	Changed   int    `json:"changed"`
}

// Snapshot is a record's attributes at one end of the pipeline.
type Snapshot struct {
	Resource   map[string]string `json:"resource"`
	Attributes map[string]string `json:"attributes"`
}

// Record is one sample record before and after the pipeline.
type Record struct {
	Title  string   `json:"title"`
	Detail string   `json:"detail"`
	Before Snapshot `json:"before"`
	// After is nil when the record was dropped.
	After     *Snapshot `json:"after"`
	DroppedBy string    `json:"dropped_by,omitempty"`
	ChangedBy []string  `json:"changed_by"`
}

// Result is a preview of one pipeline.
type Result struct {
	Signal string `json:"signal"`
	// Signals are the signals the config has pipelines for; Pipelines the pipelines of this signal.
	Signals   []string `json:"signals"`
	Pipeline  string   `json:"pipeline"`
	Pipelines []string `json:"pipelines"`
	Steps     []Step   `json:"steps"`
	Records   []Record `json:"records"`
	In        int      `json:"in"`
	Out       int      `json:"out"`
	// Exact is false when a processor was not previewed or only approximated.
	Exact bool `json:"exact"`
	// LeftOut is how many sample records beyond MaxRecords were not previewed.
	LeftOut int `json:"left_out"`
}

// Request says what to preview. Signal and Pipeline may be empty: the
// first signal the config handles, and its first pipeline, are used.
// Sample is OTLP JSON; empty uses the built-in sample.
type Request struct {
	Config   string
	Signal   string
	Pipeline string
	Sample   string
}

// ErrInput wraps problems with the request itself (as opposed to bugs).
type ErrInput struct{ msg string }

func (e *ErrInput) Error() string { return e.msg }

func bad(format string, args ...any) error { return &ErrInput{fmt.Sprintf(format, args...)} }

type config struct {
	Processors map[string]map[string]any `yaml:"processors"`
	Service    struct {
		Pipelines map[string]struct {
			Processors []string `yaml:"processors"`
		} `yaml:"pipelines"`
	} `yaml:"service"`
}

// typeOf returns the type of a component or pipeline ID: "logs" for "logs/errors".
func typeOf(id string) string {
	t, _, _ := strings.Cut(id, "/")
	return t
}

// Run previews one pipeline of a config.
func Run(req Request) (*Result, error) {
	var cfg config
	if err := yaml.Unmarshal([]byte(req.Config), &cfg); err != nil {
		return nil, bad("the config is not valid YAML: %v", err)
	}
	res := &Result{Signal: req.Signal, Exact: true}
	bySignal := map[string][]string{}
	for name := range cfg.Service.Pipelines {
		bySignal[typeOf(name)] = append(bySignal[typeOf(name)], name)
	}
	for _, s := range Signals {
		if len(bySignal[s]) > 0 {
			sort.Strings(bySignal[s])
			res.Signals = append(res.Signals, s)
		}
	}
	if len(res.Signals) == 0 {
		return nil, bad("the config has no logs, traces or metrics pipeline under service.pipelines")
	}
	if res.Signal == "" {
		res.Signal = res.Signals[0]
	}
	if !slices.Contains(Signals, res.Signal) {
		return nil, bad("signal must be logs, traces or metrics")
	}
	res.Pipelines = bySignal[res.Signal]
	if len(res.Pipelines) == 0 {
		return nil, bad("the config has no %s pipeline", res.Signal)
	}
	res.Pipeline = req.Pipeline
	if res.Pipeline == "" {
		res.Pipeline = res.Pipelines[0]
	}
	if !slices.Contains(res.Pipelines, res.Pipeline) {
		return nil, bad("the config has no pipeline named %q", res.Pipeline)
	}

	sample := req.Sample
	if strings.TrimSpace(sample) == "" {
		sample = Sample(res.Signal)
	}
	records, total, err := parse(res.Signal, sample)
	if err != nil {
		return nil, &ErrInput{err.Error()}
	}
	res.In, res.LeftOut = len(records), total-len(records)

	state := make([]Record, len(records))
	alive := make([]bool, len(records))
	for i, r := range records {
		state[i] = Record{Title: r.title, Detail: r.detail, Before: Snapshot{clone(r.resource), clone(r.attributes)}, ChangedBy: []string{}}
		alive[i] = true
	}
	for _, id := range cfg.Service.Pipelines[res.Pipeline].Processors {
		step := Step{ID: id, Component: typeOf(id)}
		settings, defined := cfg.Processors[id]
		before := make([]Snapshot, len(records))
		for i := range records {
			if alive[i] {
				step.In++
				before[i] = Snapshot{clone(records[i].resource), clone(records[i].attributes)}
			}
		}
		keep := func(int, *record) bool { return true }
		if !defined {
			step.Status, step.Note = StatusNotPreviewed, "The pipeline names this processor but the config does not define it."
		} else {
			step.Status, step.Note, keep = model(res.Signal, step.Component, settings)
		}
		for i := range records {
			if !alive[i] {
				continue
			}
			if !keep(i, &records[i]) {
				alive[i] = false
				state[i].DroppedBy = id
				step.Dropped++
				continue
			}
			step.Out++
			if !maps.Equal(before[i].Resource, records[i].resource) || !maps.Equal(before[i].Attributes, records[i].attributes) {
				step.Changed++
				state[i].ChangedBy = append(state[i].ChangedBy, id)
			}
		}
		if step.Status == StatusNotPreviewed || step.Status == StatusApproximate {
			res.Exact = false
		}
		res.Steps = append(res.Steps, step)
	}
	for i := range records {
		if alive[i] {
			res.Out++
			state[i].After = &Snapshot{records[i].resource, records[i].attributes}
		}
	}
	res.Records = state
	if res.Steps == nil {
		res.Steps = []Step{}
	}
	return res, nil
}

// decide is a processor's effect on one record: it may change the
// record's attributes, and reports whether the record is kept.
type decide = func(index int, r *record) bool

func pass(int, *record) bool { return true }

func notPreviewed(why string) (string, string, decide) {
	return StatusNotPreviewed, why + " Shown here as passing everything through unchanged, which may not be what the collector does.", pass
}

// model returns how a processor of the given type and settings behaves.
func model(signal, component string, settings map[string]any) (status, note string, fn decide) {
	switch component {
	case "batch":
		return StatusPassthrough, "Groups records into batches for sending. It does not change or drop them.", pass
	case "memory_limiter":
		return StatusPassthrough, "Refuses data only when the collector is short of memory. It does not change telemetry.", pass
	case "resource":
		return attributeActions(settings["attributes"], func(r *record) map[string]string { return r.resource }, "resource attributes")
	case "attributes":
		if settings["include"] != nil || settings["exclude"] != nil {
			return notPreviewed("This processor uses include/exclude matching, which the preview does not model.")
		}
		return attributeActions(settings["actions"], func(r *record) map[string]string { return r.attributes }, "attributes")
	case "filter":
		return filter(signal, settings)
	case "probabilistic_sampler":
		return sampler(signal, settings)
	}
	return notPreviewed(fmt.Sprintf("The preview does not model the %q processor.", component))
}

func text(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// attributeActions models the insert, update, upsert and delete actions
// shared by the resource and attributes processors.
func attributeActions(raw any, target func(*record) map[string]string, what string) (string, string, decide) {
	list, _ := raw.([]any)
	if len(list) == 0 {
		return notPreviewed("This processor has no actions the preview understands.")
	}
	type action struct {
		key, kind, value, from string
		copies                 bool
	}
	var actions []action
	for _, item := range list {
		m, _ := item.(map[string]any)
		a := action{key: text(m["key"]), kind: strings.ToLower(text(m["action"])), value: text(m["value"])}
		if a.kind == "" {
			a.kind = "insert"
		}
		if from, ok := m["from_attribute"]; ok {
			a.from, a.copies = text(from), true
		}
		supported := a.key != "" && slices.Contains([]string{"insert", "update", "upsert", "delete"}, a.kind) &&
			m["pattern"] == nil && m["from_context"] == nil && m["regex_pattern"] == nil
		if !supported {
			return notPreviewed(fmt.Sprintf("This processor uses an action the preview does not model (%s %s).", a.kind, a.key))
		}
		actions = append(actions, a)
	}
	return StatusApplied, fmt.Sprintf("Applies %d %s to the %s of every record.", len(actions), plural(len(actions), "action"), what), func(_ int, r *record) bool {
		m := target(r)
		for _, a := range actions {
			if a.kind == "delete" {
				delete(m, a.key)
				continue
			}
			value := a.value
			if a.copies {
				v, ok := m[a.from]
				if !ok {
					continue
				}
				value = v
			}
			_, exists := m[a.key]
			if a.kind == "upsert" || (a.kind == "insert" && !exists) || (a.kind == "update" && exists) {
				m[a.key] = value
			}
		}
		return true
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// filter models the filter processor's OTTL conditions for one signal: a
// record is dropped when any condition holds.
func filter(signal string, settings map[string]any) (string, string, decide) {
	section, _ := settings[signal].(map[string]any)
	if len(section) == 0 {
		return StatusPassthrough, "This filter has no conditions for " + signal + ", so it lets them all through.", pass
	}
	contexts := map[string][]string{"logs": {"log_record"}, "traces": {"span"}, "metrics": {"metric", "datapoint"}}[signal]
	type rule struct {
		context string
		cond    condition
	}
	var rules []rule
	for key, raw := range section {
		if !slices.Contains(contexts, key) {
			return notPreviewed(fmt.Sprintf("This filter uses %s.%s, which the preview does not model.", signal, key))
		}
		list, _ := raw.([]any)
		for _, item := range list {
			expr, _ := item.(string)
			cond, err := parseCondition(expr)
			if err == nil {
				// Check every field it names exists in this context, on an empty record.
				_, err = cond.eval(fieldsOf(&record{}, key))
			}
			if err != nil {
				return notPreviewed(fmt.Sprintf("This filter has a condition the preview cannot evaluate (%s).", expr))
			}
			rules = append(rules, rule{key, cond})
		}
	}
	return StatusApplied, fmt.Sprintf("Drops records matching %s of its %d %s.", map[bool]string{true: "its condition", false: "any"}[len(rules) == 1], len(rules), plural(len(rules), "condition")),
		func(_ int, r *record) bool {
			for _, rule := range rules {
				if hit, _ := rule.cond.eval(fieldsOf(r, rule.context)); hit {
					return false
				}
			}
			return true
		}
}

// sampler models the probabilistic sampler: the right share is kept, and
// records of one trace stay together, but which ones are kept is this
// preview's own choice, not the collector's.
func sampler(signal string, settings map[string]any) (string, string, decide) {
	pct, ok := settings["sampling_percentage"].(float64)
	if n, isInt := settings["sampling_percentage"].(int); isInt {
		pct, ok = float64(n), true
	}
	if !ok || signal == "metrics" {
		return notPreviewed("The preview cannot tell what share this sampler keeps.")
	}
	pct = min(100, max(0, pct))
	note := fmt.Sprintf("Keeps about %s%% of %s, whole traces together. Which ones are kept below is only an illustration: the collector makes its own choice, and a small sample rarely lands on the exact share.",
		strconv.FormatFloat(pct, 'g', -1, 64), signal)
	return StatusApproximate, note, func(i int, r *record) bool {
		key := r.traceID
		if key == "" {
			key = "record-" + strconv.Itoa(i)
		}
		h := fnv.New32a()
		h.Write([]byte(key))
		return float64(h.Sum32()%10000) < pct*100
	}
}

// IsInput reports whether err is a problem with the request.
func IsInput(err error) bool {
	var e *ErrInput
	return errors.As(err, &e)
}
