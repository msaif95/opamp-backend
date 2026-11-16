package preview_test

import (
	"strings"
	"testing"

	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/preview"
)

const base = `
receivers:
  otlp:
exporters:
  debug:
`

func run(t *testing.T, cfg, signal, sample string) *preview.Result {
	t.Helper()
	res, err := preview.Run(preview.Request{Config: base + cfg, Signal: signal, Sample: sample})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func step(t *testing.T, res *preview.Result, id string) preview.Step {
	t.Helper()
	for _, s := range res.Steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no step %q in %+v", id, res.Steps)
	return preview.Step{}
}

func titles(res *preview.Result, kept bool) []string {
	var out []string
	for _, r := range res.Records {
		if (r.After != nil) == kept {
			out = append(out, r.Title)
		}
	}
	return out
}

func TestAttributeProcessors(t *testing.T) {
	res := run(t, `
processors:
  resource:
    attributes:
      - {key: team, value: payments, action: upsert}
      - {key: deployment.environment, value: live, action: update}
      - {key: host.name, action: delete}
      - {key: service, from_attribute: service.name, action: insert}
      - {key: missing.copy, from_attribute: nope, action: insert}
  attributes:
    actions:
      - {key: user.email, action: delete}
      - {key: http.route, value: redacted, action: update}
      - {key: seen, value: 1, action: insert}
service:
  pipelines:
    logs: {receivers: [otlp], processors: [resource, attributes], exporters: [debug]}
`, "logs", "")
	if !res.Exact || res.In != 8 || res.Out != 8 || res.Signal != "logs" || res.Pipeline != "logs" {
		t.Fatalf("result = %+v", res)
	}
	if s := step(t, res, "resource"); s.Status != preview.StatusApplied || s.Changed != 8 || s.Dropped != 0 {
		t.Errorf("resource step = %+v", s)
	}
	if s := step(t, res, "attributes"); s.Changed != 8 {
		t.Errorf("attributes step = %+v", s)
	}
	// "order placed": the second built-in log record.
	r := res.Records[1]
	a := r.After
	if a.Resource["team"] != "payments" || a.Resource["deployment.environment"] != "live" || a.Resource["service"] != "checkout" {
		t.Errorf("resource after = %v", a.Resource)
	}
	if _, has := a.Resource["host.name"]; has {
		t.Error("host.name not deleted")
	}
	if _, has := a.Resource["missing.copy"]; has {
		t.Error("copy from a missing attribute created a value")
	}
	if _, has := a.Attributes["user.email"]; has || a.Attributes["http.route"] != "redacted" || a.Attributes["seen"] != "1" || a.Attributes["order.id"] != "A-10293" {
		t.Errorf("attributes after = %v", a.Attributes)
	}
	// "update" does not create: a record with no http.route gets none.
	if _, has := res.Records[0].After.Attributes["http.route"]; has {
		t.Error("update created http.route")
	}
	// The record as it came in is kept for comparison.
	if r.Before.Resource["host.name"] != "checkout-7d9f" || r.Before.Attributes["user.email"] != "ana@example.com" || len(r.ChangedBy) != 2 {
		t.Errorf("before = %+v, changed by %v", r.Before, r.ChangedBy)
	}
}

func TestFilter(t *testing.T) {
	res := run(t, `
processors:
  filter:
    error_mode: ignore
    logs:
      log_record:
        - severity_number != SEVERITY_NUMBER_UNSPECIFIED and severity_number < SEVERITY_NUMBER_WARN
        - attributes["shard"] == "products-3" or resource.attributes["service.name"] == "nope"
service:
  pipelines:
    logs: {receivers: [otlp], processors: [filter], exporters: [debug]}
`, "logs", "")
	want := []string{"payment provider slow: 2.4s", "payment declined", "plain line with no severity"}
	if got := titles(res, true); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("kept %v, want %v", got, want)
	}
	if s := step(t, res, "filter"); s.Status != preview.StatusApplied || s.In != 8 || s.Out != 3 || s.Dropped != 5 {
		t.Errorf("filter step = %+v", s)
	}
	if res.Records[0].DroppedBy != "filter" || res.Records[0].After != nil || !res.Exact {
		t.Errorf("dropped record = %+v", res.Records[0])
	}

	// Numbers in attributes compare as numbers; spans and metrics have their own fields.
	res = run(t, `
processors:
  filter:
    traces:
      span:
        - attributes["http.status_code"] < 400 and name != "charge card"
    metrics:
      metric:
        - name == "process.memory.usage"
      datapoint:
        - metric.name == "http.server.request.count" and attributes["http.status_code"] >= 400
service:
  pipelines:
    traces: {receivers: [otlp], processors: [filter], exporters: [debug]}
    metrics: {receivers: [otlp], processors: [filter], exporters: [debug]}
`, "traces", "")
	// Spans with no status code are kept: a missing attribute is not less than anything.
	if got := titles(res, true); strings.Join(got, "|") != "charge card|POST /checkout|query index|GET /search" {
		t.Errorf("spans kept = %v", got)
	}
	if strings.Join(res.Signals, ",") != "traces,metrics" {
		t.Errorf("signals = %v", res.Signals)
	}
	res = run(t, `
processors:
  filter:
    metrics:
      metric:
        - name == "process.memory.usage"
      datapoint:
        - metric.name == "http.server.request.count" and attributes["http.status_code"] >= 400
service:
  pipelines:
    metrics: {receivers: [otlp], processors: [filter], exporters: [debug]}
`, "", "")
	if res.Signal != "metrics" || res.In != 5 || res.Out != 3 {
		t.Errorf("metrics: %d in, %d out, kept %v", res.In, res.Out, titles(res, true))
	}
}

func TestWhatIsNotModelledIsSaidSo(t *testing.T) {
	res := run(t, `
processors:
  batch: {}
  memory_limiter: {limit_mib: 512}
  transform:
    log_statements: [{context: log, statements: ['set(body, "x")']}]
  filter:
    logs:
      log_record: ['IsMatch(body, ".*slow.*")']
  filter/old:
    logs:
      include: {match_type: strict, bodies: [x]}
  attributes:
    actions: [{key: user.email, action: hash}]
  attributes/scoped:
    include: {match_type: strict, services: [checkout]}
    actions: [{key: a, value: b, action: insert}]
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, transform, filter, filter/old, attributes, attributes/scoped, undefined, batch]
      exporters: [debug]
`, "logs", "")
	for id, want := range map[string]string{
		"memory_limiter": preview.StatusPassthrough, "batch": preview.StatusPassthrough, "transform": preview.StatusNotPreviewed,
		"filter": preview.StatusNotPreviewed, "filter/old": preview.StatusNotPreviewed, "attributes": preview.StatusNotPreviewed,
		"attributes/scoped": preview.StatusNotPreviewed, "undefined": preview.StatusNotPreviewed,
	} {
		if s := step(t, res, id); s.Status != want || s.Note == "" || s.Out != 8 || s.Changed != 0 {
			t.Errorf("%s = %+v, want %s and nothing touched", id, s, want)
		}
	}
	if res.Exact {
		t.Error("a preview with unmodelled processors claims to be exact")
	}
	if len(res.Steps) != 8 || res.Steps[0].ID != "memory_limiter" || res.Steps[7].ID != "batch" {
		t.Errorf("steps out of order: %+v", res.Steps)
	}
}

func TestSampler(t *testing.T) {
	cfg := func(pct string) string {
		return `
processors:
  probabilistic_sampler: {sampling_percentage: ` + pct + `}
service:
  pipelines:
    traces: {receivers: [otlp], processors: [probabilistic_sampler], exporters: [debug]}
`
	}
	if res := run(t, cfg("100"), "traces", ""); res.Out != res.In || res.Exact {
		t.Errorf("100%%: %d of %d kept, exact=%v", res.Out, res.In, res.Exact)
	}
	if res := run(t, cfg("0"), "traces", ""); res.Out != 0 {
		t.Errorf("0%%: %d kept", res.Out)
	}
	// Spans of one trace are kept or dropped together.
	res := run(t, cfg("50"), "traces", "")
	if s := step(t, res, "probabilistic_sampler"); s.Status != preview.StatusApproximate {
		t.Errorf("step = %+v", s)
	}
	kept := func(i int) bool { return res.Records[i].After != nil }
	if kept(0) != kept(1) || kept(4) != kept(5) {
		t.Error("a trace was split by the sampler")
	}
}

func TestOwnSampleAndPipelineChoice(t *testing.T) {
	own := `{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"mine"}}]},
	  "scopeLogs":[{"logRecords":[
	    {"severityNumber":"SEVERITY_NUMBER_ERROR","body":{"stringValue":"boom"},"attributes":[{"key":"n","value":{"intValue":"7"}},{"key":"ok","value":{"boolValue":false}}]},
	    {"severityNumber":9,"body":{"stringValue":"fine"}}]}]}]}`
	cfg := `
processors:
  filter:
    logs:
      log_record: ['severity_number >= SEVERITY_NUMBER_ERROR']
service:
  pipelines:
    logs: {receivers: [otlp], exporters: [debug]}
    logs/errors: {receivers: [otlp], processors: [filter], exporters: [debug]}
`
	res := run(t, cfg, "logs", own)
	if res.Pipeline != "logs" || len(res.Steps) != 0 || res.Out != 2 || strings.Join(res.Pipelines, ",") != "logs,logs/errors" {
		t.Errorf("default pipeline: %+v", res)
	}
	if r := res.Records[0]; r.Detail != "ERROR" || r.Before.Attributes["n"] != "7" || r.Before.Attributes["ok"] != "false" || r.Before.Resource["service.name"] != "mine" {
		t.Errorf("own record = %+v", r)
	}
	res, err := preview.Run(preview.Request{Config: base + cfg, Signal: "logs", Pipeline: "logs/errors", Sample: own})
	if err != nil || res.Out != 1 || titles(res, true)[0] != "fine" {
		t.Errorf("named pipeline: %+v, %v", res, err)
	}

	for name, req := range map[string]preview.Request{
		"not yaml":             {Config: "a: [", Signal: "logs"},
		"no pipelines":         {Config: base},
		"no such signal":       {Config: base + cfg, Signal: "traces"},
		"unknown signal":       {Config: base + cfg, Signal: "profiles"},
		"no such pipeline":     {Config: base + cfg, Signal: "logs", Pipeline: "logs/nope"},
		"sample not json":      {Config: base + cfg, Signal: "logs", Sample: "{"},
		"sample of wrong kind": {Config: base + cfg, Signal: "logs", Sample: preview.Sample("traces")},
	} {
		if _, err := preview.Run(req); !preview.IsInput(err) {
			t.Errorf("%s: err = %v, want an input error", name, err)
		}
	}
}

// Every processor the config builder offers must be modelled: a builder
// user should never see "not previewed".
func TestEveryBuilderProcessorIsModelled(t *testing.T) {
	spec := pipeline.Spec{
		Sources: []pipeline.Component{{Type: "otlp"}},
		Processors: []pipeline.Component{
			{Type: "memory_limiter"},
			{Type: "add_resource_attributes", Params: map[string]any{"attributes": map[string]any{"team": "payments"}}},
			{Type: "remove_attributes", Params: map[string]any{"keys": []any{"user.email"}}},
			{Type: "drop_low_severity_logs", Params: map[string]any{"min_severity": "WARN"}},
			{Type: "sample", Params: map[string]any{"percentage": 50.0}},
			{Type: "batch"},
		},
		Destinations: []pipeline.Component{{Type: "debug"}},
	}
	body, issues := pipeline.Render(spec)
	if body == "" {
		t.Fatalf("render: %v", issues)
	}
	offered := 0
	for _, typ := range pipeline.Catalog() {
		if typ.Kind == pipeline.KindProcessor {
			offered++
		}
	}
	if offered != len(spec.Processors) {
		t.Fatalf("the builder offers %d processors but this test covers %d: add the new one here and to the preview", offered, len(spec.Processors))
	}
	for _, signal := range preview.Signals {
		res, err := preview.Run(preview.Request{Config: body, Signal: signal})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range res.Steps {
			if s.Status == preview.StatusNotPreviewed {
				t.Errorf("%s: builder processor %s is not previewed: %s", signal, s.ID, s.Note)
			}
		}
		if signal == "logs" {
			// WARN and above plus the record with no severity survive the filter; the sampler then takes its share.
			if s := step(t, res, "filter"); s.Out != 4 || s.Dropped != 4 {
				t.Errorf("logs filter step = %+v", s)
			}
			for _, r := range res.Records {
				if r.After != nil && (r.After.Resource["team"] != "payments" || r.After.Attributes["user.email"] != "") {
					t.Errorf("record after = %+v", r.After)
				}
			}
		}
	}
}
