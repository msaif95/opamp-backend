package pipeline

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
)

func c(typ string, kv ...any) Component {
	p := map[string]any{}
	for i := 0; i < len(kv); i += 2 {
		p[kv[i].(string)] = kv[i+1]
	}
	return Component{Type: typ, Params: p}
}

func mustRender(t *testing.T, spec Spec) (map[string]any, []agentconfig.Issue) {
	t.Helper()
	body, issues := Render(spec)
	if agentconfig.HasErrors(issues) {
		t.Fatalf("render failed: %+v", issues)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("output is not YAML: %v\n%s", err, body)
	}
	return doc, issues
}

func pipeline(doc map[string]any, signal string) map[string]any {
	p, _ := doc["service"].(map[string]any)["pipelines"].(map[string]any)[signal].(map[string]any)
	return p
}

func TestRenderRoutesBySignal(t *testing.T) {
	doc, issues := mustRender(t, Spec{
		Sources: []Component{c("otlp"), c("host_metrics"), c("file_logs", "include", []any{"/var/log/*.log"})},
		Processors: []Component{
			c("memory_limiter"), c("drop_low_severity_logs", "min_severity", "WARN"),
			c("add_resource_attributes", "attributes", map[string]any{"env": "prod"}), c("batch"),
		},
		Destinations: []Component{
			c("otlp_grpc", "endpoint", "gw:4317"),
			c("prometheus_remote_write", "endpoint", "https://prom/api/v1/write"),
		},
	})
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
	logs, metrics, traces := pipeline(doc, "logs"), pipeline(doc, "metrics"), pipeline(doc, "traces")
	join := func(v any) string {
		var out []string
		for _, x := range v.([]any) {
			out = append(out, x.(string))
		}
		return strings.Join(out, ",")
	}
	// Logs: OTLP and files in; the severity filter applies; remote write is metrics-only so it is not an exporter.
	if join(logs["receivers"]) != "otlp,filelog" || join(logs["processors"]) != "memory_limiter,filter,resource,batch" || join(logs["exporters"]) != "otlp" {
		t.Errorf("logs pipeline = %v", logs)
	}
	// Metrics: host metrics in, no log filter, both destinations.
	if join(metrics["receivers"]) != "otlp,hostmetrics" || join(metrics["processors"]) != "memory_limiter,resource,batch" || join(metrics["exporters"]) != "otlp,prometheusremotewrite" {
		t.Errorf("metrics pipeline = %v", metrics)
	}
	if join(traces["receivers"]) != "otlp" || join(traces["exporters"]) != "otlp" {
		t.Errorf("traces pipeline = %v", traces)
	}
	filter := doc["processors"].(map[string]any)["filter"].(map[string]any)["logs"].(map[string]any)["log_record"].([]any)[0].(string)
	if !strings.Contains(filter, "severity_number < SEVERITY_NUMBER_WARN") || !strings.Contains(filter, "UNSPECIFIED") {
		t.Errorf("filter condition = %q", filter)
	}
}

func TestRenderNumbersRepeatedComponentsAndDropsUnused(t *testing.T) {
	doc, issues := mustRender(t, Spec{
		Sources:      []Component{c("host_metrics"), c("file_logs", "include", []any{"/x.log"})},
		Destinations: []Component{c("otlp_grpc", "endpoint", "a:4317"), c("otlp_grpc", "endpoint", "b:4317", "insecure", true), c("prometheus_remote_write", "endpoint", "https://p")},
		Processors:   []Component{c("sample", "percentage", float64(25))}, // logs and traces only
	})
	exporters := doc["exporters"].(map[string]any)
	if _, ok := exporters["otlp/2"]; !ok || exporters["otlp/2"].(map[string]any)["tls"].(map[string]any)["insecure"] != true {
		t.Errorf("second OTLP destination not rendered as otlp/2: %v", exporters)
	}
	if got := pipeline(doc, "metrics")["processors"]; got != nil {
		t.Errorf("sampler applied to metrics: %v", got)
	}
	if pipeline(doc, "logs")["processors"].([]any)[0] != "probabilistic_sampler" {
		t.Error("sampler not applied to logs")
	}
	if len(issues) != 0 {
		t.Errorf("issues = %+v", issues)
	}

	// A logs source with a metrics-only destination next to a working metrics path: the file source is unused.
	doc, issues = mustRender(t, Spec{
		Sources:      []Component{c("host_metrics"), c("file_logs", "include", []any{"/x.log"})},
		Destinations: []Component{c("prometheus_remote_write", "endpoint", "https://p")},
	})
	if _, ok := doc["receivers"].(map[string]any)["filelog"]; ok {
		t.Error("unused source left in the config")
	}
	if len(issues) != 1 || issues[0].Severity != agentconfig.SeverityWarning || !strings.Contains(issues[0].Message, "Log files is not used") {
		t.Errorf("issues = %+v", issues)
	}
}

func TestRenderRejects(t *testing.T) {
	for name, tc := range map[string]struct {
		spec Spec
		want string
	}{
		"empty":            {Spec{}, "add at least one source"},
		"no destination":   {Spec{Sources: []Component{c("otlp")}}, "add at least one destination"},
		"unknown type":     {Spec{Sources: []Component{c("nope")}, Destinations: []Component{c("debug")}}, `unknown source type "nope"`},
		"missing required": {Spec{Sources: []Component{c("otlp")}, Destinations: []Component{c("otlp_grpc")}}, "Endpoint: is required"},
		"bad enum":         {Spec{Sources: []Component{c("otlp")}, Destinations: []Component{c("debug", "verbosity", "loud")}}, "must be one of"},
		"bad multi":        {Spec{Sources: []Component{c("host_metrics", "scrapers", []any{"gpu"})}, Destinations: []Component{c("debug")}}, `"gpu" is not one of`},
		"wrong type":       {Spec{Sources: []Component{c("otlp")}, Processors: []Component{c("batch", "send_batch_size", "many")}, Destinations: []Component{c("debug")}}, "must be a number"},
		"fraction for int": {Spec{Sources: []Component{c("otlp")}, Processors: []Component{c("batch", "send_batch_size", 1.5)}, Destinations: []Component{c("debug")}}, "whole number"},
		"nothing flows":    {Spec{Sources: []Component{c("file_logs", "include", []any{"/x"})}, Destinations: []Component{c("prometheus_remote_write", "endpoint", "https://p")}}, "nothing would flow"},
		"empty list":       {Spec{Sources: []Component{c("file_logs")}, Destinations: []Component{c("debug")}}, "needs at least one value"},
	} {
		body, issues := Render(tc.spec)
		found := false
		for _, i := range issues {
			found = found || (i.Severity == agentconfig.SeverityError && strings.Contains(i.Message, tc.want))
		}
		if !found || body != "" {
			t.Errorf("%s: want error containing %q and no body; got %+v, body %d bytes", name, tc.want, issues, len(body))
		}
	}
}

// Every catalog type must render with only its required fields filled in, and be reachable in some pipeline.
func TestEveryCatalogTypeRenders(t *testing.T) {
	fill := func(tp Type) Component {
		comp := Component{Type: tp.Type, Params: map[string]any{}}
		for _, f := range tp.Fields {
			if !f.Required || f.Default != nil {
				continue
			}
			switch f.Type {
			case FieldList:
				comp.Params[f.Key] = []any{"value"}
			case FieldMap:
				comp.Params[f.Key] = map[string]any{"key": "value"}
			default:
				comp.Params[f.Key] = "value"
			}
		}
		return comp
	}
	for _, tp := range Catalog() {
		spec := Spec{Sources: []Component{c("otlp")}, Destinations: []Component{c("debug")}}
		switch tp.Kind {
		case KindSource:
			spec.Sources = []Component{fill(tp)}
		case KindProcessor:
			spec.Processors = []Component{fill(tp)}
		case KindDestination:
			spec.Destinations = []Component{fill(tp)}
		}
		if _, issues := Render(spec); len(issues) != 0 {
			t.Errorf("%s %s: %+v", tp.Kind, tp.Type, issues)
		}
		if tp.Label == "" || tp.Description == "" || len(tp.Signals) == 0 {
			t.Errorf("%s %s: missing label, description or signals", tp.Kind, tp.Type)
		}
	}
}
