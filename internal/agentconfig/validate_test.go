package agentconfig

import (
	"strings"
	"testing"
)

const validConfig = `
receivers:
  otlp:
    protocols:
      grpc:
processors:
  batch:
connectors:
  spanmetrics:
exporters:
  debug:
extensions:
  health_check:
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug, spanmetrics]
    metrics:
      receivers: [spanmetrics]
      exporters: [debug]
`

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		body      string
		wantError string // substring of an expected error; "" means no errors
		wantWarn  string
	}{
		"valid, connectors on both sides": {body: validConfig},
		"empty":                           {body: "  \n", wantError: "empty"},
		"bad yaml":                        {body: "receivers: [", wantError: "invalid YAML"},
		"scalar root":                     {body: "just a string", wantError: "invalid YAML"},
		"undefined exporter": {
			body:      strings.Replace(validConfig, "exporters: [debug]", "exporters: [otlphttp]", 1),
			wantError: `exporter "otlphttp" is not defined`,
		},
		"undefined processor": {
			body:      strings.Replace(validConfig, "processors: [batch]", "processors: [memory_limiter]", 1),
			wantError: `processor "memory_limiter" is not defined`,
		},
		"undefined extension": {
			body:      strings.Replace(validConfig, "extensions: [health_check]", "extensions: [pprof]", 1),
			wantError: `extension "pprof" is not defined`,
		},
		"pipeline without receivers": {
			body:      strings.Replace(validConfig, "      receivers: [otlp]\n", "", 1),
			wantError: "at least one receiver",
		},
		"section not a mapping": {
			body:      strings.Replace(validConfig, "processors:\n  batch:", "processors: [batch]", 1),
			wantError: `"processors" must be a mapping`,
		},
		"unknown section":    {body: validConfig + "\nrecievers: {}\n", wantWarn: `unknown top-level section "recievers"`},
		"no service section": {body: "receivers:\n  otlp:\n", wantWarn: "no service section"},
	} {
		issues := Validate(tc.body, nil)
		if got := find(issues, SeverityError, tc.wantError); !got {
			t.Errorf("%s: want error containing %q, got %+v", name, tc.wantError, issues)
		}
		if tc.wantWarn != "" && !find(issues, SeverityWarning, tc.wantWarn) {
			t.Errorf("%s: want warning containing %q, got %+v", name, tc.wantWarn, issues)
		}
	}
}

// find reports whether issues contain a matching one; with want == "" it
// reports whether there are no issues of that severity at all.
func find(issues []Issue, severity, want string) bool {
	for _, i := range issues {
		if i.Severity != severity {
			continue
		}
		if want == "" {
			return false
		}
		if strings.Contains(i.Message, want) {
			return true
		}
	}
	return want == ""
}
