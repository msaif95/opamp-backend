package agentconfig

import (
	"strings"
	"testing"
)

func testPolicy() *ComponentPolicy {
	return &ComponentPolicy{
		Receivers:  map[string]bool{"otlp": true, "hostmetrics": true},
		Processors: map[string]bool{"batch": true, "memory_limiter": true},
		Exporters:  map[string]bool{"otlp": true, "debug": true},
		Extensions: map[string]bool{"health_check": true},
		Blocked:    map[string]bool{"exec": true, "script": true},
	}
}

func TestComponentPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		body      string
		policy    *ComponentPolicy
		wantError string
	}{
		"allowed components pass": {
			body: `
receivers:
  otlp:
processors:
  batch:
exporters:
  debug:
extensions:
  health_check:
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
`,
			policy: testPolicy(),
		},
		"nil policy skips check": {
			body: `
receivers:
  exec:
exporters:
  debug:
service:
  pipelines:
    logs:
      receivers: [exec]
      exporters: [debug]
`,
			policy: nil,
		},
		"blocked receiver": {
			body: `
receivers:
  exec:
exporters:
  debug:
service:
  pipelines:
    logs:
      receivers: [exec]
      exporters: [debug]
`,
			policy:    testPolicy(),
			wantError: "blocked for security reasons",
		},
		"blocked script processor": {
			body: `
receivers:
  otlp:
processors:
  script:
exporters:
  debug:
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [script]
      exporters: [debug]
`,
			policy:    testPolicy(),
			wantError: "blocked for security reasons",
		},
		"unknown receiver type": {
			body: `
receivers:
  kafka:
exporters:
  debug:
service:
  pipelines:
    logs:
      receivers: [kafka]
      exporters: [debug]
`,
			policy:    testPolicy(),
			wantError: `receiver type "kafka" is not in the allowed`,
		},
		"unknown exporter type": {
			body: `
receivers:
  otlp:
exporters:
  elasticsearch:
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [elasticsearch]
`,
			policy:    testPolicy(),
			wantError: `exporter type "elasticsearch" is not in the allowed`,
		},
		"unknown extension": {
			body: `
receivers:
  otlp:
exporters:
  debug:
extensions:
  pprof:
service:
  extensions: [pprof]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
`,
			policy:    testPolicy(),
			wantError: `extension type "pprof" is not in the allowed`,
		},
		"instance suffix stripped": {
			body: `
receivers:
  otlp/grpc:
  otlp/http:
exporters:
  debug:
service:
  pipelines:
    logs:
      receivers: [otlp/grpc, otlp/http]
      exporters: [debug]
`,
			policy: testPolicy(),
		},
		"connector checked against receivers and exporters": {
			body: `
receivers:
  otlp:
connectors:
  otlp:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp]
    metrics:
      receivers: [otlp]
      exporters: [debug]
`,
			policy: testPolicy(),
		},
		"unknown connector rejected": {
			body: `
receivers:
  otlp:
connectors:
  spanmetrics:
exporters:
  debug:
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [spanmetrics]
    metrics:
      receivers: [spanmetrics]
      exporters: [debug]
`,
			policy:    testPolicy(),
			wantError: `connector type "spanmetrics" is not in the allowed`,
		},
		"allowed when added to policy": {
			body: `
receivers:
  kafka:
exporters:
  debug:
service:
  pipelines:
    logs:
      receivers: [kafka]
      exporters: [debug]
`,
			policy: &ComponentPolicy{
				Receivers:  map[string]bool{"otlp": true, "kafka": true},
				Processors: map[string]bool{},
				Exporters:  map[string]bool{"debug": true},
				Extensions: map[string]bool{},
				Blocked:    map[string]bool{"exec": true},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			issues := Validate(tc.body, tc.policy)
			hasErr := false
			for _, i := range issues {
				if i.Severity == SeverityError && tc.wantError != "" && strings.Contains(i.Message, tc.wantError) {
					hasErr = true
				}
			}
			if tc.wantError != "" && !hasErr {
				t.Errorf("want error containing %q, got %+v", tc.wantError, issues)
			}
			if tc.wantError == "" && HasErrors(issues) {
				t.Errorf("want no errors, got %+v", issues)
			}
		})
	}
}

func TestComponentType(t *testing.T) {
	for input, want := range map[string]string{
		"otlp":      "otlp",
		"otlp/grpc": "otlp",
		"batch/1":   "batch",
		"a/b/c":     "a",
	} {
		if got := componentType(input); got != want {
			t.Errorf("componentType(%q) = %q, want %q", input, got, want)
		}
	}
}
