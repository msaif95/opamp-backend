package agentconfig

import (
	"strings"
	"testing"
)

const mergeBase = `# shared by every environment
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    timeout: 5s # keep small
  memory_limiter:
    limit_mib: 512
exporters:
  otlp:
    endpoint: gateway.example.com:4317
    headers:
      x-team: platform
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [otlp]
`

func TestMerge(t *testing.T) {
	got, err := Merge(mergeBase, `
# production differences
processors:
  batch:
    timeout: 10s
  memory_limiter: ~
  resource:
    attributes:
      - {key: env, value: prod, action: upsert}
exporters:
  otlp:
    endpoint: prod-gateway.example.com:4317
    headers:
      x-env: prod
service:
  pipelines:
    logs:
      processors: [resource, batch]
`)
	if err != nil {
		t.Fatal(err)
	}
	want := `# shared by every environment
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    timeout: 10s
  resource:
    attributes:
      - {key: env, value: prod, action: upsert}
exporters:
  otlp:
    endpoint: prod-gateway.example.com:4317
    headers:
      x-team: platform
      x-env: prod
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [resource, batch]
      exporters: [otlp]
`
	if got != want {
		t.Errorf("merged:\n%s\nwant:\n%s", got, want)
	}
	if issues := Validate(got); HasErrors(issues) {
		t.Errorf("merged config does not validate: %v", issues)
	}
}

func TestMergeEdges(t *testing.T) {
	// No overrides (or only comments) leaves the base exactly as written.
	for _, none := range []string{"", "  \n", "# nothing yet\n", "~"} {
		if got, err := Merge(mergeBase, none); err != nil || got != mergeBase {
			t.Errorf("overrides %q changed the base (err %v)", none, err)
		}
	}
	// A value replaces a mapping and the other way round; removing a missing key is not an error.
	got, err := Merge("a:\n  b: 1\nc: 2\n", "a: off\nc:\n  d: 3\nnope: ~\n")
	if err != nil || got != "a: off\nc:\n  d: 3\n" {
		t.Errorf("replace across kinds = %q, %v", got, err)
	}
	// An empty component is written {} in overrides, since null means remove.
	got, _ = Merge("receivers:\n  otlp:\n", "receivers:\n  zipkin: {}\n")
	if got != "receivers:\n  otlp:\n  zipkin: {}\n" {
		t.Errorf("adding an empty component = %q", got)
	}
	for name, bad := range map[string][2]string{
		"overrides not yaml": {mergeBase, "a: ["},
		"overrides a list":   {mergeBase, "- a\n- b\n"},
		"overrides a value":  {mergeBase, "just text"},
		"base not a mapping": {"- a\n", "a: 1"},
	} {
		if _, err := Merge(bad[0], bad[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDerivedHeader(t *testing.T) {
	once := withHeader("base", "a: 1\n")
	if !strings.HasPrefix(once, `# Derived from the base config "base" plus overrides.`) || !strings.HasSuffix(once, "\na: 1\n") {
		t.Errorf("header = %q", once)
	}
	if again := withHeader("base", once); again != once {
		t.Errorf("header added twice:\n%s", again)
	}
}
