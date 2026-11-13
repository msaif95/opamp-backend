package k8sbridge

import (
	"bytes"
	"strings"
	"testing"
)

const web = `apiVersion: opentelemetry.io/v1beta1
kind: OpenTelemetryCollector
metadata:
  name: web
  namespace: apps
  resourceVersion: "123"
  labels:
    opentelemetry.io/opamp-managed: "true"
spec:
  mode: deployment
  replicas: 2
  config:
    receivers: {otlp: {protocols: {grpc: {}}}}
    exporters: {debug: {}}
    service: {pipelines: {traces: {receivers: [otlp], exporters: [debug]}}}
status:
  version: 0.162.0
`

var (
	other    = strings.NewReplacer("name: web", "name: other").Replace(web)
	readOnly = strings.NewReplacer("name: web", "name: watch", "opamp-managed", "opamp-reporting").Replace(web)
	files    = map[string]string{"apps/web": web, "apps/other": other, "apps/watch": readOnly}
)

func TestCollectors(t *testing.T) {
	got := Collectors(files, []byte(`{"healthy":true,"component_health_map":{"apps/web":{"healthy":false,"component_health_map":{"apps/web-collector-1":{"healthy":false,"status":"Pending"}}}}}`))
	if len(got) != 3 || got[1].Key != "apps/watch" || got[1].Managed || !got[2].Managed {
		t.Fatalf("collectors = %+v", got)
	}
	w := got[2]
	if w.Mode != "deployment" || w.Replicas == nil || *w.Replicas != 2 || w.Healthy == nil || *w.Healthy || len(w.Pods) != 1 || w.Pods[0].Status != "Pending" {
		t.Fatalf("web = %+v", w)
	}
	if !strings.Contains(w.Config, "receivers:") || got[0].Healthy != nil {
		t.Fatalf("config %q, other health %v", w.Config, got[0].Healthy)
	}
}

func TestDesired(t *testing.T) {
	// Nothing assigned: the bridge is left alone.
	if out, hash, err := Desired(files, nil); out != nil || hash != nil || err != nil {
		t.Fatalf("unconfigured bridge got %v", out)
	}
	// An assignment to a collector the bridge no longer reports does not count either.
	if out, _, _ := Desired(files, map[string]string{"apps/gone": "receivers: {}"}); out != nil {
		t.Fatalf("stale assignment produced %v", out)
	}
	newConfig := "receivers:\n  otlp:\n    protocols:\n      http: {}\nexporters:\n  debug: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [debug]\n"
	out, hash, err := Desired(files, map[string]string{"apps/web": newConfig})
	if err != nil {
		t.Fatal(err)
	}
	// Every managed collector is sent (the bridge deletes missing ones); the read-only one never is.
	if len(out) != 2 || out["apps/other"] == nil || out["apps/watch"] != nil {
		t.Fatalf("files sent: %v", len(out))
	}
	sent := string(out["apps/web"])
	if !strings.Contains(sent, "http: {}") || strings.Contains(sent, "grpc") || !strings.Contains(sent, "replicas: 2") ||
		strings.Contains(sent, "resourceVersion") || strings.Contains(sent, "status:") || !strings.Contains(sent, ManagedLabel) {
		t.Fatalf("web as sent:\n%s", sent)
	}
	// The untouched collector goes back with the config it reported.
	if untouched := string(out["apps/other"]); !strings.Contains(untouched, "grpc") {
		t.Fatalf("other as sent:\n%s", untouched)
	}
	// Once the bridge applies it and reports the new config, the result is unchanged: no push loop.
	applied := map[string]string{"apps/web": sent, "apps/other": other, "apps/watch": readOnly}
	if _, again, _ := Desired(applied, map[string]string{"apps/web": newConfig}); !bytes.Equal(hash, again) {
		t.Fatal("hash changed after the bridge applied the config")
	}
	// The operator adds defaults to what it is given; the collector still counts as running the assigned config.
	running := "exporters: {debug: {}}\nreceivers: {otlp: {protocols: {http: {}}}}\nservice: {telemetry: {metrics: {level: basic}}, pipelines: {logs: {exporters: [debug], receivers: [otlp]}}}\n"
	if !SameConfig(running, newConfig) {
		t.Fatal("running config with operator defaults not recognised as the assigned one")
	}
	if SameConfig(strings.Replace(running, "http", "grpc", 1), newConfig) || SameConfig(strings.Replace(running, "[debug]", "[debug, otlp]", 1), newConfig) {
		t.Fatal("a different running config was accepted")
	}
}
