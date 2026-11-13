// Package k8sbridge understands what an OpenTelemetry Operator OpAMP Bridge
// reports and what it expects back. A bridge is one OpAMP agent standing in
// for every OpenTelemetryCollector resource it watches in a cluster: it
// reports each as a named file ("namespace/name" -> the resource as YAML)
// and accepts the same shape as remote config.
package k8sbridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"go.yaml.in/yaml/v3"
)

const (
	// ModeAttribute is reported by every bridge; its presence identifies one.
	ModeAttribute = "opentelemetry.io/opamp.bridge.mode"
	// ManagedLabel marks a collector the bridge may change. Collectors with
	// only the reporting label are visible but read-only.
	ManagedLabel = "opentelemetry.io/opamp-managed"
)

// Pod is one pod of a collector.
type Pod struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Status  string `json:"status"`
}

// Collector is one OpenTelemetryCollector resource seen through a bridge.
type Collector struct {
	// Key is "namespace/name", the name the bridge knows it by.
	Key       string `json:"key"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Managed collectors can be given a config; others are reported only.
	Managed bool `json:"managed"`
	// Mode is deployment, daemonset, statefulset or sidecar.
	Mode     string `json:"mode"`
	Replicas *int   `json:"replicas"`
	Image    string `json:"image,omitempty"`
	// Healthy is nil when the bridge has not reported the collector's health.
	Healthy *bool `json:"healthy"`
	Pods    []Pod `json:"pods"`
	// Config is the collector's pipeline config (spec.config) as YAML.
	Config string `json:"config"`
}

type resource struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name      string            `yaml:"name"`
		Namespace string            `yaml:"namespace"`
		Labels    map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec map[string]any `yaml:"spec"`
}

// health mirrors the JSON form of the OpAMP ComponentHealth message.
type health struct {
	Healthy  bool              `json:"healthy"`
	Status   string            `json:"status"`
	Children map[string]health `json:"component_health_map"`
}

func marshal(v any) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(v)
	return buf.String()
}

func managed(labels map[string]string) bool {
	_, ok := labels[ManagedLabel]
	return ok
}

// Collectors lists the collectors a bridge reports, by key. files is the
// bridge's effective config (key -> resource YAML) and healthJSON its
// reported health.
func Collectors(files map[string]string, healthJSON []byte) []Collector {
	var root health
	_ = json.Unmarshal(healthJSON, &root)
	out := make([]Collector, 0, len(files))
	for key, body := range files {
		var r resource
		if yaml.Unmarshal([]byte(body), &r) != nil || r.Kind != "OpenTelemetryCollector" {
			continue
		}
		c := Collector{Key: key, Namespace: r.Metadata.Namespace, Name: r.Metadata.Name, Managed: managed(r.Metadata.Labels), Pods: []Pod{}}
		c.Mode, _ = r.Spec["mode"].(string)
		c.Image, _ = r.Spec["image"].(string)
		if n, ok := r.Spec["replicas"].(int); ok {
			c.Replicas = &n
		}
		if cfg, ok := r.Spec["config"]; ok {
			c.Config = marshal(cfg)
		}
		if h, ok := root.Children[key]; ok {
			healthy := h.Healthy
			c.Healthy = &healthy
			for name, pod := range h.Children {
				c.Pods = append(c.Pods, Pod{Name: name, Healthy: pod.Healthy, Status: pod.Status})
			}
			sort.Slice(c.Pods, func(i, j int) bool { return c.Pods[i].Name < c.Pods[j].Name })
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// SameConfig reports whether a collector is running the assigned config:
// everything in assigned is present, with the same value, in running.
// Formatting and key order are ignored, and so are settings only running
// has, because the operator adds defaults (such as the collector's own
// metrics endpoint) to what it was given.
func SameConfig(running, assigned string) bool {
	var x, y any
	if yaml.Unmarshal([]byte(running), &x) != nil || yaml.Unmarshal([]byte(assigned), &y) != nil {
		return false
	}
	return covers(x, y)
}

func covers(have, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		h, ok := have.(map[string]any)
		if !ok {
			// "batch:" and "batch: {}" mean the same.
			return have == nil && len(w) == 0
		}
		for k, v := range w {
			// The key itself must be there: "http: {}" is not satisfied by a config without http.
			if hv, present := h[k]; !present || !covers(hv, v) {
				return false
			}
		}
		return true
	case nil:
		h, isMap := have.(map[string]any)
		return have == nil || (isMap && len(h) == 0)
	default:
		return marshal(have) == marshal(want)
	}
}

// Desired builds the remote config for a bridge: one file per managed
// collector, with spec.config replaced by the assigned config where there is
// one. assigned maps collector key to a collector config (YAML).
//
// Every managed collector is included even when nothing is assigned to it,
// because the bridge deletes managed collectors that are missing from a
// remote config. Each file is rebuilt from what the bridge reported (name,
// namespace, labels and spec only), so sending it back changes nothing and
// the hash is stable while the cluster and the assignments are.
//
// It returns nil when no assignment applies to a reported managed collector:
// a bridge nobody has configured from here is left alone.
func Desired(files map[string]string, assigned map[string]string) (out map[string][]byte, hash []byte, err error) {
	out = map[string][]byte{}
	applies := false
	for key, body := range files {
		var r resource
		if yaml.Unmarshal([]byte(body), &r) != nil || r.Kind != "OpenTelemetryCollector" || !managed(r.Metadata.Labels) {
			continue
		}
		if cfg, ok := assigned[key]; ok {
			var parsed map[string]any
			if err := yaml.Unmarshal([]byte(cfg), &parsed); err != nil {
				return nil, nil, fmt.Errorf("config for %s is not valid YAML: %w", key, err)
			}
			if r.Spec == nil {
				r.Spec = map[string]any{}
			}
			r.Spec["config"] = parsed
			applies = true
		}
		out[key] = []byte(marshal(map[string]any{
			"apiVersion": r.APIVersion, "kind": r.Kind,
			"metadata": map[string]any{"name": r.Metadata.Name, "namespace": r.Metadata.Namespace, "labels": r.Metadata.Labels},
			"spec":     r.Spec,
		}))
	}
	if !applies {
		return nil, nil, nil
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sum := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(sum, "%s\x00%d\x00", k, len(out[k]))
		sum.Write(out[k])
	}
	return out, sum.Sum(nil), nil
}
