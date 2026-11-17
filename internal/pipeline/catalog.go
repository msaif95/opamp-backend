// Package pipeline turns a pipeline built in the console (sources,
// processors, destinations chosen from a catalog) into OpenTelemetry
// Collector YAML.
package pipeline

// Kinds of component.
const (
	KindSource      = "source"
	KindProcessor   = "processor"
	KindDestination = "destination"
)

// Field types.
const (
	FieldString = "string"
	FieldInt    = "int"
	FieldNumber = "number"
	FieldBool   = "bool"
	FieldEnum   = "enum"
	// FieldMulti is several values chosen from Options.
	FieldMulti = "multi"
	// FieldList is a free list of strings.
	FieldList = "list"
	// FieldMap is free key/value pairs.
	FieldMap = "map"
)

// Field is one setting of a component type, as shown in the builder form.
type Field struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"`
	Required bool     `json:"required"`
	Default  any      `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"`
	Help     string   `json:"help,omitempty"`
}

// Type is one entry of the catalog.
type Type struct {
	Kind        string `json:"kind"`
	Type        string `json:"type"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Signals this component can handle: logs, metrics, traces.
	Signals []string `json:"signals"`
	Fields  []Field  `json:"fields"`

	// component is the collector component this renders to, e.g. "otlp".
	component string
	build     func(p params) map[string]any
}

var allSignals = []string{"logs", "metrics", "traces"}

// Catalog lists every component type the builder offers, in display order.
// Every entry is checked against a real collector; see docs in AGENTS.md
// before adding one.
func Catalog() []Type { return catalog }

// CatalogComponents returns the OTel Collector component names the builder
// uses, grouped by section. These form the default allowlist for raw YAML
// config validation.
func CatalogComponents() (receivers, processors, exporters map[string]bool) {
	receivers = make(map[string]bool)
	processors = make(map[string]bool)
	exporters = make(map[string]bool)
	for _, t := range catalog {
		switch t.Kind {
		case KindSource:
			receivers[t.component] = true
		case KindProcessor:
			processors[t.component] = true
		case KindDestination:
			exporters[t.component] = true
		}
	}
	return
}

var catalog = []Type{
	// Sources -----------------------------------------------------------
	{
		Kind: KindSource, Type: "otlp", Label: "OTLP", component: "otlp", Signals: allSignals,
		Description: "Receive logs, metrics and traces sent by applications or other collectors over OTLP.",
		Fields: []Field{
			{Key: "grpc_endpoint", Label: "gRPC listen address", Type: FieldString, Default: "0.0.0.0:4317", Help: "Leave empty to disable gRPC."},
			{Key: "http_endpoint", Label: "HTTP listen address", Type: FieldString, Default: "0.0.0.0:4318", Help: "Leave empty to disable HTTP."},
		},
		build: func(p params) map[string]any {
			protocols := map[string]any{}
			if e := p.str("grpc_endpoint"); e != "" {
				protocols["grpc"] = map[string]any{"endpoint": e}
			}
			if e := p.str("http_endpoint"); e != "" {
				protocols["http"] = map[string]any{"endpoint": e}
			}
			return map[string]any{"protocols": protocols}
		},
	},
	{
		Kind: KindSource, Type: "host_metrics", Label: "Host metrics", component: "hostmetrics", Signals: []string{"metrics"},
		Description: "Collect CPU, memory, disk and network metrics from the host the collector runs on.",
		Fields: []Field{
			{Key: "interval", Label: "Collection interval", Type: FieldString, Default: "60s", Required: true},
			{Key: "scrapers", Label: "Metrics to collect", Type: FieldMulti, Required: true,
				Options: []string{"cpu", "memory", "disk", "filesystem", "load", "network", "paging", "processes"},
				Default: []string{"cpu", "memory", "disk", "filesystem", "load", "network"}},
		},
		build: func(p params) map[string]any {
			scrapers := map[string]any{}
			for _, s := range p.list("scrapers") {
				scrapers[s] = map[string]any{}
			}
			return map[string]any{"collection_interval": p.str("interval"), "scrapers": scrapers}
		},
	},
	{
		Kind: KindSource, Type: "file_logs", Label: "Log files", component: "filelog", Signals: []string{"logs"},
		Description: "Tail log files on the host.",
		Fields: []Field{
			{Key: "include", Label: "Files to read", Type: FieldList, Required: true, Help: "Paths or globs, for example /var/log/app/*.log"},
			{Key: "start_at", Label: "Start reading from", Type: FieldEnum, Options: []string{"end", "beginning"}, Default: "end",
				Help: "\"end\" reads only new lines; \"beginning\" also reads what is already in the files."},
		},
		build: func(p params) map[string]any {
			return map[string]any{"include": p.list("include"), "start_at": p.str("start_at")}
		},
	},
	{
		Kind: KindSource, Type: "prometheus", Label: "Prometheus scrape", component: "prometheus", Signals: []string{"metrics"},
		Description: "Scrape Prometheus metrics endpoints.",
		Fields: []Field{
			{Key: "job_name", Label: "Job name", Type: FieldString, Required: true, Default: "app"},
			{Key: "targets", Label: "Targets", Type: FieldList, Required: true, Help: "host:port of each endpoint to scrape"},
			{Key: "interval", Label: "Scrape interval", Type: FieldString, Required: true, Default: "30s"},
		},
		build: func(p params) map[string]any {
			return map[string]any{"config": map[string]any{"scrape_configs": []any{map[string]any{
				"job_name": p.str("job_name"), "scrape_interval": p.str("interval"),
				"static_configs": []any{map[string]any{"targets": p.list("targets")}},
			}}}}
		},
	},

	// Processors --------------------------------------------------------
	{
		Kind: KindProcessor, Type: "memory_limiter", Label: "Memory limiter", component: "memory_limiter", Signals: allSignals,
		Description: "Refuse data when the collector is close to its memory limit, instead of crashing. Put it first.",
		Fields: []Field{
			{Key: "limit_mib", Label: "Memory limit (MiB)", Type: FieldInt, Required: true, Default: 512},
			{Key: "spike_limit_mib", Label: "Spike allowance (MiB)", Type: FieldInt, Required: true, Default: 128},
		},
		build: func(p params) map[string]any {
			return map[string]any{"check_interval": "1s", "limit_mib": p.int("limit_mib"), "spike_limit_mib": p.int("spike_limit_mib")}
		},
	},
	{
		Kind: KindProcessor, Type: "add_resource_attributes", Label: "Add resource attributes", component: "resource", Signals: allSignals,
		Description: "Stamp every record with fixed attributes such as environment or team.",
		Fields:      []Field{{Key: "attributes", Label: "Attributes", Type: FieldMap, Required: true}},
		build: func(p params) map[string]any {
			var actions []any
			for _, kv := range p.pairs("attributes") {
				actions = append(actions, map[string]any{"key": kv[0], "value": kv[1], "action": "upsert"})
			}
			return map[string]any{"attributes": actions}
		},
	},
	{
		Kind: KindProcessor, Type: "remove_attributes", Label: "Remove attributes", component: "attributes", Signals: allSignals,
		Description: "Delete attributes from every record, for example to drop sensitive or high-cardinality fields.",
		Fields:      []Field{{Key: "keys", Label: "Attribute names", Type: FieldList, Required: true}},
		build: func(p params) map[string]any {
			var actions []any
			for _, k := range p.list("keys") {
				actions = append(actions, map[string]any{"key": k, "action": "delete"})
			}
			return map[string]any{"actions": actions}
		},
	},
	{
		Kind: KindProcessor, Type: "drop_low_severity_logs", Label: "Drop low-severity logs", component: "filter", Signals: []string{"logs"},
		Description: "Drop log records below a severity to cut volume. Records with no severity are kept.",
		Fields: []Field{{Key: "min_severity", Label: "Keep this severity and above", Type: FieldEnum, Required: true,
			Options: []string{"DEBUG", "INFO", "WARN", "ERROR"}, Default: "INFO"}},
		build: func(p params) map[string]any {
			cond := "severity_number != SEVERITY_NUMBER_UNSPECIFIED and severity_number < SEVERITY_NUMBER_" + p.str("min_severity")
			return map[string]any{"error_mode": "ignore", "logs": map[string]any{"log_record": []any{cond}}}
		},
	},
	{
		Kind: KindProcessor, Type: "sample", Label: "Sample", component: "probabilistic_sampler", Signals: []string{"logs", "traces"},
		Description: "Keep only a percentage of traces and logs.",
		Fields:      []Field{{Key: "percentage", Label: "Percentage to keep", Type: FieldNumber, Required: true, Default: 10}},
		build: func(p params) map[string]any {
			return map[string]any{"sampling_percentage": p.number("percentage")}
		},
	},
	{
		Kind: KindProcessor, Type: "batch", Label: "Batch", component: "batch", Signals: allSignals,
		Description: "Group records into batches before export, which most destinations need for throughput. Put it last.",
		Fields: []Field{
			{Key: "timeout", Label: "Send at least every", Type: FieldString, Required: true, Default: "5s"},
			{Key: "send_batch_size", Label: "Batch size", Type: FieldInt, Required: true, Default: 8192},
		},
		build: func(p params) map[string]any {
			return map[string]any{"timeout": p.str("timeout"), "send_batch_size": p.int("send_batch_size")}
		},
	},

	// Destinations ------------------------------------------------------
	{
		Kind: KindDestination, Type: "otlp_grpc", Label: "OTLP (gRPC)", component: "otlp", Signals: allSignals,
		Description: "Send to any OTLP gRPC endpoint: another collector, a gateway or a vendor backend.",
		Fields: []Field{
			{Key: "endpoint", Label: "Endpoint", Type: FieldString, Required: true, Help: "host:port, for example gateway.example.com:4317"},
			{Key: "insecure", Label: "Plaintext (no TLS)", Type: FieldBool, Default: false},
			{Key: "headers", Label: "Headers", Type: FieldMap, Help: "For example an API key header. Write ${secret:NAME} as the value to keep it out of the config."},
		},
		build: func(p params) map[string]any {
			out := map[string]any{"endpoint": p.str("endpoint"), "tls": map[string]any{"insecure": p.bool("insecure")}}
			if h := p.kv("headers"); len(h) > 0 {
				out["headers"] = h
			}
			return out
		},
	},
	{
		Kind: KindDestination, Type: "otlp_http", Label: "OTLP (HTTP)", component: "otlphttp", Signals: allSignals,
		Description: "Send to any OTLP HTTP endpoint.",
		Fields: []Field{
			{Key: "endpoint", Label: "Endpoint URL", Type: FieldString, Required: true, Help: "For example https://otlp.example.com"},
			{Key: "headers", Label: "Headers", Type: FieldMap, Help: "For example an API key header. Write ${secret:NAME} as the value to keep it out of the config."},
		},
		build: func(p params) map[string]any {
			out := map[string]any{"endpoint": p.str("endpoint")}
			if h := p.kv("headers"); len(h) > 0 {
				out["headers"] = h
			}
			return out
		},
	},
	{
		Kind: KindDestination, Type: "prometheus_remote_write", Label: "Prometheus remote write", component: "prometheusremotewrite", Signals: []string{"metrics"},
		Description: "Send metrics to Prometheus, Mimir, Thanos or anything accepting remote write.",
		Fields: []Field{
			{Key: "endpoint", Label: "Remote write URL", Type: FieldString, Required: true},
			{Key: "headers", Label: "Headers", Type: FieldMap, Help: "Write ${secret:NAME} as a value to keep it out of the config."},
		},
		build: func(p params) map[string]any {
			out := map[string]any{"endpoint": p.str("endpoint")}
			if h := p.kv("headers"); len(h) > 0 {
				out["headers"] = h
			}
			return out
		},
	},
	{
		Kind: KindDestination, Type: "file", Label: "File", component: "file", Signals: allSignals,
		Description: "Write telemetry to a file on the collector's host as JSON lines.",
		Fields:      []Field{{Key: "path", Label: "File path", Type: FieldString, Required: true}},
		build:       func(p params) map[string]any { return map[string]any{"path": p.str("path")} },
	},
	{
		Kind: KindDestination, Type: "debug", Label: "Debug (collector log)", component: "debug", Signals: allSignals,
		Description: "Print telemetry to the collector's own log. For testing a pipeline, not for production.",
		Fields:      []Field{{Key: "verbosity", Label: "Detail", Type: FieldEnum, Options: []string{"basic", "normal", "detailed"}, Default: "basic"}},
		build:       func(p params) map[string]any { return map[string]any{"verbosity": p.str("verbosity")} },
	},
}
