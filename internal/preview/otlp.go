package preview

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

//go:embed samples/*.json
var samples embed.FS

// Sample returns the built-in sample for a signal, as OTLP JSON.
func Sample(signal string) string {
	b, _ := samples.ReadFile("samples/" + signal + ".json")
	return string(b)
}

// MaxRecords is how many records of a sample are previewed; the rest are left out and reported.
const MaxRecords = 200

// record is one log record, span or metric data point, flattened: the
// resource attributes are copied onto each record so every processor can
// be applied record by record.
type record struct {
	title, detail string
	// severity is the log severity number (0 when unspecified); name the span or metric name.
	severity     int
	severityText string
	name         string
	traceID      string
	resource     map[string]string
	attributes   map[string]string
}

type anyValue struct {
	StringValue *string         `json:"stringValue"`
	IntValue    json.RawMessage `json:"intValue"`
	DoubleValue *float64        `json:"doubleValue"`
	BoolValue   *bool           `json:"boolValue"`
	ArrayValue  json.RawMessage `json:"arrayValue"`
	KvlistValue json.RawMessage `json:"kvlistValue"`
	BytesValue  *string         `json:"bytesValue"`
}

// text renders a value the way it reads in a table.
func (v anyValue) text() string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case len(v.IntValue) > 0:
		return strings.Trim(string(v.IntValue), `"`)
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'g', -1, 64)
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	case len(v.ArrayValue) > 0:
		return string(v.ArrayValue)
	case len(v.KvlistValue) > 0:
		return string(v.KvlistValue)
	case v.BytesValue != nil:
		return *v.BytesValue
	}
	return ""
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

func attrs(kvs []keyValue) map[string]string {
	m := make(map[string]string, len(kvs))
	for _, kv := range kvs {
		m[kv.Key] = kv.Value.text()
	}
	return m
}

func clone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

type resource struct {
	Attributes []keyValue `json:"attributes"`
}

// number reads a JSON number that OTLP may also write as a string.
type number string

func (n *number) UnmarshalJSON(b []byte) error {
	*n = number(strings.Trim(string(b), `"`))
	return nil
}

type dataPoint struct {
	Attributes []keyValue `json:"attributes"`
	AsInt      number     `json:"asInt"`
	AsDouble   number     `json:"asDouble"`
	Count      number     `json:"count"`
	Sum        number     `json:"sum"`
}

func (d dataPoint) value() string {
	switch {
	case d.AsInt != "":
		return string(d.AsInt)
	case d.AsDouble != "":
		return string(d.AsDouble)
	case d.Count != "":
		return "count " + string(d.Count)
	}
	return ""
}

type points struct {
	DataPoints []dataPoint `json:"dataPoints"`
}

type otlp struct {
	ResourceLogs []struct {
		Resource  resource `json:"resource"`
		ScopeLogs []struct {
			LogRecords []struct {
				Body           anyValue        `json:"body"`
				SeverityNumber json.RawMessage `json:"severityNumber"`
				SeverityText   string          `json:"severityText"`
				Attributes     []keyValue      `json:"attributes"`
				TraceID        string          `json:"traceId"`
			} `json:"logRecords"`
		} `json:"scopeLogs"`
	} `json:"resourceLogs"`
	ResourceSpans []struct {
		Resource   resource `json:"resource"`
		ScopeSpans []struct {
			Spans []struct {
				Name       string          `json:"name"`
				Kind       json.RawMessage `json:"kind"`
				TraceID    string          `json:"traceId"`
				Attributes []keyValue      `json:"attributes"`
			} `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
	ResourceMetrics []struct {
		Resource     resource `json:"resource"`
		ScopeMetrics []struct {
			Metrics []struct {
				Name                 string  `json:"name"`
				Unit                 string  `json:"unit"`
				Gauge                *points `json:"gauge"`
				Sum                  *points `json:"sum"`
				Histogram            *points `json:"histogram"`
				ExponentialHistogram *points `json:"exponentialHistogram"`
				Summary              *points `json:"summary"`
			} `json:"metrics"`
		} `json:"scopeMetrics"`
	} `json:"resourceMetrics"`
}

var severityNames = [...]string{"", "TRACE", "TRACE2", "TRACE3", "TRACE4", "DEBUG", "DEBUG2", "DEBUG3", "DEBUG4", "INFO", "INFO2", "INFO3", "INFO4",
	"WARN", "WARN2", "WARN3", "WARN4", "ERROR", "ERROR2", "ERROR3", "ERROR4", "FATAL", "FATAL2", "FATAL3", "FATAL4"}

// severityNumber reads "severityNumber", which OTLP JSON writes as a number or as an enum name.
func severityNumber(raw json.RawMessage) int {
	s := strings.Trim(string(raw), `"`)
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n < len(severityNames) {
		return n
	}
	if v, ok := severityConstant(s); ok {
		return v
	}
	return 0
}

// severityConstant resolves SEVERITY_NUMBER_WARN and the like.
func severityConstant(name string) (int, bool) {
	rest, ok := strings.CutPrefix(name, "SEVERITY_NUMBER_")
	if !ok {
		return 0, false
	}
	if rest == "UNSPECIFIED" {
		return 0, true
	}
	for i, n := range severityNames {
		if i > 0 && n == rest {
			return i, true
		}
	}
	return 0, false
}

var spanKinds = map[string]string{"1": "internal", "2": "server", "3": "client", "4": "producer", "5": "consumer",
	"SPAN_KIND_INTERNAL": "internal", "SPAN_KIND_SERVER": "server", "SPAN_KIND_CLIENT": "client", "SPAN_KIND_PRODUCER": "producer", "SPAN_KIND_CONSUMER": "consumer"}

func short(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// parse reads an OTLP JSON document and returns the records of one signal,
// and how many there were before the limit was applied.
func parse(signal, doc string) ([]record, int, error) {
	var d otlp
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		return nil, 0, fmt.Errorf("the sample is not valid OTLP JSON: %v", err)
	}
	var out []record
	switch signal {
	case "logs":
		for _, rl := range d.ResourceLogs {
			res := attrs(rl.Resource.Attributes)
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					sev := severityNumber(lr.SeverityNumber)
					text := lr.SeverityText
					if text == "" {
						text = severityNames[sev]
					}
					out = append(out, record{title: short(lr.Body.text()), detail: text, severity: sev, severityText: lr.SeverityText,
						traceID: lr.TraceID, resource: clone(res), attributes: attrs(lr.Attributes)})
				}
			}
		}
	case "traces":
		for _, rs := range d.ResourceSpans {
			res := attrs(rs.Resource.Attributes)
			for _, ss := range rs.ScopeSpans {
				for _, sp := range ss.Spans {
					out = append(out, record{title: short(sp.Name), detail: spanKinds[strings.Trim(string(sp.Kind), `"`)], name: sp.Name,
						traceID: sp.TraceID, resource: clone(res), attributes: attrs(sp.Attributes)})
				}
			}
		}
	case "metrics":
		for _, rm := range d.ResourceMetrics {
			res := attrs(rm.Resource.Attributes)
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					for kind, p := range map[string]*points{"gauge": m.Gauge, "sum": m.Sum, "histogram": m.Histogram, "histogram (exponential)": m.ExponentialHistogram, "summary": m.Summary} {
						if p == nil {
							continue
						}
						for _, dp := range p.DataPoints {
							title := m.Name
							if v := dp.value(); v != "" {
								title += " = " + v
								if m.Unit != "" && m.Unit != "1" {
									title += " " + m.Unit
								}
							}
							out = append(out, record{title: short(title), detail: kind, name: m.Name, resource: clone(res), attributes: attrs(dp.Attributes)})
						}
					}
				}
			}
		}
	}
	if len(out) == 0 {
		top := map[string]string{"logs": "resourceLogs", "traces": "resourceSpans", "metrics": "resourceMetrics"}[signal]
		return nil, 0, errors.New("the sample holds no " + signal + ": expected OTLP JSON with " + top + " at the top")
	}
	total := len(out)
	if total > MaxRecords {
		out = out[:MaxRecords]
	}
	return out, total, nil
}
