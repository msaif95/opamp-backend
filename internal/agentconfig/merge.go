package agentconfig

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Merge lays overrides over a base config and returns the resulting YAML.
// It follows the rules the collector itself uses when given several config
// sources: mappings are merged key by key, and anything else (a value, a
// list) is replaced by the override. Additionally, a key set to null (~) in
// the overrides is removed from the result. The base's order and comments
// are kept; keys the base does not have are added after its own.
func Merge(base, overrides string) (string, error) {
	var b, o yaml.Node
	if err := yaml.Unmarshal([]byte(base), &b); err != nil {
		return "", fmt.Errorf("the base config is not valid YAML: %w", err)
	}
	if err := yaml.Unmarshal([]byte(overrides), &o); err != nil {
		return "", fmt.Errorf("the overrides are not valid YAML: %w", err)
	}
	// Nothing but comments or whitespace: the base as it is.
	if o.Kind == 0 || len(o.Content) == 0 || isNull(o.Content[0]) {
		return base, nil
	}
	if b.Kind == 0 || len(b.Content) == 0 || b.Content[0].Kind != yaml.MappingNode {
		return "", errors.New("the base config must be a YAML mapping")
	}
	if o.Content[0].Kind != yaml.MappingNode {
		return "", errors.New("the overrides must be a YAML mapping, laid out like the config itself")
	}
	mergeMapping(b.Content[0], o.Content[0])
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&b); err != nil {
		return "", err
	}
	_ = enc.Close()
	return out.String(), nil
}

func isNull(n *yaml.Node) bool { return n.Kind == yaml.ScalarNode && n.Tag == "!!null" }

func mergeMapping(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i], src.Content[i+1]
		at := -1
		for j := 0; j+1 < len(dst.Content); j += 2 {
			if dst.Content[j].Value == key.Value {
				at = j
				break
			}
		}
		switch {
		case isNull(value):
			if at >= 0 {
				dst.Content = append(dst.Content[:at], dst.Content[at+2:]...)
			}
		case at < 0:
			dst.Content = append(dst.Content, key, value)
		case dst.Content[at+1].Kind == yaml.MappingNode && value.Kind == yaml.MappingNode:
			mergeMapping(dst.Content[at+1], value)
		default:
			dst.Content[at+1] = value
		}
	}
}

// derivedHeader marks a generated body, so someone reading it on a collector knows where to change it.
func derivedHeader(baseName string) string {
	return fmt.Sprintf("# Derived from the base config %q plus overrides. Change the base or the overrides in the console, not this text.\n", baseName)
}

// withHeader puts the derived-config header first, replacing one already there.
func withHeader(baseName, body string) string {
	if strings.HasPrefix(body, "# Derived from the base config ") {
		_, body, _ = strings.Cut(body, "\n")
	}
	return derivedHeader(baseName) + body
}
