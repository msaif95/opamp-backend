// Package targeting resolves label selectors to sets of agents.
package targeting

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	maxKeys   = 20
	maxValues = 200
)

// Selector matches agents by reported attributes. Keys are AND-ed; the
// values of one key are OR-ed. For example
//
//	{"env": ["prod"], "region": ["us-east-1", "eu-west-1"]}
//
// matches prod agents in either region. An empty selector matches every agent.
type Selector map[string][]string

// Validate rejects malformed selectors.
func (s Selector) Validate() error {
	if len(s) > maxKeys {
		return fmt.Errorf("selector has more than %d keys", maxKeys)
	}
	for k, vals := range s {
		if strings.TrimSpace(k) == "" {
			return errors.New("selector has an empty attribute key")
		}
		if len(vals) == 0 || len(vals) > maxValues {
			return fmt.Errorf("selector key %q must have between 1 and %d values", k, maxValues)
		}
	}
	return nil
}

// Where renders the selector as a SQL predicate over a JSONB attributes
// column, using positional parameters starting at firstParam. All keys and
// values are passed as parameters, never interpolated.
func (s Selector) Where(attributesColumn string, firstParam int) (string, []any) {
	if len(s) == 0 {
		return "TRUE", nil
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	terms := make([]string, 0, len(keys))
	args := make([]any, 0, 2*len(keys))
	for _, k := range keys {
		n := firstParam + len(args)
		terms = append(terms, fmt.Sprintf("%s->>$%d = ANY($%d::text[])", attributesColumn, n, n+1))
		args = append(args, k, s[k])
	}
	return strings.Join(terms, " AND "), args
}
