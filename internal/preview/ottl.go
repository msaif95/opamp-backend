package preview

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// This is a deliberately small subset of OTTL conditions, enough for the
// filters people write most: comparisons between a field and a literal,
// joined with "and" / "or". Anything else is reported as unsupported, and
// the processor using it is then not previewed rather than guessed at.
//
//	severity_number < SEVERITY_NUMBER_WARN
//	attributes["http.route"] == "/healthz" or resource.attributes["env"] != "prod"
//	name == "GET /healthz"

var errUnsupported = errors.New("unsupported")

type token struct {
	kind string // path, string, number, op, and, or, bool, nil
	text string
}

func tokenize(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '"':
			j := i + 1
			var b strings.Builder
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, errUnsupported
			}
			out = append(out, token{"string", b.String()})
			i = j + 1
		case strings.ContainsRune("=!<>", rune(c)):
			j := i + 1
			if j < len(s) && s[j] == '=' {
				j++
			}
			op := s[i:j]
			if op == "=" || op == "!" {
				return nil, errUnsupported
			}
			out = append(out, token{"op", op})
			i = j
		case c == '-' || unicode.IsDigit(rune(c)):
			j := i + 1
			for j < len(s) && (unicode.IsDigit(rune(s[j])) || s[j] == '.') {
				j++
			}
			out = append(out, token{"number", s[i:j]})
			i = j
		case unicode.IsLetter(rune(c)) || c == '_':
			j := i
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || s[j] == '_' || s[j] == '.') {
				j++
			}
			word := s[i:j]
			// A path may end in ["key"].
			if j < len(s) && s[j] == '[' {
				end := strings.Index(s[j:], `"]`)
				if j+1 >= len(s) || s[j+1] != '"' || end < 2 {
					return nil, errUnsupported
				}
				word += s[j : j+end+2]
				j += end + 2
			}
			switch word {
			case "and", "or":
				out = append(out, token{word, word})
			case "true", "false":
				out = append(out, token{"bool", word})
			case "nil":
				out = append(out, token{"nil", word})
			default:
				out = append(out, token{"path", word})
			}
			i = j
		default:
			// Parentheses, function calls and the rest of OTTL.
			return nil, errUnsupported
		}
	}
	return out, nil
}

type comparison struct {
	left, right token
	op          string
}

// condition is comparisons joined by "or" of "and" groups.
type condition [][]comparison

func parseCondition(s string) (condition, error) {
	toks, err := tokenize(s)
	if err != nil {
		return nil, err
	}
	cond := condition{nil}
	for i := 0; i < len(toks); {
		if i+2 >= len(toks) || toks[i+1].kind != "op" || toks[i].kind == "op" || toks[i+2].kind == "op" {
			return nil, errUnsupported
		}
		cmp := comparison{left: toks[i], op: toks[i+1].text, right: toks[i+2]}
		for _, t := range []token{cmp.left, cmp.right} {
			if t.kind == "and" || t.kind == "or" {
				return nil, errUnsupported
			}
		}
		cond[len(cond)-1] = append(cond[len(cond)-1], cmp)
		i += 3
		if i == len(toks) {
			break
		}
		switch toks[i].kind {
		case "and":
		case "or":
			cond = append(cond, nil)
		default:
			return nil, errUnsupported
		}
		i++
		if i == len(toks) {
			return nil, errUnsupported
		}
	}
	if len(cond[0]) == 0 {
		return nil, errUnsupported
	}
	return cond, nil
}

// fields resolves the paths a condition may use for one kind of record.
type fields func(path string) (value any, known bool)

func attribute(m map[string]string, path, prefix string) (any, bool) {
	key, ok := strings.CutPrefix(path, prefix+`["`)
	if !ok || !strings.HasSuffix(key, `"]`) {
		return nil, false
	}
	if v, ok := m[strings.TrimSuffix(key, `"]`)]; ok {
		return v, true
	}
	return nil, true
}

// fieldsOf returns the paths available in a filter context: log_record, span, metric or datapoint.
func fieldsOf(r *record, context string) fields {
	return func(path string) (any, bool) {
		if v, ok := attribute(r.resource, path, "resource.attributes"); ok {
			return v, true
		}
		if context != "metric" {
			if v, ok := attribute(r.attributes, path, "attributes"); ok {
				return v, true
			}
		}
		switch {
		case context == "log_record" && path == "severity_number":
			return float64(r.severity), true
		case context == "log_record" && path == "severity_text":
			return r.severityText, true
		case context == "log_record" && path == "body":
			return r.title, true
		case (context == "span" || context == "metric") && path == "name":
			return r.name, true
		case context == "datapoint" && path == "metric.name":
			return r.name, true
		}
		return nil, false
	}
}

func operand(t token, f fields) (any, error) {
	switch t.kind {
	case "string":
		return t.text, nil
	case "number":
		n, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, errUnsupported
		}
		return n, nil
	case "bool":
		return t.text == "true", nil
	case "nil":
		return nil, nil
	case "path":
		if n, ok := severityConstant(t.text); ok {
			return float64(n), nil
		}
		if v, ok := f(t.text); ok {
			return v, nil
		}
	}
	return nil, errUnsupported
}

func asNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case string:
		n, err := strconv.ParseFloat(x, 64)
		return n, err == nil
	}
	return 0, false
}

func compare(a any, op string, b any) bool {
	if a == nil || b == nil {
		switch op {
		case "==":
			return a == nil && b == nil
		case "!=":
			return (a == nil) != (b == nil)
		}
		return false
	}
	// Attribute values are kept as text, so a number is compared as one when both sides read as numbers.
	x, xok := asNumber(a)
	y, yok := asNumber(b)
	_, aText := a.(string)
	_, bText := b.(string)
	if xok && yok && !(aText && bText) {
		switch op {
		case "==":
			return x == y
		case "!=":
			return x != y
		case "<":
			return x < y
		case "<=":
			return x <= y
		case ">":
			return x > y
		case ">=":
			return x >= y
		}
	}
	as, bs := fmt.Sprint(a), fmt.Sprint(b)
	switch op {
	case "==":
		return as == bs
	case "!=":
		return as != bs
	}
	return false
}

// eval reports whether the condition holds for the record's fields.
func (c condition) eval(f fields) (bool, error) {
	for _, group := range c {
		all := true
		for _, cmp := range group {
			l, err := operand(cmp.left, f)
			if err != nil {
				return false, err
			}
			r, err := operand(cmp.right, f)
			if err != nil {
				return false, err
			}
			all = all && compare(l, cmp.op, r)
		}
		if all {
			return true, nil
		}
	}
	return false, nil
}
