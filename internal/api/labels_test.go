package api

import (
	"strings"
	"testing"
)

func TestLabelChangeValidate(t *testing.T) {
	ok := labelChange{Set: map[string]string{"owner": " alice ", "team/on-call": "sre", "a": "1"}, Remove: []string{"old"}}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	if ok.Set["owner"] != "alice" {
		t.Errorf("value not trimmed: %q", ok.Set["owner"])
	}
	for name, bad := range map[string]labelChange{
		"empty key":       {Set: map[string]string{"": "x"}},
		"key with space":  {Set: map[string]string{"my key": "x"}},
		"key ends in dot": {Set: map[string]string{"owner.": "x"}},
		"long key":        {Set: map[string]string{strings.Repeat("k", 64): "x"}},
		"empty value":     {Set: map[string]string{"owner": "  "}},
		"long value":      {Set: map[string]string{"owner": strings.Repeat("v", 129)}},
		"two lines":       {Set: map[string]string{"owner": "a\nb"}},
		"set and removed": {Set: map[string]string{"owner": "a"}, Remove: []string{"owner"}},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := labelChange{Set: map[string]string{}}
	for i := range 21 {
		many.Set["k"+strings.Repeat("x", i)] = "v"
	}
	if err := many.validate(); err == nil {
		t.Error("21 labels accepted")
	}
}
