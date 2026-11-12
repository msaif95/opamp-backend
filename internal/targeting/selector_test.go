package targeting

import (
	"reflect"
	"testing"
)

func TestWhere(t *testing.T) {
	sql, args := Selector{"region": {"us-east-1", "eu-west-1"}, "env": {"prod"}}.Where("a.attributes", 3)
	wantSQL := "a.attributes->>$3 = ANY($4::text[]) AND a.attributes->>$5 = ANY($6::text[])"
	wantArgs := []any{"env", []string{"prod"}, "region", []string{"us-east-1", "eu-west-1"}}
	if sql != wantSQL || !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("got %q %v", sql, args)
	}
	if sql, args := (Selector{}).Where("attributes", 1); sql != "TRUE" || args != nil {
		t.Fatalf("empty selector: got %q %v", sql, args)
	}
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		sel Selector
		ok  bool
	}{
		"empty":     {Selector{}, true},
		"simple":    {Selector{"env": {"prod"}}, true},
		"blank key": {Selector{" ": {"x"}}, false},
		"no values": {Selector{"env": {}}, false},
	} {
		if err := tc.sel.Validate(); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok = %v", name, err, tc.ok)
		}
	}
}
