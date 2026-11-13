package access

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/auth"
)

func TestScope(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	member := Scope{Projects: map[uuid.UUID]auth.Role{a: auth.RoleOperator, b: auth.RoleViewer}}
	legacy := Scope{Global: auth.RoleOperator}

	for name, tc := range map[string]struct {
		scope   Scope
		project *uuid.UUID
		need    auth.Role
		want    bool
	}{
		"admin anywhere":                       {All, &a, auth.RoleAdmin, true},
		"admin unassigned":                     {All, nil, auth.RoleOperator, true},
		"operator in own project":              {member, &a, auth.RoleOperator, true},
		"viewer cannot operate":                {member, &b, auth.RoleOperator, false},
		"viewer can view":                      {member, &b, auth.RoleViewer, true},
		"no access to another project":         {Scope{Projects: map[uuid.UUID]auth.Role{a: auth.RoleAdmin}}, &b, auth.RoleViewer, false},
		"project member cannot see unassigned": {member, nil, auth.RoleViewer, false},
		"global role covers unassigned":        {legacy, nil, auth.RoleOperator, true},
		"global role does not cover a project": {legacy, &a, auth.RoleViewer, false},
		"empty scope grants nothing":           {Scope{}, nil, auth.RoleViewer, false},
		"project admin is not a global admin":  {Scope{Projects: map[uuid.UUID]auth.Role{a: auth.RoleAdmin}}, nil, auth.RoleViewer, false},
	} {
		if got := tc.scope.Can(tc.project, tc.need); got != tc.want {
			t.Errorf("%s: Can = %v, want %v", name, got, tc.want)
		}
	}
	if !member.CanAnywhere(auth.RoleOperator) || member.CanAnywhere(auth.RoleAdmin) || (Scope{}).CanAnywhere(auth.RoleViewer) {
		t.Error("CanAnywhere wrong")
	}

	if w, args := All.Where("project_id", 3); w != "TRUE" || args != nil {
		t.Errorf("admin where = %q %v", w, args)
	}
	if w, args := member.Where("a.project_id", 3); w != "a.project_id = ANY($3)" || len(args[0].([]uuid.UUID)) != 2 {
		t.Errorf("member where = %q %v", w, args)
	}
	// A global role adds the unassigned pool; a scope with nothing matches no rows rather than all of them.
	if w, _ := legacy.Where("project_id", 1); !strings.Contains(w, "project_id IS NULL OR") {
		t.Errorf("legacy where = %q", w)
	}
	if w, args := (Scope{}).Where("project_id", 1); w != "project_id = ANY($1)" || len(args[0].([]uuid.UUID)) != 0 {
		t.Errorf("empty where = %q %v", w, args)
	}
}
