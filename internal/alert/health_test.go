package alert

import (
	"strings"
	"testing"
)

func TestFleetHealthTransitions(t *testing.T) {
	find := func(s FleetStats, rule string) ruleState {
		for _, r := range rules(s, 10, 20) {
			if r.rule == rule {
				return r
			}
		}
		t.Fatalf("rule %s missing", rule)
		return ruleState{}
	}
	for _, tc := range []struct {
		name       string
		stats      FleetStats
		rule       string
		wasFiring  bool
		wantFiring bool
		wantText   string // substring; "" means no notification
	}{
		{"healthy fleet", FleetStats{Connected: 1000, RecentlyOffline: 20, Unhealthy: 50}, ruleOffline, false, false, ""},
		{"offline spike fires", FleetStats{Connected: 800, RecentlyOffline: 200}, ruleOffline, false, true, "200 of 1000 agents (20%) went offline"},
		{"already firing: no repeat", FleetStats{Connected: 800, RecentlyOffline: 200}, ruleOffline, true, true, ""},
		// 9% is under the 10% limit but above the 8% resolve line: keep firing.
		{"hovering under the limit keeps firing", FleetStats{Connected: 910, RecentlyOffline: 90}, ruleOffline, true, true, ""},
		{"recovery resolves", FleetStats{Connected: 990, RecentlyOffline: 10}, ruleOffline, true, false, "resolved"},
		// 2 of 4 is 50%, but two agents are not a fleet problem.
		{"tiny numbers never fire", FleetStats{Connected: 2, RecentlyOffline: 2}, ruleOffline, false, false, ""},
		{"empty fleet", FleetStats{}, ruleOffline, false, false, ""},
		{"unhealthy share fires", FleetStats{Connected: 100, Unhealthy: 30}, ruleUnhealthy, false, true, "30 of 100 connected agents (30%)"},
		{"unhealthy under limit", FleetStats{Connected: 100, Unhealthy: 19}, ruleUnhealthy, false, false, ""},
	} {
		firing, text := find(tc.stats, tc.rule).transition(tc.wasFiring)
		if firing != tc.wantFiring || (tc.wantText == "") != (text == "") || !strings.Contains(text, tc.wantText) {
			t.Errorf("%s: firing=%v text=%q, want firing=%v containing %q", tc.name, firing, text, tc.wantFiring, tc.wantText)
		}
	}
	if got := rules(FleetStats{Connected: 10}, 0, 0); len(got) != 0 {
		t.Errorf("disabled rules still evaluated: %+v", got)
	}
}
