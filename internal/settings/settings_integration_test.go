package settings_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/msaif95/opamp-backend/internal/settings"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestSettings(t *testing.T) {
	db, rdb := testdb.Open(t)
	ctx := context.Background()
	defs := map[string]settings.Definition{
		settings.SSO:           {Available: true, Default: true},
		settings.LocalLogin:    {Available: true, Default: true},
		settings.AgentTLS:      {Available: true, Default: true, Locked: true},
		settings.AlertDelivery: {Available: false, Default: true},
		settings.Rebalancing:   {Available: true, Default: false},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s, err := settings.New(ctx, db, rdb, defs, log)
	if err != nil {
		t.Fatal(err)
	}

	// Defaults, and "enabled" needing the feature to be configured.
	if !s.Enabled(settings.SSO) || s.Enabled(settings.Rebalancing) || s.Enabled(settings.AlertDelivery) {
		t.Fatal("defaults wrong")
	}

	for name, tc := range map[string]struct {
		key     string
		enabled bool
		want    error
	}{
		"unknown key":             {"nope", true, settings.ErrUnknown},
		"locked":                  {settings.AgentTLS, false, settings.ErrLocked},
		"enable unconfigured":     {settings.AlertDelivery, true, settings.ErrUnavailable},
		"disable unconfigured ok": {settings.AlertDelivery, false, nil},
		"turn on":                 {settings.Rebalancing, true, nil},
		"turn off sso":            {settings.SSO, false, nil},
	} {
		if err := s.Set(ctx, tc.key, tc.enabled, "alice"); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	// With SSO off, local login is the last way in.
	if err := s.Set(ctx, settings.LocalLogin, false, "alice"); !errors.Is(err, settings.ErrLockout) {
		t.Fatalf("lockout not refused: %v", err)
	}
	if !s.Enabled(settings.Rebalancing) || s.Enabled(settings.SSO) || !s.Enabled(settings.LocalLogin) {
		t.Fatal("changes not applied")
	}

	// Another replica sees the same values, with who changed them.
	other, err := settings.New(ctx, db, rdb, defs, log)
	if err != nil {
		t.Fatal(err)
	}
	if other.Enabled(settings.SSO) || !other.Enabled(settings.Rebalancing) {
		t.Fatal("second store did not load saved values")
	}
	for _, st := range other.List() {
		if st.Key == settings.SSO && (st.Enabled || st.UpdatedBy == nil || *st.UpdatedBy != "alice") {
			t.Fatalf("sso state = %+v", st)
		}
		if st.Key == settings.AgentTLS && (!st.Locked || st.UpdatedBy != nil) {
			t.Fatalf("agent_tls state = %+v", st)
		}
	}
}
