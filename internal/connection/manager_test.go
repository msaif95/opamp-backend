package connection_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/client"
	"github.com/open-telemetry/opamp-go/client/types"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/connection"
	"github.com/msaif95/opamp-backend/internal/protocol"
	"github.com/msaif95/opamp-backend/internal/registry"
)

type fakeAuth struct{}

func (fakeAuth) Authenticate(_ context.Context, r *http.Request) (registry.Identity, error) {
	if r.Header.Get("Authorization") != "Bearer good" {
		return registry.Identity{}, auth.ErrUnauthenticated
	}
	return registry.Identity{AuthMode: "api_key"}, nil
}

type report struct {
	uid   uuid.UUID
	id    registry.Identity
	attrs map[string]string
}

type fakeRegistry struct {
	mu           sync.Mutex
	reports      []report
	disconnected []uuid.UUID
}

func (f *fakeRegistry) Report(_ context.Context, uid uuid.UUID, id registry.Identity, msg *protobufs.AgentToServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := report{uid: uid, id: id}
	if d := msg.GetAgentDescription(); d != nil {
		r.attrs = registry.FlattenAttributes(d)
	}
	f.reports = append(f.reports, r)
	return nil
}

func (f *fakeRegistry) Disconnected(_ context.Context, uid uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnected = append(f.disconnected, uid)
	return nil
}

func (f *fakeRegistry) snapshot() ([]report, []uuid.UUID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]report(nil), f.reports...), append([]uuid.UUID(nil), f.disconnected...)
}

func startManager(t *testing.T) (*connection.Manager, *fakeRegistry, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := &fakeRegistry{}
	m := connection.NewManager(fakeAuth{}, protocol.NewHandler(reg, log), reg, log)
	if err := m.Start(addr, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, reg, "ws://" + addr + connection.OpAMPPath
}

func startAgent(t *testing.T, url, token string, uid uuid.UUID, cb types.Callbacks) client.OpAMPClient {
	t.Helper()
	c := client.NewWebSocket(nil)
	err := c.SetAgentDescription(&protobufs.AgentDescription{IdentifyingAttributes: []*protobufs.KeyValue{{
		Key:   "service.name",
		Value: &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: "otelcol"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	caps := protobufs.AgentCapabilities_AgentCapabilities_ReportsStatus
	if err := c.SetCapabilities(&caps); err != nil {
		t.Fatal(err)
	}
	err = c.Start(context.Background(), types.StartSettings{
		OpAMPServerURL: url,
		Header:         http.Header{"Authorization": {"Bearer " + token}},
		InstanceUid:    types.InstanceUid(uid),
		Callbacks:      cb,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAgentConnectReportDisconnect(t *testing.T) {
	m, reg, url := startManager(t)
	uid := uuid.New()
	c := startAgent(t, url, "good", uid, types.Callbacks{})

	eventually(t, "agent report", func() bool { r, _ := reg.snapshot(); return len(r) > 0 })
	reports, _ := reg.snapshot()
	got := reports[0]
	if got.uid != uid || got.id.AuthMode != "api_key" || got.attrs["service.name"] != "otelcol" {
		t.Fatalf("unexpected first report: %+v", got)
	}
	if n := m.ConnectionCount(); n != 1 {
		t.Fatalf("ConnectionCount = %d, want 1", n)
	}

	if err := c.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "disconnect", func() bool { _, d := reg.snapshot(); return len(d) == 1 && d[0] == uid })
	eventually(t, "connection untracked", func() bool { return m.ConnectionCount() == 0 })
}

func TestUnauthenticatedAgentRejected(t *testing.T) {
	m, reg, url := startManager(t)
	failed := make(chan error, 1)
	c := startAgent(t, url, "bad", uuid.New(), types.Callbacks{
		OnConnectFailed: func(_ context.Context, err error) {
			select {
			case failed <- err:
			default:
			}
		},
	})
	defer c.Stop(context.Background())

	select {
	case <-failed:
	case <-time.After(5 * time.Second):
		t.Fatal("expected connection failure")
	}
	if r, _ := reg.snapshot(); len(r) != 0 || m.ConnectionCount() != 0 {
		t.Fatalf("unauthenticated agent reached the registry: %+v", r)
	}
}
