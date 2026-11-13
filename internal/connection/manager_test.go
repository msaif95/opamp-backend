package connection_test

import (
	"bytes"
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

	"github.com/msaif95/opamp-backend/internal/agentconfig"
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
	return registry.Identity{AuthMode: "api_key", CredentialID: &goodCredential}, nil
}

func (fakeAuth) Invalid(context.Context, []uuid.UUID, [][]byte) (map[uuid.UUID]bool, map[string]bool, error) {
	return revokedIDs, nil, nil
}

// revokedIDs is what fakeAuth.Invalid reports; tests set it.
var revokedIDs map[uuid.UUID]bool

var goodCredential = uuid.MustParse("11111111-1111-1111-1111-111111111111")

type report struct {
	uid   uuid.UUID
	id    registry.Identity
	attrs map[string]string
}

// fakeRegistry also acts as the config source: it serves a single version.
type fakeRegistry struct {
	mu           sync.Mutex
	reports      []report
	disconnected []uuid.UUID
	state        registry.ConfigState
	version      *agentconfig.Version
}

func (f *fakeRegistry) Report(_ context.Context, uid uuid.UUID, id registry.Identity, msg *protobufs.AgentToServer) (registry.ConfigState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := report{uid: uid, id: id}
	if d := msg.GetAgentDescription(); d != nil {
		r.attrs = registry.FlattenAttributes(d)
	}
	f.reports = append(f.reports, r)
	f.state.Capabilities = msg.Capabilities
	if s := msg.GetRemoteConfigStatus(); s != nil {
		f.state.RemoteConfigHash = s.LastRemoteConfigHash
	}
	return f.state, nil
}

func (f *fakeRegistry) BridgeState(context.Context, uuid.UUID) (map[string]string, []byte, map[string]registry.BridgeAssignment, error) {
	return nil, nil, nil, nil
}

func (f *fakeRegistry) ConfigState(context.Context, uuid.UUID) (registry.ConfigState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

func (f *fakeRegistry) Version(context.Context, uuid.UUID) (*agentconfig.Version, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.version, nil
}

func (f *fakeRegistry) assign(body string, hash []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.New()
	f.version = &agentconfig.Version{ID: id, Body: body, BodyHash: hash}
	f.state.DesiredConfigVersionID = &id
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
	m := connection.NewManager(fakeAuth{}, protocol.NewHandler(reg, reg, log), reg, log)
	if err := m.Start(addr, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m, reg, "ws://" + addr + connection.OpAMPPath
}

func startAgent(t *testing.T, url, token string, uid uuid.UUID, cb types.Callbacks, extraCaps ...protobufs.AgentCapabilities) client.OpAMPClient {
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
	for _, c := range extraCaps {
		caps |= c
	}
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

func TestRemoteConfigPushedAndNotReoffered(t *testing.T) {
	m, reg, url := startManager(t)
	uid := uuid.New()
	hash := []byte("hash-v1")

	received := make(chan *protobufs.AgentRemoteConfig, 8)
	var c client.OpAMPClient
	c = startAgent(t, url, "good", uid, types.Callbacks{
		OnMessage: func(_ context.Context, msg *types.MessageData) {
			if msg.RemoteConfig == nil {
				return
			}
			received <- msg.RemoteConfig
			_ = c.SetRemoteConfigStatus(&protobufs.RemoteConfigStatus{
				LastRemoteConfigHash: msg.RemoteConfig.ConfigHash,
				Status:               protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED,
			})
		},
	}, protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig,
		protobufs.AgentCapabilities_AgentCapabilities_ReportsRemoteConfig)
	defer c.Stop(context.Background())
	eventually(t, "agent report", func() bool { r, _ := reg.snapshot(); return len(r) > 0 })

	// Nothing assigned yet: a push is a no-op.
	m.Push(context.Background(), uid)

	reg.assign("receivers: {}\n", hash)
	m.Push(context.Background(), uid)
	select {
	case cfg := <-received:
		if !bytes.Equal(cfg.ConfigHash, hash) || string(cfg.Config.ConfigMap[""].Body) != "receivers: {}\n" {
			t.Fatalf("unexpected remote config: %+v", cfg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not receive pushed config")
	}

	// Once the agent acknowledges the hash, neither a push nor its own
	// status report may trigger a re-offer.
	eventually(t, "status ack", func() bool {
		st, _ := reg.ConfigState(context.Background(), uid)
		return bytes.Equal(st.RemoteConfigHash, hash)
	})
	m.Push(context.Background(), uid)
	select {
	case cfg := <-received:
		t.Fatalf("config re-offered after ack: %+v", cfg)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRemoteConfigNotOfferedWithoutCapability(t *testing.T) {
	m, reg, url := startManager(t)
	uid := uuid.New()
	reg.assign("receivers: {}\n", []byte("hash-v1"))

	received := make(chan struct{}, 1)
	c := startAgent(t, url, "good", uid, types.Callbacks{
		OnMessage: func(_ context.Context, msg *types.MessageData) {
			if msg.RemoteConfig != nil {
				received <- struct{}{}
			}
		},
	})
	defer c.Stop(context.Background())
	eventually(t, "agent report", func() bool { r, _ := reg.snapshot(); return len(r) > 0 })
	m.Push(context.Background(), uid)
	select {
	case <-received:
		t.Fatal("config offered to an agent that does not accept remote config")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRevokedCredentialDisconnectsLiveAgent(t *testing.T) {
	m, reg, url := startManager(t)
	uid := uuid.New()
	// The simulated agent would reconnect immediately; keep rejecting it by
	// pointing it at a credential check that now fails.
	c := startAgent(t, url, "good", uid, types.Callbacks{})
	defer c.Stop(context.Background())
	eventually(t, "agent report", func() bool { r, _ := reg.snapshot(); return len(r) > 0 })

	if n, err := m.EnforceCredentials(context.Background()); err != nil || n != 0 {
		t.Fatalf("valid credential: closed %d connections, err %v", n, err)
	}

	revokedIDs = map[uuid.UUID]bool{goodCredential: true}
	t.Cleanup(func() { revokedIDs = nil })
	n, err := m.EnforceCredentials(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("revoked credential: closed %d connections, err %v", n, err)
	}
	eventually(t, "disconnect recorded", func() bool { _, d := reg.snapshot(); return len(d) >= 1 && d[0] == uid })
}
