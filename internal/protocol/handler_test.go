package protocol

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/registry"
)

type oneVersion struct{ v *agentconfig.Version }

func (o oneVersion) Version(context.Context, uuid.UUID) (*agentconfig.Version, error) {
	return o.v, nil
}

func TestPausedAgentGetsEmptyPipelineThenItsConfigBack(t *testing.T) {
	v := &agentconfig.Version{ID: uuid.New(), Body: "receivers: {}", BodyHash: []byte("real-hash")}
	h := &Handler{configs: oneVersion{v}}
	accepts := uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig)
	st := registry.ConfigState{Capabilities: accepts, DesiredConfigVersionID: &v.ID, RemoteConfigHash: v.BodyHash}

	if got := h.pendingConfig(context.Background(), uuid.New(), st); got != nil {
		t.Fatal("in-sync agent was sent a config")
	}
	st.Paused = true
	got := h.pendingConfig(context.Background(), uuid.New(), st)
	if got == nil || string(got.Config.ConfigMap[""].Body) != PausedConfig || bytes.Equal(got.ConfigHash, v.BodyHash) {
		t.Fatalf("paused agent not sent the empty pipeline: %+v", got)
	}
	// Once it reports the paused config applied, nothing more is sent.
	st.RemoteConfigHash = got.ConfigHash
	if again := h.pendingConfig(context.Background(), uuid.New(), st); again != nil {
		t.Fatal("paused config re-sent after it was applied")
	}
	// Resume: the assigned config goes out again.
	st.Paused = false
	if back := h.pendingConfig(context.Background(), uuid.New(), st); back == nil || !bytes.Equal(back.ConfigHash, v.BodyHash) {
		t.Fatalf("resume did not restore the assigned config: %+v", back)
	}
}

func TestSecretsAreResolvedOnlyOnTheWayOut(t *testing.T) {
	v := &agentconfig.Version{ID: uuid.New(), Body: "key: ${secret:k}", BodyHash: []byte("stored-hash")}
	h := &Handler{configs: oneVersion{v}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	st := registry.ConfigState{Capabilities: uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig), DesiredConfigVersionID: &v.ID}

	h.ResolveSecrets = func(_ context.Context, _ uuid.UUID, body string) (string, error) {
		return strings.ReplaceAll(body, "${secret:k}", "the-value"), nil
	}
	got := h.pendingConfig(context.Background(), uuid.New(), st)
	// The collector gets the value; the hash stays that of the stored body.
	if got == nil || string(got.Config.ConfigMap[""].Body) != "key: the-value" || !bytes.Equal(got.ConfigHash, v.BodyHash) {
		t.Fatalf("resolved config = %+v", got)
	}
	// A secret that cannot be resolved means nothing is sent, not a config with a placeholder in it.
	h.ResolveSecrets = func(context.Context, uuid.UUID, string) (string, error) { return "", errors.New("missing") }
	if got := h.pendingConfig(context.Background(), uuid.New(), st); got != nil {
		t.Fatalf("config sent despite an unresolved secret: %s", got.Config.ConfigMap[""].Body)
	}
}

type fixedState struct{ st registry.ConfigState }

func (f fixedState) Report(context.Context, uuid.UUID, registry.Identity, *protobufs.AgentToServer) (registry.ConfigState, error) {
	return f.st, nil
}
func (f fixedState) ConfigState(context.Context, uuid.UUID) (registry.ConfigState, error) {
	return f.st, nil
}
func (f fixedState) BridgeState(context.Context, uuid.UUID) (map[string]string, []byte, map[string]registry.BridgeAssignment, error) {
	return nil, nil, nil, nil
}

// An agent that comes back without describing itself (a polling agent after
// an outage, for instance) is asked for its full state; one that describes
// itself, or was never away, is not.
func TestReturningAgentIsAskedForFullState(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	uid := uuid.New()
	full := uint64(protobufs.ServerToAgentFlags_ServerToAgentFlags_ReportFullState)
	for name, tc := range map[string]struct {
		returned, describes bool
		want                uint64
	}{
		"came back with a bare heartbeat": {true, false, full},
		"came back describing itself":     {true, true, 0},
		"was never away":                  {false, false, 0},
	} {
		h := NewHandler(fixedState{registry.ConfigState{Returned: tc.returned}}, oneVersion{}, log)
		msg := &protobufs.AgentToServer{InstanceUid: uid[:]}
		if tc.describes {
			msg.AgentDescription = &protobufs.AgentDescription{}
		}
		if _, resp := h.Handle(context.Background(), registry.Identity{}, msg, false); resp.Flags != tc.want {
			t.Errorf("%s: flags = %d, want %d", name, resp.Flags, tc.want)
		}
	}
}
