package protocol

import (
	"bytes"
	"context"
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
