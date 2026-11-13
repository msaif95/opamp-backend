// Package protocol turns AgentToServer messages into registry updates and
// ServerToAgent responses. It speaks only OpAMP messages and makes no
// assumption about how the agent applies them (Supervisor, extension, K8s bridge).
package protocol

import (
	"bytes"
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/logthrottle"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// ServerCapabilities advertised to every agent.
const ServerCapabilities = uint64(protobufs.ServerCapabilities_ServerCapabilities_AcceptsStatus |
	protobufs.ServerCapabilities_ServerCapabilities_AcceptsEffectiveConfig |
	protobufs.ServerCapabilities_ServerCapabilities_OffersRemoteConfig)

const configContentType = "text/yaml"

// Registry is the slice of the agent registry the handler needs.
type Registry interface {
	Report(ctx context.Context, uid uuid.UUID, id registry.Identity, msg *protobufs.AgentToServer) (registry.ConfigState, error)
	ConfigState(ctx context.Context, uid uuid.UUID) (registry.ConfigState, error)
}

// ConfigSource resolves config versions.
type ConfigSource interface {
	Version(ctx context.Context, id uuid.UUID) (*agentconfig.Version, error)
}

// Handler processes OpAMP messages.
type Handler struct {
	reg     Registry
	configs ConfigSource
	log     *slog.Logger
	// During a database outage every agent message fails the same way.
	reportErr *logthrottle.Throttle
}

// NewHandler creates a Handler.
func NewHandler(reg Registry, configs ConfigSource, log *slog.Logger) *Handler {
	return &Handler{reg: reg, configs: configs, log: log, reportErr: logthrottle.New(10 * time.Second)}
}

// Handle processes one message. needFullState asks the agent to resend its
// complete state (set by the caller on a sequence gap or a first message
// that carries no description).
func (h *Handler) Handle(ctx context.Context, id registry.Identity, msg *protobufs.AgentToServer, needFullState bool) (uuid.UUID, *protobufs.ServerToAgent) {
	resp := &protobufs.ServerToAgent{InstanceUid: msg.InstanceUid, Capabilities: ServerCapabilities}

	uid, err := uuid.FromBytes(msg.InstanceUid)
	if err != nil || uid == uuid.Nil {
		resp.ErrorResponse = &protobufs.ServerErrorResponse{
			Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_BadRequest,
			ErrorMessage: "instance_uid must be a non-zero 16-byte UUID",
		}
		return uuid.Nil, resp
	}

	state, err := h.reg.Report(ctx, uid, id, msg)
	if err != nil {
		h.reportErr.Do(func(suppressed int64) {
			h.log.ErrorContext(ctx, "agent report failed", "instance_uid", uid, "err", err, "similar_errors_suppressed", suppressed)
		})
		resp.ErrorResponse = &protobufs.ServerErrorResponse{
			Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_Unavailable,
			ErrorMessage: "registry unavailable",
		}
		return uid, resp
	}

	resp.RemoteConfig = h.pendingConfig(ctx, uid, state)
	if needFullState {
		resp.Flags = uint64(protobufs.ServerToAgentFlags_ServerToAgentFlags_ReportFullState)
	}
	return uid, resp
}

// Offer builds an unsolicited ServerToAgent carrying the agent's desired
// config, or nil if the agent already has it (or has none assigned).
func (h *Handler) Offer(ctx context.Context, uid uuid.UUID) *protobufs.ServerToAgent {
	state, err := h.reg.ConfigState(ctx, uid)
	if err != nil {
		h.log.ErrorContext(ctx, "load agent config state", "instance_uid", uid, "err", err)
		return nil
	}
	cfg := h.pendingConfig(ctx, uid, state)
	if cfg == nil {
		return nil
	}
	return &protobufs.ServerToAgent{InstanceUid: uid[:], Capabilities: ServerCapabilities, RemoteConfig: cfg}
}

// pendingConfig returns the desired config if the agent accepts remote
// config and has not yet acknowledged this exact version. An agent that
// reported the same hash as APPLYING or FAILED is not re-offered it: retry
// policy belongs to the rollout engine, not the transport.
func (h *Handler) pendingConfig(ctx context.Context, uid uuid.UUID, st registry.ConfigState) *protobufs.AgentRemoteConfig {
	if st.DesiredConfigVersionID == nil ||
		st.Capabilities&uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig) == 0 {
		return nil
	}
	v, err := h.configs.Version(ctx, *st.DesiredConfigVersionID)
	if err != nil {
		h.log.ErrorContext(ctx, "load desired config", "instance_uid", uid, "version_id", *st.DesiredConfigVersionID, "err", err)
		return nil
	}
	if bytes.Equal(v.BodyHash, st.RemoteConfigHash) {
		return nil
	}
	return &protobufs.AgentRemoteConfig{
		ConfigHash: v.BodyHash,
		Config: &protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigObject{
			"": {Body: []byte(v.Body), ContentType: configContentType},
		}},
	}
}
