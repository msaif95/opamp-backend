// Package protocol turns AgentToServer messages into registry updates and
// ServerToAgent responses. It speaks only OpAMP messages and makes no
// assumption about how the agent applies them (Supervisor, extension, K8s bridge).
package protocol

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/open-telemetry/opamp-go/protobufs"

	"github.com/msaif95/opamp-backend/internal/registry"
)

// ServerCapabilities advertised to every agent.
const ServerCapabilities = uint64(protobufs.ServerCapabilities_ServerCapabilities_AcceptsStatus |
	protobufs.ServerCapabilities_ServerCapabilities_AcceptsEffectiveConfig)

// Reporter is the slice of the registry the handler needs.
type Reporter interface {
	Report(ctx context.Context, uid uuid.UUID, id registry.Identity, msg *protobufs.AgentToServer) error
}

// Handler processes OpAMP messages.
type Handler struct {
	reg Reporter
	log *slog.Logger
}

// NewHandler creates a Handler.
func NewHandler(reg Reporter, log *slog.Logger) *Handler {
	return &Handler{reg: reg, log: log}
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

	if err := h.reg.Report(ctx, uid, id, msg); err != nil {
		h.log.ErrorContext(ctx, "agent report failed", "instance_uid", uid, "err", err)
		resp.ErrorResponse = &protobufs.ServerErrorResponse{
			Type:         protobufs.ServerErrorResponseType_ServerErrorResponseType_Unavailable,
			ErrorMessage: "registry unavailable",
		}
		return uid, resp
	}

	if needFullState {
		resp.Flags = uint64(protobufs.ServerToAgentFlags_ServerToAgentFlags_ReportFullState)
	}
	return uid, resp
}
