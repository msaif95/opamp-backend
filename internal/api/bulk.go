package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// maxBulkAgents bounds one bulk request; each agent is checked, changed and audited on its own.
const maxBulkAgents = 500

// agentActions are the operator actions on one collector, by name. Each
// returns the HTTP status of the outcome and, when refused, why.
var agentActions = map[string]func(s *Server, ctx context.Context, uid uuid.UUID, details map[string]any) (int, string){
	"restart": (*Server).restartOne,
	"pause": func(s *Server, ctx context.Context, uid uuid.UUID, d map[string]any) (int, string) {
		return s.pauseOne(ctx, uid, true, d)
	},
	"resume": func(s *Server, ctx context.Context, uid uuid.UUID, d map[string]any) (int, string) {
		return s.pauseOne(ctx, uid, false, d)
	},
	"delete": (*Server).deleteOne,
}

// agentAction serves one action on the agent in the path.
func (s *Server) agentAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid, ok := pathUUID(w, r, "uid")
		if !ok {
			return
		}
		if status, msg := agentActions[action](s, r.Context(), uid, nil); status >= 400 {
			writeError(w, status, msg)
		} else {
			w.WriteHeader(status)
		}
	}
}

// bulkAgents applies one action to many agents. Every agent is treated
// exactly as by the single-agent endpoint (project role, preconditions,
// audit event), and the answer says what happened to each: one refusal
// does not stop the rest.
func (s *Server) bulkAgents(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action       string      `json:"action"`
		InstanceUIDs []uuid.UUID `json:"instance_uids"`
		// Labels is the change to make when the action is "label".
		Labels labelChange `json:"labels"`
	}
	if !decode(w, r, &req) {
		return
	}
	do, ok := agentActions[req.Action]
	if req.Action == "label" {
		if err := req.Labels.validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(req.Labels.Set)+len(req.Labels.Remove) == 0 {
			writeError(w, http.StatusBadRequest, "labels must set or remove at least one label")
			return
		}
		do, ok = func(s *Server, ctx context.Context, uid uuid.UUID, d map[string]any) (int, string) {
			return s.labelOne(ctx, uid, req.Labels, false, d)
		}, true
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "action must be restart, pause, resume, delete or label")
		return
	}
	if len(req.InstanceUIDs) == 0 || len(req.InstanceUIDs) > maxBulkAgents {
		writeError(w, http.StatusBadRequest, "instance_uids must list between 1 and 500 collectors")
		return
	}
	type result struct {
		InstanceUID uuid.UUID `json:"instance_uid"`
		OK          bool      `json:"ok"`
		Status      int       `json:"status"`
		Error       string    `json:"error,omitempty"`
	}
	results := make([]result, 0, len(req.InstanceUIDs))
	seen := make(map[uuid.UUID]bool, len(req.InstanceUIDs))
	succeeded := 0
	for _, uid := range req.InstanceUIDs {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		status, msg := do(s, r.Context(), uid, map[string]any{"bulk": true})
		if status < 400 {
			succeeded++
		}
		results = append(results, result{InstanceUID: uid, OK: status < 400, Status: status, Error: msg})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "succeeded": succeeded, "failed": len(results) - succeeded})
}

func (s *Server) failed(ctx context.Context, what string, err error) (int, string) {
	s.Log.ErrorContext(ctx, "request failed", "action", what, "err", err)
	return http.StatusInternalServerError, "internal error"
}

func (s *Server) auditAgent(ctx context.Context, action string, uid uuid.UUID, details map[string]any) {
	u, _ := auth.UserFrom(ctx)
	s.audit(ctx, u.Subject, u.Provider, action, "agent", uid.String(), details)
}

// restartOne asks the collector's Supervisor to restart the collector process.
func (s *Server) restartOne(ctx context.Context, uid uuid.UUID, details map[string]any) (int, string) {
	a, err := s.Registry.Get(ctx, uid)
	if errors.Is(err, registry.ErrNotFound) {
		return http.StatusNotFound, "agent not found"
	}
	if err != nil {
		return s.failed(ctx, "agent.restart", err)
	}
	if status, msg := permit(ctx, a.ProjectID, auth.RoleOperator); status != 0 {
		return status, msg
	}
	if a.Capabilities&capAcceptsRestart == 0 {
		return http.StatusConflict, "this collector does not accept restart commands (set accepts_restart_command: true in its Supervisor config)"
	}
	sent, err := s.Registry.RequestRestart(ctx, uid)
	if err != nil {
		return s.failed(ctx, "agent.restart", err)
	}
	if !sent {
		return http.StatusConflict, "the collector is not connected"
	}
	s.auditAgent(ctx, "agent.restart", uid, details)
	return http.StatusAccepted, ""
}

// permitAgent loads the agent's project and checks the caller's role there.
func (s *Server) permitAgent(ctx context.Context, what string, uid uuid.UUID, need auth.Role) (int, string) {
	project, err := s.Registry.ProjectOf(ctx, uid)
	if errors.Is(err, registry.ErrNotFound) {
		return http.StatusNotFound, "not found"
	}
	if err != nil {
		return s.failed(ctx, what, err)
	}
	return permit(ctx, project, need)
}

// pauseOne stops (or resumes) collection on a collector without stopping the process.
func (s *Server) pauseOne(ctx context.Context, uid uuid.UUID, paused bool, details map[string]any) (int, string) {
	action := map[bool]string{true: "agent.pause", false: "agent.resume"}[paused]
	if status, msg := s.permitAgent(ctx, action, uid, auth.RoleOperator); status != 0 {
		return status, msg
	}
	err := s.Registry.SetPaused(ctx, uid, paused)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return http.StatusNotFound, "agent not found"
	case errors.Is(err, registry.ErrNoConfig), errors.Is(err, registry.ErrRemoteConfigUnsupported), errors.Is(err, registry.ErrBridge):
		return http.StatusConflict, err.Error()
	case err != nil:
		return s.failed(ctx, action, err)
	}
	s.auditAgent(ctx, action, uid, details)
	return http.StatusNoContent, ""
}

// deleteOne removes an offline collector from the fleet; a record of it is kept (see Registry.Delete).
func (s *Server) deleteOne(ctx context.Context, uid uuid.UUID, details map[string]any) (int, string) {
	if status, msg := s.permitAgent(ctx, "agent.delete", uid, auth.RoleOperator); status != 0 {
		return status, msg
	}
	u, _ := auth.UserFrom(ctx)
	host, err := s.Registry.Delete(ctx, uid, u.Subject)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return http.StatusNotFound, "agent not found"
	case errors.Is(err, registry.ErrConnected):
		return http.StatusConflict, err.Error()
	case err != nil:
		return s.failed(ctx, "agent.delete", err)
	}
	d := map[string]any{"host_name": host}
	for k, v := range details {
		d[k] = v
	}
	s.auditAgent(ctx, "agent.delete", uid, d)
	return http.StatusNoContent, ""
}

// deletedAgents lists the records kept of removed collectors, newest first.
func (s *Server) deletedAgents(w http.ResponseWriter, r *http.Request) {
	list, err := s.Registry.ListDeleted(r.Context(), scopeOf(r.Context()), 200)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if list == nil {
		list = []registry.DeletedAgent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": list})
}

// deletedAgent returns one removed collector's record with its history and last reported config.
func (s *Server) deletedAgent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid record id")
		return
	}
	d, err := s.Registry.GetDeleted(r.Context(), id)
	if errors.Is(err, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !s.allow(w, r, d.ProjectID, auth.RoleViewer) {
		return
	}
	writeJSON(w, http.StatusOK, d)
}
