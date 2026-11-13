package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/targeting"
)

func (s *Server) agentFacets(w http.ResponseWriter, r *http.Request) {
	project, ok := projectFilter(w, r)
	if !ok {
		return
	}
	facets, err := s.Registry.Facets(r.Context(), scopeOf(r.Context()), project)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"facets": nonNil(facets)})
}

func (s *Server) previewRollout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Selector targeting.Selector `json:"selector"`
		// ProjectID is the project whose agents are counted; omit for unassigned agents.
		ProjectID *uuid.UUID `json:"project_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := req.Selector.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Someone with no access to that project simply sees no matches.
	if !scopeOf(r.Context()).Can(req.ProjectID, auth.RoleViewer) {
		writeJSON(w, http.StatusOK, rollout.Preview{})
		return
	}
	p, err := s.Rollouts.Preview(r.Context(), req.Selector, req.ProjectID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) createRollout(w http.ResponseWriter, r *http.Request) {
	req := struct {
		ConfigVersionID uuid.UUID          `json:"config_version_id"`
		Selector        targeting.Selector `json:"selector"`
		// AllAgents must be true to target the whole fleet with an empty selector.
		AllAgents bool `json:"all_agents"`
		// GroupID targets a saved group; its selector replaces Selector.
		GroupID       *uuid.UUID `json:"group_id"`
		BatchSize     int        `json:"batch_size"`
		CanarySteps   []int      `json:"canary_steps_pct"`
		MaxFailurePct float64    `json:"max_failure_pct"`
		AutoRollback  bool       `json:"auto_rollback"`
		// ManualApproval pauses after every batch until someone resumes.
		ManualApproval bool `json:"manual_approval"`
		// ProjectID is the project whose agents are targeted; omit for unassigned
		// agents. A group's project takes precedence.
		ProjectID *uuid.UUID `json:"project_id"`
	}{BatchSize: rollout.DefaultBatchSize, MaxFailurePct: rollout.DefaultMaxFailurePct}
	if !decode(w, r, &req) {
		return
	}
	if req.GroupID != nil {
		grp, err := s.Groups.Get(r.Context(), *req.GroupID)
		if errors.Is(err, targeting.ErrGroupNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		req.Selector, req.ProjectID = grp.Selector, grp.ProjectID
	}
	if !s.targetProject(w, r, req.ProjectID, auth.RoleOperator) {
		return
	}
	if err := req.Selector.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Selector) == 0 && !req.AllAgents {
		writeError(w, http.StatusBadRequest, "selector is empty; set all_agents to target the whole fleet")
		return
	}
	v, err := s.Configs.Version(r.Context(), req.ConfigVersionID)
	if err != nil {
		s.configError(w, r, err)
		return
	}
	configProject, ok := s.allowConfig(w, r, v.TemplateID, auth.RoleViewer)
	if !ok {
		return
	}
	// Only a global admin may push a config from one project to collectors in another.
	if !sameProject(req.ProjectID, configProject) && !scopeOf(r.Context()).Admin {
		writeError(w, http.StatusConflict, "the config and the collectors are in different projects")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	ro, err := s.Rollouts.Create(r.Context(), rollout.Params{
		VersionID: v.ID, Selector: req.Selector, ProjectID: req.ProjectID, GroupID: req.GroupID, BatchSize: req.BatchSize,
		CanarySteps: req.CanarySteps, MaxFailurePct: req.MaxFailurePct, AutoRollback: req.AutoRollback, CreatedBy: u.Subject,
		ManualApproval: req.ManualApproval,
	})
	switch {
	case errors.Is(err, rollout.ErrNoAgents):
		writeError(w, http.StatusConflict, err.Error())
		return
	case errors.Is(err, rollout.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "rollout.start", "rollout", ro.ID.String(), map[string]any{
		"config_id": v.TemplateID, "version": v.Version, "selector": req.Selector,
		"agents": ro.TotalAgents, "batch_size": ro.BatchSize, "canary_steps_pct": ro.CanarySteps,
		"max_failure_pct": ro.MaxFailurePct, "auto_rollback": ro.AutoRollback, "group_id": ro.GroupID,
	})
	writeJSON(w, http.StatusCreated, ro)
}

func (s *Server) listRollouts(w http.ResponseWriter, r *http.Request) {
	rollouts, err := s.Rollouts.List(r.Context(), scopeOf(r.Context()))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rollouts": nonNil(rollouts)})
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	ro, err := s.Rollouts.Get(r.Context(), id)
	if err != nil {
		s.rolloutError(w, r, err)
		return
	}
	if !s.allow(w, r, ro.ProjectID, auth.RoleViewer) {
		return
	}
	problems, err := s.Rollouts.Problems(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rollout": ro, "problems": nonNil(problems)})
}

func (s *Server) rolloutAction(action string, do func(*Server, *http.Request, uuid.UUID) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathUUID(w, r, "id")
		if !ok {
			return
		}
		ro, err := s.Rollouts.Get(r.Context(), id)
		if err != nil {
			s.rolloutError(w, r, err)
			return
		}
		if !s.allow(w, r, ro.ProjectID, auth.RoleOperator) {
			return
		}
		if err := do(s, r, id); err != nil {
			s.rolloutError(w, r, err)
			return
		}
		u, _ := auth.UserFrom(r.Context())
		s.audit(r.Context(), u.Subject, u.Provider, "rollout."+action, "rollout", id.String(), nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) rolloutError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, rollout.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, rollout.ErrBadState):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.internal(w, r, err)
	}
}
