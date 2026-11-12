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
	facets, err := s.Registry.Facets(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"facets": nonNil(facets)})
}

func (s *Server) previewRollout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Selector targeting.Selector `json:"selector"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := req.Selector.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.Rollouts.Preview(r.Context(), req.Selector)
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
		AllAgents     bool    `json:"all_agents"`
		BatchSize     int     `json:"batch_size"`
		MaxFailurePct float64 `json:"max_failure_pct"`
	}{BatchSize: rollout.DefaultBatchSize, MaxFailurePct: rollout.DefaultMaxFailurePct}
	if !decode(w, r, &req) {
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
	u, _ := auth.UserFrom(r.Context())
	ro, err := s.Rollouts.Create(r.Context(), v.ID, req.Selector, req.BatchSize, req.MaxFailurePct, u.Subject)
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
		"agents": ro.TotalAgents, "batch_size": ro.BatchSize, "max_failure_pct": ro.MaxFailurePct,
	})
	writeJSON(w, http.StatusCreated, ro)
}

func (s *Server) listRollouts(w http.ResponseWriter, r *http.Request) {
	rollouts, err := s.Rollouts.List(r.Context())
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
