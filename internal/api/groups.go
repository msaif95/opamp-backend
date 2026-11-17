package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/targeting"
)

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Groups.List(r.Context(), scopeOf(r.Context()))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": nonNil(groups)})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string             `json:"name"`
		Description string             `json:"description"`
		Selector    targeting.Selector `json:"selector"`
		// ProjectID is the project the group belongs to; omit for unassigned.
		ProjectID *uuid.UUID `json:"project_id"`
	}
	if !decode(w, r, &req) || !s.targetProject(w, r, req.ProjectID, auth.RoleOperator) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Selector) == 0 {
		writeError(w, http.StatusBadRequest, "a group needs at least one attribute to match on")
		return
	}
	if err := req.Selector.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grp, err := s.Groups.Create(r.Context(), req.ProjectID, req.Name, req.Description, req.Selector)
	if errors.Is(err, targeting.ErrGroupNameTaken) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.create", "group", grp.ID.String(),
		map[string]any{"name": grp.Name, "selector": grp.Selector})
	writeJSON(w, http.StatusCreated, grp)
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Name        string             `json:"name"`
		Description string             `json:"description"`
		Selector    targeting.Selector `json:"selector"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Selector) == 0 {
		writeError(w, http.StatusBadRequest, "a group needs a name and at least one attribute to match on")
		return
	}
	if err := req.Selector.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := s.allowGroup(w, r, id); !ok {
		return
	}
	grp, err := s.Groups.Update(r.Context(), id, req.Name, req.Description, req.Selector)
	switch {
	case errors.Is(err, targeting.ErrGroupNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case errors.Is(err, targeting.ErrGroupNameTaken):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.update", "group", id.String(),
		map[string]any{"name": grp.Name, "selector": grp.Selector})
	writeJSON(w, http.StatusOK, grp)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, ok := s.allowGroup(w, r, id); !ok {
		return
	}
	err := s.Groups.Delete(r.Context(), id)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.delete", "group", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// setGroupConfig makes the group own a config version and rolls it out to
// the group's current members in batches. Agents that match the group later
// receive it automatically once that rollout has completed.
func (s *Server) setGroupConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	req := struct {
		ConfigVersionID uuid.UUID `json:"config_version_id"`
		BatchSize       int       `json:"batch_size"`
		CanarySteps     []int     `json:"canary_steps_pct"`
		MaxFailurePct   float64   `json:"max_failure_pct"`
		AutoRollback    bool      `json:"auto_rollback"`
	}{BatchSize: rollout.DefaultBatchSize, MaxFailurePct: rollout.DefaultMaxFailurePct}
	if !decode(w, r, &req) {
		return
	}
	grp, ok := s.allowGroup(w, r, id)
	if !ok {
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
	if !sameProject(grp.ProjectID, configProject) && !scopeOf(r.Context()).Admin {
		writeError(w, http.StatusConflict, "the config and the group are in different projects")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	// The rollout is created first: if its parameters are rejected the group is left untouched.
	ro, err := s.Rollouts.Create(r.Context(), rollout.Params{
		VersionID: v.ID, Selector: grp.Selector, ProjectID: grp.ProjectID, GroupID: &id, BatchSize: req.BatchSize,
		CanarySteps: req.CanarySteps, MaxFailurePct: req.MaxFailurePct, AutoRollback: req.AutoRollback, CreatedBy: u.Subject,
	})
	switch {
	case errors.Is(err, rollout.ErrInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, rollout.ErrNoAgents):
		ro = nil // an empty group needs no rollout; agents that join later get the config
	case err != nil:
		s.internal(w, r, err)
		return
	}
	if err := s.Groups.SetConfig(r.Context(), id, &v.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	details := map[string]any{"config_id": v.TemplateID, "version": v.Version, "version_id": v.ID}
	if ro != nil {
		details["rollout_id"] = ro.ID
		details["agents"] = ro.TotalAgents
	}
	s.audit(r.Context(), u.Subject, u.Provider, "group.config.set", "group", id.String(), details)
	writeJSON(w, http.StatusOK, map[string]any{"rollout": ro})
}

// clearGroupConfig stops the group handing out a config. Agents keep the config they have.
func (s *Server) clearGroupConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, ok := s.allowGroup(w, r, id); !ok {
		return
	}
	err := s.Groups.SetConfig(r.Context(), id, nil)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.config.clear", "group", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// allowGroup loads a group and checks the caller may change it, either
// through project-level or group-level operator access.
func (s *Server) allowGroup(w http.ResponseWriter, r *http.Request, id uuid.UUID) (*targeting.Group, bool) {
	grp, err := s.Groups.Get(r.Context(), id)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return nil, false
	}
	if err != nil {
		s.internal(w, r, err)
		return nil, false
	}
	scope := scopeOf(r.Context())
	if scope.CanGroup(id, grp.ProjectID, auth.RoleOperator) {
		return grp, true
	}
	if scope.CanGroup(id, grp.ProjectID, auth.RoleViewer) {
		writeError(w, http.StatusForbidden, "your role does not allow this")
		return nil, false
	}
	writeError(w, http.StatusNotFound, "not found")
	return nil, false
}

// viewGroup loads a group and checks the caller may at least view it.
func (s *Server) viewGroup(w http.ResponseWriter, r *http.Request, id uuid.UUID) (*targeting.Group, bool) {
	grp, err := s.Groups.Get(r.Context(), id)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return nil, false
	}
	if err != nil {
		s.internal(w, r, err)
		return nil, false
	}
	scope := scopeOf(r.Context())
	if scope.CanGroup(id, grp.ProjectID, auth.RoleViewer) {
		return grp, true
	}
	writeError(w, http.StatusNotFound, "not found")
	return nil, false
}

func (s *Server) listGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, ok := s.viewGroup(w, r, id); !ok {
		return
	}
	members, err := s.Projects.GroupMembers(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": nonNil(members)})
}

func (s *Server) setGroupMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Subject string    `json:"subject"`
		Role    auth.Role `json:"role"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	switch {
	case req.Subject == "" || strings.HasPrefix(req.Subject, "token:"):
		writeError(w, http.StatusBadRequest, "subject must be a person's sign-in name")
		return
	case req.Role != auth.RoleViewer && req.Role != auth.RoleOperator:
		writeError(w, http.StatusBadRequest, "role must be viewer or operator")
		return
	}
	grp, err := s.Groups.Get(r.Context(), id)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !s.allow(w, r, grp.ProjectID, auth.RoleOperator) {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	if err := s.Projects.SetGroupMember(r.Context(), id, req.Subject, req.Role, u.Subject); err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "group.member.set", "group", id.String(),
		map[string]any{"subject": strings.ToLower(req.Subject), "role": req.Role})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	grp, err := s.Groups.Get(r.Context(), id)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !s.allow(w, r, grp.ProjectID, auth.RoleOperator) {
		return
	}
	subject := chi.URLParam(r, "subject")
	if err := s.Projects.RemoveGroupMember(r.Context(), id, subject); err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.member.remove", "group", id.String(),
		map[string]any{"subject": strings.ToLower(subject)})
	w.WriteHeader(http.StatusNoContent)
}
