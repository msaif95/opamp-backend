package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/access"
	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// withScope resolves what the signed-in user may reach and stores it on the request.
func (s *Server) withScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := auth.UserFrom(r.Context())
		scope, err := s.Projects.Resolve(r.Context(), u)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(access.With(r.Context(), scope)))
	})
}

// allow checks the caller's role on a resource in the given project (nil
// for unassigned) and writes the refusal if it is not enough. Something the
// caller may not even view is reported as not found, so project contents
// cannot be probed by ID.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, project *uuid.UUID, need auth.Role) bool {
	scope := access.From(r.Context())
	switch {
	case scope.Can(project, need):
		return true
	case scope.Can(project, auth.RoleViewer):
		writeError(w, http.StatusForbidden, "your role in this project does not allow this")
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
	return false
}

// allowAgent loads the agent's project and checks the caller's role there.
func (s *Server) allowAgent(w http.ResponseWriter, r *http.Request, uid uuid.UUID, need auth.Role) (*uuid.UUID, bool) {
	project, err := s.Registry.ProjectOf(r.Context(), uid)
	if errors.Is(err, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return nil, false
	}
	if err != nil {
		s.internal(w, r, err)
		return nil, false
	}
	return project, s.allow(w, r, project, need)
}

// allowConfig loads the config's project and checks the caller's role there.
func (s *Server) allowConfig(w http.ResponseWriter, r *http.Request, templateID uuid.UUID, need auth.Role) (*uuid.UUID, bool) {
	project, err := s.Configs.ProjectOf(r.Context(), templateID)
	if errors.Is(err, agentconfig.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not found")
		return nil, false
	}
	if err != nil {
		s.internal(w, r, err)
		return nil, false
	}
	return project, s.allow(w, r, project, need)
}

// targetProject validates the project a new resource is being created in:
// it must exist and the caller must have the needed role there.
func (s *Server) targetProject(w http.ResponseWriter, r *http.Request, project *uuid.UUID, need auth.Role) bool {
	if project != nil {
		ok, err := s.Projects.Exists(r.Context(), *project)
		if err != nil {
			s.internal(w, r, err)
			return false
		}
		if !ok {
			writeError(w, http.StatusBadRequest, "unknown project")
			return false
		}
	}
	if !access.From(r.Context()).Can(project, need) {
		if project == nil {
			writeError(w, http.StatusForbidden, "choose a project: your account cannot create this outside a project")
		} else {
			writeError(w, http.StatusForbidden, "your role in this project does not allow this")
		}
		return false
	}
	return true
}

// sameProject reports whether two resources are in the same project.
func sameProject(a, b *uuid.UUID) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// projectFilter reads ?project_id=<uuid>|none.
func projectFilter(w http.ResponseWriter, r *http.Request) (*registry.ProjectRef, bool) {
	switch v := r.URL.Query().Get("project_id"); v {
	case "":
		return nil, true
	case "none":
		return &registry.ProjectRef{}, true
	default:
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "project_id must be a project ID or none")
			return nil, false
		}
		return &registry.ProjectRef{ID: &id}, true
	}
}

// me returns who is signed in and what they may reach.
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	scope := access.From(r.Context())
	projects, err := s.Projects.List(r.Context(), scope)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	type membership struct {
		ID   uuid.UUID `json:"id"`
		Name string    `json:"name"`
		Role auth.Role `json:"role"`
	}
	list := make([]membership, 0, len(projects))
	for _, p := range projects {
		role := scope.Projects[p.ID]
		if scope.Admin {
			role = auth.RoleAdmin
		}
		list = append(list, membership{p.ID, p.Name, role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": u.Subject, "provider": u.Provider, "role": u.Role, "admin": scope.Admin, "projects": list,
	})
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.Projects.List(r.Context(), access.From(r.Context()))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": nonNil(projects)})
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	p, err := s.Projects.Create(r.Context(), req.Name, req.Description, u.Subject)
	if errors.Is(err, access.ErrProjectNameTaken) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "project.create", "project", p.ID.String(), map[string]any{"name": p.Name})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	err := s.Projects.Delete(r.Context(), id)
	switch {
	case errors.Is(err, access.ErrProjectNotFound):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case errors.Is(err, access.ErrProjectInUse):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "project.delete", "project", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listProjectMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	members, err := s.Projects.Members(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": nonNil(members)})
}

// setProjectMember adds a person to a project or changes their role there.
func (s *Server) setProjectMember(w http.ResponseWriter, r *http.Request) {
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
		writeError(w, http.StatusBadRequest, "subject must be a person's sign-in name (their Okta email, or the local username)")
		return
	case req.Role != auth.RoleViewer && req.Role != auth.RoleOperator && req.Role != auth.RoleAdmin:
		writeError(w, http.StatusBadRequest, "role must be viewer, operator or admin")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	err := s.Projects.SetMember(r.Context(), id, req.Subject, req.Role, u.Subject)
	if errors.Is(err, access.ErrProjectNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "project.member.set", "project", id.String(),
		map[string]any{"subject": strings.ToLower(req.Subject), "role": req.Role})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeProjectMember(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	subject := chi.URLParam(r, "subject")
	if err := s.Projects.RemoveMember(r.Context(), id, subject); err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "project.member.remove", "project", id.String(), map[string]any{"subject": strings.ToLower(subject)})
	w.WriteHeader(http.StatusNoContent)
}

// setAgentProject moves a collector to a project (admin). Collectors that
// connect with an API key follow the key's project instead.
func (s *Server) setAgentProject(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	var req struct {
		ProjectID *uuid.UUID `json:"project_id"`
	}
	if !decode(w, r, &req) || !s.targetProject(w, r, req.ProjectID, auth.RoleAdmin) {
		return
	}
	a, err := s.Registry.Get(r.Context(), uid)
	if errors.Is(err, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if a.AuthMode == "api_key" {
		writeError(w, http.StatusConflict, "this collector connects with an API key, so it follows the key's project; change the key's project under Agent credentials")
		return
	}
	if err := s.Registry.SetProject(r.Context(), uid, req.ProjectID); err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "agent.project.set", "agent", uid.String(), map[string]any{"project_id": req.ProjectID})
	w.WriteHeader(http.StatusNoContent)
}

// setAPIKeyProject moves an agent API key and its collectors to a project (admin).
func (s *Server) setAPIKeyProject(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		ProjectID *uuid.UUID `json:"project_id"`
	}
	if !decode(w, r, &req) || !s.targetProject(w, r, req.ProjectID, auth.RoleAdmin) {
		return
	}
	moved, err := s.Agents.SetAPIKeyProject(r.Context(), id, req.ProjectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "API key not found")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "credential.project.set", "credential", id.String(),
		map[string]any{"project_id": req.ProjectID, "agents_moved": moved})
	writeJSON(w, http.StatusOK, map[string]any{"agents_moved": moved})
}

// scopeOf is shorthand used by list handlers.
func scopeOf(ctx context.Context) access.Scope { return access.From(ctx) }
