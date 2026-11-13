package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/registry"
)

func (s *Server) listConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := s.Configs.List(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if configs == nil {
		configs = []agentconfig.Template{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"configs": configs})
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Body string `json:"body"`
	}
	if !decode(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issues": nonNil(agentconfig.Validate(req.Body))})
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	t, versions, err := s.Configs.Get(r.Context(), id)
	if err != nil {
		s.configError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": t, "versions": versions})
}

func (s *Server) getConfigVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	n, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "version must be a number")
		return
	}
	v, err := s.Configs.VersionByNumber(r.Context(), id, n)
	if err != nil {
		s.configError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) createConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Body        string `json:"body"`
		// Builder, if set, is a pipeline from the config builder; the body is rendered from it.
		Builder *pipeline.Spec `json:"builder"`
	}
	if !decode(w, r, &req) {
		return
	}
	spec, ok := s.renderBuilder(w, req.Builder, &req.Body)
	if !ok {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	t, v, err := s.Configs.Create(r.Context(), req.Name, req.Description, req.Body, u.Subject, spec)
	if err != nil {
		s.configError(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "config.create", "config", t.ID.String(),
		map[string]any{"name": t.Name, "version_id": v.ID})
	writeJSON(w, http.StatusCreated, map[string]any{"config": t, "version": v})
}

func (s *Server) addConfigVersion(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Body        string         `json:"body"`
		Description string         `json:"description"`
		Builder     *pipeline.Spec `json:"builder"`
	}
	if !decode(w, r, &req) {
		return
	}
	spec, ok := s.renderBuilder(w, req.Builder, &req.Body)
	if !ok {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	v, err := s.Configs.AddVersion(r.Context(), id, req.Body, req.Description, u.Subject, spec)
	if err != nil {
		s.configError(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "config.version.create", "config", id.String(),
		map[string]any{"version": v.Version, "version_id": v.ID})
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) deleteConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.Configs.Delete(r.Context(), id); err != nil {
		s.configError(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "config.delete", "config", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// assignConfig sets the agent's desired config version and triggers a push.
func (s *Server) assignConfig(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	var req struct {
		ConfigVersionID uuid.UUID `json:"config_version_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	v, err := s.Configs.Version(r.Context(), req.ConfigVersionID)
	if err != nil {
		s.configError(w, r, err)
		return
	}
	err = s.Registry.SetDesiredConfig(r.Context(), uid, v.ID)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		writeError(w, http.StatusNotFound, "agent not found")
		return
	case errors.Is(err, registry.ErrRemoteConfigUnsupported):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "agent.config.assign", "agent", uid.String(),
		map[string]any{"config_id": v.TemplateID, "version": v.Version, "version_id": v.ID})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) configError(w http.ResponseWriter, r *http.Request, err error) {
	var invalid *agentconfig.InvalidError
	switch {
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "issues": invalid.Issues})
	case errors.Is(err, agentconfig.ErrNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, agentconfig.ErrReadOnly), errors.Is(err, agentconfig.ErrNameTaken),
		errors.Is(err, agentconfig.ErrUnchanged), errors.Is(err, agentconfig.ErrInUse):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.internal(w, r, err)
	}
}

func pathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid "+name)
		return uuid.Nil, false
	}
	return id, true
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// builderCatalog lists the component types the config builder offers.
func (s *Server) builderCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"types": pipeline.Catalog()})
}

// builderRender previews the collector YAML a builder pipeline produces, without saving anything.
func (s *Server) builderRender(w http.ResponseWriter, r *http.Request) {
	var spec pipeline.Spec
	if !decode(w, r, &spec) {
		return
	}
	body, issues := pipeline.Render(spec)
	writeJSON(w, http.StatusOK, map[string]any{"body": body, "issues": nonNil(issues)})
}

// renderBuilder replaces *body with the YAML rendered from a builder
// pipeline, if one was sent, and returns the pipeline to store alongside
// it. It reports false after writing an error response.
func (s *Server) renderBuilder(w http.ResponseWriter, spec *pipeline.Spec, body *string) (json.RawMessage, bool) {
	if spec == nil {
		return nil, true
	}
	rendered, issues := pipeline.Render(*spec)
	if agentconfig.HasErrors(issues) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "the pipeline is not complete", "issues": issues})
		return nil, false
	}
	*body = rendered
	raw, err := json.Marshal(spec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	return raw, true
}
