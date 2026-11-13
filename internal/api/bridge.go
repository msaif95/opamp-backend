package api

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/k8sbridge"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// bridgeCollector is one Kubernetes collector as shown on a bridge's page.
type bridgeCollector struct {
	k8sbridge.Collector
	// Assigned is the config given to this collector from the console, if any.
	Assigned *registry.BridgeAssignment `json:"assigned"`
	// InSync is true when the collector runs exactly the assigned config.
	InSync bool `json:"in_sync"`
}

// bridgeCollectors lists the OpenTelemetryCollector resources a Kubernetes OpAMP Bridge reports.
func (s *Server) bridgeCollectors(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	if _, ok := s.allowAgent(w, r, uid, auth.RoleViewer); !ok {
		return
	}
	files, health, assigned, err := s.Registry.BridgeState(r.Context(), uid)
	if errors.Is(err, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "this agent is not a Kubernetes OpAMP Bridge")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	out := []bridgeCollector{}
	for _, c := range k8sbridge.Collectors(files, health) {
		bc := bridgeCollector{Collector: c}
		if a, ok := assigned[c.Key]; ok {
			bc.Assigned, bc.InSync = &a, k8sbridge.SameConfig(c.Config, a.Body)
		}
		out = append(out, bc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"collectors": out})
}

// setBridgeCollectorConfig assigns a config version to one collector behind
// a bridge; a null version removes the assignment and leaves the collector as it is.
func (s *Server) setBridgeCollectorConfig(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	var req struct {
		// Collector is "namespace/name".
		Collector       string     `json:"collector"`
		ConfigVersionID *uuid.UUID `json:"config_version_id"`
	}
	if !decode(w, r, &req) {
		return
	}
	agentProject, ok := s.allowAgent(w, r, uid, auth.RoleOperator)
	if !ok {
		return
	}
	files, health, _, err := s.Registry.BridgeState(r.Context(), uid)
	if errors.Is(err, registry.ErrNotFound) {
		writeError(w, http.StatusNotFound, "this agent is not a Kubernetes OpAMP Bridge")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	var target *k8sbridge.Collector
	for _, c := range k8sbridge.Collectors(files, health) {
		if c.Key == req.Collector {
			target = &c
		}
	}
	switch {
	case target == nil:
		writeError(w, http.StatusNotFound, "the bridge does not report a collector with that namespace and name")
		return
	case !target.Managed:
		writeError(w, http.StatusConflict, "this collector is reported only; label it "+k8sbridge.ManagedLabel+`: "true" in the cluster to manage it from here`)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	details := map[string]any{"collector": req.Collector}
	if req.ConfigVersionID != nil {
		v, err := s.Configs.Version(r.Context(), *req.ConfigVersionID)
		if err != nil {
			s.configError(w, r, err)
			return
		}
		configProject, ok := s.allowConfig(w, r, v.TemplateID, auth.RoleViewer)
		if !ok {
			return
		}
		if !sameProject(agentProject, configProject) && !scopeOf(r.Context()).Admin {
			writeError(w, http.StatusConflict, "the config and the bridge are in different projects")
			return
		}
		details["config_id"], details["version"], details["version_id"] = v.TemplateID, v.Version, v.ID
	}
	if err := s.Registry.SetBridgeConfig(r.Context(), uid, req.Collector, req.ConfigVersionID, u.Subject); err != nil {
		s.internal(w, r, err)
		return
	}
	action := "bridge.collector.config.assign"
	if req.ConfigVersionID == nil {
		action = "bridge.collector.config.unassign"
	}
	s.audit(r.Context(), u.Subject, u.Provider, action, "agent", uid.String(), details)
	w.WriteHeader(http.StatusNoContent)
}
