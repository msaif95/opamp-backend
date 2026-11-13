package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/settings"
)

// SystemStatus is how this deployment is configured. It carries no secrets:
// only whether each protection is on.
type SystemStatus struct {
	Version string `json:"version"`
	// DevMode means the production safety checks are switched off.
	DevMode   bool   `json:"dev_mode"`
	SSOIssuer string `json:"sso_issuer"`
	// Fleet-health alert limits in percent; 0 means the rule is not configured.
	AlertOfflinePct          float64 `json:"alert_offline_pct"`
	AlertUnhealthyPct        float64 `json:"alert_unhealthy_pct"`
	AgentOfflineAfterSeconds int     `json:"agent_offline_after_seconds"`
}

// system reports configuration status, the live backend replicas and recent alerts.
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	replicas, err := s.Registry.Replicas(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	alerts, err := s.Alerts.List(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": s.Status, "protections": s.Settings.List(), "replicas": nonNil(replicas), "alerts": alerts,
	})
}

// updateSetting switches one protection on or off for every replica.
func (s *Server) updateSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	err := s.Settings.Set(r.Context(), key, *req.Enabled, u.Subject)
	switch {
	case errors.Is(err, settings.ErrUnknown):
		writeError(w, http.StatusNotFound, err.Error())
		return
	case errors.Is(err, settings.ErrLocked), errors.Is(err, settings.ErrUnavailable), errors.Is(err, settings.ErrLockout):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "setting.update", "setting", key, map[string]any{"enabled": *req.Enabled})
	w.WriteHeader(http.StatusNoContent)
}
