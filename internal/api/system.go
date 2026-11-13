package api

import "net/http"

// SystemStatus is how this deployment is configured. It carries no secrets:
// only whether each protection is on.
type SystemStatus struct {
	Version string `json:"version"`
	// DevMode means the production safety checks are switched off.
	DevMode    bool   `json:"dev_mode"`
	SSO        bool   `json:"sso"`
	SSOIssuer  string `json:"sso_issuer"`
	LocalLogin bool   `json:"local_login"`
	// AgentTLS and AgentMTLS describe the OpAMP listener agents connect to.
	AgentTLS  bool `json:"agent_tls"`
	AgentMTLS bool `json:"agent_mtls"`
	// AlertWebhook is whether alerts are delivered anywhere.
	AlertWebhook bool `json:"alert_webhook"`
	// Telemetry is whether the backend exports its own metrics and traces.
	Telemetry bool `json:"telemetry"`
	// Rebalancing is whether overloaded replicas shed connections to even out load.
	Rebalancing bool `json:"rebalancing"`
	// Fleet-health alert limits in percent; 0 means the rule is off.
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
	writeJSON(w, http.StatusOK, map[string]any{"status": s.Status, "replicas": nonNil(replicas), "alerts": alerts})
}
