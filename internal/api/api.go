// Package api serves the REST API consumed by opamp-ui.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/alert"
	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/registry"
	"github.com/msaif95/opamp-backend/internal/rollout"
	"github.com/msaif95/opamp-backend/internal/settings"
	"github.com/msaif95/opamp-backend/internal/targeting"
)

// Server holds the API dependencies.
type Server struct {
	DB       *pgxpool.Pool
	Registry *registry.Registry
	Configs  *agentconfig.Service
	Rollouts *rollout.Service
	Agents   *auth.AgentAuthenticator
	Sessions *auth.Sessions
	// OIDC is nil when single sign-on is not configured.
	OIDC   *auth.OIDC
	Groups *targeting.Groups
	Events http.Handler
	Log    *slog.Logger
	// Status describes how this deployment is configured, for the System page.
	Status   SystemStatus
	Settings *settings.Store
	Alerts   *alert.Store
	// Logins rate-limits failed local logins.
	Logins *auth.LoginLimiter
	// TrustProxyHeaders makes the client address come from X-Forwarded-For.
	// Enable only when the API is reachable solely through a trusted proxy.
	TrustProxyHeaders bool
	// Ready reports whether backing stores are reachable.
	Ready func(ctx context.Context) error
}

// Router builds the HTTP handler.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
		})
	})

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Ready(r.Context()); err != nil {
			s.Log.Warn("not ready", "err", err)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/auth/login", s.login)
		r.Get("/auth/config", s.authConfig)
		r.Get("/auth/okta/login", s.oktaLogin)
		r.Get("/auth/okta/callback", s.oktaCallback)

		r.Group(func(r chi.Router) {
			r.Use(s.Sessions.Require(auth.RoleViewer))
			r.Get("/auth/me", s.me)
			r.Get("/summary", s.summary)
			r.Get("/agents", s.listAgents)
			r.Get("/agents/facets", s.agentFacets)
			r.Get("/groups", s.listGroups)
			r.Get("/rollouts", s.listRollouts)
			r.Post("/rollouts/preview", s.previewRollout)
			r.Get("/rollouts/{id}", s.getRollout)
			r.Get("/agents/{uid}", s.getAgent)
			r.Method(http.MethodGet, "/events", s.Events)
			r.Get("/configs", s.listConfigs)
			r.Post("/configs/validate", s.validateConfig)
			r.Get("/configs/{id}", s.getConfig)
			r.Get("/configs/{id}/versions/{version}", s.getConfigVersion)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.Sessions.Require(auth.RoleOperator))
			r.Post("/configs", s.createConfig)
			r.Post("/configs/{id}/versions", s.addConfigVersion)
			r.Delete("/configs/{id}", s.deleteConfig)
			r.Put("/agents/{uid}/config", s.assignConfig)
			r.Post("/groups", s.createGroup)
			r.Put("/groups/{id}", s.updateGroup)
			r.Put("/groups/{id}/config", s.setGroupConfig)
			r.Delete("/groups/{id}/config", s.clearGroupConfig)
			r.Delete("/groups/{id}", s.deleteGroup)
			r.Post("/rollouts", s.createRollout)
			r.Post("/rollouts/{id}/rollback", s.rolloutAction("rollback", func(s *Server, r *http.Request, id uuid.UUID) error {
				return s.Rollouts.Rollback(r.Context(), id)
			}))
			r.Post("/rollouts/{id}/pause", s.rolloutAction("pause", func(s *Server, r *http.Request, id uuid.UUID) error {
				return s.Rollouts.Pause(r.Context(), id)
			}))
			r.Post("/rollouts/{id}/resume", s.rolloutAction("resume", func(s *Server, r *http.Request, id uuid.UUID) error {
				return s.Rollouts.Resume(r.Context(), id)
			}))
			r.Post("/rollouts/{id}/abort", s.rolloutAction("abort", func(s *Server, r *http.Request, id uuid.UUID) error {
				return s.Rollouts.Abort(r.Context(), id)
			}))
		})

		r.Group(func(r chi.Router) {
			r.Use(s.Sessions.Require(auth.RoleAdmin))
			r.Get("/audit", s.listAudit)
			r.Get("/system", s.system)
			r.Put("/system/settings/{key}", s.updateSetting)
			r.Get("/credentials/api-keys", s.listAPIKeys)
			r.Post("/credentials/api-keys", s.issueAPIKey)
			r.Delete("/credentials/{id}", s.revokeCredential)
			r.Get("/credentials/revoked-certs", s.listRevokedCerts)
			r.Post("/credentials/revoked-certs", s.revokeCert)
		})
	})
	return r
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !s.Settings.Enabled(settings.LocalLogin) {
		writeError(w, http.StatusForbidden, "local sign-in is switched off")
		return
	}
	client := s.clientAddr(r)
	if wait := s.Logins.Blocked(r.Context(), client); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed sign-in attempts; try again later")
		return
	}
	token, user, err := s.Sessions.LocalLogin(req.Username, req.Password)
	if err != nil {
		s.Logins.Fail(r.Context(), client)
		s.audit(r.Context(), req.Username, "local", "auth.login_failed", "user", req.Username, nil)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.audit(r.Context(), user.Subject, user.Provider, "auth.login", "user", user.Subject, nil)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": user})
}

// clientAddr returns the caller's IP address for rate limiting.
func (s *Server) clientAddr(r *http.Request) string {
	if s.TrustProxyHeaders {
		if first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ","); strings.TrimSpace(first) != "" {
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u, _ := auth.UserFrom(r.Context())
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.Registry.Summarize(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// listAgents supports ?limit=&offset=, the filters ?connected= and ?healthy=
// (true|false), ?config_status= and repeated ?attr=key=value, and ordering
// with ?sort=name|last_seen and ?order=asc|desc.
func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := registry.ListFilter{Attributes: map[string]string{}}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if f.Offset < 0 {
		f.Offset = 0
	}
	for name, dst := range map[string]**bool{"connected": &f.Connected, "healthy": &f.Healthy} {
		if v := q.Get(name); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, name+" must be true or false")
				return
			}
			*dst = &b
		}
	}
	if v := q.Get("config_status"); v != "" {
		if !slices.Contains([]string{"unset", "applied", "applying", "failed"}, v) {
			writeError(w, http.StatusBadRequest, "config_status must be unset, applied, applying or failed")
			return
		}
		f.ConfigStatus = &v
	}
	switch f.Sort = q.Get("sort"); f.Sort {
	case "", registry.SortName, registry.SortLastSeen:
	default:
		writeError(w, http.StatusBadRequest, "sort must be name or last_seen")
		return
	}
	switch q.Get("order") {
	case "", "asc":
	case "desc":
		f.Desc = true
	default:
		writeError(w, http.StatusBadRequest, "order must be asc or desc")
		return
	}
	if v := q.Get("group_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid group_id")
			return
		}
		grp, err := s.Groups.Get(r.Context(), id)
		if errors.Is(err, targeting.ErrGroupNotFound) {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		f.Selector = grp.Selector
	}
	for _, kv := range q["attr"] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			writeError(w, http.StatusBadRequest, "attr must be key=value")
			return
		}
		f.Attributes[k] = v
	}

	agents, total, err := s.Registry.List(r.Context(), f)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if agents == nil {
		agents = []registry.Agent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents, "total": total})
}

func (s *Server) getAgent(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(chi.URLParam(r, "uid"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid instance uid")
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
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Agents.ListAPIKeys(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if keys == nil {
		keys = []auth.APIKey{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": keys})
}

func (s *Server) issueAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string     `json:"name"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		writeError(w, http.StatusBadRequest, "expires_at must be in the future")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	key, err := s.Agents.IssueAPIKey(r.Context(), req.Name, u.Subject, req.ExpiresAt)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "credential.issue", "credential", key.ID.String(),
		map[string]any{"kind": "api_key", "name": key.Name})
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) revokeCredential(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	changed, err := s.Agents.Revoke(r.Context(), id)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !changed {
		writeError(w, http.StatusNotFound, "credential not found or already revoked")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "credential.revoke", "credential", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listRevokedCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.Agents.ListRevokedCerts(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked_certs": nonNil(certs)})
}

// revokeCert blocks one agent client certificate even though it chains to the trusted CA.
func (s *Server) revokeCert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string `json:"name"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	cert, err := s.Agents.RevokeCert(r.Context(), req.CertificatePEM, strings.TrimSpace(req.Name), u.Subject)
	if errors.Is(err, auth.ErrBadCertificate) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "credential.revoke_cert", "credential", cert.ID.String(),
		map[string]any{"fingerprint_sha256": cert.Fingerprint, "subject": cert.Subject})
	writeJSON(w, http.StatusCreated, cert)
}

func (s *Server) audit(ctx context.Context, actor, actorAuth, action, targetType, targetID string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	b, _ := json.Marshal(details)
	_, err := s.DB.Exec(ctx, `
INSERT INTO audit_events (actor, actor_auth, action, target_type, target_id, details)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)`, actor, actorAuth, action, targetType, targetID, b)
	if err != nil {
		s.Log.ErrorContext(ctx, "audit write failed", "action", action, "err", err)
	}
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
