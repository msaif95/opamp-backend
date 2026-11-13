package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/settings"
)

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"local": s.Settings.Enabled(settings.LocalLogin), "okta": s.ssoOn(),
	})
}

// ssoOn reports whether single sign-on is configured and not switched off.
func (s *Server) ssoOn() bool { return s.OIDC != nil && s.Settings.Enabled(settings.SSO) }

func (s *Server) oktaLogin(w http.ResponseWriter, r *http.Request) {
	if !s.ssoOn() {
		writeError(w, http.StatusNotFound, "single sign-on is not configured or is switched off")
		return
	}
	redirect, cookie, err := s.OIDC.Begin()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// oktaCallback completes the login and hands the session token to the UI in
// the URL fragment, which browsers never send to servers or write to access logs.
func (s *Server) oktaCallback(w http.ResponseWriter, r *http.Request) {
	if !s.ssoOn() {
		writeError(w, http.StatusNotFound, "single sign-on is not configured or is switched off")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: auth.OIDCCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.OIDC.SecureCookies()})
	fail := func(msg string) {
		http.Redirect(w, r, "/#login_error="+url.QueryEscape(msg), http.StatusFound)
	}

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.Log.WarnContext(r.Context(), "sso provider returned an error", "error", e, "description", q.Get("error_description"))
		fail("Sign-in was cancelled or denied by the identity provider.")
		return
	}
	cookie, err := r.Cookie(auth.OIDCCookie)
	if err != nil {
		fail("Sign-in session expired. Please try again.")
		return
	}
	id, err := s.OIDC.Complete(r.Context(), cookie.Value, q.Get("state"), q.Get("code"))
	if errors.Is(err, auth.ErrNoRole) {
		s.audit(r.Context(), "unknown", "okta", "auth.login_denied", "user", "", map[string]any{"reason": "no mapped group"})
		fail(err.Error())
		return
	}
	if err != nil {
		s.Log.WarnContext(r.Context(), "sso login failed", "err", err)
		fail("Sign-in failed. Please try again.")
		return
	}

	_, err = s.DB.Exec(r.Context(), `
INSERT INTO users (provider, subject, email, display_name, last_login_at) VALUES ('okta', $1, $2, $3, now())
ON CONFLICT (provider, subject) DO UPDATE SET email = EXCLUDED.email, display_name = EXCLUDED.display_name, last_login_at = now()`,
		id.ProviderSub, id.Email, id.Name)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	token, err := s.Sessions.Issue(id.User)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), id.User.Subject, "okta", "auth.login", "user", id.User.Subject, map[string]any{"role": id.User.Role})
	http.Redirect(w, r, "/#token="+url.QueryEscape(token), http.StatusFound)
}

// AuditEvent is one audit log entry.
type AuditEvent struct {
	ID         int64          `json:"id"`
	OccurredAt string         `json:"occurred_at"`
	Actor      string         `json:"actor"`
	ActorAuth  string         `json:"actor_auth"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   *string        `json:"target_id"`
	Details    map[string]any `json:"details"`
}

// listAudit supports ?limit=, ?before=<id> for paging and ?q= to search
// action, actor and target.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var before *int64
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "before must be an event id")
			return
		}
		before = &n
	}
	rows, err := s.DB.Query(r.Context(), `
SELECT id, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), actor, actor_auth, action, target_type, target_id, details
FROM audit_events
WHERE ($1::bigint IS NULL OR id < $1)
  AND ($2 = '' OR action ILIKE '%' || $2 || '%' OR actor ILIKE '%' || $2 || '%' OR target_id ILIKE '%' || $2 || '%')
ORDER BY id DESC LIMIT $3`, before, q.Get("q"), limit)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Actor, &e.ActorAuth, &e.Action, &e.TargetType, &e.TargetID, &e.Details); err != nil {
			s.internal(w, r, err)
			return
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.Tokens.List(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": nonNil(tokens)})
}

// createToken issues a console API token for the CLI or automation. The secret is returned once.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string    `json:"name"`
		Role        auth.Role `json:"role"`
		ExpiresDays int       `json:"expires_days"`
	}
	if !decode(w, r, &req) {
		return
	}
	switch {
	case strings.TrimSpace(req.Name) == "":
		writeError(w, http.StatusBadRequest, "name is required")
		return
	case req.Role != auth.RoleViewer && req.Role != auth.RoleOperator && req.Role != auth.RoleAdmin:
		writeError(w, http.StatusBadRequest, "role must be viewer, operator or admin")
		return
	case req.ExpiresDays < 0:
		writeError(w, http.StatusBadRequest, "expires_days must be 0 or more")
		return
	}
	var expires *time.Time
	if req.ExpiresDays > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresDays)
		expires = &t
	}
	u, _ := auth.UserFrom(r.Context())
	tok, err := s.Tokens.Create(r.Context(), req.Name, req.Role, u.Subject, expires)
	if errors.Is(err, auth.ErrTokenNameTaken) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "api_token.create", "api_token", tok.ID.String(),
		map[string]any{"name": tok.Name, "role": tok.Role})
	writeJSON(w, http.StatusCreated, tok)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	err := s.Tokens.Revoke(r.Context(), id)
	if errors.Is(err, auth.ErrTokenNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "api_token.revoke", "api_token", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}
