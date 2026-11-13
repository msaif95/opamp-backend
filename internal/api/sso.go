package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/msaif95/opamp-backend/internal/auth"
)

func (s *Server) authConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"local": s.Sessions.LocalEnabled(), "okta": s.OIDC != nil})
}

func (s *Server) oktaLogin(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeError(w, http.StatusNotFound, "single sign-on is not configured")
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
	if s.OIDC == nil {
		writeError(w, http.StatusNotFound, "single sign-on is not configured")
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
