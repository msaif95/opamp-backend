package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Role is a global RBAC role. Higher roles include lower ones.
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

var roleRank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// Allows reports whether r satisfies the required role.
// RoleNone is the global role of someone who only has project memberships.
const RoleNone Role = ""

func (r Role) Allows(required Role) bool { return roleRank[r] >= roleRank[required] && roleRank[r] > 0 }

// User is the authenticated human principal attached to a request.
type User struct {
	Subject  string `json:"subject"`
	Provider string `json:"provider"` // okta | local
	Role     Role   `json:"role"`
	// TokenProject is set for an API token bound to one project.
	TokenProject *uuid.UUID `json:"-"`
	// TokenLimits are an API token's own rate limits, where it has any.
	TokenLimits TokenLimits `json:"-"`
	sessionID   string
}

type claims struct {
	Provider string `json:"idp"`
	Role     Role   `json:"role"`
	jwt.RegisteredClaims
}

const (
	sessionIssuer = "opamp-backend"
	sessionTTL    = 8 * time.Hour
	localAdmin    = "admin"
)

// ErrInvalidCredentials is returned for a failed local login.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Sessions issues and verifies human session tokens.
type Sessions struct {
	key                []byte
	localAdminPassword string
	// APITokens resolves a console API token to the user it acts as.
	APITokens func(ctx context.Context, secret string) (User, error)

	// Store, if set, makes sessions revocable and subject to IdleTimeout.
	// Without it a session is valid until its token expires.
	Store SessionStore
	// IdleTimeout ends a session not used for this long; MaxAge ends it regardless.
	IdleTimeout time.Duration
	MaxAge      time.Duration
	// OnStoreError is called when the store cannot be reached. The session
	// is then accepted on its signature alone: failing closed would lock
	// every administrator out of the console during a Redis outage.
	OnStoreError func(err error)
}

// NewSessions creates a Sessions. An empty localAdminPassword disables local login.
func NewSessions(key []byte, localAdminPassword string) *Sessions {
	return &Sessions{key: key, localAdminPassword: localAdminPassword, IdleTimeout: 30 * time.Minute, MaxAge: sessionTTL}
}

// LocalEnabled reports whether the break-glass local admin login is configured.
func (s *Sessions) LocalEnabled() bool { return s.localAdminPassword != "" }

// LocalLogin authenticates the break-glass local admin and returns a session token.
func (s *Sessions) LocalLogin(username, password string) (string, User, error) {
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(localAdmin))
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(s.localAdminPassword))
	if s.localAdminPassword == "" || userOK&passOK != 1 {
		return "", User{}, ErrInvalidCredentials
	}
	u := User{Subject: localAdmin, Provider: "local", Role: RoleAdmin}
	tok, err := s.Issue(u)
	return tok, u, err
}

// Issue signs a session token for u.
func (s *Sessions) Issue(u User) (string, error) {
	now := time.Now()
	id := uuid.NewString()
	if s.Store != nil {
		if err := s.Store.Start(context.Background(), id, strings.ToLower(u.Subject), s.IdleTimeout); err != nil {
			return "", err
		}
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Provider: u.Provider,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    sessionIssuer,
			ID:        id,
			Subject:   u.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.MaxAge)),
		},
	}).SignedString(s.key)
}

// Verify parses and validates a session token.
func (s *Sessions) Verify(token string) (User, error) {
	var c claims
	_, err := jwt.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return s.key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(sessionIssuer), jwt.WithExpirationRequired())
	if err != nil {
		return User{}, err
	}
	if s.Store != nil {
		live, err := s.Store.Touch(context.Background(), c.ID, s.IdleTimeout)
		switch {
		case err != nil:
			if s.OnStoreError != nil {
				s.OnStoreError(err)
			}
		case !live:
			return User{}, ErrSessionEnded
		}
	}
	return User{Subject: c.Subject, Provider: c.Provider, Role: c.Role, sessionID: c.ID}, nil
}

// ErrSessionEnded is returned for a session that was signed out, ended by an administrator or left idle too long.
var ErrSessionEnded = errors.New("session ended")

// End signs out the session behind u.
func (s *Sessions) End(ctx context.Context, u User) error {
	if s.Store == nil || u.sessionID == "" {
		return nil
	}
	return s.Store.End(ctx, u.sessionID)
}

// EndAll signs a person out everywhere and returns how many sessions were ended.
func (s *Sessions) EndAll(ctx context.Context, subject string) (int, error) {
	if s.Store == nil {
		return 0, nil
	}
	return s.Store.EndAll(ctx, strings.ToLower(subject))
}

type userKey struct{}

// UserFrom returns the authenticated user stored on the request context.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey{}).(User)
	return u, ok
}

// Require is middleware that enforces a valid session with at least the given role.
// The token is read from the Authorization header, or the access_token query
// parameter for EventSource clients, which cannot set headers.
func (s *Sessions) Require(role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok {
				token = r.URL.Query().Get("access_token")
			}
			var (
				u   User
				err error
			)
			if strings.HasPrefix(token, TokenPrefix) && s.APITokens != nil {
				u, err = s.APITokens(r.Context(), token)
			} else {
				u, err = s.Verify(token)
			}
			if err != nil {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			// RoleNone admits any signed-in user; what they may reach is decided per project.
			if role != RoleNone && !u.Role.Allows(role) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
		})
	}
}
