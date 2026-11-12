package auth

import (
	"context"
	"crypto/subtle"
	"errors"
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
func (r Role) Allows(required Role) bool { return roleRank[r] >= roleRank[required] && roleRank[r] > 0 }

// User is the authenticated human principal attached to a request.
type User struct {
	Subject  string `json:"subject"`
	Provider string `json:"provider"` // okta | local
	Role     Role   `json:"role"`
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
}

// NewSessions creates a Sessions. An empty localAdminPassword disables local login.
func NewSessions(key []byte, localAdminPassword string) *Sessions {
	return &Sessions{key: key, localAdminPassword: localAdminPassword}
}

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
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Provider: u.Provider,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    sessionIssuer,
			Subject:   u.Subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(sessionTTL)),
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
	return User{Subject: c.Subject, Provider: c.Provider, Role: c.Role}, nil
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
			u, err := s.Verify(token)
			if err != nil {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			if !u.Role.Allows(role) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
		})
	}
}
