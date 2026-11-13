package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const (
	// OIDCCookie carries the signed login-flow state between redirect and callback.
	OIDCCookie  = "opamp_oidc"
	oidcFlowTTL = 10 * time.Minute
	flowIssuer  = "opamp-backend/oidc-flow"
)

// ErrNoRole is returned when a user authenticates with the identity
// provider but belongs to no group mapped to a role.
var ErrNoRole = errors.New("your account is not in a group that grants access, and has not been added to any project")

// OIDCConfig configures single sign-on (Okta or any OIDC provider).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// GroupsClaim is the ID token claim listing the user's groups.
	GroupsClaim    string
	AdminGroups    []string
	OperatorGroups []string
	ViewerGroups   []string
}

// OIDC runs the authorization-code flow with PKCE.
type OIDC struct {
	// IsProjectMember reports whether a subject belongs to any project.
	IsProjectMember func(ctx context.Context, subject string) bool
	cfg             OIDCConfig
	oauth           oauth2.Config
	verifier        *oidc.IDTokenVerifier
	key             []byte
}

// OIDCIdentity is what the identity provider told us about the user.
type OIDCIdentity struct {
	User        User
	ProviderSub string
	Email       string
	Name        string
}

// NewOIDC performs provider discovery. key signs the short-lived flow cookie.
func NewOIDC(ctx context.Context, cfg OIDCConfig, key []byte) (*OIDC, error) {
	if cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("OIDC requires a client ID and redirect URL")
	}
	if len(cfg.AdminGroups)+len(cfg.OperatorGroups)+len(cfg.ViewerGroups) == 0 {
		return nil, errors.New("OIDC requires at least one group mapped to a role")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", cfg.Issuer, err)
	}
	return &OIDC{
		cfg: cfg,
		key: key,
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// SecureCookies reports whether the flow cookie must be HTTPS-only.
func (o *OIDC) SecureCookies() bool {
	u, err := url.Parse(o.cfg.RedirectURL)
	return err == nil && u.Scheme == "https"
}

type flowClaims struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	jwt.RegisteredClaims
}

// Begin starts a login. It returns the provider URL to redirect the browser
// to and the flow cookie to set on that redirect.
func (o *OIDC) Begin() (redirectURL string, cookie *http.Cookie, err error) {
	state, nonce := randomString(), randomString()
	verifier := oauth2.GenerateVerifier()
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, flowClaims{
		State: state, Nonce: nonce, Verifier: verifier,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    flowIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(oidcFlowTTL)),
		},
	}).SignedString(o.key)
	if err != nil {
		return "", nil, err
	}
	cookie = &http.Cookie{
		Name: OIDCCookie, Value: signed, Path: "/", MaxAge: int(oidcFlowTTL.Seconds()),
		HttpOnly: true, Secure: o.SecureCookies(), SameSite: http.SameSiteLaxMode,
	}
	return o.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), cookie, nil
}

// Complete finishes a login: it checks the callback against the flow
// cookie, exchanges the code, verifies the ID token and maps groups to a role.
func (o *OIDC) Complete(ctx context.Context, flowCookie, state, code string) (*OIDCIdentity, error) {
	var flow flowClaims
	_, err := jwt.ParseWithClaims(flowCookie, &flow, func(*jwt.Token) (any, error) { return o.key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(flowIssuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("login session expired or invalid: %w", err)
	}
	if state == "" || state != flow.State {
		return nil, errors.New("login state mismatch")
	}

	token, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("identity provider returned no id_token")
	}
	idToken, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != flow.Nonce {
		return nil, errors.New("id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	role, hasRole := o.roleFor(claims[o.cfg.GroupsClaim])
	id := &OIDCIdentity{ProviderSub: idToken.Subject}
	id.Email, _ = claims["email"].(string)
	id.Name, _ = claims["name"].(string)
	subject := id.Email
	if subject == "" {
		subject = idToken.Subject
	}
	if !hasRole {
		// No group grants a global role. Someone an admin has added to a
		// project may still sign in; they only see their projects.
		if o.IsProjectMember == nil || !o.IsProjectMember(ctx, subject) {
			return nil, ErrNoRole
		}
		role = RoleNone
	}
	id.User = User{Subject: subject, Provider: "okta", Role: role}
	return id, nil
}

// roleFor returns the highest role granted by the user's groups.
func (o *OIDC) roleFor(groupsClaim any) (Role, bool) {
	list, _ := groupsClaim.([]any)
	groups := make([]string, 0, len(list))
	for _, g := range list {
		if s, ok := g.(string); ok {
			groups = append(groups, s)
		}
	}
	for _, m := range []struct {
		role   Role
		groups []string
	}{{RoleAdmin, o.cfg.AdminGroups}, {RoleOperator, o.cfg.OperatorGroups}, {RoleViewer, o.cfg.ViewerGroups}} {
		if slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(m.groups, g) }) {
			return m.role, true
		}
	}
	return "", false
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
