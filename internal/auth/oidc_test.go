package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIssuer is a minimal OIDC provider: discovery, JWKS and a token
// endpoint that enforces PKCE and returns a signed ID token.
type fakeIssuer struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	challenge string // code_challenge seen on the authorize redirect
	nonce     string
	groups    []string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if r.FormValue("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": f.srv.URL, "aud": "client-1", "sub": "00u123", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": f.nonce, "email": "saif@example.com", "name": "Saif", "groups": f.groups,
		})
		tok.Header["kid"] = "k1"
		signed, _ := tok.SignedString(key)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": signed})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// begin starts a login and plays the browser: it records what the provider
// would have seen on the authorize redirect.
func (f *fakeIssuer) begin(t *testing.T, o *OIDC) (cookie, state string) {
	t.Helper()
	redirect, c, err := o.Begin()
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "client-1" {
		t.Fatalf("unexpected authorize URL: %s", redirect)
	}
	f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce")
	return c.Value, q.Get("state")
}

func newTestOIDC(t *testing.T, f *fakeIssuer) *OIDC {
	t.Helper()
	o, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: f.srv.URL, ClientID: "client-1", ClientSecret: "s", RedirectURL: "http://localhost/cb",
		AdminGroups: []string{"opamp-admins"}, OperatorGroups: []string{"opamp-operators", "sre"}, ViewerGroups: []string{"everyone"},
	}, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestOIDCLoginMapsGroupsToHighestRole(t *testing.T) {
	f := newFakeIssuer(t)
	o := newTestOIDC(t, f)
	for _, tc := range []struct {
		groups []string
		want   Role
	}{
		{[]string{"everyone", "sre", "opamp-admins"}, RoleAdmin},
		{[]string{"everyone", "sre"}, RoleOperator},
		{[]string{"everyone"}, RoleViewer},
	} {
		f.groups = tc.groups
		cookie, state := f.begin(t, o)
		id, err := o.Complete(context.Background(), cookie, state, "good-code")
		if err != nil {
			t.Fatalf("%v: %v", tc.groups, err)
		}
		if id.User.Role != tc.want || id.User.Subject != "saif@example.com" || id.User.Provider != "okta" || id.ProviderSub != "00u123" {
			t.Errorf("%v: got %+v", tc.groups, id)
		}
	}
}

func TestOIDCLoginRejections(t *testing.T) {
	f := newFakeIssuer(t)
	o := newTestOIDC(t, f)

	f.groups = []string{"unrelated"}
	cookie, state := f.begin(t, o)
	if _, err := o.Complete(context.Background(), cookie, state, "good-code"); !errors.Is(err, ErrNoRole) {
		t.Errorf("no mapped group: err = %v, want ErrNoRole", err)
	}

	f.groups = []string{"opamp-admins"}
	cookie, state = f.begin(t, o)
	if _, err := o.Complete(context.Background(), cookie, "attacker-state", "good-code"); err == nil {
		t.Error("state mismatch accepted")
	}
	if _, err := o.Complete(context.Background(), "not-a-cookie", state, "good-code"); err == nil {
		t.Error("forged flow cookie accepted")
	}
	if _, err := o.Complete(context.Background(), cookie, state, "bad-code"); err == nil {
		t.Error("bad code accepted")
	}

	// A token minted for a different login (replayed) carries the wrong nonce.
	cookie, state = f.begin(t, o)
	f.nonce = "some-other-login"
	if _, err := o.Complete(context.Background(), cookie, state, "good-code"); err == nil {
		t.Error("nonce mismatch accepted")
	}

	// PKCE: a code intercepted without the verifier is useless.
	cookie, state = f.begin(t, o)
	f.challenge = "someone-elses-challenge"
	if _, err := o.Complete(context.Background(), cookie, state, "good-code"); err == nil {
		t.Error("PKCE verifier mismatch accepted")
	}
}
