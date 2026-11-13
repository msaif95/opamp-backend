// Command fakeidp is a DEVELOPMENT-ONLY OpenID Connect provider for trying
// the single sign-on flow without Okta. It signs in whoever asks, with the
// groups given on the command line. Never expose it beyond localhost.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type pending struct{ challenge, nonce, clientID string }

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "listen address (keep it on localhost)")
	email := flag.String("email", "dev.user@example.com", "email of the signed-in user")
	groups := flag.String("groups", "opamp-admins", "comma-separated groups of the signed-in user")
	flag.Parse()
	issuer := "http://" + *addr

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	var (
		mu    sync.Mutex
		codes = map[string]pending{}
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
			"jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "dev", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		redirect, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || !strings.HasPrefix(redirect.Host, "localhost") && !strings.HasPrefix(redirect.Host, "127.0.0.1") {
			http.Error(w, "fakeidp only redirects to localhost", http.StatusBadRequest)
			return
		}
		code := randomString()
		mu.Lock()
		codes[code] = pending{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), clientID: q.Get("client_id")}
		mu.Unlock()
		rq := redirect.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		redirect.RawQuery = rq.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		p, ok := codes[r.FormValue("code")]
		delete(codes, r.FormValue("code"))
		mu.Unlock()
		sum := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuer, "aud": p.clientID, "sub": "fakeidp|" + *email, "nonce": p.nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
			"email": *email, "name": "Dev User", "groups": strings.Split(*groups, ","),
		})
		tok.Header["kid"] = "dev"
		signed, err := tok.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"access_token": randomString(), "token_type": "Bearer", "id_token": signed})
	})

	log.Printf("DEV-ONLY fake identity provider on %s (user %s, groups %s)", issuer, *email, *groups)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		log.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
