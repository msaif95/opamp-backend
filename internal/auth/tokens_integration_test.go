package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestAPITokens(t *testing.T) {
	db, _ := testdb.Open(t)
	ctx := context.Background()
	tokens := auth.NewTokens(db)

	tok, err := tokens.Create(ctx, "ci", auth.RoleOperator, nil, "alice", nil)
	if err != nil || !strings.HasPrefix(tok.Secret, auth.TokenPrefix) {
		t.Fatalf("create: %v %+v", err, tok)
	}
	if _, err := tokens.Create(ctx, "ci", auth.RoleViewer, nil, "alice", nil); !errors.Is(err, auth.ErrTokenNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
	u, err := tokens.Authenticate(ctx, tok.Secret)
	if err != nil || u.Role != auth.RoleOperator || u.Subject != "token:ci" || u.Provider != "token" {
		t.Fatalf("authenticate: %v %+v", err, u)
	}
	if _, err := tokens.Authenticate(ctx, tok.Secret+"x"); err == nil {
		t.Fatal("wrong secret accepted")
	}

	// Through the middleware: a token is accepted where a session would be, with its own role.
	sessions := auth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "")
	sessions.APITokens = tokens.Authenticate
	call := func(role auth.Role, secret string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		sessions.Require(role)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
		return rec.Code
	}
	if call(auth.RoleOperator, tok.Secret) != 200 || call(auth.RoleAdmin, tok.Secret) != 403 || call(auth.RoleViewer, auth.TokenPrefix+"nope") != 401 {
		t.Fatal("middleware did not apply the token's role")
	}

	// Expired and revoked tokens stop working at once.
	past := time.Now().Add(-time.Hour)
	old, _ := tokens.Create(ctx, "old", auth.RoleAdmin, nil, "alice", &past)
	if _, err := tokens.Authenticate(ctx, old.Secret); err == nil {
		t.Fatal("expired token accepted")
	}
	if err := tokens.Revoke(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if call(auth.RoleViewer, tok.Secret) != 401 {
		t.Fatal("revoked token accepted")
	}
	if err := tokens.Revoke(ctx, tok.ID); !errors.Is(err, auth.ErrTokenNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	list, _ := tokens.List(ctx)
	if len(list) != 2 || list[0].Secret != "" {
		t.Fatalf("list = %+v", list)
	}
}
