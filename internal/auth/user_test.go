package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestLocalLogin(t *testing.T) {
	s := NewSessions(testKey, "s3cret")
	if _, _, err := s.LocalLogin("admin", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, _, err := s.LocalLogin("other", "s3cret"); err == nil {
		t.Fatal("wrong username accepted")
	}
	tok, _, err := s.LocalLogin("admin", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Verify(tok)
	if err != nil || u.Role != RoleAdmin || u.Provider != "local" {
		t.Fatalf("verify = %+v, %v", u, err)
	}
	if _, err := NewSessions([]byte("another-key-another-key-another-k"), "").Verify(tok); err == nil {
		t.Fatal("token verified with wrong key")
	}
}

func TestLocalLoginDisabledWhenPasswordEmpty(t *testing.T) {
	if _, _, err := NewSessions(testKey, "").LocalLogin("admin", ""); err == nil {
		t.Fatal("login accepted with local admin disabled")
	}
}

func TestRequire(t *testing.T) {
	s := NewSessions(testKey, "")
	viewer, _ := s.Issue(User{Subject: "v", Provider: "okta", Role: RoleViewer})
	bogus, _ := s.Issue(User{Subject: "x", Provider: "okta", Role: "superuser"})

	h := s.Require(RoleOperator)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	admin, _ := s.Issue(User{Subject: "a", Provider: "local", Role: RoleAdmin})

	for name, tc := range map[string]struct {
		token string
		want  int
	}{
		"no token":     {"", http.StatusUnauthorized},
		"garbage":      {"not-a-jwt", http.StatusUnauthorized},
		"viewer":       {viewer, http.StatusForbidden},
		"unknown role": {bogus, http.StatusForbidden},
		"admin":        {admin, http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", name, rec.Code, tc.want)
		}
	}
}
