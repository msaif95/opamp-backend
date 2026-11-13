package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

type memSessions struct {
	live map[string]string
	fail error
}

func (m *memSessions) Start(_ context.Context, id, subject string, _ time.Duration) error {
	m.live[id] = subject
	return nil
}
func (m *memSessions) Touch(_ context.Context, id string, _ time.Duration) (bool, error) {
	_, ok := m.live[id]
	return ok, m.fail
}
func (m *memSessions) End(_ context.Context, id string) error { delete(m.live, id); return nil }
func (m *memSessions) EndAll(_ context.Context, subject string) (int, error) {
	n := 0
	for id, s := range m.live {
		if s == subject {
			delete(m.live, id)
			n++
		}
	}
	return n, nil
}

func TestSessionsCanBeEnded(t *testing.T) {
	store := &memSessions{live: map[string]string{}}
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), "")
	s.Store = store
	a1, _ := s.Issue(User{Subject: "Alice@Example.com", Provider: "okta", Role: RoleViewer})
	a2, _ := s.Issue(User{Subject: "alice@example.com", Provider: "okta", Role: RoleViewer})
	bob, _ := s.Issue(User{Subject: "bob", Provider: "okta", Role: RoleViewer})

	u, err := s.Verify(a1)
	if err != nil {
		t.Fatal(err)
	}
	// Signing out ends that session only.
	if err := s.End(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(a1); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("signed-out session: err = %v", err)
	}
	if _, err := s.Verify(a2); err != nil {
		t.Fatalf("other session of the same person ended too: %v", err)
	}
	// An administrator ends all of a person's sessions, whatever the case of the name.
	if n, _ := s.EndAll(context.Background(), "ALICE@example.com"); n != 1 {
		t.Fatalf("ended %d sessions, want 1", n)
	}
	if _, err := s.Verify(a2); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("session survived EndAll: %v", err)
	}
	if _, err := s.Verify(bob); err != nil {
		t.Fatalf("another person was signed out: %v", err)
	}
	// An idle session has dropped out of the store: same result.
	delete(store.live, func() string { u, _ := s.Verify(bob); return u.sessionID }())
	if _, err := s.Verify(bob); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("expired idle session accepted: %v", err)
	}
	// If the store cannot be reached, a validly signed session is still accepted, and the problem is reported.
	carol, _ := s.Issue(User{Subject: "carol", Provider: "okta", Role: RoleViewer})
	store.fail = errors.New("redis down")
	reported := false
	s.OnStoreError = func(error) { reported = true }
	if _, err := s.Verify(carol); err != nil || !reported {
		t.Fatalf("store outage: err = %v, reported = %v", err, reported)
	}
}
