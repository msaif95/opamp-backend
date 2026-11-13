package secrets_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/secrets"
	"github.com/msaif95/opamp-backend/internal/testdb"
)

func TestSecrets(t *testing.T) {
	db, _ := testdb.Open(t)
	ctx := context.Background()
	s, err := secrets.New(db, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, nil, "vendor_key", "s3cr3t-value", "alice"); err != nil {
		t.Fatal(err)
	}
	body := "headers:\n  api-key: ${secret:vendor_key}\n"
	got, err := s.Resolve(ctx, nil, body)
	if err != nil || !strings.Contains(got, "api-key: s3cr3t-value") {
		t.Fatalf("resolve: %q, %v", got, err)
	}
	// The value is not in the database in clear text.
	var raw []byte
	_ = db.QueryRow(ctx, `SELECT ciphertext FROM secrets`).Scan(&raw)
	if strings.Contains(string(raw), "s3cr3t") {
		t.Fatal("secret stored in clear text")
	}
	if _, err := s.Resolve(ctx, nil, "x: ${secret:missing}"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	// A different key cannot read it, and a store without a key refuses.
	other, _ := secrets.New(db, "another-key-another-key-another-key!")
	if _, err := other.Resolve(ctx, nil, body); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
	off, _ := secrets.New(db, "")
	if _, err := off.Resolve(ctx, nil, body); !errors.Is(err, secrets.ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	// What a collector reports back has the reference put back in place of the value.
	red, err := s.Redact(ctx, nil, "exporters:\n  otlp:\n    headers:\n      api-key: s3cr3t-value\n")
	if err != nil || strings.Contains(red, "s3cr3t") || !strings.Contains(red, "api-key: ${secret:vendor_key}") {
		t.Fatalf("redact: %q, %v", red, err)
	}
	// Values that would change the meaning of the YAML they are placed in are refused.
	for _, bad := range []string{"short", "has a space", "*alias-like", "12345678", "ends-with-colon:", "line\nbreak-value", `quote"inside`} {
		if err := s.Set(ctx, nil, "bad", bad, "alice"); err == nil {
			t.Errorf("value %q was accepted", bad)
		}
	}
	// A value the collector would try to expand is escaped on the way out and still hidden on the way back.
	if err := s.Set(ctx, nil, "odd", "abc${HOME}xyz", "alice"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Resolve(ctx, nil, "k: ${secret:odd}"); got != "k: abc$${HOME}xyz" {
		t.Fatalf("escaping: %q", got)
	}
	if err := s.Delete(ctx, func() uuid.UUID {
		list, _ := s.List(ctx)
		for _, x := range list {
			if x.Name == "odd" {
				return x.ID
			}
		}
		return uuid.Nil
	}()); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(ctx); len(list) != 1 || list[0].Name != "vendor_key" {
		t.Fatalf("list = %+v", list)
	}
}
