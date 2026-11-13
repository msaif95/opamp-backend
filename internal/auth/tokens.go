package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenPrefix marks a console API token, as opposed to a browser session.
const TokenPrefix = "opamp_pat_"

var (
	ErrTokenNameTaken = errors.New("an API token with this name already exists")
	ErrTokenNotFound  = errors.New("API token not found")
)

// APIToken is a long-lived credential for the CLI and automation. It acts
// with a fixed role; the secret is shown once, when it is created.
type APIToken struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Role       Role       `json:"role"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	// Secret is only set in the response to Create.
	Secret string `json:"secret,omitempty"`
}

// Tokens stores console API tokens.
type Tokens struct{ db *pgxpool.Pool }

// NewTokens creates a Tokens store.
func NewTokens(db *pgxpool.Pool) *Tokens { return &Tokens{db: db} }

const tokenColumns = `id, name, role::text, created_by, created_at, expires_at, revoked_at, last_used_at`

func scanToken(row pgx.CollectableRow) (APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.Name, &t.Role, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt)
	return t, err
}

// Create issues a token. Only its hash is stored.
func (t *Tokens) Create(ctx context.Context, name string, role Role, createdBy string, expiresAt *time.Time) (*APIToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	secret := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	rows, err := t.db.Query(ctx, `
INSERT INTO api_tokens (name, role, token_hash, created_by, expires_at) VALUES ($1, $2::rbac_role, $3, $4, $5)
RETURNING `+tokenColumns, strings.TrimSpace(name), string(role), sum[:], createdBy, expiresAt)
	if err != nil {
		return nil, err
	}
	tok, err := pgx.CollectExactlyOneRow(rows, scanToken)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrTokenNameTaken
	}
	if err != nil {
		return nil, err
	}
	tok.Secret = secret
	return &tok, nil
}

// List returns all tokens, newest first.
func (t *Tokens) List(ctx context.Context) ([]APIToken, error) {
	rows, err := t.db.Query(ctx, `SELECT `+tokenColumns+` FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanToken)
}

// Revoke disables a token immediately.
func (t *Tokens) Revoke(ctx context.Context, id uuid.UUID) error {
	tag, err := t.db.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTokenNotFound
	}
	return nil
}

// Authenticate resolves a token secret to the user it acts as. It is
// checked against the database on every request, so revocation is immediate.
func (t *Tokens) Authenticate(ctx context.Context, secret string) (User, error) {
	sum := sha256.Sum256([]byte(secret))
	var (
		name string
		role Role
	)
	// last_used_at is refreshed at most once a minute to keep this a cheap read most of the time.
	err := t.db.QueryRow(ctx, `
UPDATE api_tokens SET last_used_at = CASE WHEN last_used_at IS NULL OR last_used_at < now() - interval '1 minute' THEN now() ELSE last_used_at END
WHERE token_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
RETURNING name, role::text`, sum[:]).Scan(&name, &role)
	if err != nil {
		return User{}, ErrInvalidCredentials
	}
	return User{Subject: "token:" + name, Provider: "token", Role: role}, nil
}
