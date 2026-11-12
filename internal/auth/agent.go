// Package auth implements agent authentication (mTLS + API key) and human
// session authentication with global RBAC.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/msaif95/opamp-backend/internal/registry"
)

const apiKeyPrefix = "opamp_"

// ErrUnauthenticated is returned when an agent presents no valid credential.
var ErrUnauthenticated = errors.New("unauthenticated")

// AgentAuthenticator validates agent connections in either auth mode.
type AgentAuthenticator struct {
	db *pgxpool.Pool
}

// NewAgentAuthenticator creates an AgentAuthenticator.
func NewAgentAuthenticator(db *pgxpool.Pool) *AgentAuthenticator {
	return &AgentAuthenticator{db: db}
}

// Authenticate resolves the identity of an incoming OpAMP connection.
// A CA-verified client certificate takes precedence over a bearer API key.
func (a *AgentAuthenticator) Authenticate(ctx context.Context, r *http.Request) (registry.Identity, error) {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		return a.authenticateCert(ctx, r.TLS.VerifiedChains[0][0])
	}
	if key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && key != "" {
		return a.authenticateKey(ctx, key)
	}
	return registry.Identity{}, ErrUnauthenticated
}

// authenticateCert accepts any certificate that chained to the trusted client
// CA (verified by the TLS stack) unless its fingerprint has been revoked.
// Certificates enrolled through the backend have a credentials row; ones
// issued directly by cert-manager do not, and are accepted on CA trust alone.
func (a *AgentAuthenticator) authenticateCert(ctx context.Context, leaf *x509.Certificate) (registry.Identity, error) {
	sum := sha256.Sum256(leaf.Raw)
	var (
		id      uuid.UUID
		revoked *time.Time
	)
	err := a.db.QueryRow(ctx,
		`SELECT id, revoked_at FROM credentials WHERE kind = 'mtls_cert' AND key_hash = $1`, sum[:]).Scan(&id, &revoked)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return registry.Identity{AuthMode: "mtls"}, nil
	case err != nil:
		return registry.Identity{}, fmt.Errorf("lookup cert credential: %w", err)
	case revoked != nil:
		return registry.Identity{}, ErrUnauthenticated
	}
	a.touch(ctx, id)
	return registry.Identity{AuthMode: "mtls", CredentialID: &id}, nil
}

func (a *AgentAuthenticator) authenticateKey(ctx context.Context, key string) (registry.Identity, error) {
	sum := sha256.Sum256([]byte(key))
	var id uuid.UUID
	err := a.db.QueryRow(ctx, `
SELECT id FROM credentials
WHERE kind = 'api_key' AND key_hash = $1 AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())`, sum[:]).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return registry.Identity{}, ErrUnauthenticated
	}
	if err != nil {
		return registry.Identity{}, fmt.Errorf("lookup api key: %w", err)
	}
	a.touch(ctx, id)
	return registry.Identity{AuthMode: "api_key", CredentialID: &id}, nil
}

func (a *AgentAuthenticator) touch(ctx context.Context, id uuid.UUID) {
	// Throttled so 20k reconnecting agents don't each cause a row write.
	_, _ = a.db.Exec(ctx, `
UPDATE credentials SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '5 minutes')`, id)
}

// APIKey is a credential record; Secret is only populated at issuance.
type APIKey struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Secret    string     `json:"secret,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	LastUsed  *time.Time `json:"last_used_at"`
}

// IssueAPIKey creates a new agent API key. The secret is returned once and
// only its SHA-256 is stored.
func (a *AgentAuthenticator) IssueAPIKey(ctx context.Context, name, createdBy string, expiresAt *time.Time) (*APIKey, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	k := &APIKey{Name: name, CreatedBy: createdBy, ExpiresAt: expiresAt,
		Secret: apiKeyPrefix + base64.RawURLEncoding.EncodeToString(raw)}
	sum := sha256.Sum256([]byte(k.Secret))
	err := a.db.QueryRow(ctx, `
INSERT INTO credentials (kind, name, key_hash, created_by, expires_at)
VALUES ('api_key', $1, $2, $3, $4) RETURNING id, created_at`,
		name, sum[:], createdBy, expiresAt).Scan(&k.ID, &k.CreatedAt)
	return k, err
}

// ListAPIKeys returns all API key credentials (without secrets).
func (a *AgentAuthenticator) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := a.db.Query(ctx, `
SELECT id, name, created_by, created_at, expires_at, revoked_at, last_used_at
FROM credentials WHERE kind = 'api_key' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (APIKey, error) {
		var k APIKey
		err := row.Scan(&k.ID, &k.Name, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt, &k.RevokedAt, &k.LastUsed)
		return k, err
	})
}

// Revoke revokes a credential of either kind. Reports whether a row changed.
func (a *AgentAuthenticator) Revoke(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := a.db.Exec(ctx, `UPDATE credentials SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	return tag.RowsAffected() > 0, err
}

// ServerTLSConfig builds the OpAMP listener TLS config. When clientCAFile is
// set, client certs are verified if presented (agents without one fall back
// to API-key auth).
func ServerTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Reload per handshake so cert-manager renewals are picked up without a restart.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			return &cert, err
		},
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", clientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg, nil
}
