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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/msaif95/opamp-backend/internal/registry"
)

const apiKeyPrefix = "opamp_"

var (
	// ErrUnauthenticated is returned when an agent presents no valid credential.
	ErrUnauthenticated = errors.New("unauthenticated")
	// ErrBadCertificate is returned when a certificate to revoke cannot be parsed.
	ErrBadCertificate = errors.New("not a PEM-encoded X.509 certificate")
)

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
		return registry.Identity{AuthMode: "mtls", CertFingerprint: sum[:], CertNotAfter: leaf.NotAfter}, nil
	case err != nil:
		return registry.Identity{}, fmt.Errorf("lookup cert credential: %w", err)
	case revoked != nil:
		return registry.Identity{}, ErrUnauthenticated
	}
	a.touch(ctx, id)
	return registry.Identity{AuthMode: "mtls", CredentialID: &id, CertFingerprint: sum[:], CertNotAfter: leaf.NotAfter}, nil
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

// Invalid reports which of the given credentials are no longer valid:
// revoked or expired credential IDs, and revoked certificate fingerprints
// (keyed by the raw fingerprint bytes). It is used to cut live connections
// whose credential was withdrawn after they connected.
func (a *AgentAuthenticator) Invalid(ctx context.Context, ids []uuid.UUID, fingerprints [][]byte) (map[uuid.UUID]bool, map[string]bool, error) {
	rows, err := a.db.Query(ctx, `
SELECT id, key_hash FROM credentials
WHERE (id = ANY($1) OR (kind = 'mtls_cert' AND key_hash = ANY($2)))
  AND (revoked_at IS NOT NULL OR (expires_at IS NOT NULL AND expires_at <= now()))`, ids, fingerprints)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	badIDs, badCerts := map[uuid.UUID]bool{}, map[string]bool{}
	for rows.Next() {
		var (
			id   uuid.UUID
			hash []byte
		)
		if err := rows.Scan(&id, &hash); err != nil {
			return nil, nil, err
		}
		badIDs[id] = true
		badCerts[string(hash)] = true
	}
	return badIDs, badCerts, rows.Err()
}

// RevokedCert is a client certificate that is refused despite chaining to the trusted CA.
type RevokedCert struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint_sha256"`
	Subject     string    `json:"subject"`
	RevokedBy   string    `json:"revoked_by"`
	RevokedAt   time.Time `json:"revoked_at"`
}

// RevokeCert blocks a client certificate by its PEM encoding. Revoking an
// already revoked certificate is a no-op.
func (a *AgentAuthenticator) RevokeCert(ctx context.Context, certPEM, name, revokedBy string) (*RevokedCert, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrBadCertificate
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrBadCertificate
	}
	sum := sha256.Sum256(cert.Raw)
	if name == "" {
		name = cert.Subject.CommonName
	}
	rc := &RevokedCert{Fingerprint: hex.EncodeToString(sum[:]), Subject: cert.Subject.String()}
	err = a.db.QueryRow(ctx, `
INSERT INTO credentials (kind, name, key_hash, subject, created_by, expires_at, revoked_at)
VALUES ('mtls_cert', $1, $2, $3, $4, $5, now())
ON CONFLICT (key_hash) DO UPDATE SET revoked_at = COALESCE(credentials.revoked_at, now())
RETURNING id, name, created_by, revoked_at`,
		name, sum[:], rc.Subject, revokedBy, cert.NotAfter).Scan(&rc.ID, &rc.Name, &rc.RevokedBy, &rc.RevokedAt)
	return rc, err
}

// ListRevokedCerts returns the blocked client certificates, newest first.
func (a *AgentAuthenticator) ListRevokedCerts(ctx context.Context) ([]RevokedCert, error) {
	rows, err := a.db.Query(ctx, `
SELECT id, name, encode(key_hash, 'hex'), COALESCE(subject, ''), created_by, revoked_at
FROM credentials WHERE kind = 'mtls_cert' AND revoked_at IS NOT NULL ORDER BY revoked_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (RevokedCert, error) {
		var c RevokedCert
		err := row.Scan(&c.ID, &c.Name, &c.Fingerprint, &c.Subject, &c.RevokedBy, &c.RevokedAt)
		return c, err
	})
}

// Revoke revokes a credential of either kind. Reports whether a row changed.
func (a *AgentAuthenticator) Revoke(ctx context.Context, id uuid.UUID) (bool, error) {
	tag, err := a.db.Exec(ctx, `UPDATE credentials SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	return tag.RowsAffected() > 0, err
}

// ServerTLSConfig builds the OpAMP listener TLS config. When clientCAFile is
// set, client certs are verified if presented (agents without one fall back
// to API-key auth). Both the server certificate and the client CA bundle
// are re-read when their files change, so cert-manager renewals and CA
// rotation take effect without a restart.
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
		cas := &caBundle{path: clientCAFile}
		pool, err := cas.pool()
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			pool, err := cas.pool()
			if err != nil {
				// Keep serving with the last good bundle rather than refusing every agent.
				return nil, nil
			}
			c := cfg.Clone()
			c.ClientCAs = pool
			c.GetConfigForClient = nil
			return c, nil
		}
	}
	return cfg, nil
}

// caBundle is a CA file that is re-parsed only when it changes on disk.
type caBundle struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	cached  *x509.CertPool
}

func (b *caBundle) pool() (*x509.CertPool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	info, err := os.Stat(b.path)
	if err != nil {
		return b.cached, fmt.Errorf("stat client CA: %w", err)
	}
	if b.cached != nil && info.ModTime().Equal(b.modTime) && info.Size() == b.size {
		return b.cached, nil
	}
	data, err := os.ReadFile(b.path)
	if err != nil {
		return b.cached, fmt.Errorf("read client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return b.cached, fmt.Errorf("no certificates found in %s", b.path)
	}
	b.cached, b.modTime, b.size = pool, info.ModTime(), info.Size()
	return pool, nil
}
