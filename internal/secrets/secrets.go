// Package secrets keeps values such as destination API keys out of config
// bodies. A config refers to one as ${secret:NAME}; the value is stored
// encrypted (AES-256-GCM, key from SECRETS_ENCRYPTION_KEY) and substituted
// only when the config is sent to a collector.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.yaml.in/yaml/v3"
)

var (
	ErrNoKey    = errors.New("secrets are not enabled: set SECRETS_ENCRYPTION_KEY")
	ErrNotFound = errors.New("secret not found")
	nameRE      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	refRE       = regexp.MustCompile(`\$\{secret:([A-Za-z0-9_.-]{1,64})\}`)
)

// Secret is a stored secret, without its value.
type Secret struct {
	ID        uuid.UUID  `json:"id"`
	ProjectID *uuid.UUID `json:"project_id"`
	Name      string     `json:"name"`
	UpdatedBy string     `json:"updated_by"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Store encrypts, stores and resolves secrets.
type Store struct {
	db   *pgxpool.Pool
	aead cipher.AEAD
}

// New creates a Store. An empty key leaves it disabled: values cannot be set or resolved.
func New(db *pgxpool.Pool, key string) (*Store, error) {
	s := &Store{db: db}
	if key == "" {
		return s, nil
	}
	if len(key) < 32 {
		return nil, errors.New("SECRETS_ENCRYPTION_KEY must be at least 32 characters")
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	s.aead, err = cipher.NewGCM(block)
	return s, err
}

// Enabled reports whether an encryption key is configured.
func (s *Store) Enabled() bool { return s.aead != nil }

// Set creates or replaces a secret's value.
func (s *Store) Set(ctx context.Context, project *uuid.UUID, name, value, by string) error {
	if !s.Enabled() {
		return ErrNoKey
	}
	if !nameRE.MatchString(name) {
		return errors.New("a secret's name may only contain letters, digits, dot, dash and underscore")
	}
	if err := checkValue(value); err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	// The name and project are bound into the ciphertext, so a value cannot be moved to another secret.
	sealed := s.aead.Seal(nonce, nonce, []byte(value), aad(project, name))
	_, err := s.db.Exec(ctx, `
INSERT INTO secrets (project_id, name, ciphertext, updated_by) VALUES ($1, $2, $3, $4)
ON CONFLICT (COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name)
DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_by = EXCLUDED.updated_by, updated_at = now()`, project, name, sealed, by)
	return err
}

// minValueLen keeps values long enough that hiding them in a reported
// config (Redact) cannot mangle unrelated text.
const minValueLen = 8

// checkValue accepts only values that can be dropped into a YAML config as
// they are. The value is substituted as text, so anything YAML would read
// differently (spaces, quotes, a leading *, a number) could change the
// meaning of the config or break it on the collector.
func checkValue(value string) error {
	if len(value) < minValueLen {
		return fmt.Errorf("a secret's value must be at least %d characters", minValueLen)
	}
	var probe map[string]any
	// Quotes, backslashes and spaces are plain text on their own line, but not
	// once the reference sits inside a quoted string such as "Bearer ${secret:x}".
	unsafe := strings.ContainsAny(value, " \t\r\n\"'\\")
	if err := yaml.Unmarshal([]byte("k: "+value+"\n"), &probe); unsafe || err != nil || len(probe) != 1 || probe["k"] != value {
		return errors.New("this value cannot be placed in a config safely: it must be one token with no spaces, quotes or YAML syntax, and not a bare number. Put any prefix such as \"Bearer \" in the config itself")
	}
	return nil
}

// forCollector escapes what the collector would otherwise expand itself.
func forCollector(value string) string { return strings.ReplaceAll(value, "${", "$${") }

func aad(project *uuid.UUID, name string) []byte {
	p := "none"
	if project != nil {
		p = project.String()
	}
	return []byte(p + "/" + name)
}

// List returns the secrets (never their values) by name.
func (s *Store) List(ctx context.Context) ([]Secret, error) {
	rows, err := s.db.Query(ctx, `SELECT id, project_id, name, updated_by, updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Secret, error) {
		var x Secret
		err := row.Scan(&x.ID, &x.ProjectID, &x.Name, &x.UpdatedBy, &x.UpdatedAt)
		return x, err
	})
}

// Names lists the names of a project's secrets, for editors that offer them.
func (s *Store) Names(ctx context.Context, project *uuid.UUID) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT name FROM secrets WHERE project_id IS NOT DISTINCT FROM $1 ORDER BY name`, project)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Delete removes a secret. Configs that still refer to it stop being delivered until it is set again.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM secrets WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// References lists the secret names a config body refers to.
func References(body string) []string {
	var names []string
	for _, m := range refRE.FindAllStringSubmatch(body, -1) {
		names = append(names, m[1])
	}
	return names
}

// values decrypts the project's secrets, all of them or only the named ones.
func (s *Store) values(ctx context.Context, project *uuid.UUID, names []string) (map[string]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT name, ciphertext FROM secrets WHERE project_id IS NOT DISTINCT FROM $1 AND ($2::text[] IS NULL OR name = ANY($2))`, project, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var (
			name   string
			sealed []byte
		)
		if err := rows.Scan(&name, &sealed); err != nil {
			return nil, err
		}
		n := s.aead.NonceSize()
		if len(sealed) < n {
			return nil, fmt.Errorf("secret %q is corrupt", name)
		}
		plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], aad(project, name))
		if err != nil {
			return nil, fmt.Errorf("secret %q cannot be decrypted (was SECRETS_ENCRYPTION_KEY changed?)", name)
		}
		values[name] = string(plain)
	}
	return values, rows.Err()
}

// Resolve replaces every ${secret:NAME} in body with the value of that
// secret in the given project. A missing secret is an error: sending a
// collector a config with a placeholder in it would break its export.
func (s *Store) Resolve(ctx context.Context, project *uuid.UUID, body string) (string, error) {
	names := References(body)
	if len(names) == 0 {
		return body, nil
	}
	if !s.Enabled() {
		return "", ErrNoKey
	}
	values, err := s.values(ctx, project, names)
	if err != nil {
		return "", err
	}
	var missing error
	out := refRE.ReplaceAllStringFunc(body, func(ref string) string {
		name := refRE.FindStringSubmatch(ref)[1]
		v, ok := values[name]
		if !ok {
			missing = fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return forCollector(v)
	})
	return out, missing
}

// Redact puts the ${secret:NAME} references back into a config a collector
// reported, so the values it was sent are not stored or shown again. Only
// the collector's own project is consulted: matching against other
// projects' secrets would let someone test guesses of their values.
func (s *Store) Redact(ctx context.Context, project *uuid.UUID, body string) (string, error) {
	if !s.Enabled() {
		return body, nil
	}
	values, err := s.values(ctx, project, nil)
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	// Longest value first, so one value containing another is replaced whole.
	sort.Slice(names, func(i, j int) bool {
		if len(values[names[i]]) != len(values[names[j]]) {
			return len(values[names[i]]) > len(values[names[j]])
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		ref := "${secret:" + name + "}"
		body = strings.ReplaceAll(body, forCollector(values[name]), ref)
		body = strings.ReplaceAll(body, values[name], ref)
	}
	return body, nil
}
