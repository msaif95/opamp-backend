// Package agentconfig manages collector config templates and their immutable
// versions, including provenance (UI-authored vs Git-sourced).
package agentconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Origins of a config.
const (
	OriginUI  = "ui"
	OriginGit = "git"
)

var (
	ErrNotFound = errors.New("config not found")
	// ErrReadOnly is returned when editing a Git-sourced config through the API.
	ErrReadOnly  = errors.New("config is Git-sourced and read-only; change it via a pull request")
	ErrNameTaken = errors.New("a config with this name already exists")
	ErrUnchanged = errors.New("body is identical to the latest version")
	ErrInUse     = errors.New("config is assigned to agents or referenced by rollouts")
)

const versionCacheN = 256

// InvalidError carries validation issues that blocked a save.
type InvalidError struct{ Issues []Issue }

func (e *InvalidError) Error() string { return "config failed validation" }

// Template is a named config with a version history.
type Template struct {
	ID uuid.UUID `json:"id"`
	// ProjectID is the project that owns the config; nil means unassigned.
	ProjectID     *uuid.UUID `json:"project_id"`
	Name          string     `json:"name"`
	Description   string     `json:"description"`
	Origin        string     `json:"origin"`
	LatestVersion int        `json:"latest_version"`
	AssignedCount int        `json:"assigned_agents"`
	// AssignedByVersion maps a version number to the agents assigned to it.
	AssignedByVersion map[int]int `json:"assigned_by_version"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdatedAt         time.Time   `json:"updated_at"`
}

// Version is one immutable revision of a template.
type Version struct {
	ID           uuid.UUID `json:"id"`
	TemplateID   uuid.UUID `json:"template_id"`
	Version      int       `json:"version"`
	Body         string    `json:"body,omitempty"`
	BodyHash     []byte    `json:"-"`
	Author       string    `json:"author"`
	Description  string    `json:"description"`
	Origin       string    `json:"origin"`
	GitCommitSHA *string   `json:"git_commit_sha"`
	// BuilderSpec is the pipeline as built in the config builder, if this
	// version was made there. Only populated when the body is.
	BuilderSpec json.RawMessage `json:"builder_spec,omitempty"`
	// AssignedCount is only populated by Service.Get.
	AssignedCount int       `json:"assigned_agents,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Service is the config management service.
type Service struct {
	db *pgxpool.Pool

	mu    sync.Mutex
	cache map[uuid.UUID]*Version
}

// NewService creates a Service.
func NewService(db *pgxpool.Pool) *Service {
	return &Service{db: db, cache: make(map[uuid.UUID]*Version)}
}

// Create creates a UI-authored template with its first version.
// builderSpec is the builder pipeline the body was rendered from, or nil for hand-written YAML.
func (s *Service) Create(ctx context.Context, project *uuid.UUID, name, description, body, author string, builderSpec json.RawMessage) (*Template, *Version, error) {
	if issues := Validate(body); HasErrors(issues) {
		return nil, nil, &InvalidError{Issues: issues}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	t := &Template{ProjectID: project, Name: name, Description: description, Origin: OriginUI, LatestVersion: 1, AssignedByVersion: map[int]int{}}
	err = tx.QueryRow(ctx, `
INSERT INTO config_templates (name, description, origin, project_id) VALUES ($1, $2, 'ui', $3)
RETURNING id, created_at, updated_at`, name, description, project).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, nil, ErrNameTaken
	}
	if err != nil {
		return nil, nil, err
	}
	v, err := insertVersion(ctx, tx, t.ID, 1, body, author, "Initial version", builderSpec)
	if err != nil {
		return nil, nil, err
	}
	return t, v, tx.Commit(ctx)
}

// AddVersion appends a new version to a UI-authored template.
func (s *Service) AddVersion(ctx context.Context, templateID uuid.UUID, body, description, author string, builderSpec json.RawMessage) (*Version, error) {
	if issues := Validate(body); HasErrors(issues) {
		return nil, &InvalidError{Issues: issues}
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Lock the template row so concurrent saves get distinct version numbers.
	var origin string
	err = tx.QueryRow(ctx, `SELECT origin::text FROM config_templates WHERE id = $1 FOR UPDATE`, templateID).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if origin == OriginGit {
		return nil, ErrReadOnly
	}

	var (
		latest     int
		latestHash []byte
	)
	err = tx.QueryRow(ctx, `
SELECT version, body_hash FROM config_versions WHERE template_id = $1 ORDER BY version DESC LIMIT 1`,
		templateID).Scan(&latest, &latestHash)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256([]byte(body)); string(sum[:]) == string(latestHash) {
		return nil, ErrUnchanged
	}

	v, err := insertVersion(ctx, tx, templateID, latest+1, body, author, description, builderSpec)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE config_templates SET updated_at = now() WHERE id = $1`, templateID); err != nil {
		return nil, err
	}
	return v, tx.Commit(ctx)
}

func insertVersion(ctx context.Context, tx pgx.Tx, templateID uuid.UUID, n int, body, author, description string, builderSpec json.RawMessage) (*Version, error) {
	sum := sha256.Sum256([]byte(body))
	v := &Version{TemplateID: templateID, Version: n, Body: body, BodyHash: sum[:],
		Author: author, Description: description, Origin: OriginUI, BuilderSpec: builderSpec}
	err := tx.QueryRow(ctx, `
INSERT INTO config_versions (template_id, version, body, body_hash, author, description, origin, builder_spec)
VALUES ($1, $2, $3, $4, $5, $6, 'ui', $7::jsonb) RETURNING id, created_at`,
		templateID, n, body, sum[:], author, description, nullableJSON(builderSpec)).Scan(&v.ID, &v.CreatedAt)
	return v, err
}

const templateSelect = `
SELECT t.id, t.name, COALESCE(t.description, ''), t.origin::text,
       COALESCE((SELECT max(version) FROM config_versions v WHERE v.template_id = t.id), 0),
       COALESCE((SELECT jsonb_object_agg(version, n) FROM (
           SELECT v.version, count(*) AS n FROM agents a JOIN config_versions v ON v.id = a.desired_config_version_id
           WHERE v.template_id = t.id GROUP BY v.version) c), '{}'::jsonb),
       t.created_at, t.updated_at, t.project_id
FROM config_templates t`

func scanTemplate(row pgx.CollectableRow) (Template, error) {
	var (
		t        Template
		assigned []byte
	)
	err := row.Scan(&t.ID, &t.Name, &t.Description, &t.Origin, &t.LatestVersion, &assigned, &t.CreatedAt, &t.UpdatedAt, &t.ProjectID)
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal(assigned, &t.AssignedByVersion); err != nil {
		return t, err
	}
	for _, n := range t.AssignedByVersion {
		t.AssignedCount += n
	}
	return t, nil
}

// Scope limits rows to the projects a caller may view (see access.Scope).
type Scope interface {
	Where(projectColumn string, firstParam int) (string, []any)
}

// ProjectOf returns the project that owns a template (nil for unassigned).
func (s *Service) ProjectOf(ctx context.Context, templateID uuid.UUID) (*uuid.UUID, error) {
	var project *uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT project_id FROM config_templates WHERE id = $1`, templateID).Scan(&project)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return project, err
}

// List returns the templates the scope may view, ordered by name.
func (s *Service) List(ctx context.Context, scope Scope) ([]Template, error) {
	where, args := scope.Where("t.project_id", 1)
	rows, err := s.db.Query(ctx, templateSelect+` WHERE `+where+` ORDER BY t.name`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanTemplate)
}

// Get returns a template and its versions (newest first, without bodies).
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Template, []Version, error) {
	rows, err := s.db.Query(ctx, templateSelect+` WHERE t.id = $1`, id)
	if err != nil {
		return nil, nil, err
	}
	t, err := pgx.CollectExactlyOneRow(rows, scanTemplate)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	rows, err = s.db.Query(ctx, versionSelect(false)+` WHERE template_id = $1 ORDER BY version DESC`, id)
	if err != nil {
		return nil, nil, err
	}
	versions, err := pgx.CollectRows(rows, scanVersion)
	for i := range versions {
		versions[i].AssignedCount = t.AssignedByVersion[versions[i].Version]
	}
	return &t, versions, err
}

func versionSelect(withBody bool) string {
	body, spec := "''", "NULL::jsonb"
	if withBody {
		body, spec = "body", "builder_spec"
	}
	return `SELECT id, template_id, version, ` + body + `, body_hash, author, COALESCE(description, ''),
       origin::text, git_commit_sha, created_at, ` + spec + ` FROM config_versions`
}

// nullableJSON stores an absent spec as SQL NULL rather than the JSON value null.
func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return []byte(raw)
}

func scanVersion(row pgx.CollectableRow) (Version, error) {
	var v Version
	var spec []byte
	err := row.Scan(&v.ID, &v.TemplateID, &v.Version, &v.Body, &v.BodyHash, &v.Author, &v.Description,
		&v.Origin, &v.GitCommitSHA, &v.CreatedAt, &spec)
	v.BuilderSpec = spec
	return v, err
}

// VersionByNumber returns one version of a template, with body.
func (s *Service) VersionByNumber(ctx context.Context, templateID uuid.UUID, n int) (*Version, error) {
	rows, err := s.db.Query(ctx, versionSelect(true)+` WHERE template_id = $1 AND version = $2`, templateID, n)
	if err != nil {
		return nil, err
	}
	return oneVersion(rows)
}

// Version returns a version by ID, with body. Versions are immutable, so
// results are cached; this is on the per-agent-message hot path.
func (s *Service) Version(ctx context.Context, id uuid.UUID) (*Version, error) {
	s.mu.Lock()
	v := s.cache[id]
	s.mu.Unlock()
	if v != nil {
		return v, nil
	}
	rows, err := s.db.Query(ctx, versionSelect(true)+` WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	if v, err = oneVersion(rows); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if len(s.cache) >= versionCacheN {
		clear(s.cache)
	}
	s.cache[id] = v
	s.mu.Unlock()
	return v, nil
}

func oneVersion(rows pgx.Rows) (*Version, error) {
	v, err := pgx.CollectExactlyOneRow(rows, scanVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &v, err
}

// Delete removes a template and its versions. It refuses while any version
// is assigned to an agent or referenced by a rollout.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.db.Exec(ctx, `
DELETE FROM config_templates t WHERE t.id = $1 AND NOT EXISTS (
    SELECT 1 FROM agents a JOIN config_versions v ON v.id = a.desired_config_version_id WHERE v.template_id = t.id)`, id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrInUse
	}
	if err != nil {
		return fmt.Errorf("delete config %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM config_templates WHERE id = $1)`, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrInUse
		}
		return ErrNotFound
	}
	s.mu.Lock()
	clear(s.cache)
	s.mu.Unlock()
	return nil
}
