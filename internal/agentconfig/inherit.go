package agentconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Config inheritance: a derived config names a base config and holds only
// overrides. Each of its versions stores the full merged body, built from
// one base version, so everything that sends, hashes or compares configs
// works on it like on any other. A derived config does not follow its base
// by itself: when the base gets a new version, the derived config is
// rebuilt on request, which makes a new version of it that can then be
// pushed like any change.

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// baseVersion is the latest version of a base config.
type baseVersion struct {
	id      uuid.UUID
	name    string
	version int
	body    string
}

func latestOf(ctx context.Context, q queryer, templateID uuid.UUID) (*baseVersion, error) {
	var b baseVersion
	err := q.QueryRow(ctx, `
SELECT v.id, t.name, v.version, v.body FROM config_versions v JOIN config_templates t ON t.id = v.template_id
WHERE v.template_id = $1 ORDER BY v.version DESC LIMIT 1`, templateID).Scan(&b.id, &b.name, &b.version, &b.body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &b, err
}

// build merges overrides over a base version and validates the result.
func build(b *baseVersion, overrides string, policy *ComponentPolicy) (string, []Issue) {
	body, err := Merge(b.body, overrides)
	if err != nil {
		return "", []Issue{{Severity: SeverityError, Path: "overrides", Message: err.Error()}}
	}
	body = withHeader(b.name, body)
	return body, Validate(body, policy)
}

// PreviewDerived returns what a config derived from the base's latest
// version with these overrides would be, with any issues, saving nothing.
func (s *Service) PreviewDerived(ctx context.Context, baseID uuid.UUID, overrides string) (body string, baseVersion int, issues []Issue, err error) {
	b, err := latestOf(ctx, s.db, baseID)
	if err != nil {
		return "", 0, nil, err
	}
	body, issues = build(b, overrides, s.Policy)
	return body, b.version, issues, nil
}

// CreateDerived creates a config derived from a base, with its first version built from the base's latest.
func (s *Service) CreateDerived(ctx context.Context, project *uuid.UUID, name, description string, baseID uuid.UUID, overrides, author string) (*Template, *Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	// The base is locked so it cannot be deleted or turned around while this is built on it.
	var (
		baseProject *uuid.UUID
		baseOfBase  *uuid.UUID
	)
	err = tx.QueryRow(ctx, `SELECT project_id, base_template_id FROM config_templates WHERE id = $1 FOR SHARE`, baseID).Scan(&baseProject, &baseOfBase)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	sameProject := (project == nil && baseProject == nil) || (project != nil && baseProject != nil && *project == *baseProject)
	if baseOfBase != nil || !sameProject {
		return nil, nil, ErrBase
	}
	b, err := latestOf(ctx, tx, baseID)
	if err != nil {
		return nil, nil, err
	}
	body, issues := build(b, overrides, s.Policy)
	if HasErrors(issues) {
		return nil, nil, &InvalidError{Issues: issues}
	}

	t := &Template{ProjectID: project, Name: name, Description: description, Origin: OriginUI, LatestVersion: 1, AssignedByVersion: map[int]int{},
		Base: &BaseRef{ID: baseID, Name: b.name, LatestVersion: b.version}}
	err = tx.QueryRow(ctx, `
INSERT INTO config_templates (name, description, origin, project_id, base_template_id) VALUES ($1, $2, 'ui', $3, $4)
RETURNING id, created_at, updated_at`, name, description, project, baseID).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, nil, ErrNameTaken
	}
	if err != nil {
		return nil, nil, err
	}
	v, err := insertDerivedVersion(ctx, tx, t.ID, 1, body, overrides, b, author, "Derived from "+b.name)
	if err != nil {
		return nil, nil, err
	}
	return t, v, tx.Commit(ctx)
}

func insertDerivedVersion(ctx context.Context, tx pgx.Tx, templateID uuid.UUID, n int, body, overrides string, b *baseVersion, author, description string) (*Version, error) {
	sum := sha256.Sum256([]byte(body))
	v := &Version{TemplateID: templateID, Version: n, Body: body, BodyHash: sum[:], Author: author, Description: description,
		Origin: OriginUI, BaseVersion: &b.version, Overrides: overrides}
	err := tx.QueryRow(ctx, `
INSERT INTO config_versions (template_id, version, body, body_hash, author, description, origin, base_version_id, overrides)
VALUES ($1, $2, $3, $4, $5, $6, 'ui', $7, $8) RETURNING id, created_at`,
		templateID, n, body, sum[:], author, description, b.id, overrides).Scan(&v.ID, &v.CreatedAt)
	return v, err
}

// AddDerivedVersion makes a new version of a derived config from its base's
// latest version. overrides nil keeps the overrides of its latest version,
// which is how a derived config is brought up to date with its base. It
// returns ErrUnchanged when the result would be what the latest version already is.
func (s *Service) AddDerivedVersion(ctx context.Context, templateID uuid.UUID, overrides *string, description, author string) (*Version, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var baseID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT base_template_id FROM config_templates WHERE id = $1 FOR UPDATE`, templateID).Scan(&baseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if baseID == nil {
		return nil, ErrNotDerived
	}
	var (
		latest          int
		latestHash      []byte
		latestOverrides string
	)
	err = tx.QueryRow(ctx, `
SELECT version, body_hash, COALESCE(overrides, '') FROM config_versions WHERE template_id = $1 ORDER BY version DESC LIMIT 1`,
		templateID).Scan(&latest, &latestHash, &latestOverrides)
	if err != nil {
		return nil, err
	}
	rebuilt := overrides == nil
	if rebuilt {
		overrides = &latestOverrides
	}
	b, err := latestOf(ctx, tx, *baseID)
	if err != nil {
		return nil, err
	}
	body, issues := build(b, *overrides, s.Policy)
	if HasErrors(issues) {
		return nil, &InvalidError{Issues: issues}
	}
	if sum := sha256.Sum256([]byte(body)); bytes.Equal(sum[:], latestHash) && *overrides == latestOverrides {
		return nil, ErrUnchanged
	}
	if description == "" && rebuilt {
		description = "Updated from " + b.name + " v" + strconv.Itoa(b.version)
	}
	v, err := insertDerivedVersion(ctx, tx, templateID, latest+1, body, *overrides, b, author, description)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE config_templates SET updated_at = now() WHERE id = $1`, templateID); err != nil {
		return nil, err
	}
	return v, tx.Commit(ctx)
}

// derived lists the configs derived from a base and whether each is up to date with its latest version.
func (s *Service) derived(ctx context.Context, q queryer, baseID uuid.UUID) ([]DerivedRef, error) {
	rows, err := q.Query(ctx, `
SELECT t.id, t.name, v.version, COALESCE(bv.version, 0), v.body_hash, COALESCE(v.overrides, '')
FROM config_templates t
JOIN LATERAL (SELECT * FROM config_versions WHERE template_id = t.id ORDER BY version DESC LIMIT 1) v ON TRUE
LEFT JOIN config_versions bv ON bv.id = v.base_version_id
WHERE t.base_template_id = $1 ORDER BY t.name`, baseID)
	if err != nil {
		return nil, err
	}
	type child struct {
		DerivedRef
		hash      []byte
		overrides string
	}
	children, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (child, error) {
		var c child
		return c, row.Scan(&c.ID, &c.Name, &c.LatestVersion, &c.BaseVersion, &c.hash, &c.overrides)
	})
	if err != nil || len(children) == 0 {
		return nil, err
	}
	b, err := latestOf(ctx, q, baseID)
	if err != nil {
		return nil, err
	}
	out := make([]DerivedRef, len(children))
	for i, c := range children {
		// Up to date means rebuilding would give the body it already has; a
		// base change that does not touch what this config keeps counts as up to date.
		if body, issues := build(b, c.overrides, s.Policy); !HasErrors(issues) {
			sum := sha256.Sum256([]byte(body))
			c.UpToDate = bytes.Equal(sum[:], c.hash)
		}
		out[i] = c.DerivedRef
	}
	return out, nil
}

// DerivedUpdate is the outcome of bringing one derived config up to date.
type DerivedUpdate struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	// Version is the new version made, or 0 if none was.
	Version int `json:"version"`
	// Error says why no version was made; empty when one was, or when it was already up to date.
	Error  string  `json:"error,omitempty"`
	Issues []Issue `json:"issues,omitempty"`
}

// UpdateDerived rebuilds every config derived from the base that is out of
// date, each on its own: one whose result no longer validates is reported
// and left as it is.
func (s *Service) UpdateDerived(ctx context.Context, baseID uuid.UUID, author string) ([]DerivedUpdate, error) {
	children, err := s.derived(ctx, s.db, baseID)
	if err != nil {
		return nil, err
	}
	out := make([]DerivedUpdate, 0, len(children))
	for _, c := range children {
		u := DerivedUpdate{ID: c.ID, Name: c.Name}
		v, err := s.AddDerivedVersion(ctx, c.ID, nil, "", author)
		var invalid *InvalidError
		switch {
		case err == nil:
			u.Version = v.Version
		case errors.Is(err, ErrUnchanged):
		case errors.As(err, &invalid):
			u.Error, u.Issues = "the result would not be a valid config", invalid.Issues
		default:
			return out, err
		}
		out = append(out, u)
	}
	return out, nil
}
