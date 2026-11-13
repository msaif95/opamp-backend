package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/targeting"
)

var (
	ErrLibraryNotFound  = errors.New("library item not found")
	ErrLibraryNameTaken = errors.New("a library item of this kind already has this name")
)

// LibraryItem is a configured source, processor or destination saved for
// reuse. A pipeline refers to it by ID; the item's current settings are
// used each time a config is saved, so configs already saved keep the
// settings they were saved with until they are saved again.
type LibraryItem struct {
	ID        uuid.UUID      `json:"id"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	Type      string         `json:"type"`
	Params    map[string]any `json:"params"`
	CreatedBy string         `json:"created_by"`
	// ProjectID is the project the item belongs to; nil means unassigned.
	ProjectID *uuid.UUID `json:"project_id"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// Library stores reusable components.
type Library struct{ db *pgxpool.Pool }

// NewLibrary creates a Library.
func NewLibrary(db *pgxpool.Pool) *Library { return &Library{db: db} }

// check validates an item's kind, type and settings against the catalog.
func check(kind, typ string, params map[string]any) []agentconfig.Issue {
	idx := slices.IndexFunc(catalog, func(t Type) bool { return t.Kind == kind && t.Type == typ })
	if idx < 0 {
		return []agentconfig.Issue{{Severity: agentconfig.SeverityError, Message: fmt.Sprintf("unknown %s type %q", kind, typ)}}
	}
	_, issues := normalize(&catalog[idx], params, kind)
	return issues
}

func scanItem(row pgx.CollectableRow) (LibraryItem, error) {
	var (
		it  LibraryItem
		raw []byte
	)
	if err := row.Scan(&it.ID, &it.Kind, &it.Name, &it.Type, &raw, &it.CreatedBy, &it.UpdatedAt, &it.ProjectID); err != nil {
		return it, err
	}
	return it, json.Unmarshal(raw, &it.Params)
}

const itemColumns = `id, kind, name, type, params, created_by, updated_at, project_id`

// List returns all items by kind and name.
func (l *Library) List(ctx context.Context, scope targeting.Scope) ([]LibraryItem, error) {
	where, args := scope.Where("project_id", 1)
	rows, err := l.db.Query(ctx, `SELECT `+itemColumns+` FROM library_components WHERE `+where+` ORDER BY kind, name`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanItem)
}

// Save creates an item, or replaces the settings of the item with the given ID.
// project is only used when creating; an item stays in the project it was created in.
func (l *Library) Save(ctx context.Context, id *uuid.UUID, project *uuid.UUID, kind, name, typ string, params map[string]any, by string) (*LibraryItem, []agentconfig.Issue, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, []agentconfig.Issue{{Severity: agentconfig.SeverityError, Message: "name is required"}}, nil
	}
	if issues := check(kind, typ, params); len(issues) > 0 {
		return nil, issues, nil
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, nil, err
	}
	var rows pgx.Rows
	if id == nil {
		rows, err = l.db.Query(ctx, `
INSERT INTO library_components (kind, name, type, params, created_by, project_id) VALUES ($1, $2, $3, $4::jsonb, $5, $6)
RETURNING `+itemColumns, kind, name, typ, raw, by, project)
	} else {
		// Kind and type are fixed once created: configs referring to the item rely on them.
		rows, err = l.db.Query(ctx, `
UPDATE library_components SET name = $2, params = $3::jsonb, updated_at = now()
WHERE id = $1 AND kind = $4 AND type = $5 RETURNING `+itemColumns, *id, name, raw, kind, typ)
	}
	if err != nil {
		return nil, nil, err
	}
	it, err := pgx.CollectExactlyOneRow(rows, scanItem)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil, ErrLibraryNotFound
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		return nil, nil, ErrLibraryNameTaken
	case err != nil:
		return nil, nil, err
	}
	return &it, nil, nil
}

// ProjectOf returns the project an item belongs to (nil for unassigned).
func (l *Library) ProjectOf(ctx context.Context, id uuid.UUID) (*uuid.UUID, error) {
	var project *uuid.UUID
	err := l.db.QueryRow(ctx, `SELECT project_id FROM library_components WHERE id = $1`, id).Scan(&project)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrLibraryNotFound
	}
	return project, err
}

// Delete removes an item. Configs already saved are unaffected; a pipeline
// that still refers to it reports the missing item when next opened.
func (l *Library) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := l.db.Exec(ctx, `DELETE FROM library_components WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLibraryNotFound
	}
	return nil
}

// Resolve returns a copy of spec in which every component that refers to a
// library item carries that item's current type and settings.
// Items outside the scope are treated as missing.
func (l *Library) Resolve(ctx context.Context, scope targeting.Scope, spec Spec) (Spec, []agentconfig.Issue, error) {
	var ids []uuid.UUID
	groups := []struct {
		kind, name string
		comps      *[]Component
	}{{KindSource, "sources", &spec.Sources}, {KindProcessor, "processors", &spec.Processors}, {KindDestination, "destinations", &spec.Destinations}}
	for _, g := range groups {
		*g.comps = slices.Clone(*g.comps)
		for _, c := range *g.comps {
			if c.Library != nil {
				ids = append(ids, *c.Library)
			}
		}
	}
	if len(ids) == 0 {
		return spec, nil, nil
	}
	scopeWhere, scopeArgs := scope.Where("project_id", 2)
	rows, err := l.db.Query(ctx, `SELECT `+itemColumns+` FROM library_components WHERE id = ANY($1) AND `+scopeWhere, append([]any{ids}, scopeArgs...)...)
	if err != nil {
		return spec, nil, err
	}
	items, err := pgx.CollectRows(rows, scanItem)
	if err != nil {
		return spec, nil, err
	}
	byID := map[uuid.UUID]LibraryItem{}
	for _, it := range items {
		byID[it.ID] = it
	}
	var issues []agentconfig.Issue
	for _, g := range groups {
		for i, c := range *g.comps {
			if c.Library == nil {
				continue
			}
			it, ok := byID[*c.Library]
			if !ok || it.Kind != g.kind {
				issues = append(issues, agentconfig.Issue{Severity: agentconfig.SeverityError, Path: fmt.Sprintf("%s[%d]", g.name, i),
					Message: "this piece refers to a library item that no longer exists; remove it or pick another"})
				continue
			}
			(*g.comps)[i].Type, (*g.comps)[i].Params = it.Type, it.Params
		}
	}
	return spec, issues, nil
}
