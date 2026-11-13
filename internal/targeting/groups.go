package targeting

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrGroupNotFound  = errors.New("group not found")
	ErrGroupNameTaken = errors.New("a group with this name already exists")
)

// Group is a saved, named selector. Membership is dynamic: it is whatever
// agents match the selector at the time it is evaluated.
type Group struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Selector    Selector  `json:"selector"`
	// Members is the number of agents currently matching the selector.
	Members   int       `json:"members"`
	CreatedAt time.Time `json:"created_at"`
}

// Groups stores saved selectors.
type Groups struct{ db *pgxpool.Pool }

// NewGroups creates a Groups store.
func NewGroups(db *pgxpool.Pool) *Groups { return &Groups{db: db} }

// List returns all groups by name with their current member counts.
func (g *Groups) List(ctx context.Context) ([]Group, error) {
	rows, err := g.db.Query(ctx, `
SELECT id, name, COALESCE(description, ''), selector, created_at FROM agent_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	groups, err := pgx.CollectRows(rows, scanGroup)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		where, args := groups[i].Selector.Where("attributes", 1)
		if err := g.db.QueryRow(ctx, `SELECT count(*) FROM agents WHERE `+where, args...).Scan(&groups[i].Members); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// Get returns one group (without a member count).
func (g *Groups) Get(ctx context.Context, id uuid.UUID) (*Group, error) {
	rows, err := g.db.Query(ctx, `
SELECT id, name, COALESCE(description, ''), selector, created_at FROM agent_groups WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	grp, err := pgx.CollectExactlyOneRow(rows, scanGroup)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrGroupNotFound
	}
	return &grp, err
}

// Create saves a selector under a name.
func (g *Groups) Create(ctx context.Context, name, description string, sel Selector) (*Group, error) {
	selJSON, err := json.Marshal(sel)
	if err != nil {
		return nil, err
	}
	grp := &Group{Name: name, Description: description, Selector: sel}
	err = g.db.QueryRow(ctx, `
INSERT INTO agent_groups (name, description, selector) VALUES ($1, $2, $3::jsonb) RETURNING id, created_at`,
		name, description, selJSON).Scan(&grp.ID, &grp.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrGroupNameTaken
	}
	return grp, err
}

// Update replaces a group's name, description and selector.
func (g *Groups) Update(ctx context.Context, id uuid.UUID, name, description string, sel Selector) (*Group, error) {
	selJSON, err := json.Marshal(sel)
	if err != nil {
		return nil, err
	}
	grp := &Group{ID: id, Name: name, Description: description, Selector: sel}
	err = g.db.QueryRow(ctx, `
UPDATE agent_groups SET name = $2, description = $3, selector = $4::jsonb, updated_at = now()
WHERE id = $1 RETURNING created_at`, id, name, description, selJSON).Scan(&grp.CreatedAt)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrGroupNotFound
	case errors.As(err, &pgErr) && pgErr.Code == "23505":
		return nil, ErrGroupNameTaken
	}
	return grp, err
}

// Delete removes a group. Past rollouts keep their own copy of the selector.
func (g *Groups) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := g.db.Exec(ctx, `DELETE FROM agent_groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

func scanGroup(row pgx.CollectableRow) (Group, error) {
	var (
		grp Group
		sel []byte
	)
	if err := row.Scan(&grp.ID, &grp.Name, &grp.Description, &sel, &grp.CreatedAt); err != nil {
		return grp, err
	}
	return grp, json.Unmarshal(sel, &grp.Selector)
}
