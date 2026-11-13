// Package access decides what a signed-in user may see and change.
//
// Every collector, config, group, bulk push and library item belongs to a
// project or is unassigned. A global admin may do anything. Otherwise a
// user acts in a project with the role they were given there, and on
// unassigned resources with their global role (which is how everything
// worked before projects existed).
package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/msaif95/opamp-backend/internal/auth"
)

// Scope is what one request may reach.
type Scope struct {
	// Admin may reach everything.
	Admin bool
	// Global is the role that applies to unassigned resources.
	Global auth.Role
	// Projects holds the user's role in each project they belong to.
	Projects map[uuid.UUID]auth.Role
}

// Can reports whether the scope grants at least the needed role on a
// resource in the given project (nil means unassigned).
func (s Scope) Can(project *uuid.UUID, need auth.Role) bool {
	switch {
	case s.Admin:
		return true
	case project == nil:
		return s.Global.Allows(need)
	}
	return s.Projects[*project].Allows(need)
}

// CanAnywhere reports whether the scope grants the role on anything at all.
func (s Scope) CanAnywhere(need auth.Role) bool {
	if s.Admin || s.Global.Allows(need) {
		return true
	}
	for _, role := range s.Projects {
		if role.Allows(need) {
			return true
		}
	}
	return false
}

// Where returns a SQL condition limiting rows to those the scope may view,
// for a nullable project column. Parameters start at $firstParam.
func (s Scope) Where(column string, firstParam int) (string, []any) {
	if s.Admin {
		return "TRUE", nil
	}
	ids := make([]uuid.UUID, 0, len(s.Projects))
	for id := range s.Projects {
		ids = append(ids, id)
	}
	cond := fmt.Sprintf("%s = ANY($%d)", column, firstParam)
	if s.Global.Allows(auth.RoleViewer) {
		cond = fmt.Sprintf("(%s IS NULL OR %s)", column, cond)
	}
	return cond, []any{ids}
}

// All is the scope of internal jobs and global admins.
var All = Scope{Admin: true}

type scopeKey struct{}

// With stores the scope on a context.
func With(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// From returns the request's scope; with none set it grants nothing.
func From(ctx context.Context) Scope {
	s, _ := ctx.Value(scopeKey{}).(Scope)
	return s
}

// Project is a named owner of resources.
type Project struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	// Counts are only populated by List.
	Members int `json:"members"`
	Agents  int `json:"agents"`
}

// Member is a person's role in a project.
type Member struct {
	Subject string    `json:"subject"`
	Role    auth.Role `json:"role"`
	AddedBy string    `json:"added_by"`
	AddedAt time.Time `json:"added_at"`
}

var (
	ErrProjectNotFound  = errors.New("project not found")
	ErrProjectNameTaken = errors.New("a project with this name already exists")
	ErrProjectInUse     = errors.New("the project still owns collectors, credentials, configs, groups or bulk pushes; move or delete them first")
)

// Projects stores projects and their members.
type Projects struct{ db *pgxpool.Pool }

// NewProjects creates a Projects store.
func NewProjects(db *pgxpool.Pool) *Projects { return &Projects{db: db} }

// normalize makes subjects compare case-insensitively: Okta emails differ in case between systems.
func normalize(subject string) string { return strings.ToLower(strings.TrimSpace(subject)) }

// Resolve builds the scope for a signed-in user.
func (p *Projects) Resolve(ctx context.Context, u auth.User) (Scope, error) {
	if u.Role == auth.RoleAdmin {
		return All, nil
	}
	// An API token bound to a project acts only there.
	if u.TokenProject != nil {
		return Scope{Projects: map[uuid.UUID]auth.Role{*u.TokenProject: u.Role}}, nil
	}
	s := Scope{Global: u.Role, Projects: map[uuid.UUID]auth.Role{}}
	if u.Provider == "token" {
		return s, nil // a token is not a person and has no memberships
	}
	rows, err := p.db.Query(ctx, `SELECT project_id, role::text FROM project_members WHERE subject = $1`, normalize(u.Subject))
	if err != nil {
		return Scope{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id   uuid.UUID
			role auth.Role
		)
		if err := rows.Scan(&id, &role); err != nil {
			return Scope{}, err
		}
		s.Projects[id] = role
	}
	return s, rows.Err()
}

// IsMember reports whether the subject belongs to any project.
func (p *Projects) IsMember(ctx context.Context, subject string) (bool, error) {
	var ok bool
	err := p.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM project_members WHERE subject = $1)`, normalize(subject)).Scan(&ok)
	return ok, err
}

// List returns the projects the scope may view, by name.
func (p *Projects) List(ctx context.Context, s Scope) ([]Project, error) {
	// Unassigned is not a project, so only real memberships (or admin) list anything.
	where, args := Scope{Admin: s.Admin, Projects: s.Projects}.Where("p.id", 1)
	rows, err := p.db.Query(ctx, `
SELECT p.id, p.name, p.description, p.created_by, p.created_at,
       (SELECT count(*) FROM project_members m WHERE m.project_id = p.id),
       (SELECT count(*) FROM agents a WHERE a.project_id = p.id)
FROM projects p WHERE `+where+` ORDER BY p.name`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Project, error) {
		var pr Project
		err := row.Scan(&pr.ID, &pr.Name, &pr.Description, &pr.CreatedBy, &pr.CreatedAt, &pr.Members, &pr.Agents)
		return pr, err
	})
}

// Exists reports whether a project exists.
func (p *Projects) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	err := p.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1)`, id).Scan(&ok)
	return ok, err
}

// Create adds a project.
func (p *Projects) Create(ctx context.Context, name, description, by string) (*Project, error) {
	pr := Project{Name: strings.TrimSpace(name), Description: strings.TrimSpace(description), CreatedBy: by}
	err := p.db.QueryRow(ctx, `INSERT INTO projects (name, description, created_by) VALUES ($1, $2, $3) RETURNING id, created_at`,
		pr.Name, pr.Description, by).Scan(&pr.ID, &pr.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return nil, ErrProjectNameTaken
	}
	return &pr, err
}

// Delete removes a project and its memberships. It is refused while the project owns anything.
func (p *Projects) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := p.db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrProjectInUse
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrProjectNotFound
	}
	return nil
}

// Members lists a project's members by name.
func (p *Projects) Members(ctx context.Context, id uuid.UUID) ([]Member, error) {
	rows, err := p.db.Query(ctx, `SELECT subject, role::text, added_by, added_at FROM project_members WHERE project_id = $1 ORDER BY subject`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Member, error) {
		var m Member
		err := row.Scan(&m.Subject, &m.Role, &m.AddedBy, &m.AddedAt)
		return m, err
	})
}

// SetMember adds a person to a project or changes their role there.
func (p *Projects) SetMember(ctx context.Context, id uuid.UUID, subject string, role auth.Role, by string) error {
	_, err := p.db.Exec(ctx, `
INSERT INTO project_members (project_id, subject, role, added_by) VALUES ($1, $2, $3::rbac_role, $4)
ON CONFLICT (project_id, subject) DO UPDATE SET role = EXCLUDED.role, added_by = EXCLUDED.added_by, added_at = now()`,
		id, normalize(subject), string(role), by)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return ErrProjectNotFound
	}
	return err
}

// RemoveMember takes a person out of a project.
func (p *Projects) RemoveMember(ctx context.Context, id uuid.UUID, subject string) error {
	_, err := p.db.Exec(ctx, `DELETE FROM project_members WHERE project_id = $1 AND subject = $2`, id, normalize(subject))
	return err
}
