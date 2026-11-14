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
	// DeletedAt is set once the project has been deleted; it is then kept only as a record.
	DeletedAt *time.Time `json:"deleted_at"`
	DeletedBy *string    `json:"deleted_by"`
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
	rows, err := p.db.Query(ctx, `
SELECT m.project_id, m.role::text FROM project_members m JOIN projects p ON p.id = m.project_id
WHERE m.subject = $1 AND p.deleted_at IS NULL`, normalize(u.Subject))
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
	err := p.db.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM project_members m JOIN projects p ON p.id = m.project_id WHERE m.subject = $1 AND p.deleted_at IS NULL)`, normalize(subject)).Scan(&ok)
	return ok, err
}

// List returns the projects the scope may view, by name. Deleted projects
// are left out unless includeDeleted is set.
func (p *Projects) List(ctx context.Context, s Scope, includeDeleted bool) ([]Project, error) {
	// Unassigned is not a project, so only real memberships (or admin) list anything.
	where, args := Scope{Admin: s.Admin, Projects: s.Projects}.Where("p.id", 1)
	rows, err := p.db.Query(ctx, `
SELECT p.id, p.name, p.description, p.created_by, p.created_at, p.deleted_at, p.deleted_by,
       (SELECT count(*) FROM project_members m WHERE m.project_id = p.id),
       (SELECT count(*) FROM agents a WHERE a.project_id = p.id)
FROM projects p WHERE `+where+` AND (p.deleted_at IS NULL OR $`+fmt.Sprint(len(args)+1)+`) ORDER BY p.deleted_at IS NOT NULL, p.name`, append(args, includeDeleted)...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Project, error) {
		var pr Project
		err := row.Scan(&pr.ID, &pr.Name, &pr.Description, &pr.CreatedBy, &pr.CreatedAt, &pr.DeletedAt, &pr.DeletedBy, &pr.Members, &pr.Agents)
		return pr, err
	})
}

// Exists reports whether a project exists and has not been deleted.
func (p *Projects) Exists(ctx context.Context, id uuid.UUID) (bool, error) {
	var ok bool
	err := p.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND deleted_at IS NULL)`, id).Scan(&ok)
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

// Deleted says what deleting a project switched off.
type Deleted struct {
	APIKeys    int64 `json:"api_keys_revoked"`
	Tokens     int64 `json:"tokens_revoked"`
	Collectors int64 `json:"collectors"`
	Pushes     int64 `json:"pushes_aborted"`
}

// Delete retires a project. Nothing is removed: the project is marked
// deleted and kept as a record, together with its collectors, configs and
// history. Its agent API keys and API tokens are revoked, so its collectors
// are disconnected and cannot come back, pushes still in progress are
// aborted, and nobody but global administrators can see it any more.
func (p *Projects) Delete(ctx context.Context, id uuid.UUID, by string) (Deleted, error) {
	var d Deleted
	tx, err := p.db.Begin(ctx)
	if err != nil {
		return d, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE projects SET deleted_at = now(), deleted_by = $2 WHERE id = $1 AND deleted_at IS NULL`, id, by)
	if err != nil {
		return d, err
	}
	if tag.RowsAffected() == 0 {
		return d, ErrProjectNotFound
	}
	for _, step := range []struct {
		n   *int64
		sql string
	}{
		{&d.APIKeys, `UPDATE credentials SET revoked_at = now() WHERE project_id = $1 AND revoked_at IS NULL`},
		{&d.Tokens, `UPDATE api_tokens SET revoked_at = now() WHERE project_id = $1 AND revoked_at IS NULL`},
		{&d.Pushes, `UPDATE rollouts SET status = 'aborted', finished_at = now(), error = 'the project was deleted'
		             WHERE project_id = $1 AND status IN ('pending', 'running', 'paused')`},
		// Groups stop handing out configs; collectors are counted, and stop being asked to change.
		{nil, `UPDATE agent_groups SET config_version_id = NULL WHERE project_id = $1`},
		{&d.Collectors, `UPDATE agents SET paused = FALSE WHERE project_id = $1`},
	} {
		tag, err := tx.Exec(ctx, step.sql, id)
		if err != nil {
			return d, err
		}
		if step.n != nil {
			*step.n = tag.RowsAffected()
		}
	}
	return d, tx.Commit(ctx)
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

// Person is someone who has signed in, or has been added to a project
// ahead of their first sign-in.
type Person struct {
	// Subject is the sign-in name memberships are keyed by.
	Subject string `json:"subject"`
	Name    string `json:"name"`
	// Provider is okta or local; empty for someone who has never signed in.
	Provider string `json:"provider"`
	// GlobalRole is the role they had at their last sign-in ("" for none).
	GlobalRole  string       `json:"global_role"`
	LastLoginAt *time.Time   `json:"last_login_at"`
	Projects    []Membership `json:"projects"`
}

// Membership is one project a person belongs to.
type Membership struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Role auth.Role `json:"role"`
}

// People lists everyone known to the console, by sign-in name.
func (p *Projects) People(ctx context.Context) ([]Person, error) {
	rows, err := p.db.Query(ctx, `
WITH signed_in AS (
    SELECT lower(COALESCE(NULLIF(email, ''), subject)) AS subject, COALESCE(display_name, '') AS name,
           provider::text AS provider, global_role, last_login_at
    FROM users
), names AS (
    SELECT subject FROM signed_in UNION SELECT subject FROM project_members
)
SELECT n.subject, COALESCE(s.name, ''), COALESCE(s.provider, ''), COALESCE(s.global_role, ''), s.last_login_at
FROM names n LEFT JOIN signed_in s USING (subject) ORDER BY n.subject`)
	if err != nil {
		return nil, err
	}
	people, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Person, error) {
		pr := Person{Projects: []Membership{}}
		err := row.Scan(&pr.Subject, &pr.Name, &pr.Provider, &pr.GlobalRole, &pr.LastLoginAt)
		return pr, err
	})
	if err != nil {
		return nil, err
	}
	index := map[string]int{}
	for i, pr := range people {
		index[pr.Subject] = i
	}
	rows, err = p.db.Query(ctx, `
SELECT m.subject, p.id, p.name, m.role::text FROM project_members m JOIN projects p ON p.id = m.project_id ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			subject string
			m       Membership
		)
		if err := rows.Scan(&subject, &m.ID, &m.Name, &m.Role); err != nil {
			return nil, err
		}
		if i, ok := index[subject]; ok {
			people[i].Projects = append(people[i].Projects, m)
		}
	}
	return people, rows.Err()
}

// RecordSignIn notes a sign-in so the person appears on the Users page.
func (p *Projects) RecordSignIn(ctx context.Context, provider, providerSubject, email, name string, role auth.Role) error {
	_, err := p.db.Exec(ctx, `
INSERT INTO users (provider, subject, email, display_name, global_role, last_login_at) VALUES ($1::identity_provider, $2, $3, $4, $5, now())
ON CONFLICT (provider, subject) DO UPDATE SET email = EXCLUDED.email, display_name = EXCLUDED.display_name,
    global_role = EXCLUDED.global_role, last_login_at = now()`, provider, providerSubject, email, name, string(role))
	return err
}
