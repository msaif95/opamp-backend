package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client talks to the console API with an API token.
type client struct {
	base  string
	token string
	// project is the ID of the project commands act in; empty means unassigned resources.
	project string
	http    *http.Client
}

func newClient(base, token string) *client {
	return &client{base: strings.TrimRight(base, "/") + "/api/v1", token: token, http: &http.Client{Timeout: 60 * time.Second}}
}

// apiError is a non-2xx answer from the API.
type apiError struct {
	Status  int
	Message string
	Issues  []issue
}

type issue struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

func (e *apiError) Error() string {
	msg := fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
	for _, i := range e.Issues {
		msg += fmt.Sprintf("\n  %s %s: %s", i.Severity, i.Path, i.Message)
	}
	return msg
}

// do sends a request and decodes a JSON answer into out (which may be nil).
func (c *client) do(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &apiError{Status: resp.StatusCode}
		var parsed struct {
			Error  string  `json:"error"`
			Issues []issue `json:"issues"`
		}
		if json.Unmarshal(raw, &parsed) == nil && parsed.Error != "" {
			e.Message, e.Issues = parsed.Error, parsed.Issues
		} else {
			e.Message = strings.TrimSpace(string(raw))
		}
		return e
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// API shapes: only the fields the CLI uses.

type configSummary struct {
	ID            string  `json:"id"`
	ProjectID     *string `json:"project_id"`
	Name          string  `json:"name"`
	Origin        string  `json:"origin"`
	LatestVersion int     `json:"latest_version"`
	Assigned      int     `json:"assigned_agents"`
}

type configVersion struct {
	ID          string `json:"id"`
	TemplateID  string `json:"template_id"`
	Version     int    `json:"version"`
	Body        string `json:"body"`
	Description string `json:"description"`
	Author      string `json:"author"`
}

type group struct {
	ID          string              `json:"id"`
	ProjectID   *string             `json:"project_id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Selector    map[string][]string `json:"selector"`
	Members     int                 `json:"members"`
}

type agent struct {
	UID        string            `json:"instance_uid"`
	Attributes map[string]string `json:"attributes"`
	Connected  bool              `json:"connected"`
	Healthy    *bool             `json:"healthy"`
	Paused     bool              `json:"paused"`
	Version    *string           `json:"agent_version"`
	Config     *struct {
		Name    string `json:"template_name"`
		Version int    `json:"version"`
		InSync  bool   `json:"in_sync"`
	} `json:"desired_config"`
}

type rolloutInfo struct {
	ID              string         `json:"id"`
	ConfigName      string         `json:"config_name"`
	ConfigVersion   int            `json:"config_version"`
	Status          string         `json:"status"`
	TotalAgents     int            `json:"total_agents"`
	TotalBatches    int            `json:"total_batches"`
	BatchesReleased int            `json:"batches_released"`
	Counts          map[string]int `json:"counts"`
	Error           *string        `json:"error"`
	CreatedBy       string         `json:"created_by"`
}

func (c *client) configs() ([]configSummary, error) {
	var out struct {
		Configs []configSummary `json:"configs"`
	}
	return out.Configs, c.do("GET", "/configs", nil, &out)
}

func (c *client) configByName(name string) (*configSummary, error) {
	all, err := c.configs()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name && c.inProject(all[i].ProjectID) {
			return &all[i], nil
		}
	}
	return nil, nil
}

// inProject reports whether a resource's project is the one the client acts in.
func (c *client) inProject(id *string) bool {
	if id == nil {
		return c.project == ""
	}
	return *id == c.project
}

// projectField adds project_id to a request body when a project is selected.
func (c *client) projectField(body map[string]any) map[string]any {
	if c.project != "" {
		body["project_id"] = c.project
	}
	return body
}

// useProject selects the project with the given name.
func (c *client) useProject(name string) error {
	var out struct {
		Projects []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := c.do("GET", "/projects", nil, &out); err != nil {
		return err
	}
	for _, p := range out.Projects {
		if p.Name == name {
			c.project = p.ID
			return nil
		}
	}
	return fmt.Errorf("no project named %q that this token can see", name)
}

func (c *client) version(configID string, n int) (*configVersion, error) {
	var v configVersion
	return &v, c.do("GET", fmt.Sprintf("/configs/%s/versions/%d", configID, n), nil, &v)
}

func (c *client) groups() ([]group, error) {
	var out struct {
		Groups []group `json:"groups"`
	}
	return out.Groups, c.do("GET", "/groups", nil, &out)
}

func (c *client) agents(selector map[string]string, limit int) ([]agent, int, error) {
	q := url.Values{"limit": {fmt.Sprint(limit)}, "sort": {"name"}}
	if c.project != "" {
		q.Set("project_id", c.project)
	}
	for k, v := range selector {
		q.Add("attr", k+"="+v)
	}
	var out struct {
		Agents []agent `json:"agents"`
		Total  int     `json:"total"`
	}
	return out.Agents, out.Total, c.do("GET", "/agents?"+q.Encode(), nil, &out)
}

func (c *client) rollout(id string) (*rolloutInfo, error) {
	var out struct {
		Rollout rolloutInfo `json:"rollout"`
	}
	return &out.Rollout, c.do("GET", "/rollouts/"+id, nil, &out)
}
