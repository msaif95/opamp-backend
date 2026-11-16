package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/registry"
)

// labelKey: letters, digits and . _ / - ; starts and ends with a letter or digit; at most 63 characters.
var labelKey = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._/-]{0,61}[A-Za-z0-9])?$`)

const maxLabelValue = 128

// labelChange is what to do to an agent's labels.
type labelChange struct {
	Set    map[string]string `json:"set"`
	Remove []string          `json:"remove"`
}

// validate trims values and rejects keys and values that are not allowed.
func (c *labelChange) validate() error {
	if len(c.Set) > registry.MaxLabels {
		return registry.ErrTooManyLabels
	}
	for k, v := range c.Set {
		if !labelKey.MatchString(k) {
			return fmt.Errorf("label key %q: use letters, digits and . _ / - (at most 63 characters, starting and ending with a letter or digit)", k)
		}
		v = strings.TrimSpace(v)
		if v == "" || len(v) > maxLabelValue || strings.ContainsFunc(v, unicode.IsControl) {
			return fmt.Errorf("label %q: the value must be 1 to %d characters on one line", k, maxLabelValue)
		}
		c.Set[k] = v
	}
	for _, k := range c.Remove {
		if _, both := c.Set[k]; both {
			return fmt.Errorf("label %q is both set and removed", k)
		}
	}
	return nil
}

// labelOne changes one agent's labels on behalf of the caller (operator in the agent's project).
func (s *Server) labelOne(ctx context.Context, uid uuid.UUID, change labelChange, replace bool, details map[string]any) (int, string) {
	if status, msg := s.permitAgent(ctx, "agent.labels", uid, auth.RoleOperator); status != 0 {
		return status, msg
	}
	labels, err := s.Registry.SetLabels(ctx, uid, change.Set, change.Remove, replace)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		return http.StatusNotFound, "agent not found"
	case errors.Is(err, registry.ErrTooManyLabels):
		return http.StatusConflict, err.Error()
	case err != nil:
		return s.failed(ctx, "agent.labels", err)
	}
	d := map[string]any{"labels": labels}
	if !replace {
		d["set"] = change.Set
		if len(change.Remove) > 0 {
			d["remove"] = change.Remove
		}
	}
	for k, v := range details {
		d[k] = v
	}
	s.auditAgent(ctx, "agent.labels", uid, d)
	return http.StatusNoContent, ""
}

// setAgentLabels replaces the labels on one agent: PUT {"labels": {"owner": "alice"}}.
func (s *Server) setAgentLabels(w http.ResponseWriter, r *http.Request) {
	uid, ok := pathUUID(w, r, "uid")
	if !ok {
		return
	}
	var req struct {
		Labels map[string]string `json:"labels"`
	}
	if !decode(w, r, &req) {
		return
	}
	change := labelChange{Set: req.Labels}
	if err := change.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if status, msg := s.labelOne(r.Context(), uid, change, true, nil); status >= 400 {
		writeError(w, status, msg)
	} else {
		w.WriteHeader(status)
	}
}
