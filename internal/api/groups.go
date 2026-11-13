package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/targeting"
)

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Groups.List(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": nonNil(groups)})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string             `json:"name"`
		Description string             `json:"description"`
		Selector    targeting.Selector `json:"selector"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Selector) == 0 {
		writeError(w, http.StatusBadRequest, "a group needs at least one attribute to match on")
		return
	}
	if err := req.Selector.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grp, err := s.Groups.Create(r.Context(), req.Name, req.Description, req.Selector)
	if errors.Is(err, targeting.ErrGroupNameTaken) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.create", "group", grp.ID.String(),
		map[string]any{"name": grp.Name, "selector": grp.Selector})
	writeJSON(w, http.StatusCreated, grp)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	err := s.Groups.Delete(r.Context(), id)
	if errors.Is(err, targeting.ErrGroupNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "group.delete", "group", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}
