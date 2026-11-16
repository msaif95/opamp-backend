package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/msaif95/opamp-backend/internal/auth"
)

// userSettingKeys are the per-user settings the console keeps: saved fleet
// views, and which cards a person's overview shows. Each is a JSON list
// whose items the console defines; the backend bounds its size.
var userSettingKeys = map[string]bool{"fleet_views": true, "overview_cards": true}

const (
	maxUserSettingBytes = 32 << 10
	maxUserSettingItems = 50
)

// settingsOwner identifies whose settings a request reads or writes: always the caller's own.
func settingsOwner(r *http.Request) string {
	u, _ := auth.UserFrom(r.Context())
	return u.Provider + ":" + strings.ToLower(u.Subject)
}

// getUserSetting returns one of the caller's own settings; {"value": null} when never set.
func (s *Server) getUserSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if !userSettingKeys[key] {
		writeError(w, http.StatusNotFound, "unknown setting")
		return
	}
	var value json.RawMessage
	err := s.DB.QueryRow(r.Context(), `SELECT value FROM user_settings WHERE owner = $1 AND key = $2`, settingsOwner(r), key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		value = json.RawMessage("null")
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"value": value})
}

// putUserSetting replaces one of the caller's own settings: PUT {"value": [...]}.
func (s *Server) putUserSetting(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	if !userSettingKeys[key] {
		writeError(w, http.StatusNotFound, "unknown setting")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUserSettingBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "that is more than can be saved here")
		return
	}
	var req struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.Value == nil {
		writeError(w, http.StatusBadRequest, "value must be a list")
		return
	}
	if len(req.Value) > maxUserSettingItems {
		writeError(w, http.StatusBadRequest, "at most 50 can be saved")
		return
	}
	value, _ := json.Marshal(req.Value)
	_, err = s.DB.Exec(r.Context(), `
INSERT INTO user_settings (owner, key, value) VALUES ($1, $2, $3::jsonb)
ON CONFLICT (owner, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, settingsOwner(r), key, value)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
