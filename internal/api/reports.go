package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/msaif95/opamp-backend/internal/auth"
	"github.com/msaif95/opamp-backend/internal/compliance"
)

// maxReportDays is the longest period a report made on request can cover.
const maxReportDays = 366

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	reports, err := s.Reports.List(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": nonNil(reports)})
}

// createReport makes a compliance report now, covering the last `days` days.
func (s *Server) createReport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Days < 1 || req.Days > maxReportDays {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("days must be between 1 and %d", maxReportDays))
		return
	}
	now := time.Now().UTC()
	if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
		req.Name = fmt.Sprintf("Last %d days, %s", req.Days, now.Format("2 Jan 2006"))
	}
	u, _ := auth.UserFrom(r.Context())
	rep, err := s.Reports.Generate(r.Context(), req.Name, now.AddDate(0, 0, -req.Days), now, u.Subject, nil)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "report.generate", "report", rep.ID.String(), map[string]any{"name": rep.Name, "days": req.Days})
	rep.Body = compliance.Body{}
	writeJSON(w, http.StatusCreated, rep)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) (*compliance.Report, bool) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return nil, false
	}
	rep, err := s.Reports.Get(r.Context(), id)
	if errors.Is(err, compliance.ErrNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return nil, false
	}
	if err != nil {
		s.internal(w, r, err)
		return nil, false
	}
	return rep, true
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	if rep, ok := s.report(w, r); ok {
		writeJSON(w, http.StatusOK, rep)
	}
}

// downloadReport sends a report as a file: ?format=html (printable), json
// (everything), collectors (fleet snapshot CSV) or changes (audit trail CSV).
func (s *Server) downloadReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	kinds := map[string][2]string{
		"html":       {"text/html; charset=utf-8", "html"},
		"json":       {"application/json", "json"},
		"collectors": {"text/csv; charset=utf-8", "collectors.csv"},
		"changes":    {"text/csv; charset=utf-8", "changes.csv"},
	}
	kind, known := kinds[format]
	if !known {
		writeError(w, http.StatusBadRequest, "format must be html, json, collectors or changes")
		return
	}
	rep, ok := s.report(w, r)
	if !ok {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "report.download", "report", rep.ID.String(), map[string]any{"name": rep.Name, "format": format})
	w.Header().Set("Content-Type", kind[0])
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, rep.FileName(kind[1])))
	var err error
	switch format {
	case "html":
		err = rep.WriteHTML(w)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(rep)
	case "collectors":
		err = rep.WriteCollectorsCSV(w)
	case "changes":
		err = rep.WriteChangesCSV(w)
	}
	if err != nil {
		s.Log.ErrorContext(r.Context(), "write report", "err", err)
	}
}

func (s *Server) deleteReport(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.report(w, r)
	if !ok {
		return
	}
	if err := s.Reports.Delete(r.Context(), rep.ID); err != nil && !errors.Is(err, compliance.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "report.delete", "report", rep.ID.String(), map[string]any{"name": rep.Name})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listReportSchedules(w http.ResponseWriter, r *http.Request) {
	schedules, err := s.Reports.Schedules(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedules": nonNil(schedules)})
}

func (s *Server) createReportSchedule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		Frequency string `json:"frequency"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	u, _ := auth.UserFrom(r.Context())
	sch, err := s.Reports.CreateSchedule(r.Context(), req.Name, req.Frequency, u.Subject)
	switch {
	case errors.Is(err, compliance.ErrFrequency):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, compliance.ErrScheduleNameTaken):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "report_schedule.create", "report_schedule", sch.ID.String(), map[string]any{"name": sch.Name, "frequency": sch.Frequency})
	writeJSON(w, http.StatusCreated, sch)
}

// scheduleError writes the response for a failed schedule operation.
func (s *Server) scheduleError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, compliance.ErrScheduleNotFound) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.internal(w, r, err)
}

func (s *Server) updateReportSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	sch, err := s.Reports.SetScheduleEnabled(r.Context(), id, *req.Enabled)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "report_schedule.update", "report_schedule", id.String(), map[string]any{"name": sch.Name, "enabled": sch.Enabled})
	writeJSON(w, http.StatusOK, sch)
}

func (s *Server) deleteReportSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := s.Reports.DeleteSchedule(r.Context(), id); err != nil {
		s.scheduleError(w, r, err)
		return
	}
	u, _ := auth.UserFrom(r.Context())
	s.audit(r.Context(), u.Subject, u.Provider, "report_schedule.delete", "report_schedule", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// runReportSchedule makes a schedule's report for the last whole period straight away.
func (s *Server) runReportSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	u, _ := auth.UserFrom(r.Context())
	rep, err := s.Reports.RunNow(r.Context(), id, u.Subject)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	s.audit(r.Context(), u.Subject, u.Provider, "report.generate", "report", rep.ID.String(), map[string]any{"name": rep.Name, "schedule_id": id})
	rep.Body = compliance.Body{}
	writeJSON(w, http.StatusCreated, rep)
}
