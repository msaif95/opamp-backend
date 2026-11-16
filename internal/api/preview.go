package api

import (
	"net/http"

	"github.com/msaif95/opamp-backend/internal/agentconfig"
	"github.com/msaif95/opamp-backend/internal/pipeline"
	"github.com/msaif95/opamp-backend/internal/preview"
)

// previewConfig shows what a config's processors would do to sample
// telemetry, without saving or sending anything. The config is given as
// YAML (body) or as a builder pipeline; secret references are left as
// written, never resolved.
func (s *Server) previewConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Body    string         `json:"body"`
		Builder *pipeline.Spec `json:"builder"`
		// Signal is logs, traces or metrics; empty picks the first the config handles.
		Signal   string `json:"signal"`
		Pipeline string `json:"pipeline"`
		// Sample is OTLP JSON to preview against; empty uses the built-in sample.
		Sample string `json:"sample"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Builder != nil {
		resolved, issues, err := s.Library.Resolve(r.Context(), scopeOf(r.Context()), *req.Builder)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		if !agentconfig.HasErrors(issues) {
			req.Body, issues = pipeline.Render(resolved)
		}
		if agentconfig.HasErrors(issues) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "the pipeline has problems; fix them to preview it", "issues": issues})
			return
		}
	}
	res, err := preview.Run(preview.Request{Config: req.Body, Signal: req.Signal, Pipeline: req.Pipeline, Sample: req.Sample})
	if preview.IsInput(err) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// previewSamples returns the built-in sample telemetry as OTLP JSON, as a starting point for supplying one's own.
func (s *Server) previewSamples(w http.ResponseWriter, _ *http.Request) {
	out := map[string]string{}
	for _, signal := range preview.Signals {
		out[signal] = preview.Sample(signal)
	}
	writeJSON(w, http.StatusOK, out)
}
