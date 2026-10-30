package transport

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/limits"
)

var ErrPayloadTooLarge = limits.ErrExceeded

// Decode the complete bounded body before any mutation, including trailing data.
func readRequestJSON(w http.ResponseWriter, r *http.Request, out any, n int64, setting string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, n)
	raw, err := limits.Read(r.Body, n, "request", setting)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) || errors.Is(err, limits.ErrExceeded) {
		writeJSON(w, http.StatusRequestEntityTooLarge, api.ErrorBody{Error: (&limits.SizeError{Scope: "request", Setting: setting, Limit: n}).Error()})
		return false
	}
	if err != nil || json.Unmarshal(raw, out) != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "invalid JSON request"})
		return false
	}
	return true
}

// Buffer the bounded encoding before sending HTTP 200, so callers never receive
// a successful status followed by a truncated list or snapshot.
func (s *Server) writeVaultJSON(w http.ResponseWriter, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "failed to encode vault response"})
		return
	}
	if int64(len(body)) > s.cfg.MaxVaultBytes {
		err := &limits.SizeError{Scope: "vault response", Setting: "max_vault_bytes", Limit: s.cfg.MaxVaultBytes}
		writeJSON(w, http.StatusRequestEntityTooLarge, api.ErrorBody{Error: err.Error()})
		return
	}
	w.Header().Set("Content-Type", api.ContentTypeJSON)
	_, _ = w.Write(body)
}
