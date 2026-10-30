package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func (c *Client) Snapshot(ctx context.Context) (*vault.Snapshot, error) {
	var out vault.Snapshot
	if err := c.doJSONLimit(ctx, http.MethodGet, c.apiURL(api.PathVaultSnapshot), nil, http.StatusOK, &out, c.maxVaultBytes, "max_vault_bytes"); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ReplaceVault(ctx context.Context, expected *vault.Snapshot, next *vault.Snapshot, emptyOnly bool) error {
	body := api.ReplaceVaultBody{ExpectedRevision: expected.Revision, ExpectedGeneration: expected.Generation, Snapshot: next, EmptyOnly: emptyOnly}
	return c.doJSONLimit(ctx, http.MethodPut, c.apiURL(api.PathVaultSnapshot), body, http.StatusOK, nil, c.maxVaultBytes, "max_vault_bytes")
}

func writeVaultChanged(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, api.ErrorBody{Error: api.ErrorVaultChanged})
}

func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.store.Snapshot(r.Context(), true)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	s.writeVaultJSON(w, snapshot)
}

func (s *Server) handlePutSnapshot(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var body api.ReplaceVaultBody
	if !readRequestJSON(w, r, &body, s.cfg.MaxVaultBytes, "max_vault_bytes") {
		return
	}
	if body.Snapshot == nil || len(body.Snapshot.Salt) < 16 || body.Snapshot.KeyCheck == nil || body.Snapshot.Generation == "" || body.Snapshot.Generation == body.ExpectedGeneration || body.Snapshot.KDF == nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "invalid vault snapshot"})
		return
	}
	for _, rec := range body.Snapshot.Records {
		if rec == nil {
			writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "nil record in vault snapshot"})
			return
		}
		encoded, err := json.Marshal(rec)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "invalid record in vault snapshot"})
			return
		}
		if int64(len(encoded)) > s.cfg.MaxBodyBytes {
			err := &limits.SizeError{Scope: "snapshot record", Setting: "max_body_bytes", Limit: s.cfg.MaxBodyBytes}
			writeJSON(w, http.StatusRequestEntityTooLarge, api.ErrorBody{Error: err.Error()})
			return
		}
	}
	if err := s.store.ReplaceVault(r.Context(), body.ExpectedRevision, body.ExpectedGeneration, body.Snapshot, body.EmptyOnly); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeVaultChanged(w)
			return
		}
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct{}{})
}
