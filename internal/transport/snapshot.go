package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func (c *Client) Snapshot(ctx context.Context) (*vault.Snapshot, error) {
	var out vault.Snapshot
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL(api.PathVaultSnapshot), nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ReplaceVault(ctx context.Context, expected *vault.Snapshot, next *vault.Snapshot, emptyOnly bool) error {
	body := api.ReplaceVaultBody{ExpectedRevision: expected.Revision, ExpectedGeneration: expected.Generation, Snapshot: next, EmptyOnly: emptyOnly}
	return c.doJSON(ctx, http.MethodPut, c.apiURL(api.PathVaultSnapshot), body, http.StatusOK, nil)
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
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handlePutSnapshot(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	var body api.ReplaceVaultBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Snapshot == nil || len(body.Snapshot.Salt) < 16 || body.Snapshot.KeyCheck == nil || body.Snapshot.Generation == "" || body.Snapshot.Generation == body.ExpectedGeneration || body.Snapshot.KDF == nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "invalid vault snapshot"})
		return
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
