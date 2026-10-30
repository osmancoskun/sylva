package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
)

// GetKeyCheck fetches the encrypted, immutable vault key verifier.
func (c *Client) GetKeyCheck(ctx context.Context) (*crypto.Envelope, error) {
	out, err := c.GetKeyCheckState(ctx)
	if err != nil {
		return nil, err
	}
	return &out.Envelope, nil
}

func (c *Client) GetKeyCheckState(ctx context.Context) (*api.KeyCheckBody, error) {
	var out api.KeyCheckBody
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL(api.PathVaultKeyCheck), nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutKeyCheck initializes the verifier; an existing verifier returns a conflict.
func (c *Client) PutKeyCheck(ctx context.Context, env *crypto.Envelope) error {
	return c.doJSON(ctx, http.MethodPut, c.apiURL(api.PathVaultKeyCheck), env, http.StatusCreated, nil)
}

func (s *Server) handleGetKeyCheck(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.store.Snapshot(r.Context(), false)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if snapshot.KeyCheck == nil {
		writeStorageError(w, storage.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, api.KeyCheckBody{Envelope: *snapshot.KeyCheck, Generation: snapshot.Generation})
}

func (s *Server) handlePutKeyCheck(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var env crypto.Envelope
	if !readRequestJSON(w, r, &env, s.cfg.MaxBodyBytes, "max_body_bytes") {
		return
	}
	if len(env.Nonce) != 12 || len(env.Ciphertext) < 16 {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "invalid vault key verifier"})
		return
	}
	if _, err := s.store.GetMetadata(r.Context(), storage.MetadataKDFSalt); err != nil {
		writeStorageError(w, err)
		return
	}
	raw, err := json.Marshal(env)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "encode vault key verifier"})
		return
	}
	if err := s.store.CreateMetadata(storage.WithGeneration(r.Context(), r.Header.Get(api.HeaderGeneration)), storage.MetadataKeyCheck, raw); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			writeVaultChanged(w)
			return
		}
		if errors.Is(err, storage.ErrConflict) {
			writeJSON(w, http.StatusConflict, api.ErrorBody{Error: "vault key verifier is already initialized"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "persist vault key verifier"})
		return
	}
	writeJSON(w, http.StatusCreated, env)
}
