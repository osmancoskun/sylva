package transport

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func (s *Server) handlePutRecord(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var rec vault.EncryptedRecord
	if !readRequestJSON(w, r, &rec, s.cfg.MaxBodyBytes, "max_body_bytes") {
		return
	}
	if rec.ID == "" || rec.BlindIndex == "" || rec.Type == "" || !vault.ValidProfileID(rec.ProfileID) {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "record id, type, and blind_index are required"})
		return
	}

	if err := s.store.Put(storage.WithGeneration(r.Context(), r.Header.Get(api.HeaderGeneration)), &rec); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			writeVaultChanged(w)
			return
		}
		if errors.Is(err, storage.ErrConflict) {
			writeJSON(w, http.StatusConflict, api.ErrorBody{Error: api.ErrorRecordExists})
			return
		}
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "failed to persist record"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	id := r.PathValue(api.ParamID)
	var rec vault.EncryptedRecord
	if !readRequestJSON(w, r, &rec, s.cfg.MaxBodyBytes, "max_body_bytes") {
		return
	}
	if rec.ID == "" {
		rec.ID = id
	}
	if rec.ID != id || rec.BlindIndex == "" || rec.Type == "" || !vault.ValidProfileID(rec.ProfileID) {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "record id, type, and blind_index are required"})
		return
	}

	if err := s.store.Update(storage.WithGeneration(r.Context(), r.Header.Get(api.HeaderGeneration)), &rec); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			writeVaultChanged(w)
			return
		}
		if errors.Is(err, storage.ErrVersionConflict) {
			writeJSON(w, http.StatusConflict, api.ErrorBody{Error: api.ErrorRecordVersionConflict})
			return
		}
		if errors.Is(err, storage.ErrNotFound) {
			writeStorageError(w, err)
			return
		}
		if errors.Is(err, storage.ErrConflict) {
			writeJSON(w, http.StatusConflict, api.ErrorBody{Error: api.ErrorRecordExists})
			return
		}
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "failed to persist record"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleGetRecordByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue(api.ParamID)
	rec, err := s.store.GetByID(r.Context(), id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue(api.ParamID)
	if err := s.store.Delete(storage.WithGeneration(r.Context(), r.Header.Get(api.HeaderGeneration)), id); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			writeVaultChanged(w)
			return
		}
		writeStorageError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if blind := q.Get(api.QueryBlindIndex); blind != "" {
		rec, err := s.store.GetByBlindIndex(r.Context(), blind)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rec)
		return
	}

	var secretType vault.SecretType
	if raw := q.Get(api.QuerySecretType); raw != "" {
		secretType = vault.SecretType(raw)
	}
	var recs []*vault.EncryptedRecord
	var err error
	if q.Has(api.QueryProfileID) {
		profile := q.Get(api.QueryProfileID)
		if !vault.ValidProfileID(profile) {
			writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "invalid profile ID"})
			return
		}
		recs, err = s.store.ListProfile(r.Context(), profile, secretType)
	} else {
		recs, err = s.store.List(r.Context(), secretType)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "failed to list records"})
		return
	}
	if recs == nil {
		recs = []*vault.EncryptedRecord{}
	}
	s.writeVaultJSON(w, api.RecordsBody{Records: recs})
}

func (s *Server) handleGetSalt(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.store.Snapshot(r.Context(), false)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if len(snapshot.Salt) == 0 {
		writeStorageError(w, storage.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, api.SaltBody{SaltHex: hex.EncodeToString(snapshot.Salt), KDF: snapshot.KDF})
}

func (s *Server) handlePutSalt(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var body api.SaltBody
	if !readRequestJSON(w, r, &body, s.cfg.MaxBodyBytes, "max_body_bytes") {
		return
	}
	if body.SaltHex == "" {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "salt_hex is required"})
		return
	}
	salt, err := hex.DecodeString(body.SaltHex)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorBody{Error: "salt_hex must be valid hex"})
		return
	}

	existing, err := s.store.GetMetadata(r.Context(), storage.MetadataKDFSalt)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "failed to read vault salt"})
		return
	}
	if err == nil {
		if hex.EncodeToString(existing) != body.SaltHex {
			writeJSON(w, http.StatusConflict, api.ErrorBody{Error: "vault salt is already initialized with a different value"})
			return
		}
		writeJSON(w, http.StatusOK, body)
		return
	}

	if err := s.store.CreateMetadata(storage.WithGeneration(r.Context(), r.Header.Get(api.HeaderGeneration)), storage.MetadataKDFSalt, salt); err != nil {
		if errors.Is(err, storage.ErrVaultChanged) {
			writeVaultChanged(w)
			return
		}
		if errors.Is(err, storage.ErrConflict) {
			writeJSON(w, http.StatusConflict, api.ErrorBody{Error: "vault salt is already initialized"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "failed to persist vault salt"})
		return
	}
	writeJSON(w, http.StatusCreated, body)
}

func writeStorageError(w http.ResponseWriter, err error) {
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, api.ErrorBody{Error: "not found"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, api.ErrorBody{Error: "storage error"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"failed to encode response"}`)
	}
	w.Header().Set("Content-Type", api.ContentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
