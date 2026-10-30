package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

func TestClientResponseLimitsIncludeUnknownLengthBodies(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		for _, size := range []int{24, 32, 33} {
			for _, endpoint := range []string{"list", "snapshot"} {
				t.Run(endpoint+strings.Repeat("x", size)+map[bool]string{true: "/chunked", false: "/length"}[chunked], func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if chunked {
							w.(http.Flusher).Flush()
						}
						_, _ = w.Write([]byte(`{"records":[]}` + strings.Repeat(" ", size-len(`{"records":[]}`))))
					}))
					defer server.Close()
					c, err := NewClient(config.ClientConfig{ServerURL: server.URL, MaxBodyBytes: 16, MaxVaultBytes: 32})
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					if endpoint == "list" {
						_, err = c.ListRecords(context.Background(), "")
					} else {
						_, err = c.Snapshot(context.Background())
					}
					if size > 32 {
						if !errors.Is(err, ErrPayloadTooLarge) || !strings.Contains(err.Error(), "max_vault_bytes") {
							t.Fatalf("overflow: %v", err)
						}
					} else if err != nil {
						t.Fatalf("valid response: %v", err)
					}
				})
			}
		}
	}
}

func TestOversizedRecordIsRejectedBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	c, err := NewClient(config.ClientConfig{ServerURL: server.URL, MaxBodyBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.PutRecord(context.Background(), &vault.EncryptedRecord{ID: strings.Repeat("x", 100)}); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized request: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("oversized request reached server")
	}
}

func TestServerReadsWholeBodyBeforeReplacingVault(t *testing.T) {
	next := &vault.Snapshot{Generation: "next", Salt: make([]byte, 16), KeyCheck: &crypto.Envelope{Nonce: make([]byte, 12), Ciphertext: make([]byte, 16)}, KDF: &config.CryptoConfig{KDFTime: 1, KDFMemoryKB: 1024, KDFThreads: 1, KDFKeyLen: 32, KDFSaltLen: 16}, Records: []*vault.EncryptedRecord{}}
	body, err := json.Marshal(api.ReplaceVaultBody{Snapshot: next})
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"exact", "overflow", "trailing JSON", "oversized record"} {
		t.Run(variant, func(t *testing.T) {
			store, err := storage.OpenSQLite(filepath.Join(t.TempDir(), "vault.db"), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			payload := append([]byte{}, body...)
			limit := int64(len(body))
			want := http.StatusOK
			if variant == "overflow" {
				payload = append(payload, ' ')
				want = http.StatusRequestEntityTooLarge
			}
			if variant == "trailing JSON" {
				payload = append(payload, []byte(" {}")...)
				limit += 3
				want = http.StatusBadRequest
			}
			if variant == "oversized record" {
				copy := *next
				copy.Records = []*vault.EncryptedRecord{{ID: "oversized", Type: vault.SecretTypeToken, BlindIndex: "oversized", Version: 1, Envelope: crypto.Envelope{Nonce: make([]byte, 12), Ciphertext: make([]byte, 1024)}}}
				payload, err = json.Marshal(api.ReplaceVaultBody{Snapshot: &copy})
				if err != nil {
					t.Fatal(err)
				}
				limit = int64(len(payload))
				want = http.StatusRequestEntityTooLarge
			}
			srv := NewServer(config.ServerConfig{MaxBodyBytes: 64, MaxVaultBytes: limit, APIPrefix: "/api/v1"}, store, nil)
			r := httptest.NewRequest(http.MethodPut, "/api/v1/vault/snapshot", bytes.NewReader(payload))
			r.ContentLength = -1
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body.String())
			}
			state, err := store.Snapshot(context.Background(), true)
			if err != nil {
				t.Fatal(err)
			}
			if want == http.StatusOK {
				if state.Generation != "next" {
					t.Fatal("valid replacement failed")
				}
			} else if state.Revision != 0 || len(state.Salt) != 0 {
				t.Fatal("rejected replacement changed vault")
			}
		})
	}
}

func TestServerReturns413ForAllOversizedWrites(t *testing.T) {
	for _, path := range []string{"/records", "/records/id", "/vault/salt", "/vault/key-check", "/vault/snapshot"} {
		t.Run(path, func(t *testing.T) {
			srv := NewServer(config.ServerConfig{APIPrefix: "/api/v1", MaxBodyBytes: 64, MaxVaultBytes: 128}, nil, nil)
			r := httptest.NewRequest(http.MethodPut, "/api/v1"+path, strings.NewReader(`{}`+strings.Repeat(" ", 129)))
			w := httptest.NewRecorder()
			srv.httpServer.Handler.ServeHTTP(w, r)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestServerReturns413BeforeSendingOversizedVaultJSON(t *testing.T) {
	srv := NewServer(config.ServerConfig{MaxVaultBytes: 8}, nil, nil)
	w := httptest.NewRecorder()
	srv.writeVaultJSON(w, api.RecordsBody{Records: []*vault.EncryptedRecord{}})
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d: %s", w.Code, w.Body.String())
	}
	err := &HTTPError{Status: w.Code, Body: w.Body.String()}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatal("HTTP 413 lost size error classification")
	}
}
