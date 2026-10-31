package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/vault"
)

// HTTP path fragments. Absolute paths are joined with SYLVA_API_PREFIX except
// when Endpoint.Prefixed is false (health checks).
const (
	PathPing          = "/ping"
	PathHealthz       = "/healthz"
	PathRecords       = "/records"
	PathRecordID      = "/records/{id}"
	PathVaultSalt     = "/vault/salt"
	PathVaultKeyCheck = "/vault/key-check"
	PathVaultSnapshot = "/vault/snapshot"
)

// Query and path parameter names shared by the HTTP client and server.
const (
	QueryBlindIndex = "blind_index"
	QuerySecretType = "type"
	QueryProfileID  = "profile_id"
	ParamID         = "id"
)

// Stable endpoint names used to register handlers against the catalog.
const (
	EndpointPing         = "ping"
	EndpointHealthz      = "healthz"
	EndpointPutRecord    = "records.put"
	EndpointUpdateRecord = "records.update"
	EndpointGetRecord    = "records.get"
	EndpointDeleteRecord = "records.delete"
	EndpointListRecords  = "records.list"
	EndpointGetSalt      = "vault.salt.get"
	EndpointPutSalt      = "vault.salt.put"
	EndpointGetKeyCheck  = "vault.key-check.get"
	EndpointPutKeyCheck  = "vault.key-check.put"
	EndpointGetSnapshot  = "vault.snapshot.get"
	EndpointPutSnapshot  = "vault.snapshot.put"
)

// ContentTypeJSON is the JSON media type used by every HTTP API response.
const ContentTypeJSON = "application/json; charset=utf-8"

// Endpoint describes one HTTP route in the Sylva API catalog.
type Endpoint struct {
	Name     string
	Method   string
	Path     string
	Prefixed bool
}

// HTTPEndpoints is the complete HTTP API surface. Server routing and client
// URL construction both derive from this list.
func HTTPEndpoints() []Endpoint {
	return []Endpoint{
		{Name: EndpointPing, Method: http.MethodGet, Path: PathPing, Prefixed: true},
		{Name: EndpointHealthz, Method: http.MethodGet, Path: PathHealthz, Prefixed: false},
		{Name: EndpointPutRecord, Method: http.MethodPut, Path: PathRecords, Prefixed: true},
		{Name: EndpointUpdateRecord, Method: http.MethodPut, Path: PathRecordID, Prefixed: true},
		{Name: EndpointGetRecord, Method: http.MethodGet, Path: PathRecordID, Prefixed: true},
		{Name: EndpointDeleteRecord, Method: http.MethodDelete, Path: PathRecordID, Prefixed: true},
		{Name: EndpointListRecords, Method: http.MethodGet, Path: PathRecords, Prefixed: true},
		{Name: EndpointGetSalt, Method: http.MethodGet, Path: PathVaultSalt, Prefixed: true},
		{Name: EndpointPutSalt, Method: http.MethodPut, Path: PathVaultSalt, Prefixed: true},
		{Name: EndpointGetKeyCheck, Method: http.MethodGet, Path: PathVaultKeyCheck, Prefixed: true},
		{Name: EndpointPutKeyCheck, Method: http.MethodPut, Path: PathVaultKeyCheck, Prefixed: true},
		{Name: EndpointGetSnapshot, Method: http.MethodGet, Path: PathVaultSnapshot, Prefixed: true},
		{Name: EndpointPutSnapshot, Method: http.MethodPut, Path: PathVaultSnapshot, Prefixed: true},
	}
}

// Pattern returns the Go 1.22+ ServeMux pattern for this endpoint.
func (e Endpoint) Pattern(prefix string) string {
	return e.Method + " " + e.AbsPath(prefix)
}

// AbsPath returns the URL path, optionally joined with the API prefix.
func (e Endpoint) AbsPath(prefix string) string {
	if !e.Prefixed {
		return e.Path
	}
	return Join(prefix, e.Path)
}

// Join concatenates the configured API prefix with a catalog path.
func Join(prefix, path string) string {
	return strings.TrimRight(prefix, "/") + path
}

// RecordPath builds /records/{id} with the id path-escaped.
func RecordPath(id string) string {
	return PathRecords + "/" + url.PathEscape(id)
}

// RecordsQuery builds /records?key=value using catalog query names.
func RecordsQuery(key, value string) string {
	q := url.Values{}
	q.Set(key, value)
	return PathRecords + "?" + q.Encode()
}

// StatusResponse is returned by ping and healthz.
type StatusResponse struct {
	TailscaleDNSName string    `json:"tailscale_dns_name,omitempty"`
	Status           string    `json:"status"`
	Service          string    `json:"service"`
	Version          string    `json:"version"`
	MTLS             bool      `json:"mtls_enabled"`
	Tailscale        bool      `json:"tailscale_enabled"`
	Timestamp        time.Time `json:"timestamp"`
}

// Stable error strings returned in ErrorBody.Error.
const (
	ErrorRecordExists          = "record already exists"
	ErrorRecordVersionConflict = "record changed; fetch it again before updating"
	ErrorVaultChanged          = "vault changed; unlock it again"
)

// ErrorBody is the standard HTTP error payload.
type ErrorBody struct {
	Error string `json:"error"`
}

// RecordsBody wraps a list of encrypted records.
type RecordsBody struct {
	Records []*vault.EncryptedRecord `json:"records"`
}

// SaltBody is the vault-wide Argon2id salt payload.
type SaltBody struct {
	SaltHex string               `json:"salt_hex"`
	KDF     *config.CryptoConfig `json:"kdf,omitempty"`
}

const HeaderGeneration = "X-Sylva-Generation"

type KeyCheckBody struct {
	crypto.Envelope
	Generation string `json:"generation"`
}

type ReplaceVaultBody struct {
	ExpectedRevision   int64           `json:"expected_revision"`
	ExpectedGeneration string          `json:"expected_generation"`
	EmptyOnly          bool            `json:"empty_only"`
	Snapshot           *vault.Snapshot `json:"snapshot"`
}
