package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/limits"
	"github.com/osman/sylva/internal/storage"
	"github.com/osman/sylva/internal/vault"
)

// HTTPError is a non-success HTTP response from sylvad.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	if e == nil {
		return "http error"
	}
	return fmt.Sprintf("unexpected status %d: %s", e.Status, e.Body)
}

func (e *HTTPError) Unwrap() error {
	if e == nil {
		return nil
	}
	switch e.Status {
	case http.StatusConflict:
		var body api.ErrorBody
		if json.Unmarshal([]byte(e.Body), &body) == nil && body.Error == api.ErrorVaultChanged {
			return storage.ErrVaultChanged
		}
		if json.Unmarshal([]byte(e.Body), &body) == nil && body.Error == api.ErrorRecordVersionConflict {
			return storage.ErrVersionConflict
		}
		return storage.ErrConflict
	case http.StatusNotFound:
		return storage.ErrNotFound
	case http.StatusRequestEntityTooLarge:
		return ErrPayloadTooLarge
	default:
		return nil
	}
}

// Client communicates with a remote or local sylvad server.
type Client struct {
	baseURL       string
	apiPrefix     string
	maxBodyBytes  int64
	maxVaultBytes int64
	httpClient    *http.Client
	generation    atomic.Value
	kdf           atomic.Pointer[config.CryptoConfig]
}

// NewClient constructs a new transport Client from the given ClientConfig.
func NewClient(cfg config.ClientConfig) (*Client, error) {
	cfg.MaxBodyBytes = limits.OrDefault(cfg.MaxBodyBytes, limits.DefaultBodyBytes)
	cfg.MaxVaultBytes = limits.OrDefault(cfg.MaxVaultBytes, limits.DefaultVaultBytes)
	if err := limits.Validate("max_body_bytes", cfg.MaxBodyBytes); err != nil {
		return nil, err
	}
	if err := limits.Validate("max_vault_bytes", cfg.MaxVaultBytes); err != nil {
		return nil, err
	}
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	baseURL := strings.TrimRight(cfg.ServerURL, "/")
	return &Client{
		baseURL:       baseURL,
		apiPrefix:     strings.TrimRight(cfg.APIPrefix, "/"),
		maxBodyBytes:  cfg.MaxBodyBytes,
		maxVaultBytes: cfg.MaxVaultBytes,
		httpClient:    httpClient,
	}, nil
}

func newHTTPClient(cfg config.ClientConfig) (*http.Client, error) {
	c := &http.Client{Timeout: cfg.Timeout}
	if !cfg.EnableMTLS {
		return c, nil
	}
	tlsCfg, err := clientTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http default transport is not *http.Transport")
	}
	tr := base.Clone()
	tr.TLSClientConfig = tlsCfg
	c.Transport = tr
	return c, nil
}

func (c *Client) apiURL(path string) string {
	return c.baseURL + api.Join(c.apiPrefix, path)
}

// Close releases idle HTTP connections held by the client.
func (c *Client) Close() {
	if c == nil || c.httpClient == nil {
		return
	}
	c.httpClient.CloseIdleConnections()
}

// Ping verifies connectivity with the sylvad server and returns its status.
func (c *Client) Ping(ctx context.Context) (*StatusResponse, error) {
	var status StatusResponse
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL(api.PathPing), nil, http.StatusOK, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// PutRecord stores a new encrypted record on the server.
func (c *Client) PutRecord(ctx context.Context, rec *vault.EncryptedRecord) (*vault.EncryptedRecord, error) {
	var out vault.EncryptedRecord
	if err := c.doJSON(ctx, http.MethodPut, c.apiURL(api.PathRecords), rec, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateRecord replaces an existing encrypted record on the server.
func (c *Client) UpdateRecord(ctx context.Context, rec *vault.EncryptedRecord) (*vault.EncryptedRecord, error) {
	var out vault.EncryptedRecord
	if err := c.doJSON(ctx, http.MethodPut, c.apiURL(api.RecordPath(rec.ID)), rec, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRecord loads an encrypted record by ID.
func (c *Client) GetRecord(ctx context.Context, id string) (*vault.EncryptedRecord, error) {
	var out vault.EncryptedRecord
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL(api.RecordPath(id)), nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRecordByBlindIndex loads an encrypted record by its HMAC blind index.
func (c *Client) GetRecordByBlindIndex(ctx context.Context, blindIndex string) (*vault.EncryptedRecord, error) {
	u := c.apiURL(api.RecordsQuery(api.QueryBlindIndex, blindIndex))
	var out vault.EncryptedRecord
	if err := c.doJSON(ctx, http.MethodGet, u, nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListRecords lists encrypted records, optionally filtered by secret type.
func (c *Client) ListRecords(ctx context.Context, secretType vault.SecretType) ([]*vault.EncryptedRecord, error) {
	return c.listRecords(ctx, nil, secretType)
}

func (c *Client) ListProfileRecords(ctx context.Context, profile string, secretType vault.SecretType) ([]*vault.EncryptedRecord, error) {
	return c.listRecords(ctx, &profile, secretType)
}

func (c *Client) listRecords(ctx context.Context, profile *string, kind vault.SecretType) ([]*vault.EncryptedRecord, error) {
	query := url.Values{}
	if kind != "" {
		query.Set(api.QuerySecretType, string(kind))
	}
	if profile != nil {
		query.Set(api.QueryProfileID, *profile)
	}
	path := api.PathRecords
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	var out api.RecordsBody
	if err := c.doJSONLimit(ctx, http.MethodGet, c.apiURL(path), nil, http.StatusOK, &out, c.maxVaultBytes, "max_vault_bytes"); err != nil {
		return nil, err
	}
	if out.Records == nil {
		return nil, fmt.Errorf("invalid records response: records must be an array")
	}
	return out.Records, nil
}

// DeleteRecord removes an encrypted record by ID.
func (c *Client) DeleteRecord(ctx context.Context, id string) error {
	return c.doJSON(ctx, http.MethodDelete, c.apiURL(api.RecordPath(id)), nil, http.StatusNoContent, nil)
}

// GetSalt fetches the vault-wide Argon2id salt from the server.
func (c *Client) GetSalt(ctx context.Context) ([]byte, error) {
	var out api.SaltBody
	if err := c.doJSON(ctx, http.MethodGet, c.apiURL(api.PathVaultSalt), nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	c.kdf.Store(out.KDF)
	salt, err := parseSaltHex(out.SaltHex)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// PutSalt initializes (or confirms) the vault-wide Argon2id salt on the server.
func (c *Client) PutSalt(ctx context.Context, salt []byte) error {
	body := api.SaltBody{SaltHex: encodeSaltHex(salt)}
	return c.doJSON(ctx, http.MethodPut, c.apiURL(api.PathVaultSalt), body, 0, &api.SaltBody{})
}

func (c *Client) doJSON(ctx context.Context, method, reqURL string, in any, wantStatus int, out any) error {
	return c.doJSONLimit(ctx, method, reqURL, in, wantStatus, out, c.maxBodyBytes, "max_body_bytes")
}

func (c *Client) doJSONLimit(ctx context.Context, method, reqURL string, in any, wantStatus int, out any, n int64, setting string) error {
	var reader io.Reader
	if in != nil {
		payload, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		if int64(len(payload)) > n {
			return &limits.SizeError{Scope: "request", Setting: setting, Limit: n}
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", api.ContentTypeJSON)
	if generation, ok := c.generation.Load().(string); ok {
		req.Header.Set(api.HeaderGeneration, generation)
	}
	if in != nil {
		req.Header.Set("Content-Type", api.ContentTypeJSON)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return explainRequestError(reqURL, err)
	}
	if resp == nil {
		return fmt.Errorf("empty HTTP response from %s", reqURL)
	}
	defer resp.Body.Close()

	body, err := limits.Read(resp.Body, n, "response", setting)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if wantStatus != 0 && resp.StatusCode != wantStatus {
		return explainStatus(&HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))})
	}
	if wantStatus == 0 && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return explainStatus(&HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))})
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if len(body) == 0 {
		return fmt.Errorf("decode response: empty JSON body")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *Client) SetGeneration(generation string) { c.generation.Store(generation) }
func (c *Client) KDFConfig() *config.CryptoConfig { return c.kdf.Load() }
