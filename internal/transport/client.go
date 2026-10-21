package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/config"
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
		return storage.ErrConflict
	case http.StatusNotFound:
		return storage.ErrNotFound
	default:
		return nil
	}
}

// Client communicates with a remote or local sylvad server.
type Client struct {
	baseURL      string
	apiPrefix    string
	maxBodyBytes int64
	httpClient   *http.Client
}

// NewClient constructs a new transport Client from the given ClientConfig.
func NewClient(cfg config.ClientConfig) *Client {
	baseURL := strings.TrimRight(cfg.ServerURL, "/")
	return &Client{
		baseURL:      baseURL,
		apiPrefix:    strings.TrimRight(cfg.APIPrefix, "/"),
		maxBodyBytes: cfg.MaxBodyBytes,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
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
	u := c.apiURL(api.PathRecords)
	if secretType != "" {
		u = c.apiURL(api.RecordsQuery(api.QuerySecretType, string(secretType)))
	}
	var out api.RecordsBody
	if err := c.doJSON(ctx, http.MethodGet, u, nil, http.StatusOK, &out); err != nil {
		return nil, err
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
	var reader io.Reader
	if in != nil {
		payload, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", api.ContentTypeJSON)
	if in != nil {
		req.Header.Set("Content-Type", api.ContentTypeJSON)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", reqURL, err)
	}
	if resp == nil {
		return fmt.Errorf("empty HTTP response from %s", reqURL)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodyBytes))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if wantStatus != 0 && resp.StatusCode != wantStatus {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if wantStatus == 0 && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
