package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/osman/sylva/internal/config"
)

// Client communicates with a remote or local sylvad server.
type Client struct {
	baseURL          string
	maxResponseBytes int64
	httpClient       *http.Client
}

// NewClient constructs a new transport Client from the given ClientConfig.
func NewClient(cfg config.ClientConfig) *Client {
	baseURL := strings.TrimRight(cfg.ServerURL, "/")
	return &Client{
		baseURL:          baseURL,
		maxResponseBytes: cfg.MaxResponseBytes,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// Ping verifies connectivity with the sylvad server and returns its status.
func (c *Client) Ping(ctx context.Context) (*StatusResponse, error) {
	reqURL := c.baseURL + "/api/v1/ping"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create ping request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", reqURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxResponseBytes))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var status StatusResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, c.maxResponseBytes)).Decode(&status); err != nil {
		return nil, fmt.Errorf("decode ping response: %w", err)
	}

	return &status, nil
}
