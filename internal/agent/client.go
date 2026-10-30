package agent

import (
	"fmt"
	"net"
	"time"

	"github.com/osman/sylva/internal/api"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/limits"
)

// Client talks to a running local session agent over a unix socket.
type Client struct {
	socketPath      string
	timeout         time.Duration
	maxRequestBytes int64
}

// Dial probes the agent socket and returns a client if it is reachable.
func Dial(socketPath string, timeout time.Duration) (*Client, error) {
	return DialWithLimit(socketPath, timeout, DefaultMaxRequestBytes)
}

// DialWithLimit uses the configured frame limit for both requests and replies.
func DialWithLimit(socketPath string, timeout time.Duration, maxBytes int64) (*Client, error) {
	maxBytes = limits.OrDefault(maxBytes, DefaultMaxRequestBytes)
	if err := limits.Validate("agent_max_request_bytes", maxBytes); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("agent dial timeout must be positive")
	}
	conn, err := net.DialTimeout("unix", socketPath, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	_ = conn.Close()
	return &Client{socketPath: socketPath, timeout: timeout, maxRequestBytes: maxBytes}, nil
}

// Status reports whether the agent currently holds a master key.
func (c *Client) Status() (unlocked bool, err error) {
	resp, err := c.roundTrip(api.AgentRequest{Op: api.AgentOpStatus})
	return resp.Unlocked, err
}

// Unlock stores the derived master key in the agent process.
func (c *Client) Unlock(key []byte) error {
	_, err := c.roundTrip(api.AgentRequest{Op: api.AgentOpUnlock, Key: key})
	return err
}

// Lock wipes the in-memory master key.
func (c *Client) Lock() error {
	_, err := c.roundTrip(api.AgentRequest{Op: api.AgentOpLock})
	return err
}

// MasterKey returns a copy of the unlocked master key.
func (c *Client) MasterKey() ([]byte, error) {
	resp, err := c.roundTrip(api.AgentRequest{Op: api.AgentOpMasterKey})
	if err != nil {
		return nil, err
	}
	if len(resp.Key) == 0 {
		return nil, ErrLocked
	}
	return resp.Key, nil
}

// Copy writes a secret to the agent-owned clipboard and schedules auto-clear.
func (c *Client) Copy(secret, secretType, identifier string) error {
	_, err := c.roundTrip(api.AgentRequest{
		Op:         api.AgentOpCopy,
		Secret:     secret,
		Type:       secretType,
		Identifier: identifier,
	})
	return err
}

// ScheduleClear asks the agent to wipe the clipboard after its configured delay.
func (c *Client) ScheduleClear(secret string) error {
	_, err := c.roundTrip(api.AgentRequest{Op: api.AgentOpScheduleClear, Secret: secret})
	return err
}

func (c *Client) roundTrip(req api.AgentRequest) (api.AgentResponse, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return api.AgentResponse{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return api.AgentResponse{}, err
	}
	if err := writeFrame(conn, c.maxRequestBytes, req); err != nil {
		return api.AgentResponse{}, fmt.Errorf("write agent request: %w", err)
	}
	var resp api.AgentResponse
	if err := readFrame(conn, c.maxRequestBytes, &resp); err != nil {
		crypto.ZeroBytes(resp.Key)
		return api.AgentResponse{}, fmt.Errorf("read agent response: %w", err)
	}
	if resp.CleanupError != "" {
		crypto.ZeroBytes(resp.Key)
		resp.Key = nil
		return resp, fmt.Errorf("%w: %s; run sylva lock to retry cleanup", ErrCleanupIncomplete, resp.CleanupError)
	}
	if !resp.OK {
		if resp.Error == ErrLocked.Error() {
			return resp, ErrLocked
		}
		if resp.Error == "" {
			return resp, fmt.Errorf("agent request %q failed", req.Op)
		}
		return resp, fmt.Errorf("agent: %s", resp.Error)
	}
	return resp, nil
}
