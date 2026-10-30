package api

// Agent protocol operations served over the local unix socket.
const (
	AgentOpStatus        = "status"
	AgentOpUnlock        = "unlock"
	AgentOpLock          = "lock"
	AgentOpMasterKey     = "master-key"
	AgentOpCopy          = "copy"
	AgentOpScheduleClear = "schedule-clear"
)

// AgentRequest is the local session-agent request envelope.
type AgentRequest struct {
	Op         string `json:"op"`
	Key        []byte `json:"key,omitempty"`
	Secret     string `json:"secret,omitempty"`
	Type       string `json:"type,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// AgentResponse is the local session-agent response envelope.
type AgentResponse struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Unlocked bool   `json:"unlocked,omitempty"`
	Key      []byte `json:"key,omitempty"`
	// CleanupError is independent of Unlocked: a missing in-memory key does not
	// imply that the clipboard and persistent keyring were successfully cleared.
	CleanupError string `json:"cleanup_error,omitempty"`
}

// AgentOps lists every supported session-agent operation.
func AgentOps() []string {
	return []string{
		AgentOpStatus,
		AgentOpUnlock,
		AgentOpLock,
		AgentOpMasterKey,
		AgentOpCopy,
		AgentOpScheduleClear,
	}
}
