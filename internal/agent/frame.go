package agent

import (
	"bufio"
	"encoding/json"
	"io"

	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/limits"
)

// The existing json.Encoder clients send one newline-terminated JSON frame.
// Bound the frame before decoding so a JSON object followed by huge padding
// cannot mutate the session before its size has been checked.
func readFrame(r io.Reader, maxBytes int64, out any) error {
	frame, err := bufio.NewReader(io.LimitReader(r, maxBytes+1)).ReadBytes('\n')
	defer crypto.ZeroBytes(frame)
	if int64(len(frame)) > maxBytes {
		return &limits.SizeError{Scope: "agent frame", Setting: "agent_max_request_bytes", Limit: maxBytes}
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(frame, out)
}

func writeFrame(w io.Writer, maxBytes int64, in any) error {
	frame, err := json.Marshal(in)
	if err != nil {
		return err
	}
	frame = append(frame, '\n')
	defer crypto.ZeroBytes(frame)
	if int64(len(frame)) > maxBytes {
		return &limits.SizeError{Scope: "agent frame", Setting: "agent_max_request_bytes", Limit: maxBytes}
	}
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		return io.ErrShortWrite
	}
	return err
}
