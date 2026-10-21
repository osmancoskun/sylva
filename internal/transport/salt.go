package transport

import (
	"encoding/hex"
	"fmt"
)

func encodeSaltHex(salt []byte) string {
	return hex.EncodeToString(salt)
}

func parseSaltHex(raw string) ([]byte, error) {
	salt, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("decode salt hex: %w", err)
	}
	return salt, nil
}
