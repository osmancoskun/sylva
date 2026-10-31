package vault

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/osman/sylva/internal/crypto"
)

type ProfilePayload struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func ProfileIdentifier(name string) string { return "sylva-profile:" + name }

// Empty is the legacy/default profile; other IDs are random 128-bit values.
func ValidProfileID(id string) bool {
	if id == "" {
		return true
	}
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 16 && id == strings.ToLower(id)
}

func profileKey(master []byte, id string) ([]byte, error) {
	if !ValidProfileID(id) {
		return nil, errors.New("invalid profile ID")
	}
	if id == "" {
		return append([]byte{}, master...), nil
	}
	return crypto.DeriveSubkey(master, "sylva-profile-key-v1:"+id)
}

func LookupProfileBlindIndex(master []byte, id string, kind SecretType, identifier string) (string, error) {
	key, err := profileKey(master, id)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(key)
	return LookupBlindIndex(key, kind, identifier)
}

func profileAAD(profile, id string, kind SecretType, index string, version int) []byte {
	aad := buildAAD(id, kind, index, version)
	if profile == "" {
		return aad
	}
	return append([]byte("sylva-profile-v1:"+profile+"|"), aad...)
}
