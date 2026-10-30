// Package vault defines the domain models for secrets managed by Sylva
// (logins, SSH credentials, project .env bundles, and API tokens) and handles
// sealing/unsealing them into zero-knowledge AES-256-GCM encrypted records.
package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/osman/sylva/internal/crypto"
)

// SecretType identifies the category of a vault secret.
type SecretType string

const (
	// SecretTypeLogin represents domain/website credentials (supporting domain tree inheritance).
	SecretTypeLogin SecretType = "login"

	// SecretTypeSSH represents SSH private/public keys and connection credentials.
	SecretTypeSSH SecretType = "ssh"

	// SecretTypeEnv represents project environment variable bundles (.env).
	SecretTypeEnv SecretType = "env"

	// SecretTypeToken represents API keys and personal access tokens.
	SecretTypeToken SecretType = "token"
)

const (
	subkeyPurposeEncryption = "sylva-vault-encryption-v1"
	subkeyPurposeBlindIndex = "sylva-vault-blind-index-v1"
)

// LoginPayload stores credentials for a domain or subdomain.
// If InheritFromParent is true, the entry resolves its password from the nearest
// ancestor domain in the domain hierarchy rather than storing a duplicate secret.
type LoginPayload struct {
	Domain            string `json:"domain"`
	Username          string `json:"username"`
	Password          string `json:"password,omitempty"`
	InheritFromParent bool   `json:"inherit_from_parent,omitempty"`
	ParentDomain      string `json:"parent_domain,omitempty"`
	URL               string `json:"url,omitempty"`
	Notes             string `json:"notes,omitempty"`
}

// SSHPayload stores SSH key material and connection details.
type SSHPayload struct {
	Name       string `json:"name"`
	Host       string `json:"host,omitempty"`
	User       string `json:"user,omitempty"`
	Port       int    `json:"port,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Notes      string `json:"notes,omitempty"`
}

// EnvPayload stores key-value environment variables for a project.
type EnvPayload struct {
	Project     string            `json:"project"`
	Environment string            `json:"environment,omitempty"`
	Variables   map[string]string `json:"variables"`
	Notes       string            `json:"notes,omitempty"`
}

// TokenPayload stores API tokens or personal access tokens.
type TokenPayload struct {
	Name      string     `json:"name"`
	Service   string     `json:"service,omitempty"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Notes     string     `json:"notes,omitempty"`
}

// SecretItem is the plaintext in-memory representation of a vault entry on the client.
type SecretItem struct {
	// Version is the authenticated source revision used for optimistic updates.
	// It is reconstructed from the envelope rather than serialized in plaintext.
	Version    int           `json:"-"`
	ID         string        `json:"id"`
	Type       SecretType    `json:"type"`
	Identifier string        `json:"identifier"`
	ParentID   string        `json:"parent_id,omitempty"`
	Login      *LoginPayload `json:"login,omitempty"`
	SSH        *SSHPayload   `json:"ssh,omitempty"`
	Env        *EnvPayload   `json:"env,omitempty"`
	Token      *TokenPayload `json:"token,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`
}

// Validate checks that the SecretItem has a valid type, identifier, and matching payload.
func (s *SecretItem) Validate() error {
	if s == nil {
		return errors.New("secret item cannot be nil")
	}
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("secret ID cannot be empty")
	}
	if strings.TrimSpace(s.Identifier) == "" {
		return errors.New("secret identifier cannot be empty")
	}

	switch s.Type {
	case SecretTypeLogin:
		if s.Login == nil {
			return errors.New("login payload is required for login secret type")
		}
		if strings.TrimSpace(s.Login.Domain) == "" {
			return errors.New("login domain cannot be empty")
		}
		if !s.Login.InheritFromParent && s.Login.Password == "" {
			return errors.New("login password is required when not inheriting from parent domain")
		}
	case SecretTypeSSH:
		if s.SSH == nil {
			return errors.New("ssh payload is required for ssh secret type")
		}
		if strings.TrimSpace(s.SSH.Name) == "" {
			return errors.New("ssh entry name cannot be empty")
		}
	case SecretTypeEnv:
		if s.Env == nil {
			return errors.New("env payload is required for env secret type")
		}
		if strings.TrimSpace(s.Env.Project) == "" {
			return errors.New("env project name cannot be empty")
		}
		if len(s.Env.Variables) == 0 {
			return errors.New("env variables map cannot be empty")
		}
	case SecretTypeToken:
		if s.Token == nil {
			return errors.New("token payload is required for token secret type")
		}
		if strings.TrimSpace(s.Token.Name) == "" || s.Token.Token == "" {
			return errors.New("token name and token value are required")
		}
	default:
		return fmt.Errorf("unsupported secret type %q", s.Type)
	}

	return nil
}

// EncryptedRecord is the zero-knowledge structure persisted by the server and local cache.
// The server never sees the plaintext identifier or secret payload.
type EncryptedRecord struct {
	ID               string          `json:"id"`
	Type             SecretType      `json:"type"`
	BlindIndex       string          `json:"blind_index"`
	ParentBlindIndex string          `json:"parent_blind_index,omitempty"`
	Envelope         crypto.Envelope `json:"envelope"`
	Version          int             `json:"version"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// Seal validates a SecretItem, serializes it to JSON, computes its blind index,
// and encrypts the payload with AES-256-GCM bound to the record's metadata via AAD.
func Seal(masterKey []byte, item *SecretItem, version int) (*EncryptedRecord, error) {
	if item == nil {
		return nil, errors.New("secret item cannot be nil")
	}
	if err := item.Validate(); err != nil {
		return nil, fmt.Errorf("validate secret item: %w", err)
	}
	if version <= 0 {
		version = 1
	}

	encKey, err := crypto.DeriveSubkey(masterKey, subkeyPurposeEncryption)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(encKey)

	idxKey, err := crypto.DeriveSubkey(masterKey, subkeyPurposeBlindIndex)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(idxKey)

	blindIdx, err := crypto.ComputeBlindIndex(idxKey, string(item.Type)+":"+item.Identifier)
	if err != nil {
		return nil, fmt.Errorf("compute blind index: %w", err)
	}

	var parentBlindIdx string
	if item.ParentID != "" {
		parentBlindIdx, err = crypto.ComputeBlindIndex(idxKey, string(item.Type)+":"+item.ParentID)
		if err != nil {
			return nil, fmt.Errorf("compute parent blind index: %w", err)
		}
	}

	now := time.Now().UTC()
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now

	plaintext, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("marshal secret item: %w", err)
	}
	defer crypto.ZeroBytes(plaintext)

	aad := buildAAD(item.ID, item.Type, blindIdx, version)
	env, err := crypto.Encrypt(encKey, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt secret item: %w", err)
	}

	return &EncryptedRecord{
		ID:               item.ID,
		Type:             item.Type,
		BlindIndex:       blindIdx,
		ParentBlindIndex: parentBlindIdx,
		Envelope:         *env,
		Version:          version,
		CreatedAt:        item.CreatedAt,
		UpdatedAt:        item.UpdatedAt,
	}, nil
}

// Unseal authenticates and decrypts an EncryptedRecord back into a plaintext SecretItem.
func Unseal(masterKey []byte, rec *EncryptedRecord) (*SecretItem, error) {
	if rec == nil {
		return nil, errors.New("encrypted record cannot be nil")
	}

	encKey, err := crypto.DeriveSubkey(masterKey, subkeyPurposeEncryption)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(encKey)

	aad := buildAAD(rec.ID, rec.Type, rec.BlindIndex, rec.Version)
	plaintext, err := crypto.Decrypt(encKey, &rec.Envelope, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt record %s: %w", rec.ID, err)
	}
	defer crypto.ZeroBytes(plaintext)

	var item SecretItem
	if err := json.Unmarshal(plaintext, &item); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted item: %w", err)
	}
	item.Version = rec.Version

	return &item, nil
}

// LookupBlindIndex computes the blind index for querying a specific secret type and identifier.
func LookupBlindIndex(masterKey []byte, secretType SecretType, identifier string) (string, error) {
	idxKey, err := crypto.DeriveSubkey(masterKey, subkeyPurposeBlindIndex)
	if err != nil {
		return "", err
	}
	defer crypto.ZeroBytes(idxKey)

	return crypto.ComputeBlindIndex(idxKey, string(secretType)+":"+identifier)
}

func buildAAD(id string, secretType SecretType, blindIndex string, version int) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|v%d", id, secretType, blindIndex, version))
}
