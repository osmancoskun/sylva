package vault_test

import (
	"path/filepath"
	"testing"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/vault"
)

func TestMain(m *testing.M) {
	leakcheck.Verify(m)
}

func deriveTestMasterKey(t *testing.T) []byte {
	t.Helper()
	config.IsolateProcessEnv(t)
	envPath := filepath.Join("..", "..", ".env.example")
	cfg, err := config.LoadCryptoConfig(envPath)
	if err != nil {
		t.Fatalf("failed to load crypto config: %v", err)
	}
	salt, err := crypto.GenerateSalt(cfg.KDFSaltLen)
	if err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}
	key, err := crypto.DeriveKey([]byte("vault-test-master-passphrase"), salt, cfg)
	if err != nil {
		t.Fatalf("failed to derive master key: %v", err)
	}
	return key
}

func TestSealAndUnsealAllSecretTypes(t *testing.T) {
	masterKey := deriveTestMasterKey(t)
	defer crypto.ZeroBytes(masterKey)

	items := []*vault.SecretItem{
		{
			ID:         "rec-login-1",
			Type:       vault.SecretTypeLogin,
			Identifier: "company.com",
			Login: &vault.LoginPayload{
				Domain:   "company.com",
				Username: "osman@company.com",
				Password: "root-domain-password",
			},
		},
		{
			ID:         "rec-login-2",
			Type:       vault.SecretTypeLogin,
			Identifier: "mail.company.com",
			ParentID:   "company.com",
			Login: &vault.LoginPayload{
				Domain:            "mail.company.com",
				Username:          "osman@company.com",
				InheritFromParent: true,
				ParentDomain:      "company.com",
			},
		},
		{
			ID:         "rec-env-1",
			Type:       vault.SecretTypeEnv,
			Identifier: "sylva-prod",
			Env: &vault.EnvPayload{
				Project:     "sylva",
				Environment: "production",
				Variables: map[string]string{
					"DB_HOST": "10.0.0.12",
					"API_KEY": "secret-val",
				},
			},
		},
		{
			ID:         "rec-ssh-1",
			Type:       vault.SecretTypeSSH,
			Identifier: "homelab-node",
			SSH: &vault.SSHPayload{
				Name:       "homelab-node",
				Host:       "100.64.0.5",
				User:       "root",
				Port:       22,
				PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
			},
		},
		{
			ID:         "rec-token-1",
			Type:       vault.SecretTypeToken,
			Identifier: "github-pat",
			Token: &vault.TokenPayload{
				Name:    "github-pat",
				Service: "github.com",
				Token:   "ghp_example1234567890",
			},
		},
	}

	for _, item := range items {
		rec, err := vault.Seal(masterKey, item, 1)
		if err != nil {
			t.Fatalf("Seal(%s) failed: %v", item.ID, err)
		}

		expectedBlindIdx, err := vault.LookupBlindIndex(masterKey, item.Type, item.Identifier)
		if err != nil {
			t.Fatalf("LookupBlindIndex failed: %v", err)
		}
		if rec.BlindIndex != expectedBlindIdx {
			t.Errorf("BlindIndex mismatch: got %s, want %s", rec.BlindIndex, expectedBlindIdx)
		}

		unsealed, err := vault.Unseal(masterKey, rec)
		if err != nil {
			t.Fatalf("Unseal(%s) failed: %v", item.ID, err)
		}

		if unsealed.Identifier != item.Identifier || unsealed.Type != item.Type {
			t.Errorf("unsealed item mismatch: got %+v, want %+v", unsealed, item)
		}

		// Verify that swapping metadata (e.g., Version or BlindIndex) on the server invalidates decryption via AAD.
		tampered := *rec
		tampered.Version = 2
		if _, err := vault.Unseal(masterKey, &tampered); err == nil {
			t.Errorf("expected Unseal(%s) to fail when record version metadata is tampered", item.ID)
		}
	}
}
