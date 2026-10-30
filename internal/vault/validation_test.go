package vault_test

import (
	"testing"

	"github.com/osman/sylva/internal/vault"
)

func TestMissingSecretFieldsReturnErrors(t *testing.T) {
	cases := map[string]*vault.SecretItem{
		"nil item":         nil,
		"zero item":        {},
		"blank ID":         {ID: " \t", Identifier: "name", Type: vault.SecretTypeToken, Token: &vault.TokenPayload{Name: "name", Token: "secret"}},
		"blank identifier": {ID: "id", Identifier: " \n", Type: vault.SecretTypeToken, Token: &vault.TokenPayload{Name: "name", Token: "secret"}},
		"unknown type":     {ID: "id", Identifier: "name", Type: "unknown"},
		"missing login":    {ID: "id", Identifier: "example.test", Type: vault.SecretTypeLogin},
		"missing token":    {ID: "id", Identifier: "name", Type: vault.SecretTypeToken},
		"missing env":      {ID: "id", Identifier: "name", Type: vault.SecretTypeEnv},
		"missing SSH":      {ID: "id", Identifier: "name", Type: vault.SecretTypeSSH},
		"empty token":      {ID: "id", Identifier: "name", Type: vault.SecretTypeToken, Token: &vault.TokenPayload{Name: "name"}},
		"empty env map":    {ID: "id", Identifier: "name", Type: vault.SecretTypeEnv, Env: &vault.EnvPayload{Project: "name"}},
		"blank SSH name":   {ID: "id", Identifier: "name", Type: vault.SecretTypeSSH, SSH: &vault.SSHPayload{Name: " \t"}},
		"missing password": {ID: "id", Identifier: "example.test", Type: vault.SecretTypeLogin, Login: &vault.LoginPayload{Domain: "example.test"}},
	}
	key := make([]byte, 32)
	for name, item := range cases {
		t.Run(name, func(t *testing.T) {
			if err := item.Validate(); err == nil {
				t.Fatal("invalid item passed validation")
			}
			if rec, err := vault.Seal(key, item, 1); err == nil || rec != nil {
				t.Fatal("invalid item produced an encrypted record")
			}
		})
	}
	if item, err := vault.Unseal(key, nil); err == nil || item != nil {
		t.Fatal("nil encrypted record accepted")
	}
}
