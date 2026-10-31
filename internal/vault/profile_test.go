package vault_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/osman/sylva/internal/vault"
)

func TestProfilesBindEncryptionAndBlindIndexes(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	indexes := map[string]bool{}
	for _, profile := range []string{"", strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		item := &vault.SecretItem{ID: "record", ProfileID: profile, Type: vault.SecretTypeToken, Identifier: "github", Token: &vault.TokenPayload{Name: "github", Token: "secret"}}
		rec, err := vault.Seal(key, item, 1)
		if err != nil {
			t.Fatal(err)
		}
		index, err := vault.LookupProfileBlindIndex(key, profile, item.Type, item.Identifier)
		if err != nil || rec.BlindIndex != index || indexes[index] {
			t.Fatalf("profile indexes collide or disagree: %v", err)
		}
		indexes[index] = true
		if _, err := vault.Unseal(key, rec); err != nil {
			t.Fatal(err)
		}
		rec.ProfileID = strings.Repeat("c", 32)
		if _, err := vault.Unseal(key, rec); err == nil {
			t.Fatal("moved ciphertext to another profile")
		}
		rec.ProfileID = ""
		if profile != "" {
			if _, err := vault.Unseal(key, rec); err == nil {
				t.Fatal("stripped the profile binding")
			}
		}
	}
}
