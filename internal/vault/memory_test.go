package vault_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/vault"
)

func BenchmarkVaultRoundTrip(b *testing.B) {
	for _, size := range []int{1024, 64 * 1024} {
		b.Run(fmt.Sprintf("payload_%d", size), func(b *testing.B) {
			key := make([]byte, 32)
			defer crypto.ZeroBytes(key)
			item := &vault.SecretItem{ID: "benchmark", Type: vault.SecretTypeToken, Identifier: "benchmark", Token: &vault.TokenPayload{Name: "benchmark", Token: strings.Repeat("x", size)}}
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				rec, err := vault.Seal(key, item, 1)
				if err != nil {
					b.Fatal(err)
				}
				got, err := vault.Unseal(key, rec)
				if err != nil {
					b.Fatal(err)
				}
				if got.Token == nil || got.Token.Token != item.Token.Token {
					b.Fatal("round trip changed the payload")
				}
			}
		})
	}
}
