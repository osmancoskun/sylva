package crypto_test

import (
	"bytes"
	"testing"

	"github.com/osman/sylva/internal/crypto"
)

func TestDecryptRejectsMissingEnvelopeFields(t *testing.T) {
	for name, env := range map[string]*crypto.Envelope{
		"nil": nil, "empty": {}, "missing ciphertext": {Nonce: make([]byte, 12)},
		"short nonce": {Nonce: []byte{1}, Ciphertext: make([]byte, 16)},
	} {
		t.Run(name, func(t *testing.T) {
			plain, err := crypto.Decrypt(make([]byte, 32), env, nil)
			if err == nil || plain != nil {
				t.Fatal("incomplete envelope returned plaintext")
			}
		})
	}
}

func FuzzEncryptDecrypt(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add([]byte("secret"), []byte("record|v1"))
	f.Add([]byte{0, 255, 0, 128}, []byte{0, 255})
	f.Fuzz(func(t *testing.T, plain, aad []byte) {
		key := make([]byte, 32)
		env, err := crypto.Encrypt(key, plain, aad)
		if err != nil {
			t.Fatal(err)
		}
		got, err := crypto.Decrypt(key, env, aad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("encrypted data did not round trip")
		}
		crypto.ZeroBytes(got)
		env.Ciphertext[0] ^= 1
		if got, err := crypto.Decrypt(key, env, aad); err == nil || got != nil {
			t.Fatal("tampered ciphertext returned plaintext")
		}
	})
}

func FuzzDecryptMalformedEnvelope(f *testing.F) {
	f.Add([]byte{}, []byte{}, []byte{}, []byte{})
	f.Add(make([]byte, 32), make([]byte, 12), make([]byte, 16), []byte("aad"))
	f.Fuzz(func(t *testing.T, key, nonce, ciphertext, aad []byte) {
		plain, err := crypto.Decrypt(key, &crypto.Envelope{Nonce: nonce, Ciphertext: ciphertext}, aad)
		if err != nil && plain != nil {
			t.Fatal("failed authentication returned plaintext")
		}
		crypto.ZeroBytes(plain)
	})
}
