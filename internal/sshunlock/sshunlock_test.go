package sshunlock_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/osman/sylva/internal/crypto"
	"github.com/osman/sylva/internal/leakcheck"
	"github.com/osman/sylva/internal/sshunlock"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestMain(m *testing.M) { leakcheck.Verify(m) }

func identity(t *testing.T, ring agent.Agent) ssh.PublicKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Add(agent.AddedKey{PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func registration(t *testing.T) (string, string, []byte, agent.Agent) {
	t.Helper()
	ring := agent.NewKeyring()
	key := identity(t, ring)
	master, err := crypto.GenerateSalt(32)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { crypto.ZeroBytes(master) })
	endpoint := sshunlock.Endpoint("https://vault.example", "/api/v1")
	path := sshunlock.Path(filepath.Join(t.TempDir(), "ssh"), endpoint)
	if err := sshunlock.Register(path, endpoint, key, master, ring); err != nil {
		t.Fatal(err)
	}
	return path, endpoint, master, ring
}

func TestRegistrationRequiresTheSelectedAgentKeyAndPreservesExistingFile(t *testing.T) {
	path, endpoint, master, ring := registration(t)
	_ = identity(t, ring) // Another loaded identity must not affect selection.
	got, err := sshunlock.Open(path, endpoint, ring)
	if err != nil {
		t.Fatal(err)
	}
	defer crypto.ZeroBytes(got)
	if !bytes.Equal(got, master) {
		t.Fatal("unwrapped key differs from the registered key")
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(original, master) {
		t.Fatal("registration contains the plaintext vault key")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("registration permissions: info=%v err=%v", info, err)
	}
	if _, err := sshunlock.Open(path, endpoint, agent.NewKeyring()); err == nil {
		t.Fatal("empty agent opened the registration")
	}
	if err := sshunlock.Register(path, endpoint, identity(t, ring), master, ring); err == nil {
		t.Fatal("existing registration was replaced")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("failed registration changed the original file")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary credentials left behind: entries=%v err=%v", entries, err)
	}
}

type countedSigner struct {
	sshunlock.Signer
	calls int
}

func (s *countedSigner) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	s.calls++
	return s.Signer.Sign(key, data)
}

func TestServerBindingAndFilePermissionsAreCheckedBeforeSigning(t *testing.T) {
	path, endpoint, _, ring := registration(t)
	signer := &countedSigner{Signer: ring}
	for _, other := range []string{
		sshunlock.Endpoint("https://other.example", "/api/v1"),
		sshunlock.Endpoint("https://vault.example", "/other-api"),
	} {
		if _, err := sshunlock.Open(path, other, signer); err == nil {
			t.Fatal("different server/API binding accepted")
		}
		if sshunlock.Path(filepath.Dir(path), other) == path {
			t.Fatal("different server/API shares a registration path")
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := sshunlock.Open(path, endpoint, signer); err == nil {
		t.Fatal("world-readable registration accepted")
	}
	if signer.calls != 0 {
		t.Fatal("agent contacted before registration validation")
	}
}

func TestTamperedRegistrationCannotRecoverAKey(t *testing.T) {
	for _, field := range []string{"salt", "public_key", "nonce", "ciphertext", "format", "trailing JSON", "oversized"} {
		t.Run(field, func(t *testing.T) {
			path, endpoint, _, ring := registration(t)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]json.RawMessage
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "salt", "public_key", "nonce", "ciphertext":
				target := value
				if field == "nonce" || field == "ciphertext" {
					target = make(map[string]json.RawMessage)
					if err := json.Unmarshal(value["envelope"], &target); err != nil {
						t.Fatal(err)
					}
				}
				var data []byte
				if field == "public_key" {
					data = identity(t, ring).Marshal()
				} else {
					if err := json.Unmarshal(target[field], &data); err != nil {
						t.Fatal(err)
					}
					data[0] ^= 1
				}
				target[field], err = json.Marshal(data)
				if err != nil {
					t.Fatal(err)
				}
				if field == "nonce" || field == "ciphertext" {
					value["envelope"], err = json.Marshal(target)
					if err != nil {
						t.Fatal(err)
					}
				}
			case "format":
				value["format"] = json.RawMessage(`"future-unsupported-format"`)
			}
			raw, err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if field == "trailing JSON" {
				raw = append(raw, []byte(" {}")...)
			} else if field == "oversized" {
				raw = append(raw, bytes.Repeat([]byte(" "), 16*1024)...)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := sshunlock.Open(path, endpoint, ring); err == nil || got != nil {
				t.Fatal("tampered registration returned a key")
			}
		})
	}
}

type wrongSigner struct{ ssh.Signer }

func (s wrongSigner) Sign(_ ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return s.Signer.Sign(rand.Reader, data)
}

func TestInvalidAgentSignatureNeverCreatesRegistration(t *testing.T) {
	ring := agent.NewKeyring()
	public := identity(t, ring)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registration.json")
	err = sshunlock.Register(path, "server", public, make([]byte, 32), wrongSigner{other})
	if err == nil {
		t.Fatal("agent signature from another private key was accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid agent signature left a registration")
	}
}

func TestPublicKeySelectionRejectsMultipleKeysAndOptions(t *testing.T) {
	key := identity(t, agent.NewKeyring())
	raw := ssh.MarshalAuthorizedKey(key)
	if _, err := sshunlock.ParsePublicKey(raw); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte{}, raw...), raw...),
		append([]byte("restrict "), raw...),
		[]byte("not an SSH public key"),
	} {
		if _, err := sshunlock.ParsePublicKey(invalid); err == nil {
			t.Fatal("ambiguous or invalid public key selection accepted")
		}
	}
}
