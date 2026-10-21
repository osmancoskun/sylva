package main

import (
	"testing"

	"github.com/osman/sylva/internal/vault"
)

func TestParseSetArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		rest       []string
		identifier string
		password   string
		typ        string
		wantID     string
		wantPass   string
		wantType   string
		wantErr    bool
	}{
		{name: "empty"},
		{
			name:   "id only",
			rest:   []string{"company.com"},
			wantID: "company.com",
		},
		{
			name:     "id and password",
			rest:     []string{"company.com", "secret"},
			wantID:   "company.com",
			wantPass: "secret",
		},
		{
			name:     "id password env",
			rest:     []string{"SYLVA_EXAMPLE", "secret", "env"},
			wantID:   "SYLVA_EXAMPLE",
			wantPass: "secret",
			wantType: "env",
		},
		{
			name:     "id password ssh",
			rest:     []string{"10.0.0.1", "secret", "ssh"},
			wantID:   "10.0.0.1",
			wantPass: "secret",
			wantType: "ssh",
		},
		{
			name:     "id and type only",
			rest:     []string{"SYLVA_EXAMPLE", "env"},
			wantID:   "SYLVA_EXAMPLE",
			wantType: "env",
		},
		{
			name:     "flag type wins over trailing type",
			rest:     []string{"company.com", "secret", "ssh"},
			typ:      "domain",
			wantID:   "company.com",
			wantPass: "secret",
			wantType: "domain",
		},
		{
			name:    "too many args",
			rest:    []string{"a", "b", "c", "d"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			id, pass, typ, err := parseSetArgs(tt.rest, tt.identifier, tt.password, tt.typ)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSetArgs: %v", err)
			}
			if id != tt.wantID || pass != tt.wantPass || typ != tt.wantType {
				t.Fatalf("got id=%q pass=%q type=%q, want id=%q pass=%q type=%q", id, pass, typ, tt.wantID, tt.wantPass, tt.wantType)
			}
		})
	}
}

func TestLooksLikeHost(t *testing.T) {
	t.Parallel()
	if !looksLikeHost("company.com") || !looksLikeHost("10.0.0.1") || !looksLikeHost("::1") {
		t.Fatal("expected hosts to match")
	}
	if looksLikeHost("SYLVA_EXAMPLE") || looksLikeHost("github-token") {
		t.Fatal("expected non-hosts to stay tokens")
	}
}

func TestParseKnownType(t *testing.T) {
	t.Parallel()
	kind, err := parseKnownType("domain")
	if err != nil || kind != vault.SecretTypeLogin {
		t.Fatalf("domain: %q %v", kind, err)
	}
	if _, err := parseKnownType("nope"); err == nil {
		t.Fatal("expected unknown type")
	}
}

func TestSplitFlagsAndArgs(t *testing.T) {
	t.Parallel()
	pos, flags := splitFlagsAndArgs([]string{"mail.company.com", "--inherit"})
	if len(pos) != 1 || pos[0] != "mail.company.com" {
		t.Fatalf("pos=%v", pos)
	}
	if len(flags) != 1 || flags[0] != "--inherit" {
		t.Fatalf("flags=%v", flags)
	}
}
