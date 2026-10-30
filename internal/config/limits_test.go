package config_test

import (
	"testing"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/limits"
)

func TestTransferLimitDefaultsAndOverrides(t *testing.T) {
	config.IsolateProcessEnv(t)
	sc, err := config.LoadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cc, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if sc.MaxBodyBytes != limits.DefaultBodyBytes || sc.MaxVaultBytes != limits.DefaultVaultBytes || cc.MaxBodyBytes != sc.MaxBodyBytes || cc.MaxVaultBytes != sc.MaxVaultBytes || cc.MaxBackupBytes != limits.DefaultBackupBytes {
		t.Fatal("inconsistent transfer defaults")
	}
	t.Setenv("SYLVA_MAX_BODY_BYTES", "2048")
	t.Setenv("SYLVA_MAX_VAULT_BYTES", "8192")
	t.Setenv("SYLVA_MAX_BACKUP_BYTES", "16384")
	sc, err = config.LoadServerConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cc, err = config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if sc.MaxBodyBytes != 2048 || sc.MaxVaultBytes != 8192 || cc.MaxVaultBytes != 8192 || cc.MaxBackupBytes != 16384 {
		t.Fatal("transfer overrides ignored")
	}
}

func TestInvalidTransferLimitsAreRejected(t *testing.T) {
	for _, key := range []string{"SYLVA_MAX_BODY_BYTES", "SYLVA_MAX_VAULT_BYTES", "SYLVA_MAX_BACKUP_BYTES"} {
		for _, value := range []string{"0", "-1", "9223372036854775807"} {
			t.Run(key+"="+value, func(t *testing.T) {
				config.IsolateProcessEnv(t)
				t.Setenv(key, value)
				if _, err := config.LoadClientConfig(""); err == nil {
					t.Fatal("invalid client limit accepted")
				}
				if key != "SYLVA_MAX_BACKUP_BYTES" {
					if _, err := config.LoadServerConfig(""); err == nil {
						t.Fatal("invalid server limit accepted")
					}
				}
			})
		}
	}
}
