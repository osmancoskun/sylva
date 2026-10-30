package config_test

import (
	"testing"
	"time"

	"github.com/osman/sylva/internal/config"
)

func TestAgentLifecycleSettings(t *testing.T) {
	config.IsolateProcessEnv(t)
	cfg, err := config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentRequestTimeout != 5*time.Second || cfg.AgentMaxRequestBytes != 1<<20 || cfg.AgentMaxConnections != 64 {
		t.Fatal("unexpected agent defaults")
	}
	t.Setenv("SYLVA_AGENT_REQUEST_TIMEOUT", "150ms")
	t.Setenv("SYLVA_AGENT_MAX_REQUEST_BYTES", "4096")
	t.Setenv("SYLVA_AGENT_MAX_CONNECTIONS", "2")
	t.Setenv("SYLVA_AGENT_IDLE_TIMEOUT", "30s")
	cfg, err = config.LoadClientConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AgentRequestTimeout != 150*time.Millisecond || cfg.AgentMaxRequestBytes != 4096 || cfg.AgentMaxConnections != 2 || cfg.AgentIdleTimeout != 30*time.Second {
		t.Fatal("agent overrides ignored")
	}
}

func TestInvalidAgentLifecycleSettings(t *testing.T) {
	for key, values := range map[string][]string{
		"SYLVA_AGENT_REQUEST_TIMEOUT":   {"0s", "-1s"},
		"SYLVA_AGENT_MAX_REQUEST_BYTES": {"0", "-1", "9223372036854775807"},
		"SYLVA_AGENT_MAX_CONNECTIONS":   {"0", "-1"},
	} {
		for _, value := range values {
			t.Run(key+"="+value, func(t *testing.T) {
				config.IsolateProcessEnv(t)
				t.Setenv(key, value)
				if _, err := config.LoadClientConfig(""); err == nil {
					t.Fatal("invalid agent setting accepted")
				}
			})
		}
	}
}
