package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Default locations for optional transport features.
const (
	DefaultLocalConfigPath      = ".sylva/config"
	DefaultCACertPath           = ".sylva/certs/ca.pem"
	DefaultServerCertPath       = ".sylva/certs/server.pem"
	DefaultServerKeyPath        = ".sylva/certs/server.key"
	DefaultClientCertPath       = ".sylva/certs/client.pem"
	DefaultClientKeyPath        = ".sylva/certs/client.key"
	DefaultTailscaleNode        = "sylva"
	DefaultTailscaleStateDir    = ".sylva/tsnet"
	DefaultTailscaleAuthKeyFile = ".sylva/tsnet.authkey"
	tailscaleStateFileName      = "tailscaled.state"
)

// LocalConfigPath is .sylva/config unless SYLVA_LOCAL_CONFIG is set.
func LocalConfigPath() string {
	return localConfigPath()
}

func localConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("SYLVA_LOCAL_CONFIG")); p != "" {
		return p
	}
	return DefaultLocalConfigPath
}

// SetLocalFeature writes mtls or tailscale intent into the local config file
// without dropping other keys already stored there.
func SetLocalFeature(feature string, enabled bool) error {
	switch feature {
	case "mtls", "tailscale":
	default:
		return fmt.Errorf("unknown feature %q (expected mtls or tailscale)", feature)
	}
	return writeLocalKey(feature, fmt.Sprintf("%t", enabled))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !st.IsDir()
}

func tailscaleStatePresent(dir string) bool {
	return fileExists(filepath.Join(dir, tailscaleStateFileName))
}

func readOptionalFile(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func requireExistingFiles(role string, paths ...string) error {
	for _, p := range paths {
		if !fileExists(p) {
			return fmt.Errorf("mTLS %s: missing %s (create certs under .sylva/certs, then sylva enable mtls)", role, p)
		}
	}
	return nil
}
