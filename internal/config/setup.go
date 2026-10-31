package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Only connection settings and the active profile may be written by setup.
// Passwords, auth tokens and private-key contents never enter this map.
var setupKeys = []string{"backend", "profile", "git_remote", "git_branch", "server_url", "mtls", "ca_cert_path", "client_cert_path", "client_key_path"}

func SetupDefaults(envPath string) (map[string]string, error) {
	s, err := loadSettings(envPath)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, key := range setupKeys {
		values[key] = s.get(key)
	}
	if values["server_url"] == "" {
		values["server_url"] = s.get("scheme") + "://" + net.JoinHostPort(s.get("host"), s.get("port"))
	}
	return values, nil
}

func validateSetup(values map[string]string) error {
	for key, value := range values {
		allowed := false
		for _, known := range setupKeys {
			if key == known {
				allowed = true
				break
			}
		}
		if !allowed || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("invalid setup setting %q", key)
		}
		if override := strings.TrimSpace(os.Getenv(envVarFor(key))); override != "" && override != value {
			if key == "backend" && strings.EqualFold(override, value) {
				continue
			}
			if key == "mtls" {
				before, errBefore := strconv.ParseBool(override)
				after, errAfter := strconv.ParseBool(value)
				if errBefore == nil && errAfter == nil && before == after {
					continue
				}
			}
			return fmt.Errorf("%s overrides the selected %s; unset it before changing this setting", envVarFor(key), key)
		}
	}
	return nil
}

// PreviewSetup validates the final effective client settings without touching
// the local configuration, including certificate files and env precedence.
func PreviewSetup(envPath string, values map[string]string) (ClientConfig, error) {
	s, err := loadSettings(envPath)
	if err != nil {
		return ClientConfig{}, err
	}
	if err := validateSetup(values); err != nil {
		return ClientConfig{}, err
	}
	for key, value := range values {
		s.vals[key], s.src[key] = value, sourceFile
	}
	return clientFromSettings(s, envPath)
}

// SaveSetup publishes all choices together, preserving unrelated local keys.
func SaveSetup(values map[string]string) error {
	if err := validateSetup(values); err != nil {
		return err
	}
	return writeLocalKeys(values)
}
