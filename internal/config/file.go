package config

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed default.conf
var defaultConf string

type source int

const (
	sourceDefault source = iota
	sourceFile
	sourceEnv
)

type settings struct {
	vals map[string]string
	src  map[string]source
}

// envAllowlist is loaded from .env into the process. Everything else belongs
// in default.conf / .sylva/config. Process environment can still override any
// known key (Docker, tests, a later move of host/port into the config file).
var envAllowlist = map[string]bool{
	"SYLVA_HOST":              true,
	"SYLVA_PORT":              true,
	"SYLVA_SERVER_ADDR":       true,
	"SYLVA_SERVER_URL":        true,
	"SYLVA_TAILSCALE_AUTHKEY": true,
	"SYLVA_MASTER_PASSPHRASE": true,
}

var envName = map[string]string{
	"mtls":      "SYLVA_MTLS_ENABLED",
	"tailscale": "SYLVA_TAILSCALE_ENABLED",
}

func envVarFor(key string) string {
	if e, ok := envName[key]; ok {
		return e
	}
	return "SYLVA_" + strings.ToUpper(key)
}

func knownKey(key string) bool {
	switch key {
	case "service_name", "version", "log_level",
		"host", "port", "scheme", "api_prefix", "server_addr", "server_url",
		"server_read_header_timeout", "server_read_timeout", "server_write_timeout",
		"server_idle_timeout", "server_shutdown_timeout", "client_timeout", "max_body_bytes",
		"server_db_path", "client_cache_enabled", "client_cache_path",
		"sqlite_busy_timeout", "record_initial_version",
		"kdf_time", "kdf_memory_kb", "kdf_threads", "kdf_key_len", "kdf_salt_len", "password_default_len",
		"master_passphrase",
		"clipboard_clear_after", "clipboard_backend", "clipboard_file",
		"agent_enabled", "agent_socket_path", "agent_log_path",
		"keyring_enabled", "keyring_service", "keyring_user",
		"mtls", "ca_cert_path", "server_cert_path", "server_key_path", "client_cert_path", "client_key_path",
		"tailscale", "tailscale_node", "tailscale_state_dir", "tailscale_authkey", "tailscale_tags":
		return true
	default:
		return false
	}
}

func parseKV(r io.Reader, origin string) (map[string]string, []string, error) {
	vals := make(map[string]string)
	var order []string
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			return nil, nil, fmt.Errorf("invalid config syntax at %s:%d", origin, lineNum)
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if origin != ".env" && !knownKey(key) {
			return nil, nil, fmt.Errorf("unknown config key %q at %s:%d", key, origin, lineNum)
		}
		if _, seen := vals[key]; !seen {
			order = append(order, key)
		}
		vals[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan %s: %w", origin, err)
	}
	return vals, order, nil
}

func loadSettings(envPath string) (*settings, error) {
	defaults, _, err := parseKV(strings.NewReader(defaultConf), "default.conf")
	if err != nil {
		return nil, err
	}
	s := &settings{
		vals: make(map[string]string, len(defaults)+8),
		src:  make(map[string]source, len(defaults)+8),
	}
	for k, v := range defaults {
		s.vals[k] = v
		s.src[k] = sourceDefault
	}

	if err := overlayFile(s, localConfigPath()); err != nil {
		return nil, err
	}

	if envPath != "" {
		if err := loadDotEnvAllowlist(envPath); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	overlayEnv(s)
	return s, nil
}

func overlayFile(s *settings, path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open local config %s: %w", path, err)
	}
	defer file.Close()
	vals, _, err := parseKV(file, path)
	if err != nil {
		return err
	}
	for k, v := range vals {
		s.vals[k] = v
		s.src[k] = sourceFile
	}
	return nil
}

func overlayEnv(s *settings) {
	for _, key := range knownKeys() {
		env := envVarFor(key)
		raw, ok := os.LookupEnv(env)
		if !ok {
			continue
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		s.vals[key] = raw
		s.src[key] = sourceEnv
	}
}

func knownKeys() []string {
	return []string{
		"service_name", "version", "log_level",
		"host", "port", "scheme", "api_prefix", "server_addr", "server_url",
		"server_read_header_timeout", "server_read_timeout", "server_write_timeout",
		"server_idle_timeout", "server_shutdown_timeout", "client_timeout", "max_body_bytes",
		"server_db_path", "client_cache_enabled", "client_cache_path",
		"sqlite_busy_timeout", "record_initial_version",
		"kdf_time", "kdf_memory_kb", "kdf_threads", "kdf_key_len", "kdf_salt_len", "password_default_len",
		"master_passphrase",
		"clipboard_clear_after", "clipboard_backend", "clipboard_file",
		"agent_enabled", "agent_socket_path", "agent_log_path",
		"keyring_enabled", "keyring_service", "keyring_user",
		"mtls", "ca_cert_path", "server_cert_path", "server_key_path", "client_cert_path", "client_key_path",
		"tailscale", "tailscale_node", "tailscale_state_dir", "tailscale_authkey", "tailscale_tags",
	}
}

func loadDotEnvAllowlist(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	vals, _, err := parseKV(file, ".env")
	if err != nil {
		return err
	}
	for key, val := range vals {
		if !envAllowlist[key] {
			continue
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		if err := os.Setenv(key, val); err != nil {
			return fmt.Errorf("set env %s: %w", key, err)
		}
	}
	return nil
}

func (s *settings) get(key string) string {
	return strings.TrimSpace(s.vals[key])
}

func (s *settings) explicit(key string) bool {
	return s.src[key] == sourceFile || s.src[key] == sourceEnv
}

func (s *settings) boolVal(key string) (bool, error) {
	raw := s.get(key)
	if raw == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid boolean for %s=%q: %w", key, raw, err)
	}
	return b, nil
}

func (s *settings) durationVal(key string) (time.Duration, error) {
	raw := s.get(key)
	if raw == "" {
		return 0, fmt.Errorf("missing %s", key)
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s=%q: %w", key, raw, err)
	}
	return d, nil
}

func (s *settings) intVal(key string) (int, error) {
	raw := s.get(key)
	if raw == "" {
		return 0, fmt.Errorf("missing %s", key)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s=%q: %w", key, raw, err)
	}
	return n, nil
}

func (s *settings) int64Val(key string) (int64, error) {
	raw := s.get(key)
	if raw == "" {
		return 0, fmt.Errorf("missing %s", key)
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s=%q: %w", key, raw, err)
	}
	return n, nil
}

func (s *settings) uint32Val(key string) (uint32, error) {
	raw := s.get(key)
	if raw == "" {
		return 0, fmt.Errorf("missing %s", key)
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid uint32 for %s=%q: %w", key, raw, err)
	}
	return uint32(n), nil
}

func (s *settings) uint8Val(key string) (uint8, error) {
	raw := s.get(key)
	if raw == "" {
		return 0, fmt.Errorf("missing %s", key)
	}
	n, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid uint8 for %s=%q: %w", key, raw, err)
	}
	return uint8(n), nil
}

func writeLocalKey(key, value string) error {
	if !knownKey(key) {
		return fmt.Errorf("unknown config key %q", key)
	}
	path := localConfigPath()
	vals := map[string]string{}
	var order []string
	if file, err := os.Open(path); err == nil {
		parsed, parsedOrder, err := parseKV(file, path)
		_ = file.Close()
		if err != nil {
			return err
		}
		vals = parsed
		order = parsedOrder
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("open local config %s: %w", path, err)
	}
	if _, seen := vals[key]; !seen {
		order = append(order, key)
	}
	vals[key] = value

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create local config dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "config.*")
	if err != nil {
		return fmt.Errorf("create local config: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := fmt.Fprintf(tmp, "# Local Sylva config. Unset keys use shipped defaults.\n"); err != nil {
		_ = tmp.Close()
		return err
	}
	for _, k := range order {
		if _, err := fmt.Fprintf(tmp, "%s=%s\n", k, vals[k]); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("write local config %s: %w", path, err)
	}
	return nil
}
