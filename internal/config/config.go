// Package config loads Sylva runtime settings from shipped defaults,
// .sylva/config, and a small .env allowlist (host, port, secrets).
package config

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/osman/sylva/internal/limits"
)

// CryptoConfig holds centralized parameters for Argon2id key derivation and
// password generation.
type CryptoConfig struct {
	KDFTime            uint32
	KDFMemoryKB        uint32
	KDFThreads         uint8
	KDFKeyLen          uint32
	KDFSaltLen         int
	PasswordDefaultLen int
}

// ServerConfig holds runtime configuration for the sylvad server daemon.
type ServerConfig struct {
	ServiceName          string
	Version              string
	LogLevel             slog.Level
	Host                 string
	Port                 string
	ListenAddr           string
	APIPrefix            string
	DBPath               string
	MaxBodyBytes         int64
	MaxVaultBytes        int64
	SQLiteBusyTimeout    time.Duration
	RecordInitialVersion int
	ReadHeaderTimeout    time.Duration
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	IdleTimeout          time.Duration
	ShutdownTimeout      time.Duration
	EnableMTLS           bool
	CACertPath           string
	ServerCertPath       string
	ServerKeyPath        string
	EnableTailscale      bool
	TailscaleNode        string
	TailscaleStateDir    string
	TailscaleAuthKey     string
	TailscaleTags        []string
}

// ClientConfig holds runtime configuration for the sylva CLI client.
type ClientConfig struct {
	Version              string
	Scheme               string
	Host                 string
	Port                 string
	ServerURL            string
	APIPrefix            string
	Timeout              time.Duration
	MaxBodyBytes         int64
	MaxVaultBytes        int64
	MaxBackupBytes       int64
	CacheEnabled         bool
	CachePath            string
	SQLiteBusyTimeout    time.Duration
	RecordInitialVersion int
	MasterPassphrase     string
	ClipboardClearAfter  time.Duration
	ClipboardBackend     string
	ClipboardFile        string
	AgentEnabled         bool
	AgentIdleTimeout     time.Duration
	AgentSocketPath      string
	AgentLogPath         string
	LogLevel             slog.Level
	KeyringEnabled       bool
	KeyringService       string
	KeyringUser          string
	ConfigPath           string
	EnableMTLS           bool
	CACertPath           string
	ClientCertPath       string
	ClientKeyPath        string
	Crypto               CryptoConfig
}

// LoadDotEnv reads allowlisted secrets and bind settings from a .env file
// into the process environment when they are not already set.
func LoadDotEnv(path string) error {
	return loadDotEnvAllowlist(path)
}

func cryptoFromSettings(s *settings) (CryptoConfig, error) {
	kdfTime, err := s.uint32Val("kdf_time")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfMemoryKB, err := s.uint32Val("kdf_memory_kb")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfThreads, err := s.uint8Val("kdf_threads")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfKeyLen, err := s.uint32Val("kdf_key_len")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfSaltLen, err := s.intVal("kdf_salt_len")
	if err != nil {
		return CryptoConfig{}, err
	}
	pwdDefaultLen, err := s.intVal("password_default_len")
	if err != nil {
		return CryptoConfig{}, err
	}
	return CryptoConfig{
		KDFTime:            kdfTime,
		KDFMemoryKB:        kdfMemoryKB,
		KDFThreads:         kdfThreads,
		KDFKeyLen:          kdfKeyLen,
		KDFSaltLen:         kdfSaltLen,
		PasswordDefaultLen: pwdDefaultLen,
	}, nil
}

// LoadCryptoConfig loads Argon2id and password-length settings.
func LoadCryptoConfig(envPath string) (CryptoConfig, error) {
	s, err := loadSettings(envPath)
	if err != nil {
		return CryptoConfig{}, err
	}
	return cryptoFromSettings(s)
}

func resolveMTLS(s *settings) (bool, error) {
	if s.explicit("mtls") {
		return s.boolVal("mtls")
	}
	return false, nil
}

func resolveTailscale(s *settings) (bool, error) {
	if s.explicit("tailscale") {
		return s.boolVal("tailscale")
	}
	return tailscaleStatePresent(firstNonEmpty(s.get("tailscale_state_dir"), DefaultTailscaleStateDir)), nil
}

// LoadServerConfig merges defaults, .sylva/config, and .env allowlist.
func LoadServerConfig(envPath string) (ServerConfig, error) {
	s, err := loadSettings(envPath)
	if err != nil {
		return ServerConfig{}, err
	}

	host := s.get("host")
	port := s.get("port")
	if host == "" || port == "" {
		return ServerConfig{}, fmt.Errorf("host and port are required (set them in .env or .sylva/config)")
	}
	listenAddr := s.get("server_addr")
	if listenAddr == "" {
		listenAddr = net.JoinHostPort(host, port)
	}

	logLevel, err := parseLogLevel(s.get("log_level"))
	if err != nil {
		return ServerConfig{}, err
	}
	readHeaderTimeout, err := s.durationVal("server_read_header_timeout")
	if err != nil {
		return ServerConfig{}, err
	}
	readTimeout, err := s.durationVal("server_read_timeout")
	if err != nil {
		return ServerConfig{}, err
	}
	writeTimeout, err := s.durationVal("server_write_timeout")
	if err != nil {
		return ServerConfig{}, err
	}
	idleTimeout, err := s.durationVal("server_idle_timeout")
	if err != nil {
		return ServerConfig{}, err
	}
	shutdownTimeout, err := s.durationVal("server_shutdown_timeout")
	if err != nil {
		return ServerConfig{}, err
	}
	maxBodyBytes, maxVaultBytes, err := transferLimits(s)
	if err != nil {
		return ServerConfig{}, err
	}
	sqliteBusyTimeout, err := s.durationVal("sqlite_busy_timeout")
	if err != nil {
		return ServerConfig{}, err
	}
	recordInitialVersion, err := s.intVal("record_initial_version")
	if err != nil {
		return ServerConfig{}, err
	}

	caCertPath := firstNonEmpty(s.get("ca_cert_path"), DefaultCACertPath)
	serverCertPath := firstNonEmpty(s.get("server_cert_path"), DefaultServerCertPath)
	serverKeyPath := firstNonEmpty(s.get("server_key_path"), DefaultServerKeyPath)
	enableMTLS, err := resolveMTLS(s)
	if err != nil {
		return ServerConfig{}, err
	}
	if enableMTLS {
		if err := requireExistingFiles("server", caCertPath, serverCertPath, serverKeyPath); err != nil {
			return ServerConfig{}, err
		}
	}

	tailscaleNode := firstNonEmpty(s.get("tailscale_node"), DefaultTailscaleNode)
	tailscaleStateDir := firstNonEmpty(s.get("tailscale_state_dir"), DefaultTailscaleStateDir)
	tailscaleAuthKey := firstNonEmpty(s.get("tailscale_authkey"), readOptionalFile(DefaultTailscaleAuthKeyFile))
	enableTailscale, err := resolveTailscale(s)
	if err != nil {
		return ServerConfig{}, err
	}

	return ServerConfig{
		ServiceName:          firstNonEmpty(s.get("service_name"), "sylvad"),
		Version:              s.get("version"),
		LogLevel:             logLevel,
		Host:                 host,
		Port:                 port,
		ListenAddr:           listenAddr,
		APIPrefix:            strings.TrimRight(s.get("api_prefix"), "/"),
		DBPath:               s.get("server_db_path"),
		MaxBodyBytes:         maxBodyBytes,
		MaxVaultBytes:        maxVaultBytes,
		SQLiteBusyTimeout:    sqliteBusyTimeout,
		RecordInitialVersion: recordInitialVersion,
		ReadHeaderTimeout:    readHeaderTimeout,
		ReadTimeout:          readTimeout,
		WriteTimeout:         writeTimeout,
		IdleTimeout:          idleTimeout,
		ShutdownTimeout:      shutdownTimeout,
		EnableMTLS:           enableMTLS,
		CACertPath:           caCertPath,
		ServerCertPath:       serverCertPath,
		ServerKeyPath:        serverKeyPath,
		EnableTailscale:      enableTailscale,
		TailscaleNode:        tailscaleNode,
		TailscaleStateDir:    tailscaleStateDir,
		TailscaleAuthKey:     tailscaleAuthKey,
		TailscaleTags:        splitCommaList(s.get("tailscale_tags")),
	}, nil
}

// LoadClientConfig merges defaults, .sylva/config, and .env allowlist.
func LoadClientConfig(envPath string) (ClientConfig, error) {
	s, err := loadSettings(envPath)
	if err != nil {
		return ClientConfig{}, err
	}

	scheme := s.get("scheme")
	host := s.get("host")
	port := s.get("port")
	if host == "" || port == "" {
		return ClientConfig{}, fmt.Errorf("host and port are required (set them in .env or .sylva/config)")
	}
	serverURL := s.get("server_url")
	if serverURL == "" {
		serverURL = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
	}

	timeout, err := s.durationVal("client_timeout")
	if err != nil {
		return ClientConfig{}, err
	}
	maxBodyBytes, maxVaultBytes, err := transferLimits(s)
	if err != nil {
		return ClientConfig{}, err
	}
	maxBackupBytes, err := s.int64Val("max_backup_bytes")
	if err != nil {
		return ClientConfig{}, err
	}
	if err := limits.Validate("max_backup_bytes", maxBackupBytes); err != nil {
		return ClientConfig{}, err
	}
	cacheEnabled, err := s.boolVal("client_cache_enabled")
	if err != nil {
		return ClientConfig{}, err
	}
	sqliteBusyTimeout, err := s.durationVal("sqlite_busy_timeout")
	if err != nil {
		return ClientConfig{}, err
	}
	recordInitialVersion, err := s.intVal("record_initial_version")
	if err != nil {
		return ClientConfig{}, err
	}
	clipboardClearAfter, err := s.durationVal("clipboard_clear_after")
	if err != nil {
		return ClientConfig{}, err
	}
	agentEnabled, err := s.boolVal("agent_enabled")
	if err != nil {
		return ClientConfig{}, err
	}
	agentIdleTimeout, err := s.durationVal("agent_idle_timeout")
	if err != nil || agentIdleTimeout <= 0 {
		return ClientConfig{}, fmt.Errorf("agent_idle_timeout must be a positive duration")
	}
	logLevel, err := parseLogLevel(s.get("log_level"))
	if err != nil {
		return ClientConfig{}, err
	}
	keyringEnabled, err := s.boolVal("keyring_enabled")
	if err != nil {
		return ClientConfig{}, err
	}
	cryptoCfg, err := cryptoFromSettings(s)
	if err != nil {
		return ClientConfig{}, err
	}

	caCertPath := firstNonEmpty(s.get("ca_cert_path"), DefaultCACertPath)
	clientCertPath := firstNonEmpty(s.get("client_cert_path"), DefaultClientCertPath)
	clientKeyPath := firstNonEmpty(s.get("client_key_path"), DefaultClientKeyPath)
	enableMTLS, err := resolveMTLS(s)
	if err != nil {
		return ClientConfig{}, err
	}
	if enableMTLS {
		scheme = "https"
		if err := requireExistingFiles("client", caCertPath, clientCertPath, clientKeyPath); err != nil {
			return ClientConfig{}, err
		}
		if s.get("server_url") == "" {
			serverURL = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
		} else if strings.HasPrefix(strings.ToLower(serverURL), "http://") {
			serverURL = "https://" + serverURL[len("http://"):]
		}
	}

	return ClientConfig{
		Version:              s.get("version"),
		Scheme:               scheme,
		Host:                 host,
		Port:                 port,
		ServerURL:            serverURL,
		APIPrefix:            strings.TrimRight(s.get("api_prefix"), "/"),
		Timeout:              timeout,
		MaxBodyBytes:         maxBodyBytes,
		MaxVaultBytes:        maxVaultBytes,
		MaxBackupBytes:       maxBackupBytes,
		CacheEnabled:         cacheEnabled,
		CachePath:            s.get("client_cache_path"),
		SQLiteBusyTimeout:    sqliteBusyTimeout,
		RecordInitialVersion: recordInitialVersion,
		MasterPassphrase:     s.get("master_passphrase"),
		ClipboardClearAfter:  clipboardClearAfter,
		ClipboardBackend:     strings.ToLower(s.get("clipboard_backend")),
		ClipboardFile:        s.get("clipboard_file"),
		AgentEnabled:         agentEnabled,
		AgentIdleTimeout:     agentIdleTimeout,
		AgentSocketPath:      s.get("agent_socket_path"),
		AgentLogPath:         s.get("agent_log_path"),
		LogLevel:             logLevel,
		KeyringEnabled:       keyringEnabled,
		KeyringService:       s.get("keyring_service"),
		KeyringUser:          s.get("keyring_user"),
		ConfigPath:           envPath,
		EnableMTLS:           enableMTLS,
		CACertPath:           caCertPath,
		ClientCertPath:       clientCertPath,
		ClientKeyPath:        clientKeyPath,
		Crypto:               cryptoCfg,
	}, nil
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("invalid log_level %q (expected debug, info, warn, error)", raw)
	}
}

func splitCommaList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func transferLimits(s *settings) (int64, int64, error) {
	body, err := s.int64Val("max_body_bytes")
	if err != nil {
		return 0, 0, err
	}
	if err := limits.Validate("max_body_bytes", body); err != nil {
		return 0, 0, err
	}
	vault, err := s.int64Val("max_vault_bytes")
	if err != nil {
		return 0, 0, err
	}
	if err := limits.Validate("max_vault_bytes", vault); err != nil {
		return 0, 0, err
	}
	return body, vault, nil
}
