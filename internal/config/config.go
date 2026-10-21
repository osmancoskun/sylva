// Package config provides centralized environment-driven configuration loading
// for both the Sylva client (sylva) and server daemon (sylvad).
// All runtime parameters—including network addresses, ports, timeouts, KDF
// settings, and security toggles—are loaded from a .env file or OS environment
// variables without hardcoded static values in application packages.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// CryptoConfig holds centralized parameters for Argon2id key derivation and
// password generation loaded from environment configuration.
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
	CacheEnabled         bool
	CachePath            string
	SQLiteBusyTimeout    time.Duration
	RecordInitialVersion int
	MasterPassphrase     string
	ClipboardClearAfter  time.Duration
	ClipboardBackend     string
	ClipboardFile        string
	AgentEnabled         bool
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

// LoadDotEnv reads key=value pairs from the specified file path and populates
// any environment variables that are not already set in the process environment.
func LoadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open env file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
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
			return fmt.Errorf("invalid env syntax at %s:%d", path, lineNum)
		}

		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}

		if _, exists := os.LookupEnv(key); !exists {
			if err := os.Setenv(key, val); err != nil {
				return fmt.Errorf("set env %s: %w", key, err)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan env file %s: %w", path, err)
	}
	return nil
}

// LoadCryptoConfig loads and validates cryptographic parameters from the environment.
func LoadCryptoConfig(envPath string) (CryptoConfig, error) {
	if envPath != "" {
		if err := LoadDotEnv(envPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return CryptoConfig{}, err
		}
	}

	kdfTime, err := requireUint32Env("SYLVA_KDF_TIME")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfMemoryKB, err := requireUint32Env("SYLVA_KDF_MEMORY_KB")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfThreads, err := requireUint8Env("SYLVA_KDF_THREADS")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfKeyLen, err := requireUint32Env("SYLVA_KDF_KEY_LEN")
	if err != nil {
		return CryptoConfig{}, err
	}
	kdfSaltLen, err := requireIntEnv("SYLVA_KDF_SALT_LEN")
	if err != nil {
		return CryptoConfig{}, err
	}
	pwdDefaultLen, err := requireIntEnv("SYLVA_PASSWORD_DEFAULT_LEN")
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

// LoadServerConfig loads the .env file (if present) and builds a validated
// ServerConfig strictly from environment variables.
func LoadServerConfig(envPath string) (ServerConfig, error) {
	if envPath != "" {
		if err := LoadDotEnv(envPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ServerConfig{}, err
		}
	}

	host, err := requireEnv("SYLVA_HOST")
	if err != nil {
		return ServerConfig{}, err
	}
	port, err := requireEnv("SYLVA_PORT")
	if err != nil {
		return ServerConfig{}, err
	}
	listenAddr := os.Getenv("SYLVA_SERVER_ADDR")
	if listenAddr == "" {
		listenAddr = net.JoinHostPort(host, port)
	}

	serviceName, err := requireEnv("SYLVA_SERVICE_NAME")
	if err != nil {
		return ServerConfig{}, err
	}
	version, err := requireEnv("SYLVA_VERSION")
	if err != nil {
		return ServerConfig{}, err
	}

	logLevelStr, err := requireEnv("SYLVA_LOG_LEVEL")
	if err != nil {
		return ServerConfig{}, err
	}
	logLevel, err := parseLogLevel(logLevelStr)
	if err != nil {
		return ServerConfig{}, err
	}

	readHeaderTimeout, err := requireDurationEnv("SYLVA_SERVER_READ_HEADER_TIMEOUT")
	if err != nil {
		return ServerConfig{}, err
	}
	readTimeout, err := requireDurationEnv("SYLVA_SERVER_READ_TIMEOUT")
	if err != nil {
		return ServerConfig{}, err
	}
	writeTimeout, err := requireDurationEnv("SYLVA_SERVER_WRITE_TIMEOUT")
	if err != nil {
		return ServerConfig{}, err
	}
	idleTimeout, err := requireDurationEnv("SYLVA_SERVER_IDLE_TIMEOUT")
	if err != nil {
		return ServerConfig{}, err
	}
	shutdownTimeout, err := requireDurationEnv("SYLVA_SERVER_SHUTDOWN_TIMEOUT")
	if err != nil {
		return ServerConfig{}, err
	}

	enableMTLS, err := requireBoolEnv("SYLVA_MTLS_ENABLED")
	if err != nil {
		return ServerConfig{}, err
	}
	enableTailscale, err := requireBoolEnv("SYLVA_TAILSCALE_ENABLED")
	if err != nil {
		return ServerConfig{}, err
	}
	apiPrefix, err := requireEnv("SYLVA_API_PREFIX")
	if err != nil {
		return ServerConfig{}, err
	}
	dbPath, err := requireEnv("SYLVA_SERVER_DB_PATH")
	if err != nil {
		return ServerConfig{}, err
	}
	maxBodyBytes, err := requireInt64Env("SYLVA_MAX_BODY_BYTES")
	if err != nil {
		return ServerConfig{}, err
	}
	sqliteBusyTimeout, err := requireDurationEnv("SYLVA_SQLITE_BUSY_TIMEOUT")
	if err != nil {
		return ServerConfig{}, err
	}
	recordInitialVersion, err := requireIntEnv("SYLVA_RECORD_INITIAL_VERSION")
	if err != nil {
		return ServerConfig{}, err
	}

	return ServerConfig{
		ServiceName:          serviceName,
		Version:              version,
		LogLevel:             logLevel,
		Host:                 host,
		Port:                 port,
		ListenAddr:           listenAddr,
		APIPrefix:            strings.TrimRight(apiPrefix, "/"),
		DBPath:               dbPath,
		MaxBodyBytes:         maxBodyBytes,
		SQLiteBusyTimeout:    sqliteBusyTimeout,
		RecordInitialVersion: recordInitialVersion,
		ReadHeaderTimeout:    readHeaderTimeout,
		ReadTimeout:          readTimeout,
		WriteTimeout:         writeTimeout,
		IdleTimeout:          idleTimeout,
		ShutdownTimeout:      shutdownTimeout,
		EnableMTLS:           enableMTLS,
		CACertPath:           os.Getenv("SYLVA_CA_CERT_PATH"),
		ServerCertPath:       os.Getenv("SYLVA_SERVER_CERT_PATH"),
		ServerKeyPath:        os.Getenv("SYLVA_SERVER_KEY_PATH"),
		EnableTailscale:      enableTailscale,
		TailscaleNode:        os.Getenv("SYLVA_TAILSCALE_NODE"),
	}, nil
}

// LoadClientConfig loads the .env file (if present) and builds a validated
// ClientConfig strictly from environment variables.
func LoadClientConfig(envPath string) (ClientConfig, error) {
	if envPath != "" {
		if err := LoadDotEnv(envPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return ClientConfig{}, err
		}
	}

	version, err := requireEnv("SYLVA_VERSION")
	if err != nil {
		return ClientConfig{}, err
	}
	scheme, err := requireEnv("SYLVA_SCHEME")
	if err != nil {
		return ClientConfig{}, err
	}
	host, err := requireEnv("SYLVA_HOST")
	if err != nil {
		return ClientConfig{}, err
	}
	port, err := requireEnv("SYLVA_PORT")
	if err != nil {
		return ClientConfig{}, err
	}

	serverURL := os.Getenv("SYLVA_SERVER_URL")
	if serverURL == "" {
		serverURL = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
	}

	timeout, err := requireDurationEnv("SYLVA_CLIENT_TIMEOUT")
	if err != nil {
		return ClientConfig{}, err
	}
	maxBodyBytes, err := requireInt64Env("SYLVA_MAX_BODY_BYTES")
	if err != nil {
		return ClientConfig{}, err
	}
	enableMTLS, err := requireBoolEnv("SYLVA_MTLS_ENABLED")
	if err != nil {
		return ClientConfig{}, err
	}
	apiPrefix, err := requireEnv("SYLVA_API_PREFIX")
	if err != nil {
		return ClientConfig{}, err
	}
	cacheEnabled, err := requireBoolEnv("SYLVA_CLIENT_CACHE_ENABLED")
	if err != nil {
		return ClientConfig{}, err
	}
	cachePath, err := requireEnv("SYLVA_CLIENT_CACHE_PATH")
	if err != nil {
		return ClientConfig{}, err
	}
	recordInitialVersion, err := requireIntEnv("SYLVA_RECORD_INITIAL_VERSION")
	if err != nil {
		return ClientConfig{}, err
	}
	sqliteBusyTimeout, err := requireDurationEnv("SYLVA_SQLITE_BUSY_TIMEOUT")
	if err != nil {
		return ClientConfig{}, err
	}
	clipboardClearAfter, err := requireDurationEnv("SYLVA_CLIPBOARD_CLEAR_AFTER")
	if err != nil {
		return ClientConfig{}, err
	}
	clipboardBackend, err := requireEnv("SYLVA_CLIPBOARD_BACKEND")
	if err != nil {
		return ClientConfig{}, err
	}
	agentEnabled, err := requireBoolEnv("SYLVA_AGENT_ENABLED")
	if err != nil {
		return ClientConfig{}, err
	}
	agentSocketPath, err := requireEnv("SYLVA_AGENT_SOCKET_PATH")
	if err != nil {
		return ClientConfig{}, err
	}
	agentLogPath, err := requireEnv("SYLVA_AGENT_LOG_PATH")
	if err != nil {
		return ClientConfig{}, err
	}
	logLevelStr, err := requireEnv("SYLVA_LOG_LEVEL")
	if err != nil {
		return ClientConfig{}, err
	}
	logLevel, err := parseLogLevel(logLevelStr)
	if err != nil {
		return ClientConfig{}, err
	}
	keyringEnabled, err := requireBoolEnv("SYLVA_KEYRING_ENABLED")
	if err != nil {
		return ClientConfig{}, err
	}
	keyringService, err := requireEnv("SYLVA_KEYRING_SERVICE")
	if err != nil {
		return ClientConfig{}, err
	}
	keyringUser, err := requireEnv("SYLVA_KEYRING_USER")
	if err != nil {
		return ClientConfig{}, err
	}
	cryptoCfg, err := LoadCryptoConfig("")
	if err != nil {
		return ClientConfig{}, err
	}

	return ClientConfig{
		Version:              version,
		Scheme:               scheme,
		Host:                 host,
		Port:                 port,
		ServerURL:            serverURL,
		APIPrefix:            strings.TrimRight(apiPrefix, "/"),
		Timeout:              timeout,
		MaxBodyBytes:         maxBodyBytes,
		CacheEnabled:         cacheEnabled,
		CachePath:            cachePath,
		SQLiteBusyTimeout:    sqliteBusyTimeout,
		RecordInitialVersion: recordInitialVersion,
		MasterPassphrase:     os.Getenv("SYLVA_MASTER_PASSPHRASE"),
		ClipboardClearAfter:  clipboardClearAfter,
		ClipboardBackend:     strings.ToLower(strings.TrimSpace(clipboardBackend)),
		ClipboardFile:        os.Getenv("SYLVA_CLIPBOARD_FILE"),
		AgentEnabled:         agentEnabled,
		AgentSocketPath:      agentSocketPath,
		AgentLogPath:         agentLogPath,
		LogLevel:             logLevel,
		KeyringEnabled:       keyringEnabled,
		KeyringService:       keyringService,
		KeyringUser:          keyringUser,
		ConfigPath:           envPath,
		EnableMTLS:           enableMTLS,
		CACertPath:           os.Getenv("SYLVA_CA_CERT_PATH"),
		ClientCertPath:       os.Getenv("SYLVA_CLIENT_CERT_PATH"),
		ClientKeyPath:        os.Getenv("SYLVA_CLIENT_KEY_PATH"),
		Crypto:               cryptoCfg,
	}, nil
}

func requireEnv(key string) (string, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return "", fmt.Errorf("required environment variable %s is not set (check .env)", key)
	}
	return val, nil
}

func requireDurationEnv(key string) (time.Duration, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return 0, err
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s=%q: %w", key, raw, err)
	}
	return d, nil
}

func requireBoolEnv(key string) (bool, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return false, err
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid boolean for %s=%q: %w", key, raw, err)
	}
	return b, nil
}

func requireInt64Env(key string) (int64, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s=%q: %w", key, raw, err)
	}
	return n, nil
}

func requireIntEnv(key string) (int, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s=%q: %w", key, raw, err)
	}
	return n, nil
}

func requireUint32Env(key string) (uint32, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid uint32 for %s=%q: %w", key, raw, err)
	}
	return uint32(n), nil
}

func requireUint8Env(key string) (uint8, error) {
	raw, err := requireEnv(key)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("invalid uint8 for %s=%q: %w", key, raw, err)
	}
	return uint8(n), nil
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
		return slog.LevelInfo, fmt.Errorf("invalid SYLVA_LOG_LEVEL %q (expected debug, info, warn, error)", raw)
	}
}
