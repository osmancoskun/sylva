// Package config provides centralized environment-driven configuration loading
// for both the Sylva client (sylva) and server daemon (sylvad).
// All runtime parameters—including network addresses, ports, timeouts, and
// security toggles—are loaded from a .env file or OS environment variables
// without hardcoded static values in application packages.
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

// ServerConfig holds runtime configuration for the sylvad server daemon.
type ServerConfig struct {
	ServiceName       string
	Version           string
	LogLevel          slog.Level
	Host              string
	Port              string
	ListenAddr        string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	EnableMTLS        bool
	CACertPath        string
	ServerCertPath    string
	ServerKeyPath     string
	EnableTailscale   bool
	TailscaleNode     string
}

// ClientConfig holds runtime configuration for the sylva CLI client.
type ClientConfig struct {
	Version          string
	Scheme           string
	Host             string
	Port             string
	ServerURL        string
	Timeout          time.Duration
	MaxResponseBytes int64
	EnableMTLS       bool
	CACertPath       string
	ClientCertPath   string
	ClientKeyPath    string
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

	return ServerConfig{
		ServiceName:       serviceName,
		Version:           version,
		LogLevel:          logLevel,
		Host:              host,
		Port:              port,
		ListenAddr:        listenAddr,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ShutdownTimeout:   shutdownTimeout,
		EnableMTLS:        enableMTLS,
		CACertPath:        os.Getenv("SYLVA_CA_CERT_PATH"),
		ServerCertPath:    os.Getenv("SYLVA_SERVER_CERT_PATH"),
		ServerKeyPath:     os.Getenv("SYLVA_SERVER_KEY_PATH"),
		EnableTailscale:   enableTailscale,
		TailscaleNode:     os.Getenv("SYLVA_TAILSCALE_NODE"),
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
	maxRespBytes, err := requireInt64Env("SYLVA_CLIENT_MAX_RESPONSE_BYTES")
	if err != nil {
		return ClientConfig{}, err
	}
	enableMTLS, err := requireBoolEnv("SYLVA_MTLS_ENABLED")
	if err != nil {
		return ClientConfig{}, err
	}

	return ClientConfig{
		Version:          version,
		Scheme:           scheme,
		Host:             host,
		Port:             port,
		ServerURL:        serverURL,
		Timeout:          timeout,
		MaxResponseBytes: maxRespBytes,
		EnableMTLS:       enableMTLS,
		CACertPath:       os.Getenv("SYLVA_CA_CERT_PATH"),
		ClientCertPath:   os.Getenv("SYLVA_CLIENT_CERT_PATH"),
		ClientKeyPath:    os.Getenv("SYLVA_CLIENT_KEY_PATH"),
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
