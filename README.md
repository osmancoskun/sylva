# Sylva

Zero-knowledge, self-hosted secret and credential manager with hierarchical domain inheritance, optional mTLS, and optional Tailscale integration.

## Project Layout

```text
sylva/
├── cmd/
│   ├── sylva/          # Client CLI and local session agent entrypoint
│   └── sylvad/         # Self-hosted server daemon entrypoint
├── internal/
│   ├── agent/          # Background session agent and OS keyring integration
│   ├── cli/            # CLI command definitions and interactive prompts
│   ├── clipboard/      # Cross-platform clipboard manager with auto-clear timer
│   ├── config/         # Client and server configuration management
│   ├── crypto/         # Argon2id key derivation and AES-256-GCM encryption
│   ├── pki/            # Certificate Authority (CA) and mTLS certificate management
│   ├── storage/        # Server SQLite persistence and client local encrypted cache
│   ├── transport/      # HTTP API, optional mTLS, and optional Tailscale listener
│   ├── tree/           # Reverse-DNS domain hierarchy and credential inheritance
│   └── vault/          # Secret domain models (login, ssh, env, token)
├── docs/               # Technical documentation and guides
├── Makefile            # Build, test, and verification targets
└── go.mod              # Go module definition
```
