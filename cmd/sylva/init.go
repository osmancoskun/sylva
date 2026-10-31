package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/osman/sylva/internal/agent"
	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/storage"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type initOverrides struct {
	server, profile string
	timeout         time.Duration
}

type setupPrompts struct {
	line     func(string) (string, error)
	password func(string) (string, error)
}

func runInitCommand(envPath string, args []string, overrides initOverrides) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	nonInteractive := fs.Bool("non-interactive", false, "initialize only the salt using existing settings")
	wizard := fs.Bool("wizard", false, "run interactive setup (requires a terminal)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*wizard && *nonInteractive) {
		return errors.New("usage: sylva init [--wizard | --non-interactive]")
	}
	terminal := term.IsTerminal(int(os.Stdin.Fd()))
	if *wizard && !terminal {
		return errors.New("setup wizard requires an interactive terminal; use sylva init --non-interactive for automation")
	}
	if !*nonInteractive && terminal {
		return runSetupWizard(envPath, overrides, setupPrompts{line: promptSetupLine, password: promptMasterPassphrase})
	}
	cfg, err := config.LoadClientConfig(envPath)
	if err != nil {
		return err
	}
	if overrides.server != "" {
		if cfg.Backend == "git" {
			return errors.New("--server applies to the self-hosted backend")
		}
		cfg.ServerURL = overrides.server
	}
	if overrides.profile != "" {
		cfg.Profile, err = config.NormalizeProfileName(overrides.profile)
		if err != nil {
			return err
		}
	}
	if overrides.timeout > 0 {
		cfg.Timeout = overrides.timeout
	}
	return runInit(cfg)
}

// Read exactly one line without buffering bytes intended for the subsequent
// terminal-only password reader. EOF cancels setup instead of accepting defaults.
func promptSetupLine(label string) (string, error) {
	fmt.Print(label)
	stdinMu.Lock()
	defer stdinMu.Unlock()
	var line strings.Builder
	var one [1]byte
	for line.Len() < 4096 {
		_, err := io.ReadFull(os.Stdin, one[:])
		if err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return strings.TrimSpace(line.String()), nil
		}
		if one[0] != '\r' {
			line.WriteByte(one[0])
		}
	}
	return "", errors.New("setup input is too long")
}

func (p setupPrompts) value(label, current string, required bool) (string, error) {
	for {
		prompt := label
		if current != "" {
			prompt += " [" + current + "]"
		}
		raw, err := p.line(prompt + ": ")
		if err != nil {
			return "", err
		}
		value := strings.TrimSpace(raw)
		if value == "" {
			value = current
		}
		if required && value == "" {
			fmt.Println("A value is required.")
			continue
		}
		return value, nil
	}
}

func (p setupPrompts) yesNo(label string, defaultYes bool) (bool, error) {
	choices := " [y/N]: "
	if defaultYes {
		choices = " [Y/n]: "
	}
	for {
		raw, err := p.line(label + choices)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Println("Please enter yes or no.")
		}
	}
}

func runSetupWizard(envPath string, overrides initOverrides, p setupPrompts) error {
	defaults, err := config.SetupDefaults(envPath)
	if err != nil {
		return err
	}
	if overrides.server != "" {
		defaults["server_url"] = overrides.server
	}
	if overrides.profile != "" {
		defaults["profile"] = overrides.profile
	}
	fmt.Println("Sylva first-time setup")
	fmt.Println("1/5 Storage source\n  1) Self-hosted server\n  2) Git repository")
	values := map[string]string{}
	for {
		source, err := p.value("Source", defaults["backend"], true)
		if err != nil {
			return err
		}
		switch strings.ToLower(source) {
		case "1", "self-hosted":
			values["backend"] = "self-hosted"
		case "2", "git":
			values["backend"] = "git"
		default:
			fmt.Println("Choose self-hosted or git.")
			continue
		}
		break
	}
	fmt.Println("2/5 Connection")
	if values["backend"] == "git" {
		if overrides.server != "" {
			return errors.New("--server applies to the self-hosted backend")
		}
		if err := collectGitSetup(p, defaults, values); err != nil {
			return err
		}
	} else if err := collectServerSetup(p, defaults, values); err != nil {
		return err
	}
	fmt.Println("3/5 Profile")
	fmt.Println("Existing profiles are reused; a new name creates a separate profile.")
	for {
		name, err := p.value("Profile", defaults["profile"], true)
		if err != nil {
			return err
		}
		name, err = config.NormalizeProfileName(name)
		if err != nil {
			fmt.Println(err)
			continue
		}
		values["profile"] = name
		break
	}
	fmt.Println("4/5 Unlock method")
	fmt.Println("The master passphrase remains available for recovery.")
	useSSH, err := p.yesNo("Also enable SSH-agent unlock", false)
	if err != nil {
		return err
	}
	var publicKey ssh.PublicKey
	if useSSH {
		publicKey, err = collectSetupSSHKey(p)
		if err != nil {
			return err
		}
	}
	cfg, err := config.PreviewSetup(envPath, values)
	if err != nil {
		return err
	}
	if overrides.timeout > 0 {
		cfg.Timeout = overrides.timeout
	}
	if useSSH && !cfg.AgentEnabled {
		return errors.New("SSH unlock requires agent_enabled=true")
	}
	// Validate Git URLs/branches, executable availability and TLS settings before
	// asking for a password or writing either local settings or remote metadata.
	backend, err := sylva.NewBackend(cfg)
	if err != nil {
		return err
	}
	backend.Close()
	fmt.Printf("\nSource: %s\n", cfg.Backend)
	if cfg.Backend == "git" {
		fmt.Printf("Repository: %s\nBranch: %s\n", cfg.GitRemote, cfg.GitBranch)
	} else {
		fmt.Printf("Server: %s\n", cfg.ServerURL)
	}
	fmt.Printf("Profile: %s\nConfiguration: %s\n", cfg.Profile, config.LocalConfigPath())
	proceed, err := p.yesNo("Continue with setup", true)
	if err != nil {
		return err
	}
	if !proceed {
		fmt.Println("Setup cancelled; configuration unchanged.")
		return nil
	}
	return completeSetup(cfg, values, publicKey, p)
}

func collectSetupSSHKey(p setupPrompts) (ssh.PublicKey, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	defaultPath := filepath.Join(home, ".ssh", "id_ed25519.pub")
	fmt.Println("Enter the path to your Ed25519 public-key file (.pub), or press Enter to use the shown path.")
	fmt.Println("The matching private key must already be loaded in ssh-agent.")
	for {
		path, err := p.value("Ed25519 public-key file (.pub)", defaultPath, true)
		if err != nil {
			return nil, err
		}
		publicKey, err := readSSHUnlockPublicKey(expandSetupPath(path))
		if err != nil {
			fmt.Printf("Cannot use that public-key file: %v\nPlease enter a valid .pub file path.\n", err)
			continue
		}
		return publicKey, nil
	}
}

func collectGitSetup(p setupPrompts, defaults, values map[string]string) error {
	var err error
	values["git_remote"], err = p.value("Git remote (SSH or HTTPS)", defaults["git_remote"], true)
	if err != nil {
		return err
	}
	values["git_branch"], err = p.value("Git branch", defaults["git_branch"], true)
	return err
}

func collectServerSetup(p setupPrompts, defaults, values map[string]string) error {
	server, err := p.value("Server URL", defaults["server_url"], true)
	if err != nil {
		return err
	}
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server URL must be an HTTP/HTTPS base URL without credentials, a query or a fragment")
	}
	defaultTLS, _ := strconv.ParseBool(defaults["mtls"])
	useTLS, err := p.yesNo("Use mTLS client certificates", defaultTLS || u.Scheme == "https")
	if err != nil {
		return err
	}
	values["mtls"] = strconv.FormatBool(useTLS)
	if useTLS {
		u.Scheme = "https"
		for _, field := range []struct{ key, label string }{{"ca_cert_path", "CA certificate"}, {"client_cert_path", "Client certificate"}, {"client_key_path", "Client private-key file"}} {
			value, err := p.value(field.label, defaults[field.key], true)
			if err != nil {
				return err
			}
			values[field.key] = expandSetupPath(value)
		}
	}
	values["server_url"] = u.String()
	return nil
}

func expandSetupPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func setupPassphrase(cfg config.ClientConfig, v *sylva.Vault, p setupPrompts) (string, error) {
	if strings.TrimSpace(cfg.MasterPassphrase) != "" {
		return cfg.MasterPassphrase, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	setup, err := v.NeedsPassphraseSetup(ctx)
	cancel()
	if err != nil {
		return "", err
	}
	label := "Master passphrase: "
	if setup {
		label = "New master passphrase: "
	}
	passphrase, err := p.password(label)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(passphrase) == "" {
		return "", errors.New("master passphrase cannot be empty")
	}
	if setup {
		confirmation, err := p.password("Confirm master passphrase: ")
		if err != nil {
			return "", err
		}
		if passphrase != confirmation {
			return "", errors.New("master passphrases do not match")
		}
	}
	return passphrase, nil
}

func completeSetup(cfg config.ClientConfig, values map[string]string, publicKey ssh.PublicKey, p setupPrompts) error {
	fmt.Println("5/5 Verify connection and unlock")
	rootCfg := cfg
	rootCfg.Profile, rootCfg.CacheEnabled = config.DefaultProfile, false
	v, err := sylva.OpenForCommand(rootCfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	_, err = v.Remote().Ping(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("connection check failed; configuration unchanged: %w", err)
	}
	passphrase, err := setupPassphrase(rootCfg, v, p)
	if err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
	err = v.Unlock(ctx, passphrase)
	cancel()
	if err != nil {
		return fmt.Errorf("unlock failed; configuration unchanged: %w", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
	err = v.UseProfile(ctx, cfg.Profile)
	cancel()
	if errors.Is(err, storage.ErrNotFound) {
		ctx, cancel = context.WithTimeout(context.Background(), cfg.Timeout)
		err = v.CreateProfile(ctx, cfg.Profile)
		cancel()
	}
	if err != nil {
		return err
	}
	if err := clearProfileClipboard(cfg); err != nil {
		return err
	}
	if err := config.SaveSetup(values); err != nil {
		return fmt.Errorf("vault verified, but configuration was not saved: %w", err)
	}
	if publicKey != nil {
		path, endpoint := sshRegistration(cfg)
		if err := ensureVerifiedSSH(cfg, v, publicKey, path, endpoint); err != nil {
			return fmt.Errorf("setup saved; SSH unlock setup failed: %w", err)
		}
		fmt.Println("SSH unlock enabled. Next time: sylva unlock --ssh")
	}
	if cfg.KeyringEnabled {
		if err := agent.NewKeyring(true, cfg.KeyringService, cfg.KeyringUser).Set(passphrase); err != nil {
			return fmt.Errorf("setup saved; store keyring passphrase: %w", err)
		}
	}
	if cfg.AgentEnabled {
		if err := publishSessionKey(cfg, v); err != nil {
			return fmt.Errorf("setup saved; start session with sylva unlock: %w", err)
		}
	}
	fmt.Printf("Setup complete. Active profile: %s\nUse sylva set <name> or sylva get <name>.\n", cfg.Profile)
	return nil
}
