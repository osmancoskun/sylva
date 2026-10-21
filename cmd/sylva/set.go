package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/vault"
)

func runSet(cfg config.ClientConfig, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	typ := fs.String("type", "", "password, domain, env, or ssh")
	identifier := fs.String("identifier", "", "domain, name, or project")
	username := fs.String("username", "", "username for a domain login")
	password := fs.String("password", "", "secret value")
	inherit := fs.Bool("inherit", false, "inherit the parent domain password")
	host := fs.String("host", "", "SSH host")
	sshUser := fs.String("user", "", "SSH user")
	project := fs.String("project", "", "env project")
	environment := fs.String("environment", "", "env environment")
	variable := fs.String("variable", "", "env variable name")
	pos, flagArgs := splitFlagsAndArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	id, secret, typeName, err := parseSetArgs(pos, *identifier, *password, *typ)
	if err != nil {
		return err
	}
	*identifier, *password, *typ = id, secret, typeName
	wizard := strings.TrimSpace(*identifier) == "" && strings.TrimSpace(*password) == "" && strings.TrimSpace(*typ) == ""

	kind, err := resolveSetType(*typ, *identifier, wizard)
	if err != nil {
		return err
	}

	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx := context.Background()

	switch kind {
	case vault.SecretTypeLogin:
		return setLogin(ctx, v, *identifier, *username, *password, *inherit, wizard)
	case vault.SecretTypeToken:
		return setToken(ctx, v, *identifier, *password)
	case vault.SecretTypeEnv:
		return setEnv(ctx, v, *project, *identifier, *environment, *variable, *password, wizard)
	case vault.SecretTypeSSH:
		return setSSH(ctx, v, *identifier, *host, *sshUser, *password, wizard)
	default:
		return fmt.Errorf("unsupported type %q", kind)
	}
}

func parseSetArgs(rest []string, identifier, password, typ string) (string, string, string, error) {
	if len(rest) > 0 {
		if parsed, err := parseKnownType(rest[len(rest)-1]); err == nil {
			if typ == "" {
				typ = string(parsed)
			}
			rest = rest[:len(rest)-1]
		}
	}
	switch len(rest) {
	case 0:
	case 1:
		if identifier == "" {
			identifier = rest[0]
		}
	case 2:
		if identifier == "" {
			identifier = rest[0]
		}
		if password == "" {
			password = rest[1]
		}
	default:
		return "", "", "", fmt.Errorf("usage: sylva set [<id> [<password>] [<type>]]")
	}
	return identifier, password, typ, nil
}

func parseKnownType(raw string) (vault.SecretType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "password", "token":
		return vault.SecretTypeToken, nil
	case "2", "domain", "login":
		return vault.SecretTypeLogin, nil
	case "3", "env":
		return vault.SecretTypeEnv, nil
	case "4", "ssh":
		return vault.SecretTypeSSH, nil
	default:
		return "", fmt.Errorf("unknown type")
	}
}

func resolveSetType(raw, identifier string, wizard bool) (vault.SecretType, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw != "" {
		kind, err := parseKnownType(raw)
		if err != nil {
			return "", fmt.Errorf("unknown type %q (password, domain, env, ssh)", raw)
		}
		return kind, nil
	}
	if looksLikeIP(identifier) {
		return promptSecretType(identifier, []vault.SecretType{vault.SecretTypeLogin, vault.SecretTypeSSH})
	}
	if identifier != "" {
		if looksLikeHost(identifier) {
			return vault.SecretTypeLogin, nil
		}
		return vault.SecretTypeToken, nil
	}
	if !wizard {
		return vault.SecretTypeToken, nil
	}
	return promptSecretType("this", nil)
}

func promptSecretType(identifier string, allowed []vault.SecretType) (vault.SecretType, error) {
	if len(allowed) == 0 {
		allowed = []vault.SecretType{
			vault.SecretTypeToken,
			vault.SecretTypeLogin,
			vault.SecretTypeEnv,
			vault.SecretTypeSSH,
		}
	}
	if identifier == "this" {
		fmt.Println("What are you adding?")
	} else {
		fmt.Printf("What is %s?\n", identifier)
	}
	for i, kind := range allowed {
		fmt.Printf("  %d) %s\n", i+1, secretTypeLabel(kind))
	}
	raw, err := promptLine("Type: ")
	if err != nil {
		return "", err
	}
	raw = strings.TrimSpace(raw)
	if n, convErr := strconv.Atoi(raw); convErr == nil && n >= 1 && n <= len(allowed) {
		return allowed[n-1], nil
	}
	kind, err := parseKnownType(raw)
	if err != nil {
		return "", fmt.Errorf("unknown type %q (password, domain, env, ssh)", raw)
	}
	for _, allowedKind := range allowed {
		if kind == allowedKind {
			return kind, nil
		}
	}
	return "", fmt.Errorf("unknown type %q (password, domain, env, ssh)", raw)
}

func secretTypeLabel(kind vault.SecretType) string {
	switch kind {
	case vault.SecretTypeToken:
		return "password"
	case vault.SecretTypeLogin:
		return "domain"
	case vault.SecretTypeEnv:
		return "env"
	case vault.SecretTypeSSH:
		return "ssh"
	default:
		return string(kind)
	}
}

func looksLikeHost(s string) bool {
	if looksLikeIP(s) {
		return true
	}
	return strings.Contains(s, ".")
}

func looksLikeIP(s string) bool {
	return net.ParseIP(s) != nil
}

func setLogin(ctx context.Context, v *sylva.Vault, domain, username, password string, inherit, wizard bool) error {
	if strings.TrimSpace(domain) == "" {
		var err error
		domain, err = promptLine("Domain: ")
		if err != nil {
			return err
		}
	}
	if err := rejectIfExists(ctx, v, vault.SecretTypeLogin, domain); err != nil {
		return err
	}

	if wizard && strings.TrimSpace(username) == "" {
		var err error
		username, err = promptLine("Username: ")
		if err != nil {
			return err
		}
	}

	separate := false
	if !inherit {
		ancestor, err := v.NearestLoginAncestor(ctx, domain)
		if err != nil {
			return err
		}
		if ancestor != nil && ancestor.Login != nil {
			if password != "" {
				separate = true
			} else {
				ok, err := promptYesNo(fmt.Sprintf("Found parent domain %s. Inherit its password?", ancestor.Login.Domain))
				if err != nil {
					return err
				}
				inherit = ok
				separate = !ok
			}
		}
	}

	if !inherit && password == "" {
		var err error
		password, err = promptSecretConfirm()
		if err != nil {
			return err
		}
	}

	res, err := v.LoginSet(ctx, domain, username, password, inherit, separate)
	if err != nil {
		return err
	}
	if res.Inherited {
		fmt.Printf("Stored %s (inherits from %s)\n", res.RequestedDomain, res.ResolvedDomain)
		return nil
	}
	fmt.Printf("Stored %s\n", res.RequestedDomain)
	return nil
}

func setToken(ctx context.Context, v *sylva.Vault, name, secret string) error {
	if strings.TrimSpace(name) == "" {
		var err error
		name, err = promptLine("Name: ")
		if err != nil {
			return err
		}
	}
	if err := rejectIfExists(ctx, v, vault.SecretTypeToken, name); err != nil {
		return err
	}
	if secret == "" {
		var err error
		secret, err = promptSecretConfirm()
		if err != nil {
			return err
		}
	}
	item := &vault.SecretItem{
		Type:       vault.SecretTypeToken,
		Identifier: name,
		Token: &vault.TokenPayload{
			Name:  name,
			Token: secret,
		},
	}
	if err := v.PutSecret(ctx, item); err != nil {
		return err
	}
	fmt.Printf("Stored password %s\n", name)
	return nil
}

func setEnv(ctx context.Context, v *sylva.Vault, project, identifier, environment, variable, secret string, wizard bool) error {
	if strings.TrimSpace(variable) == "" {
		variable = identifier
	}
	if strings.TrimSpace(project) == "" {
		project = identifier
	}
	if strings.TrimSpace(project) == "" {
		var err error
		project, err = promptLine("Project: ")
		if err != nil {
			return err
		}
	}
	if err := rejectIfExists(ctx, v, vault.SecretTypeEnv, project); err != nil {
		return err
	}
	if wizard && environment == "" {
		var err error
		environment, err = promptLine("Environment (optional): ")
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(variable) == "" {
		var err error
		variable, err = promptLine("Variable: ")
		if err != nil {
			return err
		}
	}
	if secret == "" {
		var err error
		secret, err = promptSecretConfirm()
		if err != nil {
			return err
		}
	}
	item := &vault.SecretItem{
		Type:       vault.SecretTypeEnv,
		Identifier: project,
		Env: &vault.EnvPayload{
			Project:     project,
			Environment: environment,
			Variables:   map[string]string{variable: secret},
		},
	}
	if err := v.PutSecret(ctx, item); err != nil {
		return err
	}
	fmt.Printf("Stored env %s\n", project)
	return nil
}

func setSSH(ctx context.Context, v *sylva.Vault, name, host, user, secret string, wizard bool) error {
	if strings.TrimSpace(name) == "" {
		var err error
		name, err = promptLine("Name: ")
		if err != nil {
			return err
		}
	}
	if err := rejectIfExists(ctx, v, vault.SecretTypeSSH, name); err != nil {
		return err
	}
	if host == "" {
		host = name
	}
	if wizard && (host == "" || host == name) {
		var err error
		host, err = promptLine("Host: ")
		if err != nil {
			return err
		}
	}
	if wizard && user == "" {
		var err error
		user, err = promptLine("User: ")
		if err != nil {
			return err
		}
	}
	if secret == "" {
		var err error
		secret, err = promptSecretConfirm()
		if err != nil {
			return err
		}
	}
	item := &vault.SecretItem{
		Type:       vault.SecretTypeSSH,
		Identifier: name,
		SSH: &vault.SSHPayload{
			Name:       name,
			Host:       host,
			User:       user,
			Passphrase: secret,
		},
	}
	if err := v.PutSecret(ctx, item); err != nil {
		return err
	}
	fmt.Printf("Stored ssh %s\n", name)
	return nil
}

func rejectIfExists(ctx context.Context, v *sylva.Vault, kind vault.SecretType, identifier string) error {
	exists, err := v.SecretExists(ctx, kind, identifier)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return sylva.AlreadyExists(kind, identifier)
}
