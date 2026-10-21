package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	sylva "github.com/osman/sylva/internal/client"
	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/vault"
)

func runGet(cfg config.ClientConfig, args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	typ := fs.String("type", "", "password, domain, env, or ssh")
	cascade := fs.Bool("cascade", false, "walk up the domain tree when the exact domain is not stored")
	variable := fs.String("variable", "", "env variable name when the project has more than one")
	pos, flagArgs := splitFlagsAndArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	identifier, typeName, err := parseGetArgs(pos, *typ)
	if err != nil {
		return err
	}

	kind, err := resolveGetType(typeName)
	if err != nil {
		return err
	}

	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if kind == "" {
		matches, err := v.ProbeValues(ctx, identifier, *cascade, *variable)
		if err != nil {
			return err
		}
		switch len(matches) {
		case 1:
			return copyToClipboard(cfg, string(matches[0].Type), identifier, matches[0].Value)
		case 0:
			kind, err = promptSecretType(identifier, nil)
			if err != nil {
				return err
			}
		default:
			var types []vault.SecretType
			for _, match := range matches {
				types = append(types, match.Type)
			}
			kind, err = promptSecretType(identifier, types)
			if err != nil {
				return err
			}
		}
	}

	gotType, secret, err := v.GetValue(ctx, identifier, kind, *cascade, *variable)
	if err != nil {
		return err
	}
	return copyToClipboard(cfg, string(gotType), identifier, secret)
}

func parseGetArgs(rest []string, typ string) (string, string, error) {
	if len(rest) > 0 {
		if parsed, err := parseKnownType(rest[len(rest)-1]); err == nil {
			if typ == "" {
				typ = string(parsed)
			}
			rest = rest[:len(rest)-1]
		}
	}
	if len(rest) != 1 {
		return "", "", fmt.Errorf("usage: sylva get <id> [<type>]")
	}
	return rest[0], typ, nil
}

func resolveStoredType(ctx context.Context, v *sylva.Vault, identifier string, kind vault.SecretType) (vault.SecretType, error) {
	if kind != "" {
		exists, err := v.SecretExists(ctx, kind, identifier)
		if err != nil {
			return "", err
		}
		if !exists {
			return "", fmt.Errorf("no %s secret named %s", secretTypeLabel(kind), identifier)
		}
		return kind, nil
	}
	matches, err := v.ProbeValues(ctx, identifier, false, "")
	if err != nil {
		return "", err
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no secret named %s", identifier)
	case 1:
		return matches[0].Type, nil
	default:
		var types []vault.SecretType
		for _, match := range matches {
			types = append(types, match.Type)
		}
		return promptSecretType(identifier, types)
	}
}

func resolveGetType(raw string) (vault.SecretType, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return "", nil
	}
	kind, err := parseKnownType(raw)
	if err != nil {
		return "", fmt.Errorf("unknown type %q (password, domain, env, ssh)", raw)
	}
	return kind, nil
}
