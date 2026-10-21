package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/vault"
)

func runUpdate(cfg config.ClientConfig, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	typ := fs.String("type", "", "password, domain, env, or ssh")
	identifier := fs.String("identifier", "", "domain, name, or project")
	username := fs.String("username", "", "username for a domain login")
	password := fs.String("password", "", "secret value")
	inherit := fs.Bool("inherit", false, "inherit the parent domain password")
	variable := fs.String("variable", "", "env variable name")
	pos, flagArgs := splitFlagsAndArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	id, secret, typeName, err := parseSetArgs(pos, *identifier, *password, *typ)
	if err != nil {
		return fmt.Errorf("usage: sylva update <id> [<password>] [<type>]")
	}
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("usage: sylva update <id> [<password>] [<type>]")
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
	ctx := context.Background()

	kind, err = resolveStoredType(ctx, v, id, kind)
	if err != nil {
		return err
	}

	if !*inherit && secret == "" {
		secret, err = promptSecretConfirm()
		if err != nil {
			return err
		}
	}

	item, err := v.GetSecret(ctx, kind, id)
	if err != nil {
		return err
	}

	switch kind {
	case vault.SecretTypeLogin:
		if item.Login == nil {
			return fmt.Errorf("domain %s has no login payload", id)
		}
		if strings.TrimSpace(*username) != "" {
			item.Login.Username = *username
		}
		if *inherit {
			ancestor, err := v.NearestLoginAncestor(ctx, item.Identifier)
			if err != nil {
				return err
			}
			if ancestor == nil || ancestor.Login == nil {
				return fmt.Errorf("no parent domain found for %s", item.Identifier)
			}
			item.ParentID = ancestor.Login.Domain
			item.Login.InheritFromParent = true
			item.Login.ParentDomain = ancestor.Login.Domain
			item.Login.Password = ""
			if item.Login.Username == "" {
				item.Login.Username = ancestor.Login.Username
			}
		} else {
			item.ParentID = ""
			item.Login.InheritFromParent = false
			item.Login.ParentDomain = ""
			item.Login.Password = secret
		}
	case vault.SecretTypeToken:
		if item.Token == nil {
			return fmt.Errorf("password %s has no payload", id)
		}
		item.Token.Token = secret
	case vault.SecretTypeEnv:
		if item.Env == nil {
			return fmt.Errorf("env %s has no payload", id)
		}
		name := *variable
		if name == "" {
			name = item.Identifier
		}
		if item.Env.Variables == nil {
			item.Env.Variables = map[string]string{}
		}
		if _, ok := item.Env.Variables[name]; !ok && len(item.Env.Variables) == 1 {
			for existing := range item.Env.Variables {
				name = existing
			}
		}
		item.Env.Variables[name] = secret
	case vault.SecretTypeSSH:
		if item.SSH == nil {
			return fmt.Errorf("ssh %s has no payload", id)
		}
		item.SSH.Passphrase = secret
	default:
		return fmt.Errorf("unsupported type %q", kind)
	}

	if err := v.UpdateSecret(ctx, item); err != nil {
		return err
	}
	fmt.Printf("Updated %s %s\n", secretTypeLabel(kind), item.Identifier)
	return nil
}
