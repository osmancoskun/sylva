package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/osman/sylva/internal/config"
)

func runDelete(cfg config.ClientConfig, args []string) error {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	typ := fs.String("type", "", "password, domain, env, or ssh")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, flagArgs := splitFlagsAndArgs(args)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	identifier, typeName, err := parseGetArgs(pos, *typ)
	if err != nil {
		return fmt.Errorf("usage: sylva delete <id> [<type>]")
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

	kind, err = resolveStoredType(ctx, v, identifier, kind)
	if err != nil {
		return err
	}

	if !*yes {
		ok, err := promptYesNo(fmt.Sprintf("Delete %s %s?", secretTypeLabel(kind), identifier))
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	if err := v.DeleteSecret(ctx, kind, identifier); err != nil {
		return err
	}
	fmt.Printf("Deleted %s %s\n", secretTypeLabel(kind), identifier)
	return nil
}
