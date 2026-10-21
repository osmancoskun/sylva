package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/osman/sylva/internal/config"
	"github.com/osman/sylva/internal/vault"
)

func runList(cfg config.ClientConfig, args []string) error {
	var kind vault.SecretType
	if len(args) > 1 {
		return fmt.Errorf("usage: sylva list [<type>]")
	}
	if len(args) == 1 {
		parsed, err := parseKnownType(args[0])
		if err != nil {
			return fmt.Errorf("unknown type %q (password, domain, env, ssh)", args[0])
		}
		kind = parsed
	}

	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	items, err := v.ListSecrets(ctx, kind)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("No secrets.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, item := range items {
		fmt.Fprintf(w, "%s\t%s\n", secretTypeLabel(item.Type), item.Identifier)
	}
	return w.Flush()
}
