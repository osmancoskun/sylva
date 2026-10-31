package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/osman/sylva/internal/agent"
	"github.com/osman/sylva/internal/clipboard"
	"github.com/osman/sylva/internal/config"
)

func runProfile(cfg config.ClientConfig, args []string) error {
	if len(args) == 1 && args[0] == "current" {
		name, err := config.NormalizeProfileName(cfg.Profile)
		if err != nil {
			return err
		}
		fmt.Println(name)
		return nil
	}
	if len(args) == 2 && (args[0] == "use" || args[0] == "switch") {
		return runSwitch(cfg, args[1])
	}
	if !(len(args) == 1 && args[0] == "list") && !(len(args) == 2 && args[0] == "create") {
		return fmt.Errorf("usage: sylva profile create <name> | list | current | use <name>")
	}
	active, err := config.NormalizeProfileName(cfg.Profile)
	if err != nil {
		return err
	}
	cfg.Profile = config.DefaultProfile
	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if args[0] == "create" {
		if err := v.CreateProfile(ctx, args[1]); err != nil {
			return err
		}
		fmt.Printf("Created profile %s; use sylva switch %s to select it\n", args[1], args[1])
		return nil
	}
	profiles, err := v.ListProfiles(ctx)
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		marker := " "
		if profile.Name == active {
			marker = "*"
		}
		fmt.Printf("%s %s\n", marker, profile.Name)
	}
	return nil
}

func runSwitch(cfg config.ClientConfig, name string) error {
	name, err := config.NormalizeProfileName(name)
	if err != nil {
		return err
	}
	if override := strings.TrimSpace(os.Getenv("SYLVA_PROFILE")); override != "" && override != name {
		return fmt.Errorf("SYLVA_PROFILE=%s overrides saved selections; unset it before switching profiles", override)
	}
	// Management always opens the root/default context, allowing recovery from
	// a saved profile that does not exist in a newly selected/restored backend.
	cfg.Profile = config.DefaultProfile
	v, err := openUnlocked(cfg)
	if err != nil {
		return err
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	if err := v.UseProfile(ctx, name); err != nil {
		return err
	}
	if err := clearProfileClipboard(cfg); err != nil {
		return fmt.Errorf("clear clipboard before switching: %w", err)
	}
	if err := config.SetActiveProfile(name); err != nil {
		return err
	}
	fmt.Printf("Active profile: %s\n", name)
	return nil
}

func clearProfileClipboard(cfg config.ClientConfig) error {
	if cfg.AgentEnabled {
		ac, err := agent.DialWithLimit(cfg.AgentSocketPath, cfg.Timeout, cfg.AgentMaxRequestBytes)
		if err != nil {
			if agentAbsent(err) {
				return nil
			}
			return err
		}
		if err := ac.ClearClipboard(); err != nil {
			// Agents already running from the previous release support Copy.
			if strings.Contains(err.Error(), "unknown agent operation") {
				return ac.Copy("", "", "")
			}
			return err
		}
		return nil
	}
	if cfg.ClipboardBackend == clipboard.BackendFile {
		clip, err := clipboard.NewManager(cfg.ClipboardBackend, cfg.ClipboardFile, cfg.ClipboardClearAfter)
		if err != nil {
			return err
		}
		defer clip.Close()
		return clip.Clear()
	}
	return nil
}
