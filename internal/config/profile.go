package config

import (
	"fmt"
	"strings"
)

const DefaultProfile = "default"

// Names are portable CLI labels. Remote storage uses random IDs, not names.
func NormalizeProfileName(name string) (string, error) {
	if name == "" {
		return DefaultProfile, nil
	}
	if len(name) > 64 || strings.TrimSpace(name) != name {
		return "", fmt.Errorf("profile names must contain 1-64 lowercase letters, numbers, hyphens or underscores")
	}
	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return "", fmt.Errorf("profile names must contain lowercase letters, numbers, hyphens or underscores")
		}
	}
	return name, nil
}

func SetActiveProfile(name string) error {
	name, err := NormalizeProfileName(name)
	if err != nil {
		return err
	}
	return writeLocalKey("profile", name)
}
