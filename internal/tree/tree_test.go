package tree_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/osman/sylva/internal/tree"
	"github.com/osman/sylva/internal/vault"
)

func TestNormalizeDomainAndAncestors(t *testing.T) {
	norm, err := tree.NormalizeDomain("https://Dev.API.Company.com:8443/v1/login")
	if err != nil {
		t.Fatalf("NormalizeDomain failed: %v", err)
	}
	if norm != "dev.api.company.com" {
		t.Errorf("got %q, want %q", norm, "dev.api.company.com")
	}

	ancestors, err := tree.AncestorChain(norm)
	if err != nil {
		t.Fatalf("AncestorChain failed: %v", err)
	}
	want := []string{"api.company.com", "company.com"}
	if !reflect.DeepEqual(ancestors, want) {
		t.Errorf("AncestorChain got %v, want %v", ancestors, want)
	}
}

func TestHierarchicalDomainInheritanceAndOverride(t *testing.T) {
	dt := tree.New()

	// 1. Add root domain company.com
	rootItem := &vault.SecretItem{
		ID:         "1",
		Type:       vault.SecretTypeLogin,
		Identifier: "company.com",
		Login: &vault.LoginPayload{
			Domain:   "company.com",
			Username: "osman@company.com",
			Password: "company-master-secret",
		},
	}
	if err := dt.Insert(rootItem); err != nil {
		t.Fatalf("Insert(company.com) failed: %v", err)
	}

	// 2. When adding mail.company.com, detect nearest parent company.com
	ancestor, found, err := dt.FindNearestAncestor("mail.company.com")
	if err != nil || !found {
		t.Fatalf("expected parent domain company.com to be found, got found=%v err=%v", found, err)
	}
	if ancestor.Login.Domain != "company.com" {
		t.Errorf("expected nearest ancestor 'company.com', got %q", ancestor.Login.Domain)
	}

	// 3. Insert mail.company.com as inheriting from company.com
	mailItem := &vault.SecretItem{
		ID:         "2",
		Type:       vault.SecretTypeLogin,
		Identifier: "mail.company.com",
		ParentID:   "company.com",
		Login: &vault.LoginPayload{
			Domain:            "mail.company.com",
			InheritFromParent: true,
			ParentDomain:      "company.com",
		},
	}
	if err := dt.Insert(mailItem); err != nil {
		t.Fatalf("Insert(mail.company.com) failed: %v", err)
	}

	// 4. Insert deep subdomain staging.mail.company.com with its OWN separate password (override)
	stagingItem := &vault.SecretItem{
		ID:         "3",
		Type:       vault.SecretTypeLogin,
		Identifier: "staging.mail.company.com",
		Login: &vault.LoginPayload{
			Domain:            "staging.mail.company.com",
			Username:          "staging-admin",
			Password:          "separate-staging-password",
			InheritFromParent: false,
		},
	}
	if err := dt.Insert(stagingItem); err != nil {
		t.Fatalf("Insert(staging.mail.company.com) failed: %v", err)
	}

	// 5. Resolve mail.company.com -> must inherit password from company.com
	resMail, err := dt.Resolve("mail.company.com", false)
	if err != nil {
		t.Fatalf("Resolve(mail.company.com) failed: %v", err)
	}
	if !resMail.Inherited || resMail.ResolvedDomain != "company.com" {
		t.Errorf("expected mail.company.com to inherit from company.com, got %+v", resMail)
	}
	if resMail.Item.Login.Password != "company-master-secret" {
		t.Errorf("expected inherited password 'company-master-secret', got %q", resMail.Item.Login.Password)
	}

	// 6. Update root company.com password -> mail.company.com and any cascading child automatically get the new password!
	rootItem.Login.Password = "rotated-company-secret-2026"

	// 7. Query an unregistered sub-subdomain dev.mail.company.com with cascade=true
	// Nearest ancestor is mail.company.com, which itself inherits from company.com!
	resDev, err := dt.Resolve("dev.mail.company.com", true)
	if err != nil {
		t.Fatalf("Resolve(dev.mail.company.com, cascade=true) failed: %v", err)
	}
	if !resDev.Inherited || resDev.Item.Login.Password != "rotated-company-secret-2026" {
		t.Errorf("expected cascading lookup to resolve rotated password, got %q", resDev.Item.Login.Password)
	}

	// 8. Resolve staging.mail.company.com -> must return its separate overridden password
	resStaging, err := dt.Resolve("staging.mail.company.com", true)
	if err != nil {
		t.Fatalf("Resolve(staging.mail.company.com) failed: %v", err)
	}
	if resStaging.Inherited || resStaging.Item.Login.Password != "separate-staging-password" {
		t.Errorf("expected overridden password for staging.mail.company.com, got %+v", resStaging)
	}

	// 9. Query unknown domain without cascade -> ErrDomainNotFound
	if _, err := dt.Resolve("unknown.org", false); !errors.Is(err, tree.ErrDomainNotFound) {
		t.Errorf("expected ErrDomainNotFound, got %v", err)
	}
}
