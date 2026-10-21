// Package tree implements a reverse-DNS hierarchical domain tree (trie) that
// supports domain and subdomain credential lookup, ancestor discovery, and
// cascading credential inheritance (e.g. dev.api.company.com -> company.com).
package tree

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/osman/sylva/internal/vault"
)

var (
	// ErrEmptyDomain indicates that an empty or invalid domain string was provided.
	ErrEmptyDomain = errors.New("domain cannot be empty")

	// ErrDomainNotFound indicates that neither the requested domain nor any of its ancestors exist in the tree.
	ErrDomainNotFound = errors.New("no credentials found for domain or its parent domains")

	// ErrInheritanceCycle indicates that a circular parent inheritance reference was detected.
	ErrInheritanceCycle = errors.New("circular domain credential inheritance detected")
)

// NormalizeDomain cleans a raw domain or URL input (stripping scheme, port, path,
// and leading/trailing dots) and returns a lowercase canonical domain name.
func NormalizeDomain(raw string) (string, error) {
	cleaned := strings.TrimSpace(strings.ToLower(raw))
	if cleaned == "" {
		return "", ErrEmptyDomain
	}

	if strings.Contains(cleaned, "://") {
		parsed, err := url.Parse(cleaned)
		if err != nil {
			return "", fmt.Errorf("parse domain URL %q: %w", raw, err)
		}
		cleaned = parsed.Hostname()
	} else {
		if slashIdx := strings.IndexByte(cleaned, '/'); slashIdx != -1 {
			cleaned = cleaned[:slashIdx]
		}
		if colonIdx := strings.IndexByte(cleaned, ':'); colonIdx != -1 {
			cleaned = cleaned[:colonIdx]
		}
	}

	cleaned = strings.Trim(cleaned, ".")
	if cleaned == "" {
		return "", ErrEmptyDomain
	}

	labels := strings.Split(cleaned, ".")
	for _, label := range labels {
		if label == "" {
			return "", fmt.Errorf("invalid domain format %q", raw)
		}
	}

	return cleaned, nil
}

// AncestorChain returns the ordered hierarchy of candidate parent domains from
// the closest parent up to the registrable root (excluding the bare TLD).
// For example, "dev.mail.company.com" returns ["mail.company.com", "company.com"].
func AncestorChain(domain string) ([]string, error) {
	norm, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	labels := strings.Split(norm, ".")
	// A domain needs at least 3 labels (e.g., sub.company.com) to have a valid parent domain (company.com).
	if len(labels) <= 2 {
		return nil, nil
	}

	var ancestors []string
	for i := 1; i <= len(labels)-2; i++ {
		ancestors = append(ancestors, strings.Join(labels[i:], "."))
	}
	return ancestors, nil
}

// Resolution describes how a domain credential query was resolved through the hierarchy.
type Resolution struct {
	RequestedDomain string
	ResolvedDomain  string
	Inherited       bool
	Item            *vault.SecretItem
}

type node struct {
	label    string
	domain   string
	item     *vault.SecretItem
	children map[string]*node
}

// DomainTree stores login items in a reverse-DNS trie (e.g. "com" -> "company" -> "mail" -> "dev").
type DomainTree struct {
	root *node
}

// New creates an empty DomainTree.
func New() *DomainTree {
	return &DomainTree{
		root: &node{
			children: make(map[string]*node),
		},
	}
}

// Insert adds or updates a login SecretItem at its normalized domain position in the tree.
func (t *DomainTree) Insert(item *vault.SecretItem) error {
	if item == nil || item.Login == nil {
		return errors.New("login secret item cannot be nil")
	}

	norm, err := NormalizeDomain(item.Login.Domain)
	if err != nil {
		return err
	}
	item.Login.Domain = norm
	item.Identifier = norm

	labels := reverseLabels(norm)
	cur := t.root
	for _, label := range labels {
		next, exists := cur.children[label]
		if !exists {
			next = &node{
				label:    label,
				children: make(map[string]*node),
			}
			cur.children[label] = next
		}
		cur = next
	}

	cur.domain = norm
	cur.item = item
	return nil
}

// FindNearestAncestor searches upward from the given subdomain and returns the closest
// existing parent SecretItem in the tree (if any). This is used during `sylva add`
// to ask: "Parent domain company.com found. Inherit its credentials?"
func (t *DomainTree) FindNearestAncestor(domain string) (*vault.SecretItem, bool, error) {
	ancestors, err := AncestorChain(domain)
	if err != nil {
		return nil, false, err
	}

	for _, ancestor := range ancestors {
		if n := t.findExactNode(ancestor); n != nil && n.item != nil {
			return n.item, true, nil
		}
	}
	return nil, false, nil
}

// Resolve retrieves the credentials for the requested domain.
//  1. If an exact entry exists and does NOT inherit from a parent, it is returned directly.
//  2. If an exact entry exists with InheritFromParent=true, it walks up the ancestor chain
//     (or explicit ParentDomain) to resolve the effective password.
//  3. If no exact entry exists and allowCascade is true, it walks up the ancestor chain
//     to find the nearest parent domain's credentials.
func (t *DomainTree) Resolve(domain string, allowCascade bool) (*Resolution, error) {
	norm, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	exactNode := t.findExactNode(norm)
	if exactNode != nil && exactNode.item != nil && exactNode.item.Login != nil {
		if !exactNode.item.Login.InheritFromParent {
			return &Resolution{
				RequestedDomain: norm,
				ResolvedDomain:  norm,
				Inherited:       false,
				Item:            exactNode.item,
			}, nil
		}

		resolvedItem, err := t.resolveInheritedItem(exactNode.item, make(map[string]bool))
		if err != nil {
			return nil, err
		}
		if resolvedItem == nil || resolvedItem.Login == nil {
			return nil, ErrDomainNotFound
		}

		// Merge the subdomain's own metadata (e.g. username if customized) with the parent's password.
		effectiveCopy := *exactNode.item
		loginCopy := *exactNode.item.Login
		loginCopy.Password = resolvedItem.Login.Password
		if loginCopy.Username == "" {
			loginCopy.Username = resolvedItem.Login.Username
		}
		effectiveCopy.Login = &loginCopy

		return &Resolution{
			RequestedDomain: norm,
			ResolvedDomain:  resolvedItem.Login.Domain,
			Inherited:       true,
			Item:            &effectiveCopy,
		}, nil
	}

	if !allowCascade {
		return nil, ErrDomainNotFound
	}

	ancestorItem, found, err := t.FindNearestAncestor(norm)
	if err != nil {
		return nil, err
	}
	if !found || ancestorItem == nil {
		return nil, ErrDomainNotFound
	}

	resolvedItem, err := t.resolveInheritedItem(ancestorItem, make(map[string]bool))
	if err != nil {
		return nil, err
	}
	if resolvedItem == nil || resolvedItem.Login == nil {
		return nil, ErrDomainNotFound
	}

	return &Resolution{
		RequestedDomain: norm,
		ResolvedDomain:  resolvedItem.Login.Domain,
		Inherited:       true,
		Item:            resolvedItem,
	}, nil
}

// Subtree returns all domain entries registered under the given domain (including itself).
func (t *DomainTree) Subtree(domain string) ([]*vault.SecretItem, error) {
	norm, err := NormalizeDomain(domain)
	if err != nil {
		return nil, err
	}

	start := t.findPrefixNode(norm)
	if start == nil {
		return nil, nil
	}

	var results []*vault.SecretItem
	collectItems(start, &results)
	return results, nil
}

func (t *DomainTree) resolveInheritedItem(item *vault.SecretItem, visited map[string]bool) (*vault.SecretItem, error) {
	if item == nil || item.Login == nil {
		return nil, ErrDomainNotFound
	}
	if !item.Login.InheritFromParent {
		return item, nil
	}

	curDomain := item.Login.Domain
	if visited[curDomain] {
		return nil, ErrInheritanceCycle
	}
	visited[curDomain] = true

	if item.Login.ParentDomain != "" {
		parentNode := t.findExactNode(item.Login.ParentDomain)
		if parentNode != nil && parentNode.item != nil {
			return t.resolveInheritedItem(parentNode.item, visited)
		}
	}

	ancestor, found, err := t.FindNearestAncestor(curDomain)
	if err != nil {
		return nil, err
	}
	if !found || ancestor == nil {
		return nil, ErrDomainNotFound
	}

	return t.resolveInheritedItem(ancestor, visited)
}

func (t *DomainTree) findExactNode(normDomain string) *node {
	n := t.findPrefixNode(normDomain)
	if n == nil || n.item == nil {
		return nil
	}
	return n
}

func (t *DomainTree) findPrefixNode(normDomain string) *node {
	labels := reverseLabels(normDomain)
	cur := t.root
	for _, label := range labels {
		next, ok := cur.children[label]
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func collectItems(n *node, out *[]*vault.SecretItem) {
	if n == nil {
		return
	}
	if n.item != nil {
		*out = append(*out, n.item)
	}
	for _, child := range n.children {
		collectItems(child, out)
	}
}

func reverseLabels(domain string) []string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}
