package main

import (
	"fmt"
	"strings"
)

// The scope-list edits shared by `mintk i` and `mintk web`. Each one validates,
// mutates the in-memory config and leaves saving to the caller — so both front
// ends enforce exactly the same rules and only differ in how they ask.
//
// Deliberately absent: changing a scope's principal and deleting a scope. Those
// stay in `mintk scopes edit`/`delete`, where they're harder to hit by accident.

// addScopeChecked appends a new scope after validating every field.
func (c *Config) addScopeChecked(name, principal, ttl, group string) error {
	name = strings.TrimSpace(name)
	principal = strings.TrimSpace(principal)
	ttl = strings.TrimSpace(ttl)
	// The name becomes a filename under sessions_dir, so it gets the same
	// constraints as a secret scope.
	if err := validScopeName(name); err != nil {
		return err
	}
	if _, exists := c.scope(name); exists {
		return fmt.Errorf("scope %q already exists", name)
	}
	if principal == "" {
		return fmt.Errorf("principal must not be empty")
	}
	if _, err := normalizeTTL(ttl); err != nil {
		return err
	}
	g, err := c.groupTarget(group)
	if err != nil {
		return err
	}
	c.Scopes = append(c.Scopes, Scope{Name: name, Principal: principal, TTL: ttl, Group: g})
	sortScopes(c)
	return nil
}

// setScopeTTL changes a scope's default mint time.
func (c *Config) setScopeTTL(name, ttl string) error {
	s, ok := c.scope(name)
	if !ok {
		return fmt.Errorf("unknown scope %q", name)
	}
	ttl = strings.TrimSpace(ttl)
	if _, err := normalizeTTL(ttl); err != nil {
		return err
	}
	s.TTL = ttl
	return nil
}

// moveScope files a scope under another group ("" = the root). The group is
// created implicitly, as with `group:` in the file.
func (c *Config) moveScope(name, group string) error {
	s, ok := c.scope(name)
	if !ok {
		return fmt.Errorf("unknown scope %q", name)
	}
	g, err := c.groupTarget(group)
	if err != nil {
		return err
	}
	s.Group = g
	return nil
}

// addGroupChecked declares a (possibly nested) group and returns its clean path.
func (c *Config) addGroupChecked(path string) (string, error) {
	p, err := normalizeGroup(path)
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", fmt.Errorf("group name must not be empty")
	}
	if !c.addGroup(p) {
		return "", fmt.Errorf("group %s already exists", groupDisplay(p))
	}
	return p, nil
}

// renameGroupChecked moves a group (and everything under it) to a new path and
// returns the clean destination. A no-op rename returns from unchanged.
func (c *Config) renameGroupChecked(from, to string) (string, error) {
	from = cleanGroupPath(from)
	if from == "" || !c.groupExists(from) {
		return "", fmt.Errorf("unknown group %s", groupDisplay(from))
	}
	dst, err := normalizeGroup(to)
	if err != nil {
		return "", err
	}
	if dst == "" {
		return "", fmt.Errorf("new path must not be empty")
	}
	if dst == from {
		return from, nil
	}
	if strings.HasPrefix(dst, from+groupSep) {
		return "", fmt.Errorf("cannot move %s into itself", groupDisplay(from))
	}
	c.renameGroup(from, dst)
	return dst, nil
}

// deleteGroupChecked removes an empty group. A group that still holds scopes or
// subgroups is refused — scopes are never deleted as a side effect.
func (c *Config) deleteGroupChecked(path string) error {
	path = cleanGroupPath(path)
	if path == "" || !c.groupExists(path) {
		return fmt.Errorf("unknown group %s", groupDisplay(path))
	}
	if c.groupScopeCount(path) > 0 || len(c.childGroups(path)) > 0 {
		return fmt.Errorf("group %s still holds scopes or subgroups — move them out first", groupDisplay(path))
	}
	c.removeGroup(path)
	return nil
}

// groupTarget resolves where a scope should be filed. An existing group is taken
// as it is, even one hand-edited with characters a new one couldn't have; only a
// path that would create a new group is validated.
func (c *Config) groupTarget(group string) (string, error) {
	if clean := cleanGroupPath(group); c.groupExists(clean) {
		return clean, nil
	}
	return normalizeGroup(group)
}
