package main

import (
	"fmt"
	"sort"
	"strings"
)

// Scope groups are a *presentation* tree, nothing more: a scope's `group:` is a
// slash-separated path ("infra/prod") that says where it sits in the menus. Scope
// names stay one flat, globally unique namespace — they are filenames under
// sessions_dir and the argument to `mintk key` — so grouping never changes what a
// cert is or how it is minted.
//
// That is also what keeps the format backward compatible: `scopes:` is still the
// same flat list of the same records, plus one optional field. yaml.v3 ignores
// unknown fields by default, so a mintk built before groups existed reads such a
// file unchanged and simply doesn't see the tree. (It will, however, drop the
// `group:`/`groups:` keys if *it* writes the file back — an old binary editing
// scopes flattens the tree.)
const groupSep = "/"

// cleanGroupPath tidies a group path without judging it: segments trimmed, empty
// segments dropped. Used on everything read from disk, where a hand-edited file
// must never become a hard error.
func cleanGroupPath(p string) string {
	var segs []string
	for _, seg := range strings.Split(p, groupSep) {
		if seg = strings.TrimSpace(seg); seg != "" {
			segs = append(segs, seg)
		}
	}
	return strings.Join(segs, groupSep)
}

// normalizeGroup is cleanGroupPath plus validation, for paths coming from the
// user. Each segment gets the same character set as a scope name. "" is the root.
func normalizeGroup(p string) (string, error) {
	clean := cleanGroupPath(p)
	if clean == "" {
		return "", nil
	}
	for _, seg := range strings.Split(clean, groupSep) {
		if !scopeNameRe.MatchString(seg) {
			return "", fmt.Errorf("invalid group segment %q (letters, digits, '.', '_', '-'; must not start with a separator)", seg)
		}
	}
	return clean, nil
}

// joinGroup appends a child segment to a parent path.
func joinGroup(parent, child string) string {
	if parent == "" {
		return child
	}
	if child == "" {
		return parent
	}
	return parent + groupSep + child
}

// parentGroup returns the path one level up ("" for a top-level group).
func parentGroup(p string) string {
	if i := strings.LastIndex(p, groupSep); i >= 0 {
		return p[:i]
	}
	return ""
}

// groupDisplay renders a group path for a menu title: the root reads as "/".
func groupDisplay(p string) string {
	if p == "" {
		return groupSep
	}
	return groupSep + p
}

// allGroups returns every group path that exists: declared in `groups:`, pointed
// at by a scope, or implied as an ancestor of either. Sorted, deduplicated.
func (c *Config) allGroups() []string {
	set := map[string]bool{}
	add := func(p string) {
		for p = cleanGroupPath(p); p != ""; p = parentGroup(p) {
			set[p] = true
		}
	}
	for _, g := range c.Groups {
		add(g)
	}
	for _, s := range c.Scopes {
		add(s.Group)
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// childGroups returns the immediate child *segments* of a group ("" = root).
func (c *Config) childGroups(parent string) []string {
	prefix := ""
	if parent != "" {
		prefix = parent + groupSep
	}
	set := map[string]bool{}
	for _, g := range c.allGroups() {
		if !strings.HasPrefix(g, prefix) {
			continue
		}
		rest := g[len(prefix):]
		if rest == "" {
			continue
		}
		if i := strings.Index(rest, groupSep); i >= 0 {
			rest = rest[:i]
		}
		set[rest] = true
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// scopeIndexes lists the scopes sitting *directly* in a group, by index into
// cfg.Scopes, name-sorted.
func (c *Config) scopeIndexes(group string) []int {
	group = cleanGroupPath(group)
	var out []int
	for i := range c.Scopes {
		if cleanGroupPath(c.Scopes[i].Group) == group {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, b int) bool { return c.Scopes[out[a]].Name < c.Scopes[out[b]].Name })
	return out
}

// groupScopeCount counts the scopes in a group *and* all of its descendants —
// what a collapsed row should advertise.
func (c *Config) groupScopeCount(group string) int {
	group = cleanGroupPath(group)
	prefix := group + groupSep
	n := 0
	for _, s := range c.Scopes {
		g := cleanGroupPath(s.Group)
		if g == group || strings.HasPrefix(g, prefix) {
			n++
		}
	}
	return n
}

// groupExists reports whether a path is a known group.
func (c *Config) groupExists(path string) bool {
	path = cleanGroupPath(path)
	if path == "" {
		return true // the root always exists
	}
	for _, g := range c.allGroups() {
		if g == path {
			return true
		}
	}
	return false
}

// addGroup declares a group so it survives being empty. Returns false when it
// already exists.
func (c *Config) addGroup(path string) bool {
	path = cleanGroupPath(path)
	if path == "" || c.groupExists(path) {
		return false
	}
	c.Groups = append(c.Groups, path)
	sort.Strings(c.Groups)
	return true
}

// removeGroup drops a group declaration. Scopes are never touched: callers only
// offer this for a group that holds none.
func (c *Config) removeGroup(path string) bool {
	path = cleanGroupPath(path)
	for i, g := range c.Groups {
		if cleanGroupPath(g) == path {
			c.Groups = append(c.Groups[:i], c.Groups[i+1:]...)
			return true
		}
	}
	return false
}

// renameGroup moves a group and everything under it to a new path, rewriting the
// scopes that pointed into it.
func (c *Config) renameGroup(from, to string) {
	from, to = cleanGroupPath(from), cleanGroupPath(to)
	if from == "" || from == to {
		return
	}
	move := func(p string) string {
		p = cleanGroupPath(p)
		switch {
		case p == from:
			return to
		case strings.HasPrefix(p, from+groupSep):
			return joinGroup(to, p[len(from)+1:])
		}
		return p
	}
	for i := range c.Scopes {
		c.Scopes[i].Group = move(c.Scopes[i].Group)
	}
	for i := range c.Groups {
		c.Groups[i] = move(c.Groups[i])
	}
	// The move can collapse two declarations into one; re-declare from scratch.
	seen := map[string]bool{}
	var kept []string
	for _, g := range c.Groups {
		if g = cleanGroupPath(g); g != "" && !seen[g] {
			seen[g] = true
			kept = append(kept, g)
		}
	}
	sort.Strings(kept)
	c.Groups = kept
	c.addGroup(to)
}

// declaredGroups is what has to be written to `groups:`: the groups no scope
// points into, which are the only ones that wouldn't survive a round-trip. The
// rest are re-derived on load, so writing them would just be noise.
func (c *Config) declaredGroups() []string {
	all := c.allGroups()
	var out []string
	for _, g := range all {
		if c.groupScopeCount(g) > 0 {
			continue
		}
		// An ancestor of another declared group is already implied by it.
		implied := false
		for _, other := range all {
			if other != g && strings.HasPrefix(other, g+groupSep) {
				implied = true
				break
			}
		}
		if !implied {
			out = append(out, g)
		}
	}
	return out
}

// normalizeGroups tidies the group paths read from disk so the rest of the code
// can compare them as plain strings.
func (c *Config) normalizeGroups() {
	for i := range c.Scopes {
		c.Scopes[i].Group = cleanGroupPath(c.Scopes[i].Group)
	}
	seen := map[string]bool{}
	var kept []string
	for _, g := range c.Groups {
		if g = cleanGroupPath(g); g != "" && !seen[g] {
			seen[g] = true
			kept = append(kept, g)
		}
	}
	sort.Strings(kept)
	c.Groups = kept
}

// --- menus -------------------------------------------------------------------

// formatGroupLine renders a group as a menu row.
func formatGroupLine(cfg *Config, path string) string {
	return fmt.Sprintf("[>] %-14s %d scope(s)", groupLeaf(path)+groupSep, cfg.groupScopeCount(path))
}

// groupLeaf is the last segment of a path.
func groupLeaf(p string) string {
	if i := strings.LastIndex(p, groupSep); i >= 0 {
		return p[i+1:]
	}
	return p
}

// treeLevel is one level of the group tree rendered as menu rows: the child
// groups first, then the scopes sitting directly here. Rows and the indices
// needed to interpret a choice are built together so they cannot drift apart.
type treeLevel struct {
	rows   []string
	groups []string // child group segments — rows[0:len(groups)]
	scopes []int    // indices into cfg.Scopes — the rows right after the groups
}

// backRow is the label for leaving a level: out of the menu at the root, one
// level up anywhere else.
func backRow(cur string) string {
	if cur == "" {
		return "[<] Back"
	}
	return "[<] Up to " + groupDisplay(parentGroup(cur))
}

// buildTreeLevel renders the group `cur`. `row` formats a scope.
func buildTreeLevel(cfg *Config, cur string, row func(Scope) string) treeLevel {
	lv := treeLevel{groups: cfg.childGroups(cur), scopes: cfg.scopeIndexes(cur)}
	for _, g := range lv.groups {
		lv.rows = append(lv.rows, formatGroupLine(cfg, joinGroup(cur, g)))
	}
	for _, i := range lv.scopes {
		lv.rows = append(lv.rows, row(cfg.Scopes[i]))
	}
	return lv
}

// pickScopeInTree walks the group tree and returns the chosen scope's index into
// cfg.Scopes. `row` renders a scope; ok is false when the user backed out of the
// top level or cancelled. With no groups configured this is a plain flat list —
// the pre-groups behaviour, unchanged.
func pickScopeInTree(cfg *Config, title string, row func(Scope) string) (int, bool) {
	cur := ""
	for {
		lv := buildTreeLevel(cfg, cur, row)
		back := len(lv.rows)
		opts := append(append([]string{}, lv.rows...), backRow(cur))

		idx, err := promptChoice(treeTitle(title, cur), opts)
		if err != nil {
			return 0, false
		}
		switch {
		case idx == back:
			if cur == "" {
				return 0, false
			}
			cur = parentGroup(cur)
		case idx < len(lv.groups):
			cur = joinGroup(cur, lv.groups[idx])
		default:
			return lv.scopes[idx-len(lv.groups)], true
		}
	}
}

// treeTitle appends the current location to a menu title once there is a tree to
// get lost in.
func treeTitle(title, group string) string {
	if group == "" {
		return title
	}
	return title + "  " + groupDisplay(group)
}

// promptGroup asks where a scope should live: an existing group, the root, or a
// new path typed in. Returns ok=false when cancelled.
func promptGroup(cfg *Config, label, current string) (string, bool) {
	groups := cfg.allGroups()
	opts := []string{"(root — no group)"}
	paths := []string{""}
	for _, g := range groups {
		opts = append(opts, groupDisplay(g))
		paths = append(paths, g)
	}
	create := len(opts)
	opts = append(opts, "[+] New group…")
	back := len(opts)
	opts = append(opts, "[<] Cancel")

	def := 0
	for i, p := range paths {
		if p == cleanGroupPath(current) {
			def = i
		}
	}
	idx, err := promptChoiceDefault(label, opts, def)
	if err != nil || idx == back {
		return "", false
	}
	if idx == create {
		return promptNewGroup(cfg, current)
	}
	return paths[idx], true
}

// promptNewGroup asks for a new group path, defaulting to a sibling of `near`.
func promptNewGroup(cfg *Config, near string) (string, bool) {
	hint := "name, or a path like infra" + groupSep + "prod"
	def := ""
	if near = cleanGroupPath(near); near != "" {
		def = near + groupSep
	}
	v, err := promptString("New group ("+hint+")", def)
	if err != nil {
		return "", false
	}
	path, err := normalizeGroup(v)
	if err != nil {
		fmt.Printf("%s: %s\n", prog, err)
		return "", false
	}
	if path == "" {
		return "", false
	}
	cfg.addGroup(path)
	return path, true
}
