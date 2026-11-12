package main

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testGroupedConfig() *Config {
	c := &Config{
		Scopes: []Scope{
			{Name: "root-scope", Principal: "p0", TTL: "8h"},
			{Name: "prod-a", Principal: "p1", TTL: "1h", Group: "infra/prod"},
			{Name: "prod-b", Principal: "p2", TTL: "1h", Group: "infra/prod"},
			{Name: "lab", Principal: "p3", TTL: "8h", Group: "infra/lab"},
			{Name: "laptop", Principal: "p4", TTL: "24h", Group: "personal"},
		},
		Groups: []string{"empty/branch"},
	}
	c.normalizeGroups()
	return c
}

func TestNormalizeGroup(t *testing.T) {
	ok := map[string]string{
		"":                  "",
		"infra":             "infra",
		" infra / prod ":    "infra/prod",
		"/infra/prod/":      "infra/prod",
		"a//b":              "a/b",
		"a.b_c-d/e":         "a.b_c-d/e",
		"///":               "",
		"infra/prod/west-1": "infra/prod/west-1",
	}
	for in, want := range ok {
		got, err := normalizeGroup(in)
		if err != nil {
			t.Errorf("normalizeGroup(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("normalizeGroup(%q) = %q, want %q", in, got, want)
		}
	}
	// A segment gets the same character set as a scope name: no spaces, no
	// traversal, no leading separator inside a segment.
	for _, bad := range []string{"in fra", "a/../b", "-lead", ".hidden/x", "a/b c"} {
		if _, err := normalizeGroup(bad); err == nil {
			t.Errorf("normalizeGroup(%q) accepted, want rejected", bad)
		}
	}
}

func TestGroupTree(t *testing.T) {
	c := testGroupedConfig()

	wantAll := []string{"empty", "empty/branch", "infra", "infra/lab", "infra/prod", "personal"}
	if got := c.allGroups(); !reflect.DeepEqual(got, wantAll) {
		t.Errorf("allGroups() = %v, want %v", got, wantAll)
	}
	if got, want := c.childGroups(""), []string{"empty", "infra", "personal"}; !reflect.DeepEqual(got, want) {
		t.Errorf("childGroups(root) = %v, want %v", got, want)
	}
	if got, want := c.childGroups("infra"), []string{"lab", "prod"}; !reflect.DeepEqual(got, want) {
		t.Errorf("childGroups(infra) = %v, want %v", got, want)
	}
	if got := c.childGroups("infra/prod"); len(got) != 0 {
		t.Errorf("childGroups(infra/prod) = %v, want none", got)
	}

	// Scopes sit only in their own group, but a group's count includes its
	// descendants — that's what a collapsed menu row advertises.
	names := func(idxs []int) []string {
		var out []string
		for _, i := range idxs {
			out = append(out, c.Scopes[i].Name)
		}
		return out
	}
	if got, want := names(c.scopeIndexes("")), []string{"root-scope"}; !reflect.DeepEqual(got, want) {
		t.Errorf("scopeIndexes(root) = %v, want %v", got, want)
	}
	if got, want := names(c.scopeIndexes("infra/prod")), []string{"prod-a", "prod-b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("scopeIndexes(infra/prod) = %v, want %v", got, want)
	}
	if got := c.scopeIndexes("infra"); len(got) != 0 {
		t.Errorf("scopeIndexes(infra) = %v, want none (its scopes are in subgroups)", names(got))
	}
	if got, want := c.groupScopeCount("infra"), 3; got != want {
		t.Errorf("groupScopeCount(infra) = %d, want %d", got, want)
	}
	if got, want := c.groupScopeCount("empty"), 0; got != want {
		t.Errorf("groupScopeCount(empty) = %d, want %d", got, want)
	}
}

func TestDeclaredGroupsKeepsOnlyEmptyLeaves(t *testing.T) {
	c := testGroupedConfig()
	// Groups holding scopes are re-derived from the scopes on load; only a group
	// nothing points at has to be written down, and only its deepest path.
	if got, want := c.declaredGroups(), []string{"empty/branch"}; !reflect.DeepEqual(got, want) {
		t.Errorf("declaredGroups() = %v, want %v", got, want)
	}
	if !c.addGroup("infra/staging") {
		t.Fatal("addGroup(infra/staging) reported the group already exists")
	}
	if c.addGroup("infra/prod") {
		t.Error("addGroup(infra/prod) added a group that already exists")
	}
	if got, want := c.declaredGroups(), []string{"empty/branch", "infra/staging"}; !reflect.DeepEqual(got, want) {
		t.Errorf("declaredGroups() after add = %v, want %v", got, want)
	}
	if !c.removeGroup("infra/staging") || c.groupExists("infra/staging") {
		t.Error("removeGroup(infra/staging) did not drop the group")
	}
}

func TestRenameGroup(t *testing.T) {
	c := testGroupedConfig()
	c.renameGroup("infra", "corp/infra")

	want := map[string]string{
		"root-scope": "",
		"prod-a":     "corp/infra/prod",
		"prod-b":     "corp/infra/prod",
		"lab":        "corp/infra/lab",
		"laptop":     "personal",
	}
	for _, s := range c.Scopes {
		if want[s.Name] != s.Group {
			t.Errorf("after rename, scope %s group = %q, want %q", s.Name, s.Group, want[s.Name])
		}
	}
	if c.groupExists("infra") {
		t.Error("old group path still exists after rename")
	}
	if got, want := c.groupScopeCount("corp"), 3; got != want {
		t.Errorf("groupScopeCount(corp) = %d, want %d", got, want)
	}
}

// The rows and the indices that interpret a click are built together, so this
// pins the mapping: groups first, then the scopes of this level, then actions.
func TestBuildScopeManageMenu(t *testing.T) {
	c := testGroupedConfig()

	root := buildScopeManageMenu(c, "")
	if got, want := root.groups, []string{"empty", "infra", "personal"}; !reflect.DeepEqual(got, want) {
		t.Errorf("root groups = %v, want %v", got, want)
	}
	if len(root.scopes) != 1 || c.Scopes[root.scopes[0]].Name != "root-scope" {
		t.Errorf("root scopes = %v, want just root-scope", root.scopes)
	}
	if root.groupMenu != -1 {
		t.Error("the root offered a rename/delete action; it is not a group")
	}
	if root.back != len(root.rows)-1 || root.rows[root.back] != "[<] Back" {
		t.Errorf("root back row = %q at %d of %d", root.rows[root.back], root.back, len(root.rows))
	}
	// Row 0 is the first child group, row len(groups) the first scope here.
	if !strings.Contains(root.rows[0], "empty"+groupSep) {
		t.Errorf("first row = %q, want the `empty/` group", root.rows[0])
	}
	if !strings.Contains(root.rows[len(root.groups)], "root-scope") {
		t.Errorf("row after the groups = %q, want root-scope", root.rows[len(root.groups)])
	}

	sub := buildScopeManageMenu(c, "infra/prod")
	if len(sub.groups) != 0 || len(sub.scopes) != 2 {
		t.Errorf("infra/prod level = %d groups / %d scopes, want 0/2", len(sub.groups), len(sub.scopes))
	}
	if sub.groupMenu < 0 {
		t.Fatal("a group level offers no rename/delete action")
	}
	if !strings.Contains(sub.rows[sub.groupMenu], groupDisplay("infra/prod")) {
		t.Errorf("group action row = %q, want it to name the group", sub.rows[sub.groupMenu])
	}
	if want := "[<] Up to " + groupDisplay("infra"); sub.rows[sub.back] != want {
		t.Errorf("back row = %q, want %q", sub.rows[sub.back], want)
	}
	// Every action index has to land on a distinct row.
	seen := map[int]bool{}
	for _, i := range []int{sub.addScope, sub.addGroup, sub.groupMenu, sub.back} {
		if i < 0 || i >= len(sub.rows) || seen[i] {
			t.Fatalf("action indices collide or fall outside the rows: %+v", sub)
		}
		seen[i] = true
	}
}

// A scopes file written with groups must stay readable by a mintk that predates
// them: `scopes:` is the same flat list of the same records, and the extra keys
// are ones an older unmarshal target simply doesn't have.
func TestScopesFileStaysReadableByPreGroupMintk(t *testing.T) {
	c := testGroupedConfig()
	data, err := yaml.Marshal(scopesDoc{Scopes: c.Scopes, Groups: c.declaredGroups()})
	if err != nil {
		t.Fatal(err)
	}

	// The pre-groups shape of scopesDoc/Scope, verbatim.
	type legacyScope struct {
		Name      string `yaml:"name"`
		Principal string `yaml:"principal"`
		TTL       string `yaml:"ttl"`
	}
	var legacy struct {
		Scopes []legacyScope `yaml:"scopes"`
	}
	if err := yaml.Unmarshal(data, &legacy); err != nil {
		t.Fatalf("a pre-groups mintk cannot parse the file: %v", err)
	}
	if len(legacy.Scopes) != len(c.Scopes) {
		t.Fatalf("legacy read got %d scopes, want %d", len(legacy.Scopes), len(c.Scopes))
	}
	for i, s := range legacy.Scopes {
		if s.Name != c.Scopes[i].Name || s.Principal != c.Scopes[i].Principal || s.TTL != c.Scopes[i].TTL {
			t.Errorf("legacy read scope %d = %+v, want %+v", i, s, c.Scopes[i])
		}
	}
}

// The reverse direction: a file written by a pre-groups mintk (no `group:`, no
// `groups:`) loads as a flat, all-at-the-root tree.
func TestPreGroupScopesFileLoadsFlat(t *testing.T) {
	const old = `scopes:
  - name: a
    principal: pa
    ttl: 8h
  - name: b
    principal: pb
    ttl: 1h
`
	var sf scopesDoc
	if err := yaml.Unmarshal([]byte(old), &sf); err != nil {
		t.Fatal(err)
	}
	c := &Config{Scopes: sf.Scopes, Groups: sf.Groups}
	c.normalizeGroups()
	if got := c.allGroups(); len(got) != 0 {
		t.Errorf("allGroups() = %v, want none", got)
	}
	if got := c.scopeIndexes(""); len(got) != 2 {
		t.Errorf("scopeIndexes(root) = %v, want both scopes", got)
	}
}

func TestScopeOpsKeepHandEditedGroups(t *testing.T) {
	cfg := &Config{Scopes: []Scope{{Name: "a", Principal: "p", TTL: "1h", Group: "odd group"}}}
	if err := cfg.addScopeChecked("b", "p", "1h", "odd group"); err != nil {
		t.Fatalf("existing hand-edited group refused: %v", err)
	}
	if err := cfg.addScopeChecked("c", "p", "1h", "new group"); err == nil {
		t.Fatal("invalid new group accepted")
	}
	if err := cfg.moveScope("a", "infra/prod"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.deleteGroupChecked("infra"); err == nil {
		t.Fatal("non-empty group deleted")
	}
	if _, err := cfg.renameGroupChecked("infra", "infra/prod/x"); err == nil {
		t.Fatal("moved a group into itself")
	}
}
