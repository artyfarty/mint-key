package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureSSHConfigHost_NewFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")

	change, err := ensureSSHConfigHost(p, "web1", "10.0.0.5", "deploy", "~/.ssh/sessions/general")
	if err != nil {
		t.Fatal(err)
	}
	if change == "" {
		t.Fatal("expected a change description")
	}
	got := readFile(t, p)
	for _, want := range []string{
		"Host web1",
		"HostName 10.0.0.5",
		"User deploy",
		"IdentityFile ~/.ssh/sessions/general",
		"IdentitiesOnly yes",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config missing %q:\n%s", want, got)
		}
	}

	// Re-running is idempotent (no change).
	change, err = ensureSSHConfigHost(p, "web1", "10.0.0.5", "deploy", "~/.ssh/sessions/general")
	if err != nil {
		t.Fatal(err)
	}
	if change != "" {
		t.Errorf("expected no change on re-run, got %q\n%s", change, readFile(t, p))
	}
}

func TestEnsureSSHConfigHost_EditExisting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	initial := `Host other
    User root

Host web1 web1.internal
    HostName 10.0.0.5
    User admin
    IdentityFile ~/.ssh/id_ed25519
    ForwardAgent yes
`
	writeFile(t, p, initial)

	// Match by the second pattern on the Host line.
	change, err := ensureSSHConfigHost(p, "web1.internal", "10.0.0.5", "admin", "~/.ssh/sessions/nexus")
	if err != nil {
		t.Fatal(err)
	}
	if change == "" {
		t.Fatal("expected a change")
	}
	got := readFile(t, p)

	// Our directives are present with the new identity.
	if !strings.Contains(got, "IdentityFile ~/.ssh/sessions/nexus") {
		t.Errorf("new IdentityFile missing:\n%s", got)
	}
	if strings.Contains(got, "id_ed25519") {
		t.Errorf("old IdentityFile should have been replaced:\n%s", got)
	}
	if strings.Count(got, "IdentitiesOnly yes") != 1 {
		t.Errorf("expected exactly one IdentitiesOnly yes:\n%s", got)
	}
	// Untouched directives in the block survive.
	if !strings.Contains(got, "ForwardAgent yes") {
		t.Errorf("ForwardAgent should be preserved:\n%s", got)
	}
	if !strings.Contains(got, "User admin") {
		t.Errorf("User should be preserved:\n%s", got)
	}
	// The other block is untouched.
	if !strings.Contains(got, "Host other") || !strings.Contains(got, "User root") {
		t.Errorf("other block clobbered:\n%s", got)
	}
}

func TestFindHostBlock(t *testing.T) {
	lines := []string{
		"Host a",
		"    User x",
		"Host b c",
		"    User y",
		"Host d",
	}
	if s, e := findHostBlock(lines, "c"); s != 2 || e != 4 {
		t.Errorf("block for c: got (%d,%d), want (2,4)", s, e)
	}
	if s, _ := findHostBlock(lines, "missing"); s != -1 {
		t.Errorf("missing alias should return -1, got %d", s)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
