package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestParseTTL(t *testing.T) {
	ok := []struct {
		in   string
		want time.Duration
	}{
		{"8h", 8 * time.Hour},
		{"90m", 90 * time.Minute},
		{"1h30m", 90 * time.Minute},
		{"1d", 24 * time.Hour},
		{"2w", 14 * 24 * time.Hour},
		{"45s", 45 * time.Second},
		{"12", 12 * time.Hour}, // a bare integer means hours, as in `mintk key`
		{"1D", 24 * time.Hour},
	}
	for _, c := range ok {
		got, err := parseTTL(c.in)
		if err != nil {
			t.Errorf("parseTTL(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseTTL(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"", "h", "8x", "0h", "-1h", "8h ago", "1.5h"} {
		if d, err := parseTTL(bad); err == nil {
			t.Errorf("parseTTL(%q) = %v, want an error", bad, d)
		}
	}
}

func TestValidScopeName(t *testing.T) {
	for _, good := range []string{"svc", "my-scope", "a.b_c", "s3"} {
		if err := validScopeName(good); err != nil {
			t.Errorf("validScopeName(%q): %v", good, err)
		}
	}
	// Anything that could escape the blob dir or the runtime dir must be refused.
	for _, bad := range []string{"", "..", "../etc/passwd", "a/b", "-x", ".hidden", "a b", "a\\b"} {
		if err := validScopeName(bad); err == nil {
			t.Errorf("validScopeName(%q) accepted, want rejected", bad)
		}
	}
}

func TestParseDotenv(t *testing.T) {
	in := `# a comment

TOKEN=abc123
export API_KEY="quoted value"
EMPTY=
SPACED = trimmed
QUOTED='single'
URL=https://example.invalid/path?a=b
`
	got, err := parseDotenv(in)
	if err != nil {
		t.Fatalf("parseDotenv: %v", err)
	}
	want := []string{
		"TOKEN=abc123",
		"API_KEY=quoted value",
		"EMPTY=",
		"SPACED=trimmed",
		"QUOTED=single",
		"URL=https://example.invalid/path?a=b", // only the first '=' splits
	}
	if len(got) != len(want) {
		t.Fatalf("parseDotenv returned %d pairs (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("pair %d = %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := parseDotenv("not an assignment\n"); err == nil {
		t.Error("parseDotenv accepted a line without '=', want an error")
	}
}

func TestEnvSafe(t *testing.T) {
	cases := map[string]string{
		"svc":       "SVC",
		"my-scope":  "MY_SCOPE",
		"a.b":       "A_B",
		"registry1": "REGISTRY1",
	}
	for in, want := range cases {
		if got := envSafe(in); got != want {
			t.Errorf("envSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseRecipients(t *testing.T) {
	got := parseRecipients("# who can read these\nage1exampleaaa\r\n\n  age1examplebbb  trailing note\n")
	want := []string{"age1exampleaaa", "age1examplebbb"}
	if len(got) != len(want) {
		t.Fatalf("parseRecipients = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("recipient %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// mountinfo lines in the shape /proc/self/mountinfo produces, including the
// optional per-mount tags before the " - " separator and an escaped mount point.
const testMountinfo = `23 28 0:22 / /proc rw,nosuid,relatime shared:12 - proc proc rw
25 28 0:6 / / rw,relatime - ext4 /dev/sdc rw,discard
29 25 0:26 / /run rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,mode=755
31 29 0:31 / /run/user/1000 rw,nosuid,nodev,relatime shared:9 - tmpfs tmpfs rw,size=1M,uid=1000
33 25 0:34 / /mnt/my\040disk rw,relatime - vfat /dev/sdd rw
`

func TestFSTypeFromMountinfo(t *testing.T) {
	cases := map[string]string{
		"/run/user/1000/mint-key/secrets/x": "tmpfs", // longest match wins over /run and /
		"/run/user/1000":                    "tmpfs",
		"/run":                              "tmpfs",
		"/home/user/secrets":                "ext4",
		"/":                                 "ext4",
		"/mnt/my disk/file":                 "vfat", // \040 decoded
		"/proc/self":                        "proc",
	}
	for path, want := range cases {
		if got := fsTypeFromMountinfo(testMountinfo, path); got != want {
			t.Errorf("fsTypeFromMountinfo(%q) = %q, want %q", path, got, want)
		}
	}
	// A path under no known mount at all yields "".
	if got := fsTypeFromMountinfo("29 25 0:26 / /run rw - tmpfs tmpfs rw\n", "/home/x"); got != "" {
		t.Errorf("unmatched path = %q, want \"\"", got)
	}
}

func TestIsEphemeralFS(t *testing.T) {
	for _, fs := range []string{"tmpfs", "ramfs"} {
		if !isEphemeralFS(fs) {
			t.Errorf("isEphemeralFS(%q) = false, want true", fs)
		}
	}
	// A grant on any of these would survive a reboot on disk — never allowed
	// without an explicit allow_non_tmpfs opt-out.
	for _, fs := range []string{"ext4", "btrfs", "9p", "overlay", "vfat", ""} {
		if isEphemeralFS(fs) {
			t.Errorf("isEphemeralFS(%q) = true, want false", fs)
		}
	}
}

func TestSplitTrailingTTL(t *testing.T) {
	// `grant <scope> <ttl>`, mirroring `mintk key <scope> [<ttl>]`.
	scopes, ttl := splitTrailingTTL([]string{"svc", "2h"}, "")
	if len(scopes) != 1 || scopes[0] != "svc" || ttl != "2h" {
		t.Errorf("got scopes=%v ttl=%q, want [svc] 2h", scopes, ttl)
	}
	// A single argument is always a scope, even if it looks like a duration.
	scopes, ttl = splitTrailingTTL([]string{"2h"}, "")
	if len(scopes) != 1 || scopes[0] != "2h" || ttl != "" {
		t.Errorf("got scopes=%v ttl=%q, want [2h] \"\"", scopes, ttl)
	}
	// An explicit --ttl wins; nothing is stolen from the scope list.
	scopes, ttl = splitTrailingTTL([]string{"a", "b"}, "30m")
	if len(scopes) != 2 || ttl != "30m" {
		t.Errorf("got scopes=%v ttl=%q, want [a b] 30m", scopes, ttl)
	}
	// Multiple scopes, none of which parse as a duration.
	scopes, ttl = splitTrailingTTL([]string{"a", "b"}, "")
	if len(scopes) != 2 || ttl != "" {
		t.Errorf("got scopes=%v ttl=%q, want [a b] \"\"", scopes, ttl)
	}
}

func TestBlobPathRejectsTraversal(t *testing.T) {
	s := &SecretsConfig{Repo: "/tmp/repo", Dir: "secrets", Scopes: []SecretScope{
		{Name: "sneaky", File: "../../etc/passwd"},
	}}
	if _, err := s.blobPath("sneaky"); err == nil {
		t.Error("blobPath accepted a file outside the blob dir, want an error")
	}
	if _, err := s.blobPath("../x"); err == nil {
		t.Error("blobPath accepted a traversing scope name, want an error")
	}
	p, err := s.blobPath("plain")
	if err != nil {
		t.Fatalf("blobPath(plain): %v", err)
	}
	if !strings.HasSuffix(p, "/secrets/plain.age") {
		t.Errorf("blobPath(plain) = %q, want it under the blob dir", p)
	}
}

func TestSecretsDefaults(t *testing.T) {
	var nilCfg *SecretsConfig
	nilCfg.applyDefaults() // must not panic: cert-only configs have no secrets block

	s := &SecretsConfig{}
	s.applyDefaults()
	if s.Dir != "secrets" || s.DefaultTTL == "" || s.Mode == "" {
		t.Errorf("applyDefaults left %+v underfilled", s)
	}
	if s.scopeTTL("anything") != s.DefaultTTL {
		t.Errorf("scopeTTL fell through to %q, want the default %q", s.scopeTTL("anything"), s.DefaultTTL)
	}
	if s.scopeFormat("anything") != "opaque" {
		t.Errorf("scopeFormat default = %q, want opaque (never parse a blob we weren't told to)", s.scopeFormat("anything"))
	}
	s.Scopes = []SecretScope{{Name: "svc", TTL: "15m", Format: "env"}}
	if s.scopeTTL("svc") != "15m" || s.scopeFormat("svc") != "env" {
		t.Error("per-scope policy did not override the defaults")
	}
}

func TestShortDuration(t *testing.T) {
	cases := map[time.Duration]string{
		2*time.Hour + 14*time.Minute: "2h14m",
		90 * time.Second:             "1m30s",
		45 * time.Second:             "45s",
		-5 * time.Second:             "0s",
	}
	for d, want := range cases {
		if got := shortDuration(d); got != want {
			t.Errorf("shortDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestUnitSafe(t *testing.T) {
	if got := unitSafe("my.scope-1"); got != "my_scope-1" {
		t.Errorf("unitSafe = %q, want my_scope-1", got)
	}
}

func TestEditWorkspacePID(t *testing.T) {
	if got := editWorkspacePID("svc.1234"); got != 1234 {
		t.Errorf("editWorkspacePID = %d, want 1234", got)
	}
	if got := editWorkspacePID("my.scope.99"); got != 99 {
		t.Errorf("editWorkspacePID = %d, want 99", got)
	}
	for _, bad := range []string{"svc", "svc.notapid", ""} {
		if got := editWorkspacePID(bad); got != 0 {
			t.Errorf("editWorkspacePID(%q) = %d, want 0", bad, got)
		}
	}
}

func TestAgeClientEnvPluginDir(t *testing.T) {
	t.Setenv("PATH", "/usr/local/bin:/mnt/c/Windows/system32:/home/u/.local/bin")
	t.Setenv("WSLENV", "")

	// Native: the plugin dir is prepended, everything else survives.
	a := &ageClient{mode: secretModeNative, pluginDir: "/opt/age"}
	got := envValue(a.env(), "PATH")
	if got != "/opt/age:/usr/local/bin:/mnt/c/Windows/system32:/home/u/.local/bin" {
		t.Errorf("native PATH = %q", got)
	}
	if v := envValue(a.env(), "WSLENV"); v != "" {
		t.Errorf("native mode set WSLENV=%q, want it untouched", v)
	}

	// wsl-windows: WSLENV=PATH/l is what actually gets our PATH across to the
	// Windows child, and it translates every entry — so Linux entries have to go
	// or they arrive as \\wsl.localhost\... UNC paths (where a Linux
	// age-plugin-yubikey would be found and fail to execute).
	w := &ageClient{mode: secretModeWSL, pluginDir: "/mnt/c/tools/age-plugin"}
	env := w.env()
	if got := envValue(env, "PATH"); got != "/mnt/c/tools/age-plugin:/mnt/c/Windows/system32" {
		t.Errorf("wsl PATH = %q, want the plugin dir plus only /mnt entries", got)
	}
	if got := envValue(env, "WSLENV"); got != "PATH/l" {
		t.Errorf("wsl WSLENV = %q, want PATH/l", got)
	}
	// Exactly one PATH assignment, or the child picks up whichever it likes.
	n := 0
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("env has %d PATH entries, want 1", n)
	}
}

func TestWSLENVWithPath(t *testing.T) {
	cases := map[string]string{
		"":             "PATH/l",
		"FOO/p":        "FOO/p:PATH/l",
		"PATH/l":       "PATH/l",         // already there
		"FOO/p:PATH/l": "FOO/p:PATH/l",   // already there, don't duplicate
		"PATHEXT":      "PATHEXT:PATH/l", // PATHEXT is not PATH
	}
	for in, want := range cases {
		if got := wslenvWithPath(in); got != want {
			t.Errorf("wslenvWithPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// envValue returns the value of key in a KEY=VALUE environment slice.
func envValue(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

// TestWindowsPluginLookupThroughInterop is the live check of the mechanism the
// wsl-windows mode rests on: does a Windows child launched with our environment
// actually resolve the plugin off PATH? Point MINTK_TEST_WIN_PLUGIN_DIR at a
// Windows-side directory (as a /mnt/... path) holding age-plugin-yubikey.exe.
func TestWindowsPluginLookupThroughInterop(t *testing.T) {
	dir := os.Getenv("MINTK_TEST_WIN_PLUGIN_DIR")
	if dir == "" || !inWSL() {
		t.Skip("set MINTK_TEST_WIN_PLUGIN_DIR (a /mnt/... dir with age-plugin-yubikey.exe) under WSL to run this")
	}
	a := &ageClient{mode: secretModeWSL, pluginDir: dir}
	cmd := exec.Command("cmd.exe", "/c", "where age-plugin-yubikey")
	cmd.Env = a.env()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the Windows child could not resolve the plugin off PATH: %v", err)
	}
	first := firstLine(stripCR(string(out)))
	if !strings.HasSuffix(strings.ToLower(first), "age-plugin-yubikey.exe") {
		t.Errorf("resolved %q, want the Windows plugin .exe first on PATH", first)
	}
}

func TestParseYubikeyList(t *testing.T) {
	// The real shape of `age-plugin-yubikey --list`: each identity is a block of
	// "# Key: Value" comment lines followed by the recipient on its own line.
	// Serial and Slot share a line; policy values carry a parenthesised gloss.
	out := "#       Serial: 12345678, Slot: 1\n" +
		"#         Name: example-one\n" +
		"#      Created: Sat, 13 Jun 2026 19:04:31 +0000\n" +
		"#   PIN policy: Once   (A PIN is required once per session, if set)\n" +
		"# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)\n" +
		"age1yubikey1qexampleaaa\n" +
		"\n" +
		"#       Serial: 12345678, Slot: 5\n" +
		"#         Name: example-two\n" +
		"# Touch policy: Always (A physical touch is required for every decryption)\n" +
		"age1yubikey1qexamplebbb\n"
	ids := parseYubikeyList(out)
	if len(ids) != 2 {
		t.Fatalf("parsed %d identities (%+v), want 2", len(ids), ids)
	}
	if ids[0].Recipient != "age1yubikey1qexampleaaa" || ids[0].Slot != "1" ||
		ids[0].Serial != "12345678" || ids[0].Name != "example-one" {
		t.Errorf("first identity = %+v", ids[0])
	}
	// The gloss in parentheses must not end up in the value.
	if ids[0].PinPolicy != "Once" || ids[0].TouchPolicy != "Cached" {
		t.Errorf("policies = pin %q touch %q, want Once/Cached", ids[0].PinPolicy, ids[0].TouchPolicy)
	}
	// Metadata must not leak from one block into the next.
	if ids[1].Slot != "5" || ids[1].Name != "example-two" || ids[1].PinPolicy != "" {
		t.Errorf("second identity = %+v", ids[1])
	}
	if ids[1].TouchPolicy != "Always" {
		t.Errorf("second touch policy = %q, want Always", ids[1].TouchPolicy)
	}
	if got := parseYubikeyList("no identities here\n"); len(got) != 0 {
		t.Errorf("parsed %v from output with no recipients, want none", got)
	}
}

func TestParseYubikeyListNameWithComma(t *testing.T) {
	// A Name containing a comma must survive: only the Serial/Slot line is split.
	ids := parseYubikeyList("#         Name: work, backup\nage1yubikey1qexampleccc\n")
	if len(ids) != 1 || ids[0].Name != "work, backup" {
		t.Fatalf("parsed %+v, want a single identity named \"work, backup\"", ids)
	}
}

func TestHasIdentityStub(t *testing.T) {
	good := "#    Serial: 12345678, Slot: 1\n#   Recipient: age1yubikey1qwexample\nAGE-PLUGIN-YUBIKEY-1QQEXAMPLE\n"
	if !hasIdentityStub(good) {
		t.Error("hasIdentityStub = false for output containing a stub")
	}
	if hasIdentityStub("#    Serial: 12345678\n# no identity in this slot\n") {
		t.Error("hasIdentityStub = true for output with no stub")
	}
}

func TestAbbrev(t *testing.T) {
	if got := abbrev("age1short"); got != "age1short" {
		t.Errorf("abbrev shortened a short string: %q", got)
	}
	long := "age1yubikey1qwaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb"
	got := abbrev(long)
	if len([]rune(got)) != 25 || !strings.HasPrefix(got, "age1yubikey1qwaa") || !strings.HasSuffix(got, "bbbbbbbb") {
		t.Errorf("abbrev(long) = %q", got)
	}
}
