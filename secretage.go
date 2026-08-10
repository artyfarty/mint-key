package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Card-access modes for the age client. This mirrors the CA `mode:` split for
// the same reason: on Windows+WSL the YubiKey is only natively reachable from
// the Windows side, so the *client* moves to Windows and only its plaintext
// output crosses back into WSL.
//
// Note the ssh-agent bridge that carries CA signing cannot be reused here: the
// ssh-agent protocol only signs, it has no decrypt operation, so an age
// identity can't ride it. See docs/secrets.md.
const (
	secretModeNative = "native"      // age + plugin run here, card via PC/SC (pcscd)
	secretModeWSL    = "wsl-windows" // WSL runs the Windows age.exe through interop
	secretModeSoft   = "software"    // plain X25519 identity file — testing only
)

// scopeNameRe constrains scope names to something safe to use as a filename and
// as a systemd unit-name fragment (no traversal, no separators).
var scopeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func validScopeName(name string) error {
	if !scopeNameRe.MatchString(name) {
		return fmt.Errorf("invalid scope name %q (letters, digits, '.', '_', '-'; must not start with a separator)", name)
	}
	return nil
}

// --- the blob repo -----------------------------------------------------------

// blobPath is the age blob backing a scope.
func (s *SecretsConfig) blobPath(name string) (string, error) {
	if err := validScopeName(name); err != nil {
		return "", err
	}
	file := name + ".age"
	if sc, ok := s.scope(name); ok && sc.File != "" {
		file = sc.File
		if filepath.Base(file) != file {
			return "", fmt.Errorf("scope %q: file %q must be a plain filename inside %s", name, file, s.Dir)
		}
	}
	return filepath.Join(s.blobDir(), file), nil
}

// listSecretScopes returns every known scope name: the blobs present in the repo
// plus any declared in the config. The repo is the source of truth for what
// exists (it travels between machines); config entries only add policy.
func (s *SecretsConfig) listSecretScopes() []string {
	seen := map[string]bool{}
	entries, _ := os.ReadDir(s.blobDir())
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".age") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".age")
		if validScopeName(name) == nil {
			seen[name] = true
		}
	}
	for _, sc := range s.Scopes {
		seen[sc.Name] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// scopeTTL is the default grant lifetime for a scope.
func (s *SecretsConfig) scopeTTL(name string) string {
	if sc, ok := s.scope(name); ok && sc.TTL != "" {
		return sc.TTL
	}
	return s.DefaultTTL
}

// scopeFormat says how `secret run` exposes a scope: "env" parses the plaintext
// as KEY=VALUE lines and injects them, "opaque" only passes the file path.
func (s *SecretsConfig) scopeFormat(name string) string {
	if sc, ok := s.scope(name); ok && sc.Format != "" {
		return sc.Format
	}
	return "opaque"
}

// recipientList resolves the recipients new/edited blobs are encrypted to:
// the inline list plus, if configured, one recipient per line of RecipientsFile
// ('#' comments and blank lines ignored).
func (s *SecretsConfig) recipientList() ([]string, error) {
	var out []string
	out = append(out, s.Recipients...)
	if s.RecipientsFile != "" {
		p := s.RecipientsFile
		if !filepath.IsAbs(expandPath(p)) {
			p = filepath.Join(s.repoPath(), p)
		} else {
			p = expandPath(p)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("recipients_file %s: %w", p, err)
		}
		out = append(out, parseRecipients(string(data))...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no recipients configured (set secrets.recipients or secrets.recipients_file)")
	}
	return out, nil
}

// parseRecipients extracts one recipient per line, dropping comments and blanks.
func parseRecipients(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line)[0])
	}
	return out
}

// --- the age client ----------------------------------------------------------

// ageClient runs the age CLI in whichever place can reach the card.
type ageClient struct {
	mode      string
	bin       string // age binary; under wsl-windows an .exe reached through interop
	identity  string // identity path, in the form the client understands
	pluginDir string // dir holding age-plugin-yubikey(.exe); prepended to the child's PATH
}

// newAgeClient resolves the configured mode into a runnable client.
func newAgeClient(s *SecretsConfig) (*ageClient, error) {
	a := &ageClient{mode: s.Mode, bin: s.Age, pluginDir: expandPath(s.PluginDir)}

	switch s.Mode {
	case secretModeNative, secretModeSoft:
		if a.bin == "" {
			a.bin = "age"
		}
		if _, err := exec.LookPath(a.bin); err != nil {
			return nil, fmt.Errorf("age binary %q not found — install age (see docs/secrets.md)", a.bin)
		}
	case secretModeWSL:
		if !inWSL() {
			return nil, fmt.Errorf("secrets.mode=%s only applies under WSL", secretModeWSL)
		}
		if a.bin == "" {
			return nil, fmt.Errorf("set secrets.age to the Windows age.exe (reached through WSL interop)")
		}
		a.bin = expandPath(a.bin)
		if !fileExists(a.bin) {
			return nil, fmt.Errorf("secrets.age %q not found", a.bin)
		}
	default:
		return nil, fmt.Errorf("unknown secrets.mode %q (%s | %s | %s)",
			s.Mode, secretModeNative, secretModeWSL, secretModeSoft)
	}

	if s.Identity == "" {
		return nil, fmt.Errorf("set secrets.identity to your age identity file")
	}
	idPath := expandPath(s.Identity)
	if !fileExists(idPath) {
		return nil, fmt.Errorf("secrets.identity %q not found", idPath)
	}
	a.identity = idPath
	if s.Mode == secretModeWSL && strings.HasPrefix(idPath, "/") {
		// The Windows client can't open a Linux path; hand it the native form.
		a.identity = toWin(idPath)
	}
	return a, nil
}

// env is the child environment. The plugin's directory has to be a *real* PATH
// entry: age refuses a plugin it resolved through "." ("cannot run executable
// found relative to current directory").
//
// Under WSL that needs more than a prepend. WSL interop does *not* pass our PATH
// to a Windows child — it hands the child the Windows PATH and drops whatever we
// put in front. The lever that does work is WSLENV: listing PATH there with the
// `/l` flag makes interop translate our PATH as a path list, so a /mnt/c/... entry
// arrives as C:\... and age.exe can resolve the plugin from it. The catch is that
// `/l` translates *every* entry, turning Linux ones into \\wsl.localhost\... UNC
// paths — including the directory holding a Linux age-plugin-yubikey, which the
// Windows client would then find and fail to execute. So the Windows client gets
// the plugin dir plus only the Windows-backed (/mnt/...) entries.
func (a *ageClient) env() []string { return pluginEnv(a.mode, a.pluginDir) }

// pluginEnv builds that environment. Shared with `secret init`, which runs the
// plugin binary directly (read-only) before there is an ageClient to speak of.
func pluginEnv(mode, pluginDir string) []string {
	src := os.Environ()
	if pluginDir == "" {
		return src
	}
	path := pluginDir
	for _, e := range filepath.SplitList(os.Getenv("PATH")) {
		if e == "" || e == pluginDir {
			continue
		}
		if mode == secretModeWSL && !strings.HasPrefix(e, "/mnt/") {
			continue
		}
		path += string(os.PathListSeparator) + e
	}

	out := make([]string, 0, len(src)+2)
	for _, kv := range src {
		if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "WSLENV=") {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, "PATH="+path)
	if mode == secretModeWSL {
		out = append(out, "WSLENV="+wslenvWithPath(os.Getenv("WSLENV")))
	}
	return out
}

// wslenvWithPath adds `PATH/l` to a WSLENV value, leaving any existing entries
// (and any PATH entry the operator already set) alone.
func wslenvWithPath(cur string) string {
	for _, e := range strings.Split(cur, ":") {
		if name, _, _ := strings.Cut(e, "/"); name == "PATH" {
			return cur
		}
	}
	if cur == "" {
		return "PATH/l"
	}
	return cur + ":PATH/l"
}

// command builds an age invocation with the plugin-aware environment.
func (a *ageClient) command(args ...string) *exec.Cmd {
	cmd := exec.Command(a.bin, args...)
	cmd.Env = a.env()
	return cmd
}

// decrypt turns one blob into its plaintext. Ciphertext goes in on stdin and
// plaintext comes back on stdout, so no path ever has to be translated for the
// Windows client and — crucially — plaintext never lands on a Windows-visible
// filesystem. stderr is passed through so the "touch your YubiKey" prompt and
// any PIN dialog are visible.
//
// This is the one card interaction of a grant. A failure is never retried
// automatically: the PIV PIN is applet-wide, so three bad attempts also block
// the CA signing slot.
func (a *ageClient) decrypt(blob []byte) ([]byte, error) {
	cmd := a.command("--decrypt", "-i", a.identity)
	cmd.Stdin = bytes.NewReader(blob)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("age decrypt failed: %s", ageError(errb.String(), err))
	}
	return out.Bytes(), nil
}

// encrypt armours plaintext to the given recipients. Armour keeps the repo
// text-only (still opaque — the host storing it can't read a thing).
func (a *ageClient) encrypt(plain []byte, recipients []string) ([]byte, error) {
	args := []string{"--encrypt", "--armor"}
	for _, r := range recipients {
		args = append(args, "-r", r)
	}
	cmd := a.command(args...)
	cmd.Stdin = bytes.NewReader(plain)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("age encrypt failed: %s", ageError(errb.String(), err))
	}
	return out.Bytes(), nil
}

// version probes the client (used by `doctor`). Windows binaries emit CRLF, so
// anything captured as *text* has to have its \r stripped — an identity file
// saved with the carriage returns left in fails with "unknown identity type".
func (a *ageClient) version() (string, error) {
	out, err := a.command("--version").Output()
	if err != nil {
		return "", err
	}
	return stripCR(strings.TrimSpace(string(out))), nil
}

// stripCR removes carriage returns from text captured off a Windows binary.
func stripCR(s string) string { return strings.ReplaceAll(s, "\r", "") }

// ageError picks the most useful line out of an age failure.
func ageError(stderr string, err error) string {
	for _, l := range strings.Split(stripCR(stderr), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "age:") {
			return l
		}
	}
	if s := firstLine(stripCR(stderr)); s != "" {
		return s
	}
	return err.Error()
}
