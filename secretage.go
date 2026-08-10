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
	scratch   string // tmpfs scratch dir for decrypts that must go through a file
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

// decrypt turns one blob into its plaintext. This is the one card interaction of
// a grant, and it is never retried automatically: the PIV PIN is applet-wide, so
// three bad attempts also block the CA signing slot.
//
// How it runs depends on whether the card is reachable from this process or only
// from Windows — see decryptPiped and decryptViaConsole.
func (a *ageClient) decrypt(blobPath string) ([]byte, error) {
	if a.mode == secretModeWSL {
		return a.decryptViaConsole(blobPath)
	}
	return a.decryptPiped(blobPath)
}

// decryptPiped is the straightforward path: ciphertext in on stdin, plaintext
// out on stdout, prompts on the inherited stderr. Used wherever the age client
// runs on this side and shares our terminal.
func (a *ageClient) decryptPiped(blobPath string) ([]byte, error) {
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, err
	}
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

// decryptViaConsole runs the Windows age client in a console window of its own.
//
// It has to. The Windows client does not prompt for the PIV PIN on stderr — it
// opens CONIN$/CONOUT$, the process's *console*. A child launched from WSL with
// pipes for stdio has no console bound to the terminal, so the prompt is written
// somewhere invisible and the client waits forever for input nobody can give:
// a silent hang, with not one byte on stderr. Inheriting the terminal for stderr
// alone doesn't fix it either — measured, both ways.
//
// So the decrypt gets a real console, and the data moves by file instead:
//   - the blob is read over `\\wsl.localhost\...`, so no ciphertext is staged on
//     a Windows filesystem either;
//   - plaintext is written straight into the tmpfs scratch dir over the same
//     share — it never touches NTFS;
//   - the window closes by itself when age exits (`start /wait`, no `/k`, no
//     `pause`), and its exit status comes back to us.
//
// The command goes through a throwaway .bat because quotes do not survive the
// WSL→Windows argv boundary: `cmd /c start "title" ...` arrives as
// `start \"title\" ...` and cmd takes the title for a program name.
func (a *ageClient) decryptViaConsole(blobPath string) ([]byte, error) {
	if a.scratch == "" {
		return nil, fmt.Errorf("no scratch dir set for the console decrypt (internal error)")
	}
	if err := os.MkdirAll(a.scratch, 0o700); err != nil {
		return nil, err
	}
	out, err := os.CreateTemp(a.scratch, "plain-*")
	if err != nil {
		return nil, err
	}
	outPath := out.Name()
	out.Close()
	defer func() {
		overwriteFile(outPath)
		os.Remove(outPath)
	}()
	// age refuses to overwrite an existing file, and we only wanted the name.
	os.Remove(outPath)

	blobWin, err := winPath(blobPath)
	if err != nil {
		return nil, err
	}
	outWin, err := winPath(outPath)
	if err != nil {
		return nil, err
	}

	batDir, err := winTempDir()
	if err != nil {
		return nil, err
	}
	bat, err := os.CreateTemp(batDir, "mintk-*.bat")
	if err != nil {
		return nil, fmt.Errorf("stage the launcher: %w", err)
	}
	batPath := bat.Name()
	defer os.Remove(batPath)
	// CRLF and a leading @echo off: this is a Windows batch file. It carries
	// paths only — never a secret.
	script := "@echo off\r\n"
	if a.pluginDir != "" {
		pd, err := winPath(a.pluginDir)
		if err != nil {
			return nil, err
		}
		script += "set PATH=" + pd + ";%PATH%\r\n"
	}
	script += fmt.Sprintf("start \"mintk secret\" /wait \"%s\" --decrypt -i \"%s\" -o \"%s\" \"%s\"\r\n",
		a.bin2win(), a.identity, outWin, blobWin)
	script += "exit /b %ERRORLEVEL%\r\n"
	if _, err := bat.WriteString(script); err != nil {
		bat.Close()
		return nil, err
	}
	bat.Close()
	batWin, err := winPath(batPath)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%s: a console window is opening for the YubiKey prompt — answer it there\n", prog)
	cmd := exec.Command("cmd.exe", "/c", batWin)
	cmd.Dir = "/mnt/c" // cmd.exe refuses a WSL working directory
	var errb bytes.Buffer
	cmd.Stderr = io.MultiWriter(os.Stderr, &errb)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("age decrypt failed (see the console window): %s", ageError(errb.String(), err))
	}
	plain, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("the decrypt produced no output — was the prompt cancelled?")
	}
	return plain, nil
}

// bin2win renders the age binary in the form the Windows shell needs.
func (a *ageClient) bin2win() string {
	if p, err := winPath(a.bin); err == nil {
		return p
	}
	return a.bin
}

// winPath converts a WSL path to the form a Windows process can open. Paths
// under /mnt/... become drive paths; everything else becomes a
// \\wsl.localhost\... share path — which reaches tmpfs, so plaintext can be
// handed to a Windows process without ever being written to a Windows disk.
func winPath(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return p, nil // already a Windows path
	}
	out, err := exec.Command("wslpath", "-w", p).Output()
	if err != nil {
		return "", fmt.Errorf("translate %s for Windows: %w", p, err)
	}
	w := strings.TrimSpace(stripCR(string(out)))
	if w == "" {
		return "", fmt.Errorf("could not translate %s for Windows", p)
	}
	return w, nil
}

// winTempDirCache memoises the Windows temp directory (one interop call).
var winTempDirCache string

// winTempDir resolves %TEMP% as a WSL path — somewhere Windows can definitely
// execute a batch file from.
func winTempDir() (string, error) {
	if winTempDirCache != "" {
		return winTempDirCache, nil
	}
	cmd := exec.Command("cmd.exe", "/c", "echo %TEMP%")
	cmd.Dir = "/mnt/c"
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve the Windows temp dir: %w", err)
	}
	win := strings.TrimSpace(stripCR(string(out)))
	if win == "" || strings.Contains(win, "%") {
		return "", fmt.Errorf("could not resolve %%TEMP%% on the Windows side")
	}
	p, err := exec.Command("wslpath", "-u", win).Output()
	if err != nil {
		return "", err
	}
	winTempDirCache = strings.TrimSpace(stripCR(string(p)))
	return winTempDirCache, nil
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
