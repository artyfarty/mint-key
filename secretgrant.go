package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A grant is a decrypted secret parked on tmpfs with a deadline. Layout under
// the runtime dir (0700):
//
//	secrets/<scope>       plaintext, mode 0600
//	grants/<scope>.json   metadata: deadline, serial, armed wiper
//	edit/<scope>.<pid>/   `secret edit` workspace
//
// Everything lives on tmpfs so a reboot wipes grants for free, and nothing
// survives to a disk that could be imaged later.
type grant struct {
	Scope     string    `json:"scope"`
	Serial    string    `json:"serial"` // identifies *this* grant; guards against a stale wiper
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`
	TTL       string    `json:"ttl"`
	Wiper     string    `json:"wiper"`          // systemd | reaper
	Unit      string    `json:"unit,omitempty"` // transient systemd unit, when used
}

func (g grant) remaining() time.Duration { return time.Until(g.ExpiresAt) }
func (g grant) expired() bool            { return !time.Now().Before(g.ExpiresAt) }

// grantStore owns the tmpfs runtime directory.
type grantStore struct {
	root string
}

// newGrantStore resolves and prepares the runtime directory, refusing to hand
// out plaintext anywhere but real tmpfs unless the operator opted out.
func newGrantStore(s *SecretsConfig) (*grantStore, error) {
	root, err := runtimeDirPath(s)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	if fs := mountFSType(root); !isEphemeralFS(fs) && !s.AllowNonTmpfs {
		return nil, fmt.Errorf("runtime dir %s is on %q, not tmpfs\n"+
			"  grants must die on reboot and never touch a disk; point secrets.runtime_dir at\n"+
			"  a tmpfs (e.g. $XDG_RUNTIME_DIR/mint-key) or set secrets.allow_non_tmpfs: true",
			root, fsOrUnknown(fs))
	}
	st := &grantStore{root: root}
	for _, d := range []string{st.secretsDir(), st.grantsDir(), st.editDir(), st.scratchDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return st, nil
}

// runtimeDirPath resolves where grants would live, creating nothing — so
// read-only callers (`doctor`) can report on it without touching the disk.
func runtimeDirPath(s *SecretsConfig) (string, error) {
	if root := expandPath(s.RuntimeDir); root != "" {
		return root, nil
	}
	return defaultRuntimeDir()
}

// nearestExistingDir walks up from p to the first directory that exists, so the
// filesystem type can be read for a path that hasn't been created yet.
func nearestExistingDir(p string) string {
	for {
		if dirExists(p) {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		p = parent
	}
}

// defaultRuntimeDir prefers the per-user runtime dir (tmpfs, wiped on logout),
// falling back to /dev/shm which is tmpfs too.
func defaultRuntimeDir() (string, error) {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "mint-key"), nil
	}
	if d := fmt.Sprintf("/run/user/%d", os.Getuid()); dirExists(d) {
		return filepath.Join(d, "mint-key"), nil
	}
	if dirExists("/dev/shm") {
		return fmt.Sprintf("/dev/shm/mint-key-%d", os.Getuid()), nil
	}
	return "", fmt.Errorf("no tmpfs runtime dir found ($XDG_RUNTIME_DIR unset, no /run/user, no /dev/shm)\n" +
		"  set secrets.runtime_dir — see docs/secrets.md (grants are Linux/WSL-only for now)")
}

func (st *grantStore) secretsDir() string       { return filepath.Join(st.root, "secrets") }
func (st *grantStore) grantsDir() string        { return filepath.Join(st.root, "grants") }
func (st *grantStore) editDir() string          { return filepath.Join(st.root, "edit") }
func (st *grantStore) scratchDir() string       { return filepath.Join(st.root, "scratch") }
func (st *grantStore) path(scope string) string { return filepath.Join(st.secretsDir(), scope) }
func (st *grantStore) meta(scope string) string { return filepath.Join(st.grantsDir(), scope+".json") }
func (st *grantStore) exists(scope string) bool { return fileExists(st.path(scope)) }
func (st *grantStore) String() string           { return st.root }

// read returns the recorded grant for a scope.
func (st *grantStore) read(scope string) (*grant, error) {
	data, err := os.ReadFile(st.meta(scope))
	if err != nil {
		return nil, err
	}
	var g grant
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, err
	}
	return &g, nil
}

// live returns the grant for a scope if it exists, hasn't expired, and its
// plaintext is still there.
func (st *grantStore) live(scope string) (*grant, bool) {
	g, err := st.read(scope)
	if err != nil || g.expired() || !st.exists(scope) {
		return nil, false
	}
	return g, true
}

// list returns every recorded grant, newest deadline last.
func (st *grantStore) list() []*grant {
	entries, _ := os.ReadDir(st.grantsDir())
	var out []*grant
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if g, err := st.read(strings.TrimSuffix(e.Name(), ".json")); err == nil {
			out = append(out, g)
		}
	}
	return out
}

// write parks the plaintext on tmpfs (0600) and records the grant.
func (st *grantStore) write(scope string, plain []byte, ttl string, d time.Duration) (*grant, error) {
	if err := validScopeName(scope); err != nil {
		return nil, err
	}
	p := st.path(scope)
	// Replace rather than truncate in place: a fresh 0600 file can't inherit
	// permissions from whatever was there before.
	_ = os.Remove(p)
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(plain); err != nil {
		f.Close()
		os.Remove(p)
		return nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return nil, err
	}

	now := time.Now()
	g := &grant{
		Scope:     scope,
		Serial:    strconv.FormatInt(now.UnixNano(), 10),
		GrantedAt: now,
		ExpiresAt: now.Add(d),
		TTL:       ttl,
	}
	if err := st.saveMeta(g); err != nil {
		st.wipeFile(scope)
		return nil, err
	}
	return g, nil
}

func (st *grantStore) saveMeta(g *grant) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(st.meta(g.Scope), append(data, '\n'), 0o600)
}

// wipeFile overwrites the plaintext before unlinking it. On tmpfs the pages are
// rewritten in place, so this is meaningfully better than a bare unlink.
func (st *grantStore) wipeFile(scope string) {
	p := st.path(scope)
	if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0o600); err == nil {
			zeros := make([]byte, 4096)
			for left := info.Size(); left > 0; {
				n := int64(len(zeros))
				if left < n {
					n = left
				}
				if _, err := f.Write(zeros[:n]); err != nil {
					break
				}
				left -= n
			}
			f.Sync()
			f.Close()
		}
	}
	_ = os.Remove(p)
}

// wipe destroys a grant. serial guards the common race: a wiper armed for an
// earlier grant firing after the scope has been re-granted. Pass "" to force.
func (st *grantStore) wipe(scope, serial string) bool {
	g, err := st.read(scope)
	if err == nil && serial != "" && g.Serial != serial {
		return false // superseded by a newer grant — leave it alone
	}
	st.wipeFile(scope)
	_ = os.Remove(st.meta(scope))
	if g != nil && g.Unit != "" && os.Getenv("INVOCATION_ID") == "" {
		// Cancel the still-pending timer so it can't fire against a later grant.
		// `systemd-run --on-active` creates <unit>.timer + <unit>.service; the
		// timer is the one holding the schedule. Skipped when we *are* the unit
		// (INVOCATION_ID set) — stopping ourselves mid-wipe helps nobody.
		_ = exec.Command("systemctl", "--user", "stop", g.Unit+".timer", g.Unit+".service").Run()
	}
	return true
}

// sweep enforces expiry independently of anything cooperative: it wipes expired
// grants, plaintext with no grant record behind it, and abandoned edit
// workspaces. Every `secret` command runs it first, and it is safe to run from a
// timer or by hand.
func (st *grantStore) sweep() int {
	n := 0
	for _, g := range st.list() {
		if g.expired() {
			st.wipe(g.Scope, "")
			n++
		}
	}
	// Plaintext without metadata is unwatched by construction — kill it.
	entries, _ := os.ReadDir(st.secretsDir())
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !fileExists(st.meta(e.Name())) {
			st.wipeFile(e.Name())
			n++
		}
	}
	// Scratch files are transient by construction: anything still here is the
	// residue of an interrupted decrypt.
	scratch, _ := os.ReadDir(st.scratchDir())
	for _, e := range scratch {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(st.scratchDir(), e.Name())
		overwriteFile(p)
		_ = os.Remove(p)
		n++
	}
	// Edit workspaces belonging to processes that are gone (crash, SIGKILL).
	dirs, _ := os.ReadDir(st.editDir())
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		if pidAlive(editWorkspacePID(d.Name())) {
			continue
		}
		st.wipeTree(filepath.Join(st.editDir(), d.Name()))
		n++
	}
	return n
}

// wipeTree overwrites and removes every file under dir.
func (st *grantStore) wipeTree(dir string) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			st.wipeTree(p)
			continue
		}
		overwriteFile(p)
		_ = os.Remove(p)
	}
	_ = os.Remove(dir)
}

// overwriteFile zeroes a regular file's contents in place.
func overwriteFile(p string) {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	f, err := os.OpenFile(p, os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	zeros := make([]byte, 4096)
	for left := info.Size(); left > 0; {
		n := int64(len(zeros))
		if left < n {
			n = left
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			return
		}
		left -= n
	}
	f.Sync()
}

// --- the independent wiper ---------------------------------------------------

// armWiper schedules the destruction of a grant in a process that outlives this
// one. This is what actually enforces the TTL: a consuming wrapper checking the
// deadline before it reads would be pointless, since anyone already on the box
// can read the tmpfs file directly and ignore any such check.
//
// First choice is a transient systemd user timer (survives the shell, survives
// mintk); the fallback is a detached child that sleeps and then wipes. If
// neither can be armed the caller must destroy the grant rather than leave
// plaintext lying around unwatched.
func (st *grantStore) armWiper(g *grant) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate own binary: %w", err)
	}
	secs := int64(time.Until(g.ExpiresAt).Seconds())
	if secs < 1 {
		secs = 1
	}

	unit := fmt.Sprintf("mintk-secret-%s-%s", unitSafe(g.Scope), g.Serial)
	if _, err := exec.LookPath("systemd-run"); err == nil {
		args := []string{
			"--user", "--quiet", "--collect",
			"--unit=" + unit,
			"--description=mintk: wipe secret grant " + g.Scope,
			fmt.Sprintf("--on-active=%ds", secs),
			"--", self, "secret", "_reap", "--root", st.root, g.Scope, g.Serial,
		}
		if err := exec.Command("systemd-run", args...).Run(); err == nil {
			g.Wiper, g.Unit = "systemd", unit
			return st.saveMeta(g)
		}
	}

	// Fallback: our own detached reaper. Setsid so it survives the terminal.
	cmd := exec.Command(self, "secret", "_reap", "--root", st.root, g.Scope, g.Serial, strconv.FormatInt(secs, 10))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devNull.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devNull, devNull, devNull
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not arm a wiper: %w", err)
	}
	_ = cmd.Process.Release()
	g.Wiper = "reaper"
	return st.saveMeta(g)
}

// unitSafe reduces a scope name to characters that are safe in a unit name.
func unitSafe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// --- filesystem helpers ------------------------------------------------------

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// isEphemeralFS reports whether a filesystem loses its contents on reboot.
func isEphemeralFS(fs string) bool { return fs == "tmpfs" || fs == "ramfs" }

func fsOrUnknown(fs string) string {
	if fs == "" {
		return "unknown"
	}
	return fs
}

// mountFSType reports the filesystem type of the mount holding path. Linux-only
// (it reads /proc/self/mountinfo); elsewhere it returns "", which callers treat
// as "can't prove this is tmpfs".
func mountFSType(path string) string {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	return fsTypeFromMountinfo(string(data), filepath.Clean(abs))
}

// fsTypeFromMountinfo picks the longest mount point that contains path and
// returns its filesystem type. Split out from mountFSType so it can be tested.
func fsTypeFromMountinfo(mountinfo, path string) string {
	best, bestType := "", ""
	for _, line := range strings.Split(mountinfo, "\n") {
		// <id> <parent> <maj:min> <root> <mountpoint> <opts> [tags...] - <fstype> ...
		sep := strings.Index(line, " - ")
		if sep < 0 {
			continue
		}
		head := strings.Fields(line[:sep])
		tail := strings.Fields(line[sep+3:])
		if len(head) < 5 || len(tail) < 1 {
			continue
		}
		mp := unescapeMount(head[4])
		if !pathWithin(path, mp) {
			continue
		}
		if len(mp) >= len(best) {
			best, bestType = mp, tail[0]
		}
	}
	return bestType
}

// pathWithin reports whether path is at or below mount point mp.
func pathWithin(path, mp string) bool {
	if mp == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mp || strings.HasPrefix(path, mp+"/")
}

// unescapeMount decodes the octal escapes mountinfo uses for space, tab,
// newline and backslash in mount points.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// editWorkspacePID extracts the pid from an edit workspace name
// ("<scope>.<pid>"); 0 when it doesn't parse.
func editWorkspacePID(name string) int {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return 0
	}
	pid, err := strconv.Atoi(name[i+1:])
	if err != nil {
		return 0
	}
	return pid
}

// pidAlive reports whether a process with that pid still exists.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
