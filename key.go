package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func keyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "key <scope> [<ttl>]",
		Short: "Mint a cert for <scope> (signed by the CA YubiKey) and load it into the agent",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl := ""
			if len(args) == 2 {
				ttl = args[1]
			}
			return runKey(args[0], ttl)
		},
	}
}

// ttlRe matches an OpenSSH-style relative time: a sequence of <int><unit>,
// unit in s/m/h/d/w (e.g. "8h", "24h", "1d", "1h30m"). A bare integer is
// treated as hours for backwards-compat with the old `mint <scope> <hours>`.
var ttlRe = regexp.MustCompile(`^([0-9]+[smhdwSMHDW])+$`)

// normalizeTTL validates a ttl and returns it; a bare integer becomes "<n>h".
func normalizeTTL(ttl string) (string, error) {
	ttl = strings.TrimSpace(ttl)
	if ttl == "" {
		return "", fmt.Errorf("empty ttl")
	}
	if _, err := strconv.Atoi(ttl); err == nil {
		return ttl + "h", nil
	}
	if !ttlRe.MatchString(ttl) {
		return "", fmt.Errorf("invalid ttl %q (use e.g. 8h, 24h, 1d, 1h30m)", ttl)
	}
	return ttl, nil
}

// ttlUnits maps the OpenSSH-style relative-time suffixes to durations.
var ttlUnits = map[byte]time.Duration{
	's': time.Second,
	'm': time.Minute,
	'h': time.Hour,
	'd': 24 * time.Hour,
	'w': 7 * 24 * time.Hour,
}

// parseTTL turns an OpenSSH-style relative time into a Duration. Certs get their
// expiry enforced by sshd, but a secret grant needs the wall-clock deadline
// locally so the wiper can be armed for it.
func parseTTL(ttl string) (time.Duration, error) {
	norm, err := normalizeTTL(ttl)
	if err != nil {
		return 0, err
	}
	var total time.Duration
	num := 0
	digits := false
	for i := 0; i < len(norm); i++ {
		ch := norm[i]
		if ch >= '0' && ch <= '9' {
			num = num*10 + int(ch-'0')
			digits = true
			continue
		}
		unit, ok := ttlUnits[byte(strings.ToLower(string(ch))[0])]
		if !ok || !digits {
			return 0, fmt.Errorf("invalid ttl %q", ttl)
		}
		total += time.Duration(num) * unit
		num, digits = 0, false
	}
	if digits || total <= 0 {
		return 0, fmt.Errorf("invalid ttl %q", ttl)
	}
	return total, nil
}

func runKey(scopeName, ttlOverride string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	sc, ok := cfg.scope(scopeName)
	if !ok {
		return fmt.Errorf("unknown scope %q (try: %s scopes list)", scopeName, prog)
	}

	ttl := sc.TTL
	if ttlOverride != "" {
		ttl = ttlOverride
	}
	ttl, err = normalizeTTL(ttl)
	if err != nil {
		return err
	}

	// Ensure the throwaway per-scope ed25519 key (private key stays on this host).
	dir := cfg.sessionsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	key := filepath.Join(dir, scopeName)
	if _, err := os.Stat(key); os.IsNotExist(err) {
		if err := run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "mint-"+scopeName, "-f", key); err != nil {
			return fmt.Errorf("generate session key: %w", err)
		}
	}

	// Common cert metadata.
	id := fmt.Sprintf("%s-%s-%s", currentUser(), scopeName, time.Now().Format("20060102T150405"))
	serial := strconv.FormatInt(time.Now().Unix(), 10)

	// Per-mode signing args shared across modes.
	certArgs := func(signOpt ...string) []string {
		a := append([]string{}, signOpt...)
		a = append(a, "-I", id, "-n", sc.Principal, "-V", "+"+ttl, "-z", serial)
		if cfg.SourceAddress != "" {
			a = append(a, "-O", "source-address="+cfg.SourceAddress)
		}
		return a
	}

	switch cfg.Mode {
	case "software":
		ck := cfg.caKeyPath()
		if ck == "" {
			return fmt.Errorf("mode=software requires ca_key")
		}
		if !fileExists(ck) {
			return fmt.Errorf("ca_key %q not found", ck)
		}
		fmt.Printf("%s: signing %s  principal=%s  +%s  [software CA]\n", prog, scopeName, sc.Principal, ttl)
		args := append([]string{"-s", ck}, certArgs()...)
		args = append(args, key+".pub")
		if err := run("ssh-keygen", args...); err != nil {
			return err
		}

	case "agent":
		if err := requireCAPub(cfg); err != nil {
			return err
		}
		if err := caInAgent(cfg.caPubPath()); err != nil {
			return err
		}
		fmt.Printf("%s: signing %s  principal=%s  +%s  [agent CA — tap to sign]\n", prog, scopeName, sc.Principal, ttl)
		args := append([]string{"-U", "-s", cfg.caPubPath()}, certArgs()...)
		args = append(args, key+".pub")
		if err := run("ssh-keygen", args...); err != nil {
			printAgentRefusedHint()
			return fmt.Errorf("agent signing failed")
		}

	case "wsl-delegate":
		if err := runWSLDelegate(cfg, scopeName, key, certArgs()); err != nil {
			return err
		}

	case "token", "":
		if err := requireCAPub(cfg); err != nil {
			return err
		}
		mod := cfg.YKCS11
		if mod == "" {
			mod = detectYKCS11()
		}
		if mod == "" {
			return fmt.Errorf("could not find a PKCS#11 module; set ykcs11")
		}
		if !fileExists(mod) {
			return fmt.Errorf("ykcs11 %q not found", mod)
		}
		fmt.Printf("%s: signing %s  principal=%s  +%s  [YubiKey — PIN + tap]\n", prog, scopeName, sc.Principal, ttl)
		args := append([]string{"-s", cfg.caPubPath(), "-D", mod}, certArgs()...)
		args = append(args, key+".pub")
		if err := run("ssh-keygen", args...); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown mode %q (agent | token | software | wsl-delegate)", cfg.Mode)
	}

	// Load into the agent with a matching lifetime (best-effort).
	loadIntoAgent(key, ttl)

	fmt.Printf("%s: minted.\n", prog)
	printCertSummary(key + "-cert.pub")
	return nil
}

// runWSLDelegate signs via the Windows ssh-keygen + Windows PKCS#11: the private
// key never leaves WSL; only the public key crosses out, the cert comes back.
func runWSLDelegate(cfg *Config, scopeName, key string, certArgs []string) error {
	if !inWSL() {
		return fmt.Errorf("mode=wsl-delegate only applies under WSL")
	}
	if err := requireCAPub(cfg); err != nil {
		return err
	}
	if cfg.WinSSHKeygen == "" || !isExecutable(cfg.WinSSHKeygen) {
		return fmt.Errorf("set win_ssh_keygen to the Windows ssh-keygen.exe (e.g. Git-Bash's)")
	}
	if cfg.WinYKCS11 == "" {
		return fmt.Errorf("set win_ykcs11 to the Windows PKCS#11 module path")
	}
	if cfg.WinStage == "" {
		return fmt.Errorf("set win_stage to a Windows-readable staging dir (e.g. /mnt/c/Users/<you>/.mint)")
	}
	stage := expandPath(cfg.WinStage)
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	caStage := filepath.Join(stage, scopeName+".ca.pub")
	pubStage := filepath.Join(stage, scopeName+".pub")
	certStage := filepath.Join(stage, scopeName+"-cert.pub")
	if err := copyFile(cfg.caPubPath(), caStage); err != nil {
		return err
	}
	if err := copyFile(key+".pub", pubStage); err != nil {
		return err
	}
	defer func() {
		os.Remove(caStage)
		os.Remove(pubStage)
		os.Remove(certStage)
	}()

	fmt.Printf("%s: signing %s  [WSL→Windows YubiKey — PIN + tap]\n", prog, scopeName)
	args := append([]string{"-s", toWinPath(caStage), "-D", cfg.WinYKCS11}, certArgs...)
	args = append(args, toWinPath(pubStage))
	if err := run(cfg.WinSSHKeygen, args...); err != nil {
		return err
	}
	if !fileExists(certStage) {
		return fmt.Errorf("Windows signing produced no cert at %s", certStage)
	}
	return copyFile(certStage, key+"-cert.pub")
}

// requireCAPub validates ca_pub is set and present.
func requireCAPub(cfg *Config) error {
	p := cfg.caPubPath()
	if p == "" || !fileExists(p) {
		return fmt.Errorf("set ca_pub to your CA public key (mode=%s)", cfg.Mode)
	}
	return nil
}

// caInAgent verifies the CA key (matching ca_pub) is loaded in the ssh-agent.
func caInAgent(caPub string) error {
	out, err := exec.Command("ssh-keygen", "-lf", caPub).Output()
	if err != nil {
		return fmt.Errorf("read CA fingerprint from %s: %w", caPub, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return fmt.Errorf("could not parse CA fingerprint from %s", caPub)
	}
	fp := fields[1] // SHA256:...

	listed, _ := exec.Command("ssh-add", "-l").Output()
	if !strings.Contains(string(listed), fp) {
		return fmt.Errorf("CA key not in the ssh-agent — plug in a CA YubiKey (and start the agent bridge)")
	}
	return nil
}

func printAgentRefusedHint() {
	fmt.Fprintf(os.Stderr, "\n%s: agent signing FAILED.\n", prog)
	fmt.Fprintf(os.Stderr, "  If the YubiKey asked for PIN/tap but you still got \"agent refused operation\",\n")
	fmt.Fprintf(os.Stderr, "  a stale cert from a *different* YubiKey is shadowing the one plugged in now. Fix:\n")
	fmt.Fprintf(os.Stderr, "    - plug in the YubiKey whose cert is currently in the store, OR\n")
	fmt.Fprintf(os.Stderr, "    - run  %s clean   to sync the store to the plugged-in YubiKey,\n", prog)
	fmt.Fprintf(os.Stderr, "  then re-run this mint.\n")
}

// loadIntoAgent adds the key+cert to the ssh-agent with a matching lifetime.
func loadIntoAgent(key, ttl string) {
	if exec.Command("ssh-add", "-t", ttl, key).Run() == nil {
		return
	}
	if exec.Command("ssh-add", key).Run() == nil {
		return
	}
	fmt.Printf("%s: note — could not add to agent (no agent?); cert at %s-cert.pub\n", prog, key)
}

// printCertSummary prints lines 2..9 of `ssh-keygen -L` (the human-readable cert).
func printCertSummary(certPath string) {
	out, err := exec.Command("ssh-keygen", "-L", "-f", certPath).Output()
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for i := 1; sc.Scan() && i <= 9; i++ {
		if i >= 2 {
			fmt.Println(sc.Text())
		}
	}
}

// --- small helpers ---

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "user"
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func isExecutable(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// run executes a command with stdio inherited so PIN/tap prompts are visible.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runOut runs a command and returns its trimmed stdout.
func runOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// runErr runs a command silently and returns only its error (for probes).
func runErr(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// runOutErr runs a command and returns trimmed stdout, trimmed stderr, and the
// error — used when the stderr matters for diagnostics.
func runOutErr(name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}

// firstLine returns the first non-empty line of s (for compact error reporting).
func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}
