package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check that the prerequisites for minting are in place (per platform)",
		Long: `Verify the local setup: OpenSSH tools, the CA public key, and the pieces the
configured signing mode needs (an agent holding the CA, a PKCS#11 module, etc.).
Read-only. Exits non-zero if a required check fails. See docs/prerequisites.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runDoctor() > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
}

// --- output helpers (colour when stdout is a terminal) ---

var dColor = term.IsTerminal(int(os.Stdout.Fd()))

func dwrap(code, s string) string {
	if !dColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}
func dok(f string, a ...any)   { fmt.Printf("  "+dwrap("32", "✓")+" "+f+"\n", a...) }
func dwarn(f string, a ...any) { fmt.Printf("  "+dwrap("33", "!")+" "+f+"\n", a...) }
func dbad(f string, a ...any)  { fmt.Printf("  "+dwrap("31", "✗")+" "+f+"\n", a...) }
func dnote(f string, a ...any) { fmt.Printf("    "+f+"\n", a...) }
func dhdr(f string, a ...any)  { fmt.Printf("\n"+dwrap("2", "== "+f+" ==")+"\n", a...) }

// runDoctor runs all checks and returns the number of failed (required) groups.
func runDoctor() int {
	fails := 0
	bump := func(n int) { fails += n }

	cfg, cfgErr := loadConfig()
	platform := "Linux/macOS"
	if inWSL() {
		platform = "WSL (Windows host)"
	}
	fmt.Printf("mintk doctor — %s\n", platform)

	bump(checkCommon())

	if cfgErr != nil {
		dhdr("Config")
		dwarn("no usable config: %s", firstLine(cfgErr.Error()))
		dnote("run 'mintk init' to create one; checking both backends meanwhile")
		bump(checkCAPresence(nil))
		bump(checkAgentMode(nil))
		bump(checkTokenMode(nil))
	} else {
		dhdr("Config")
		dok("config: %s", cfg.path)
		bump(checkCAPresence(cfg))
		switch cfg.Mode {
		case "agent":
			bump(checkAgentMode(cfg))
		case "token", "":
			bump(checkTokenMode(cfg))
		case "software":
			dhdr("Software mode")
			dwarn("software CA (testing only) — signs with a key file, no hardware")
		case "wsl-delegate":
			bump(checkWSLDelegate(cfg))
		default:
			dhdr("Mode")
			dwarn("unknown mode %q in config", cfg.Mode)
		}
		checkScopes(cfg)
		bump(checkSecrets(cfg))
	}

	dhdr("Result")
	if fails == 0 {
		dok("all required checks passed")
	} else {
		dbad("%d check group(s) need attention — see docs/prerequisites.md", fails)
	}
	return fails
}

func checkCommon() int {
	dhdr("Common")
	fail := 0
	for _, c := range []string{"ssh", "ssh-keygen", "ssh-add"} {
		if _, err := exec.LookPath(c); err == nil {
			dok("%s found", c)
		} else {
			dbad("%s missing — install the OpenSSH client", c)
			fail = 1
		}
	}
	// ssh-keygen -U (CA key in an agent) needs OpenSSH >= 7.6.
	if _, errOut, _ := runOutErr("ssh", "-V"); errOut != "" {
		if m := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`).FindStringSubmatch(errOut); m != nil {
			maj, _ := strconv.Atoi(m[1])
			min, _ := strconv.Atoi(m[2])
			if maj > 7 || (maj == 7 && min >= 6) {
				dok("OpenSSH %s.%s (supports ssh-keygen -U)", m[1], m[2])
			} else {
				dwarn("OpenSSH %s.%s is old; agent mode (-U) needs >= 7.6", m[1], m[2])
			}
		}
	}
	return fail
}

// caPub returns the configured CA public key path (expanded), or "".
func caPub(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.caPubPath()
}

func checkCAPresence(cfg *Config) int {
	if cfg != nil && cfg.Mode == "software" {
		dhdr("CA (software)")
		ck := cfg.caKeyPath()
		if ck != "" && fileExists(ck) {
			dok("CA key file: %s", ck)
			return 0
		}
		dbad("ca_key not set/found (software mode)")
		return 1
	}
	dhdr("CA public key")
	p := caPub(cfg)
	if p == "" {
		dwarn("ca_pub not set (run 'mintk init' to import it from your YubiKey)")
		return 0
	}
	if fileExists(p) {
		dok("ca.pub: %s", p)
		if fp, err := runOut("ssh-keygen", "-lf", p); err == nil {
			dnote("%s", fp)
		}
		return 0
	}
	dbad("ca.pub not found at %s", p)
	return 1
}

func checkAgentMode(cfg *Config) int {
	dhdr("Agent mode (ssh-keygen -U through an agent)")
	if _, err := exec.LookPath("ssh-add"); err != nil {
		dbad("ssh-add missing")
		return 1
	}
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		dbad("SSH_AUTH_SOCK unset — no agent reachable (start the agent bridge)")
		return 1
	}
	dok("SSH_AUTH_SOCK=%s", os.Getenv("SSH_AUTH_SOCK"))
	listed, _, err := runOutErr("ssh-add", "-l")
	if err != nil && listed == "" {
		dbad("agent not responding to ssh-add -l")
		return 1
	}
	if p := caPub(cfg); p != "" && fileExists(p) {
		if fp, e := runOut("ssh-keygen", "-lf", p); e == nil {
			f := strings.Fields(fp)
			if len(f) >= 2 && strings.Contains(listed, f[1]) {
				dok("CA key is loaded in the agent")
			} else {
				dbad("CA key NOT in the agent — plug in a CA YubiKey / start the bridge (or 'mintk clean')")
				if inWSL() {
					dnote("WSL: needs WinCryptSSHAgent + npiperelay/socat bridge — see docs/prerequisites.md")
				}
				return 1
			}
		}
	} else {
		dwarn("can't verify the CA is in the agent (ca_pub not set/found yet)")
	}
	return 0
}

func checkTokenMode(cfg *Config) int {
	dhdr("Token mode (local PKCS#11)")
	mod := ""
	if cfg != nil && cfg.YKCS11 != "" {
		mod = expandPath(cfg.YKCS11)
	} else {
		mod = detectYKCS11()
	}
	if mod == "" {
		dbad("no PKCS#11 module found (install yubico-piv-tool/libykcs11 or opensc)")
		dnote("macOS: brew install yubico-piv-tool   Linux: apt install yubico-piv-tool opensc")
		return 1
	}
	dok("PKCS#11 module: %s", mod)
	// Light probe: can we read keys off the token right now?
	if out, errOut, err := runOutErr("ssh-keygen", "-D", mod); err != nil {
		dwarn("token not readable now: %s", firstLine(errOut+" "+err.Error()))
		dnote("insert the YubiKey; on Linux pcscd must be running")
	} else if strings.TrimSpace(out) == "" {
		dwarn("module loaded but no keys on the token (PIV slots empty?)")
	} else {
		n := 0
		for _, l := range strings.Split(out, "\n") {
			if len(strings.Fields(l)) >= 2 {
				n++
			}
		}
		dok("token readable: %d key(s) present", n)
	}
	if !inWSL() && fileExists("/proc/version") { // Linux (not macOS)
		if exec.Command("pgrep", "-x", "pcscd").Run() == nil {
			dok("pcscd running")
		} else {
			dwarn("pcscd not running (needed to reach the card on Linux)")
		}
	}
	return 0
}

func checkWSLDelegate(cfg *Config) int {
	dhdr("wsl-delegate mode")
	fail := 0
	if !inWSL() {
		dwarn("mode is wsl-delegate but this isn't WSL")
	}
	if cfg.WinSSHKeygen == "" || !isExecutable(cfg.WinSSHKeygen) {
		dbad("win_ssh_keygen not set/executable (Windows ssh-keygen.exe)")
		fail = 1
	} else {
		dok("win_ssh_keygen: %s", cfg.WinSSHKeygen)
	}
	if cfg.WinYKCS11 == "" {
		dbad("win_ykcs11 not set (Windows PKCS#11 module)")
		fail = 1
	}
	if cfg.WinStage == "" {
		dbad("win_stage not set (Windows-readable staging dir)")
		fail = 1
	}
	return fail
}

// checkSecrets validates the secret-grant subsystem when it's configured at all;
// a cert-only setup skips it entirely.
func checkSecrets(cfg *Config) int {
	if cfg.Secrets == nil {
		return 0
	}
	s := cfg.Secrets
	dhdr("Secret grants (mode: %s)", s.Mode)
	fail := 0

	// The age client + its plugin.
	client, err := newAgeClient(s)
	if err != nil {
		dbad("age client: %s", firstLine(err.Error()))
		fail = 1
	} else {
		if v, verr := client.version(); verr == nil {
			dok("age: %s (%s)", client.bin, v)
		} else {
			dbad("age at %s did not run: %s", client.bin, firstLine(verr.Error()))
			fail = 1
		}
		dok("identity: %s", client.identity)
		if s.Mode != secretModeSoft {
			if s.PluginDir == "" {
				dwarn("plugin_dir not set — age must find age-plugin-yubikey on PATH")
				dnote("a plugin resolved through '.' is refused; the directory must be a real PATH entry")
			} else if dirExists(expandPath(s.PluginDir)) {
				dok("plugin_dir: %s (prepended to the age client's PATH)", expandPath(s.PluginDir))
			} else {
				dbad("plugin_dir %s does not exist", expandPath(s.PluginDir))
				fail = 1
			}
		}
	}
	if s.Mode == secretModeWSL {
		if fileExists("/proc/sys/fs/binfmt_misc/WSLInterop") || fileExists("/proc/sys/fs/binfmt_misc/WSLInterop-late") {
			dok("WSL interop enabled (Windows binaries are runnable — no usbipd, no pcscd needed)")
		} else {
			dbad("WSL interop is off — the Windows age.exe can't be executed from here")
			fail = 1
		}
	}
	if s.Mode == secretModeNative && !inWSL() && fileExists("/proc/version") {
		if exec.Command("pgrep", "-x", "pcscd").Run() == nil {
			dok("pcscd running")
		} else {
			dwarn("pcscd not running (the plugin needs it to reach the card natively)")
		}
	}
	if s.Mode == secretModeSoft {
		dwarn("software identity (testing only) — no hardware in the loop")
	}

	// The blob repo.
	if s.Repo == "" {
		dbad("secrets.repo not set (the git repo holding the blobs)")
		fail = 1
	} else if dirExists(s.blobDir()) {
		dok("blobs: %s (%d scope(s))", s.blobDir(), len(s.listSecretScopes()))
		if isGitRepo(s.repoPath()) {
			dok("backed by a git repo (use 'mintk secret pull/push')")
		} else {
			dwarn("%s is not a git repo — 'mintk secret pull/push' won't work", s.repoPath())
		}
	} else {
		dbad("blob dir %s missing (clone the secrets repo, or 'mintk secret edit <scope>' to start one)", s.blobDir())
		fail = 1
	}
	if _, rerr := s.recipientList(); rerr != nil {
		dwarn("recipients: %s", firstLine(rerr.Error()))
		dnote("needed only to write blobs ('secret edit'), not to grant them")
	} else {
		recs, _ := s.recipientList()
		dok("%d recipient(s) configured for re-encryption", len(recs))
	}

	// Where grants land, and what will destroy them. Resolved without creating
	// anything — doctor stays read-only.
	root, err := runtimeDirPath(s)
	if err != nil {
		dbad("runtime dir: %s", firstLine(err.Error()))
		return fail + 1
	}
	st := &grantStore{root: root}
	fs := mountFSType(nearestExistingDir(root))
	switch {
	case isEphemeralFS(fs):
		dok("runtime dir: %s (%s)", root, fs)
	case s.AllowNonTmpfs:
		dwarn("runtime dir: %s is on %s, allowed by allow_non_tmpfs", root, fsOrUnknown(fs))
		dnote("granted plaintext will survive a reboot on disk")
	default:
		dbad("runtime dir: %s is on %s, not tmpfs — grants would be refused", root, fsOrUnknown(fs))
		fail = 1
	}
	if _, lerr := exec.LookPath("systemd-run"); lerr == nil {
		dok("wiper: systemd-run --user transient timers (fallback: a detached reaper)")
	} else {
		dwarn("systemd-run absent — TTLs will be enforced by a detached reaper process")
		dnote("it survives the shell but not a kill -9; 'mintk secret sweep' is the backstop")
	}
	if n := len(st.list()); n > 0 {
		dnote("%d live grant(s) right now", n)
	}
	return fail
}

func checkScopes(cfg *Config) {
	if cfg.ScopesFile == "" {
		return
	}
	dhdr("Scopes file")
	p := cfg.scopesFilePath()
	if fileExists(p) {
		dok("scopes_file: %s (%d scopes)", p, len(cfg.Scopes))
	} else {
		dwarn("scopes_file set but %s missing (run 'mintk scopes pull' or add scopes)", p)
	}
	if isGitRepo(filepath.Dir(p)) {
		dok("backed by a git repo (use 'mintk scopes pull/push')")
	} else {
		dwarn("not a git repo — 'mintk scopes pull/push' won't work")
	}
}
