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
