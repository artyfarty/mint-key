package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func initCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactively create the mintk config (import the CA from a YubiKey)",
		Long: `Bootstrap ~/.config/mint-key/config.yaml on a new machine: pick a signing
mode, import the CA public key (from an inserted YubiKey via PKCS#11, from the
ssh-agent, or pasted/from a file), and optionally point at a shared scopes file
(a private git repo) so the scope list travels with you.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(force)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing config")
	return cmd
}

func runInit(force bool) error {
	path := configPath()
	if fileExists(path) && !force {
		return fmt.Errorf("config already exists at %s\n"+
			"  edit it directly, use `mintk scopes edit`, or pass --force to recreate", path)
	}
	if !isInteractive() {
		return fmt.Errorf("`init` needs a terminal")
	}

	cfg := &Config{path: path}
	cfg.applyDefaults()

	// --- signing mode ---
	modes := []string{"agent", "token", "software", "wsl-delegate"}
	modeDesc := map[string]string{
		"agent":        "CA in the ssh-agent, sign with -U — YubiKey reached via an agent bridge (WSL ↔ Windows)",
		"token":        "local PKCS#11 — YubiKey plugged into THIS machine (Linux/macOS)",
		"software":     "CA private key in a file — TESTING ONLY, no hardware",
		"wsl-delegate": "WSL → Windows ssh-keygen + Windows PKCS#11 (fallback; prefer agent)",
	}
	rec := "token"
	if inWSL() {
		rec = "agent"
	}
	var modeOpts []string
	for _, m := range modes {
		label := fmt.Sprintf("%-12s — %s", m, modeDesc[m])
		if m == rec {
			label += "  [recommended here]"
		}
		modeOpts = append(modeOpts, label)
	}
	mi, err := promptChoice("Signing mode — how mintk reaches the CA private key", modeOpts)
	if err != nil {
		return err
	}
	cfg.Mode = modes[mi]

	// --- CA material ---
	if cfg.Mode == "software" {
		ck, err := promptString("CA private key file (software/testing only)", "~/.config/mint-key/ca")
		if err != nil {
			return err
		}
		cfg.CAKey = ck
		// Derive ca_pub if the key already exists (deploy needs the public key).
		if pub, derr := runOut("ssh-keygen", "-y", "-f", expandPath(ck)); derr == nil && pub != "" {
			caDest := filepath.Join(configDir(), "ca.pub")
			_ = os.MkdirAll(configDir(), 0o755)
			if werr := os.WriteFile(caDest, []byte(pub+"\n"), 0o644); werr == nil {
				cfg.CAPub = "~/.config/mint-key/ca.pub"
				fmt.Printf("%s: derived CA public key → %s\n", prog, caDest)
			}
		} else {
			fmt.Printf("%s: note — %s doesn't exist yet; create it, then ca.pub can be derived\n", prog, expandPath(ck))
		}
	} else {
		capub, err := importCAPub(cfg)
		if err != nil {
			return err
		}
		caDest := filepath.Join(configDir(), "ca.pub")
		if err := os.MkdirAll(configDir(), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(caDest, []byte(strings.TrimRight(capub, "\n")+"\n"), 0o644); err != nil {
			return err
		}
		cfg.CAPub = "~/.config/mint-key/ca.pub"
		fmt.Printf("%s: wrote CA public key → %s\n", prog, caDest)

		if cfg.Mode == "agent" {
			cn, err := promptString("CA cert subject CN (used by `mintk clean`)", caComment(capub))
			if err != nil {
				return err
			}
			cfg.CACertCN = strings.TrimSpace(cn)
		}
	}

	// --- shared scopes file (optional) ---
	shared, err := promptYesNo("Keep scopes in a shared file (e.g. a private git repo)?", true)
	if err != nil {
		return err
	}
	if shared {
		sp, err := promptString("Path to the scopes YAML", "~/work/mint-scopes/scopes.yaml")
		if err != nil {
			return err
		}
		sp = strings.TrimSpace(sp)
		cfg.ScopesFile = sp
		dir := filepath.Dir(expandPath(sp))
		if !isGitRepo(dir) && !fileExists(expandPath(sp)) {
			url, err := promptString("git clone URL for the scopes repo (blank to skip)", "")
			if err != nil {
				return err
			}
			if strings.TrimSpace(url) != "" {
				_ = os.MkdirAll(filepath.Dir(dir), 0o755)
				if err := run("git", "clone", strings.TrimSpace(url), dir); err != nil {
					fmt.Printf("%s: warning — clone failed: %s (set up the repo manually)\n", prog, err)
				}
			}
		}
		_ = cfg.loadScopes() // best-effort: pick up any existing scopes
	}

	if err := cfg.save(); err != nil {
		return err
	}
	fmt.Printf("%s: wrote %s\n", prog, path)
	fmt.Printf("\nNext:\n")
	if len(cfg.Scopes) == 0 {
		fmt.Printf("  mintk scopes add <name> <principal> [<ttl>]   # or: mintk scopes edit\n")
	} else {
		fmt.Printf("  mintk scopes list\n")
	}
	fmt.Printf("  mintk key <scope>                            # mint (tap the YubiKey)\n")
	return nil
}

// importCAPub gathers CA public-key candidates from an inserted YubiKey (PKCS#11)
// and the ssh-agent, lets the user pick one, and falls back to paste/file.
func importCAPub(cfg *Config) (string, error) {
	type cand struct{ source, line string }
	var cands []cand
	seen := map[string]bool{}

	add := func(source, line string) {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[0], "-") {
			return // not a pubkey line
		}
		if seen[f[1]] {
			return
		}
		seen[f[1]] = true
		cands = append(cands, cand{source, line})
	}

	if mod := pickYKCS11(cfg); mod != "" {
		if out, err := runOut("ssh-keygen", "-D", mod); err == nil {
			for _, l := range strings.Split(out, "\n") {
				add("yubikey", l)
			}
		}
	}
	if out, err := runOut("ssh-add", "-L"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			add("agent", l)
		}
	}

	var options []string
	for _, c := range cands {
		options = append(options, fmt.Sprintf("[%s] %s", c.source, abbrevPub(c.line)))
	}
	pasteIdx := len(options)
	options = append(options, "Paste a public key")
	fileIdx := len(options)
	options = append(options, "Read from a file")

	idx, err := promptChoice("Import CA public key from", options)
	if err != nil {
		return "", err
	}
	switch idx {
	case pasteIdx:
		line, err := promptString("Paste the CA public key (one line)", "")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(line) == "" {
			return "", fmt.Errorf("no key provided")
		}
		return strings.TrimSpace(line), nil
	case fileIdx:
		p, err := promptString("Path to the CA public key file", "")
		if err != nil {
			return "", err
		}
		data, err := os.ReadFile(expandPath(strings.TrimSpace(p)))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	default:
		return cands[idx].line, nil
	}
}

// pickYKCS11 returns the configured or auto-detected PKCS#11 module ("" if none).
func pickYKCS11(cfg *Config) string {
	if cfg.YKCS11 != "" {
		return expandPath(cfg.YKCS11)
	}
	return detectYKCS11()
}

// caComment returns the comment field of a public-key line (a likely CN), or "".
func caComment(line string) string {
	f := strings.Fields(line)
	if len(f) >= 3 {
		return strings.Join(f[2:], " ")
	}
	return ""
}

// abbrevPub renders a pubkey line compactly: "<type> …<tail> <comment>".
func abbrevPub(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return line
	}
	blob := f[1]
	tail := blob
	if len(blob) > 16 {
		tail = "…" + blob[len(blob)-16:]
	}
	out := f[0] + " " + tail
	if c := caComment(line); c != "" {
		out += "  " + c
	}
	return out
}

// isGitRepo reports whether dir is inside a git work tree.
func isGitRepo(dir string) bool {
	if dir == "" {
		return false
	}
	return runErr("git", "-C", dir, "rev-parse", "--is-inside-work-tree") == nil
}
