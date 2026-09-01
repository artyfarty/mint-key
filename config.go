package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope maps a friendly name to a certificate principal and a default lifetime.
// The principal is what target hosts must list in their AuthorizedPrincipalsFile.
type Scope struct {
	Name      string `yaml:"name"`
	Principal string `yaml:"principal"`
	TTL       string `yaml:"ttl"`
}

// Config mirrors the bash mint config vars, now as YAML at ~/.config/mint-key/.
type Config struct {
	CAPub         string `yaml:"ca_pub"`         // CA public key (agent/token modes)
	Mode          string `yaml:"mode"`           // agent | token | software | wsl-delegate
	SessionsDir   string `yaml:"sessions_dir"`   // throwaway per-scope keys + minted certs
	SourceAddress string `yaml:"source_address"` // optional -O source-address lock

	// agent mode
	CACertCN string `yaml:"ca_cert_cn"` // CA cert subject CN — used by `clean`

	// token mode (local PKCS#11)
	YKCS11 string `yaml:"ykcs11"` // path; auto-detected when empty

	// software mode (testing only)
	CAKey string `yaml:"ca_key"` // CA private key file

	// wsl-delegate mode (YubiKey on the Windows host, sign via Windows ssh-keygen)
	WinSSHKeygen string `yaml:"win_ssh_keygen"` // Windows ssh-keygen.exe (e.g. Git-Bash's)
	WinStage     string `yaml:"win_stage"`      // Windows-readable staging dir
	WinYKCS11    string `yaml:"win_ykcs11"`     // Windows PKCS#11 module path

	// windows helpers (WSL): ykman.exe for `clean`
	WinYkman string `yaml:"win_ykman"`

	// scopes_file (optional): keep the scope list in a separate YAML — typically
	// a private git repo — so it can be shared/synced across machines. When set,
	// scopes are read from and written to this file instead of inline below.
	ScopesFile string `yaml:"scopes_file,omitempty"`

	Scopes []Scope `yaml:"scopes,omitempty"`

	// secret grants (optional subsystem — absent for cert-only setups)
	Secrets *SecretsConfig `yaml:"secrets,omitempty"`

	path           string // where this config was loaded from
	scopesExternal bool   // scopes came from ScopesFile
}

// SecretScope maps a secret scope name to its blob and its grant policy. Scopes
// are usually discovered from the blob repo; an entry here only adds policy on
// top (a non-default filename, lifetime, or consumption format).
type SecretScope struct {
	Name   string `yaml:"name"`
	File   string `yaml:"file,omitempty"`   // blob filename; default "<name>.age"
	TTL    string `yaml:"ttl,omitempty"`    // default grant lifetime for this scope
	Format string `yaml:"format,omitempty"` // env | opaque — how `secret run` exposes it
}

// SecretsConfig configures the secret-grant subsystem: where the age-encrypted
// blobs live, who they're encrypted to, and how the age client reaches the card.
type SecretsConfig struct {
	// Mode selects how the age client reaches the YubiKey — the same
	// platform/mode split as the CA `mode:`, for the same reason.
	//   native       age + age-plugin-yubikey run here and talk to the card (pcscd)
	//   wsl-windows  WSL runs the *Windows* age.exe through interop; the card
	//                stays on Windows (no usbipd, no pcscd in WSL)
	//   software     a plain age X25519 identity file — TESTING ONLY, no hardware
	Mode string `yaml:"mode"`

	// Blob storage: a git repo holding one age blob per scope.
	Repo string `yaml:"repo"`          // repo root
	Dir  string `yaml:"dir,omitempty"` // blob subdir inside the repo (default "secrets")

	// Recipients the blobs are (re-)encrypted to on `secret edit`.
	Recipients     []string `yaml:"recipients,omitempty"`
	RecipientsFile string   `yaml:"recipients_file,omitempty"` // relative to Repo

	// age client. Identity is the age *identity file* — for the YubiKey plugin
	// it is a stub naming the card + slot, not key material.
	Age       string `yaml:"age,omitempty"`        // age binary (age.exe under wsl-windows)
	PluginDir string `yaml:"plugin_dir,omitempty"` // dir holding age-plugin-yubikey(.exe)
	Identity  string `yaml:"identity,omitempty"`

	// Grants.
	RuntimeDir    string `yaml:"runtime_dir,omitempty"`     // tmpfs dir; default $XDG_RUNTIME_DIR/mint-key
	AllowNonTmpfs bool   `yaml:"allow_non_tmpfs,omitempty"` // opt out of the tmpfs requirement (unsafe)
	DefaultTTL    string `yaml:"default_ttl,omitempty"`     // default grant lifetime

	Scopes []SecretScope `yaml:"scopes,omitempty"`
}

// scopesDoc is the on-disk shape of an external scopes file.
type scopesDoc struct {
	Scopes []Scope `yaml:"scopes"`
}

// configPath resolves the active config file: $MINTK_CONFIG wins, otherwise
// ~/.config/mint-key/config.yaml.
func configPath() string {
	if p := os.Getenv("MINTK_CONFIG"); p != "" {
		return expandPath(p)
	}
	return filepath.Join(configDir(), "config.yaml")
}

// configDir is ~/.config/mint-key (honours $XDG_CONFIG_HOME).
func configDir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home(), ".config")
	}
	return filepath.Join(base, "mint-key")
}

func home() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return os.Getenv("HOME")
}

// expandPath expands a leading ~ to the user's home directory.
func expandPath(p string) string {
	if p == "~" {
		return home()
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home(), p[2:])
	}
	return p
}

// firstPubKeyLine returns the first line of `data` that actually parses as an
// SSH public key, with control characters stripped; blank lines, comments and
// junk are skipped. Whatever produced a ca.pub (a captured command's output, a
// paste, an editor) can leave garbage in it — a terminal title escape has been
// seen in the wild — and shipping that to a host's TrustedUserCAKeys is worse
// than cosmetic: sshd's key-file parser gives up at the first unparsable line,
// so anything listed after it stops being trusted.
func firstPubKeyLine(data string) (string, error) {
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimSpace(stripControl(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || !looksLikeKeyType(f[0]) {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(f[1]); err != nil {
			continue
		}
		return line, nil
	}
	return "", fmt.Errorf("no SSH public key line found")
}

// stripControl drops ASCII control characters, which is what escape sequences
// that sneak into a key file are made of.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// looksLikeKeyType reports whether tok is a plausible SSH public key algorithm.
func looksLikeKeyType(tok string) bool {
	for _, p := range []string{"ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-", "rsa-sha2-"} {
		if strings.HasPrefix(tok, p) {
			return true
		}
	}
	return false
}

// loadConfig reads and validates the config file.
func loadConfig() (*Config, error) {
	path := configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no config at %s\n"+
				"  create it (see config.example.yaml) or set $MINTK_CONFIG", path)
		}
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.path = path
	c.applyDefaults()
	if err := c.loadScopes(); err != nil {
		return nil, err
	}
	return &c, nil
}

// loadScopes pulls scopes from ScopesFile when set (a missing file is treated as
// "no scopes yet", not an error — the user may be about to add some).
func (c *Config) loadScopes() error {
	if c.ScopesFile == "" {
		return nil
	}
	c.scopesExternal = true
	p := expandPath(c.ScopesFile)
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			c.Scopes = nil
			return nil
		}
		return err
	}
	var sf scopesDoc
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("parse %s: %w", p, err)
	}
	c.Scopes = sf.Scopes
	return nil
}

// scopesFilePath returns the expanded external scopes file path ("" if unset).
func (c *Config) scopesFilePath() string {
	if c.ScopesFile == "" {
		return ""
	}
	return expandPath(c.ScopesFile)
}

// scopesDest is the file scope edits are written to (external file or the config).
func (c *Config) scopesDest() string {
	if c.ScopesFile != "" {
		return c.scopesFilePath()
	}
	return c.path
}

// applyDefaults fills in the values that have a sensible default so the rest of
// the code can rely on them being set.
func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = "agent"
	}
	if c.SessionsDir == "" {
		c.SessionsDir = filepath.Join(home(), ".ssh", "sessions")
	}
	c.Secrets.applyDefaults()
}

// applyDefaults fills in the secret-grant defaults. Safe on a nil receiver — a
// config without a `secrets:` block simply has the subsystem unconfigured.
func (s *SecretsConfig) applyDefaults() {
	if s == nil {
		return
	}
	if s.Mode == "" {
		// Mirror the CA mode recommendation: under WSL the card is reachable
		// from Windows, everywhere else the local age client talks to it.
		if inWSL() {
			s.Mode = secretModeWSL
		} else {
			s.Mode = secretModeNative
		}
	}
	if s.Dir == "" {
		s.Dir = "secrets"
	}
	if s.DefaultTTL == "" {
		s.DefaultTTL = "8h"
	}
	if s.Age == "" && s.Mode != secretModeWSL {
		s.Age = "age"
	}
}

// secretsConfig returns the secret-grant config, or an error explaining that the
// subsystem isn't set up yet.
func (c *Config) secretsConfig() (*SecretsConfig, error) {
	if c.Secrets == nil {
		return nil, fmt.Errorf("no `secrets:` block in %s\n"+
			"  see config.example.yaml and docs/secrets.md to set up secret grants", c.path)
	}
	return c.Secrets, nil
}

// repoPath is the expanded blob-repo root.
func (s *SecretsConfig) repoPath() string { return expandPath(s.Repo) }

// blobDir is the expanded directory holding one age blob per scope.
func (s *SecretsConfig) blobDir() string { return filepath.Join(s.repoPath(), s.Dir) }

// scope looks up the declared policy for a secret scope.
func (s *SecretsConfig) scope(name string) (*SecretScope, bool) {
	for i := range s.Scopes {
		if s.Scopes[i].Name == name {
			return &s.Scopes[i], true
		}
	}
	return nil, false
}

// sessionsDir returns the expanded throwaway-key directory.
func (c *Config) sessionsDir() string { return expandPath(c.SessionsDir) }

// caPubPath returns the expanded CA public key path.
func (c *Config) caPubPath() string { return expandPath(c.CAPub) }

// caKeyPath returns the expanded CA private key path (software mode).
func (c *Config) caKeyPath() string { return expandPath(c.CAKey) }

// scope looks up a scope by name.
func (c *Config) scope(name string) (*Scope, bool) {
	for i := range c.Scopes {
		if c.Scopes[i].Name == name {
			return &c.Scopes[i], true
		}
	}
	return nil, false
}

// save writes the config back to its file as YAML, creating the directory if
// needed. The private `path` field is preserved across the round-trip.
func (c *Config) save() error {
	if c.path == "" {
		c.path = configPath()
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	// Don't duplicate scopes inline when they live in an external file.
	out := *c
	if c.ScopesFile != "" {
		out.Scopes = nil
	}
	data, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0o600)
}

// saveScopes persists the scope list to the external scopes file when one is
// configured, otherwise back into the main config.
func (c *Config) saveScopes() error {
	if c.ScopesFile == "" {
		return c.save()
	}
	p := c.scopesFilePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(scopesDoc{Scopes: c.Scopes})
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}
