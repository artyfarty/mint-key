package main

import (
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

	path           string // where this config was loaded from
	scopesExternal bool   // scopes came from ScopesFile
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
