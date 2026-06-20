package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

func deployCmd() *cobra.Command {
	var noSSHConfig bool
	cmd := &cobra.Command{
		Use:   "deploy <scope> <user@host|alias>",
		Short: "Enroll a host to trust the CA and accept the scope's principal (ssh-copy-id for the CA)",
		Long: `Uses your current SSH access to the target to, via sudo:
  - append ca_pub to /etc/ssh/trusted-user-ca-keys.pub (dedup'd)
  - ensure sshd_config has TrustedUserCAKeys + AuthorizedPrincipalsFile
  - append the scope's principal to /etc/ssh/auth_principals/<login-user>
  - sshd -t, then reload sshd
The target may be a full user@host or a ~/.ssh/config alias (resolved via
ssh -G). sudo can prompt for a password interactively (a PTY is allocated).
Then, unless --no-ssh-config, ~/.ssh/config is updated so "ssh <target>" uses
the minted cert (IdentityFile = the scope's session key, IdentitiesOnly yes).
Idempotent; reports what changed.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runDeploy(cfg, args[0], args[1], !noSSHConfig)
		},
	}
	cmd.Flags().BoolVar(&noSSHConfig, "no-ssh-config", false,
		"Don't add/edit the host in ~/.ssh/config")
	return cmd
}

func runDeploy(cfg *Config, scopeName, target string, editSSHConfig bool) error {
	sc, ok := cfg.scope(scopeName)
	if !ok {
		return fmt.Errorf("unknown scope %q (try: %s scopes list)", scopeName, prog)
	}
	caPub := cfg.caPubPath()
	if caPub == "" || !fileExists(caPub) {
		return fmt.Errorf("set ca_pub to your CA public key")
	}
	caLine, err := os.ReadFile(caPub)
	if err != nil {
		return err
	}

	user, hostname := resolveSSHTarget(target)
	fmt.Printf("%s: target %q → login user %q, host %q\n", prog, target, user, hostname)

	script := buildTrustScript(strings.TrimSpace(string(caLine)), user, sc.Principal)

	// 1) stream the script to a temp file on the host (plain user, no sudo).
	remotePath := "/tmp/mintk-trust.sh"
	stage := exec.Command("ssh", target, "cat > "+remotePath+" && chmod 700 "+remotePath)
	stage.Stdin = strings.NewReader(script)
	stage.Stdout = os.Stdout
	stage.Stderr = os.Stderr
	if err := stage.Run(); err != nil {
		return fmt.Errorf("stage script on %s: %w", target, err)
	}

	// 2) run it under sudo over a PTY session so sudo can prompt for a password
	//    interactively. The script is read from the file (not stdin), leaving the
	//    terminal free for the password prompt.
	fmt.Printf("%s: enrolling %s on %s (principal=%s) — sudo may prompt for a password...\n",
		prog, scopeName, target, sc.Principal)
	apply := exec.Command("ssh", "-t", target,
		"sudo bash "+remotePath+"; rc=$?; rm -f "+remotePath+"; exit $rc")
	apply.Stdin = os.Stdin
	apply.Stdout = os.Stdout
	apply.Stderr = os.Stderr
	if err := apply.Run(); err != nil {
		return fmt.Errorf("remote enroll failed: %w", err)
	}

	// 3) make `ssh <target>` use the minted cert.
	if editSSHConfig {
		alias := aliasOf(target)
		identityFile := path.Join(cfg.SessionsDir, scopeName) // keep ~ form for ssh
		change, err := ensureSSHConfigHost(sshConfigPath(), alias, hostname, user, identityFile)
		if err != nil {
			fmt.Printf("%s: warning — could not update ~/.ssh/config: %s\n", prog, err)
		} else if change != "" {
			fmt.Printf("%s: ssh config — %s\n", prog, change)
		} else {
			fmt.Printf("%s: ssh config already up to date for %s\n", prog, alias)
		}
		fmt.Printf("%s: now `mintk key %s` then `ssh %s`.\n", prog, scopeName, alias)
	}
	return nil
}

// sshConfigPath returns ~/.ssh/config.
func sshConfigPath() string {
	return path.Join(home(), ".ssh", "config")
}

// buildTrustScript renders the idempotent host-side enrollment script with the
// CA line, login user, and principal embedded as safely-quoted shell literals.
func buildTrustScript(caLine, user, principal string) string {
	var b strings.Builder
	b.WriteString("#!/usr/bin/env bash\nset -euo pipefail\n")
	b.WriteString("ca_line=" + shQuote(caLine) + "\n")
	b.WriteString("user=" + shQuote(user) + "\n")
	b.WriteString("principal=" + shQuote(principal) + "\n")
	b.WriteString(`
if [ "$(id -u)" != 0 ]; then echo "trust: must run as root" >&2; exit 1; fi
id "$user" >/dev/null 2>&1 || { echo "trust: login user '$user' does not exist" >&2; exit 1; }

ca_store=/etc/ssh/trusted-user-ca-keys.pub
sshd_config=/etc/ssh/sshd_config
princ_dir=/etc/ssh/auth_principals
ca_body=$(printf '%s\n' "$ca_line" | awk '{print $2}')

# 1) add the CA pubkey (dedup by key body)
touch "$ca_store"; chmod 644 "$ca_store"
if ! grep -qF "$ca_body" "$ca_store" 2>/dev/null; then
  printf '%s\n' "$ca_line" >> "$ca_store"
  echo "trust: added CA to $ca_store"
else
  echo "trust: CA already trusted in $ca_store"
fi

# 2) ensure sshd_config directives
ensure_directive() {
  local key=$1 val=$2
  if grep -Eq "^[[:space:]]*${key}[[:space:]]" "$sshd_config"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$sshd_config"
  else
    printf '%s %s\n' "$key" "$val" >> "$sshd_config"
  fi
}
ensure_directive TrustedUserCAKeys "$ca_store"
ensure_directive AuthorizedPrincipalsFile "$princ_dir/%u"

# 3) principal for the login user (append, dedup — keep any existing principals)
install -d -m 755 "$princ_dir"
touch "$princ_dir/$user"; chmod 644 "$princ_dir/$user"
if ! grep -qxF "$principal" "$princ_dir/$user" 2>/dev/null; then
  printf '%s\n' "$principal" >> "$princ_dir/$user"
  echo "trust: $user now accepts principal '$principal'"
else
  echo "trust: $user already accepts principal '$principal'"
fi

# 4) validate + reload
sshd -t || { echo "trust: sshd config validation failed — NOT reloading" >&2; exit 1; }
if   command -v systemctl >/dev/null 2>&1; then systemctl reload ssh 2>/dev/null || systemctl reload sshd
elif command -v service   >/dev/null 2>&1; then service ssh reload 2>/dev/null || service sshd reload
else kill -HUP "$(cat /var/run/sshd.pid 2>/dev/null || pgrep -o sshd)"; fi
echo "trust: sshd reloaded — done"
`)
	return b.String()
}

// shQuote single-quotes a string for safe embedding in a bash script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
