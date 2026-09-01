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
	var identity string
	var password bool
	cmd := &cobra.Command{
		Use:   "deploy <scope> <user@host|alias>",
		Short: "Enroll a host to trust the CA and accept the scope's principal (ssh-copy-id for the CA)",
		Long: `Uses your current SSH access to the target to, via sudo:
  - append ca_pub to /etc/ssh/trusted-user-ca-keys.pub (dedup'd)
  - ensure sshd_config has TrustedUserCAKeys + AuthorizedPrincipalsFile
  - append the scope's principal to /etc/ssh/auth_principals/<login-user>
  - sshd -t, then reload sshd (a no-op on macOS: launchd re-reads the config
    per connection, so there is no daemon to signal)
The target may be a full user@host or a ~/.ssh/config alias (resolved via
ssh -G). Everything runs over a single SSH connection, so you are asked to
authenticate exactly once (one password, or one YubiKey tap); sudo then prompts
on the allocated PTY.
Bootstrapping a host you have no key on: --password authenticates with the
account password (public-key auth is turned off for that connection), so no key
needs to be installed by hand first. Use -i/--identity instead to pick a
specific key (passed straight to ssh -i).
Then, unless --no-ssh-config, ~/.ssh/config is updated so "ssh <target>" uses
the minted cert (IdentityFile = the scope's session key, IdentitiesOnly yes).
Idempotent; reports what changed.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runDeploy(cfg, args[0], args[1], !noSSHConfig, identity, password)
		},
	}
	cmd.Flags().BoolVar(&noSSHConfig, "no-ssh-config", false,
		"Don't add/edit the host in ~/.ssh/config")
	cmd.Flags().StringVarP(&identity, "identity", "i", "",
		"SSH identity file to authenticate to the target (ssh -i)")
	cmd.Flags().BoolVar(&password, "password", false,
		"Authenticate to the target with a password instead of a key (bootstrap a fresh host)")
	return cmd
}

func runDeploy(cfg *Config, scopeName, target string, editSSHConfig bool, identity string, password bool) error {
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

	// Auth options for the (single) ssh invocation. With -i we also force
	// IdentitiesOnly so the explicit key is the only one offered; with --password
	// we turn public-key auth off entirely so a fresh host needs no key at all.
	var authOpts []string
	switch {
	case password:
		authOpts = append(authOpts,
			"-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=keyboard-interactive,password")
	case identity != "":
		authOpts = append(authOpts, "-i", expandPath(identity), "-o", "IdentitiesOnly=yes")
	}

	// One connection does the whole job: the script travels inside the remote
	// command as a quoted here-doc (not over stdin), so the PTY stays free for
	// sudo's password prompt and you authenticate only once.
	fmt.Printf("%s: enrolling %s on %s (principal=%s) — sudo may prompt for a password...\n",
		prog, scopeName, target, sc.Principal)
	remote := "umask 077\ncat > " + remoteScriptPath + " <<'MINTK_TRUST_EOF'\n" +
		script + "MINTK_TRUST_EOF\n" +
		"sudo bash " + remoteScriptPath + "; rc=$?; rm -f " + remoteScriptPath + "; exit $rc\n"

	apply := exec.Command("ssh", append(append([]string{}, authOpts...), "-t", target, remote)...)
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

// remoteScriptPath is where the enrollment script lands on the target; it is
// removed again as soon as sudo is done with it.
const remoteScriptPath = "/tmp/mintk-trust.sh"

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

# 2) ensure sshd_config directives.
# NB: no "sed -i" — BSD/macOS sed would eat the next argument as the backup
# suffix. Rewrite through a temp file and copy back, keeping mode and owner.
ensure_directive() {
  key=$1; val=$2
  if grep -Eq "^[[:space:]]*${key}[[:space:]]" "$sshd_config"; then
    tmp=$(mktemp) || { echo "trust: mktemp failed" >&2; return 1; }
    sed -E "s|^[[:space:]]*${key}[[:space:]].*|${key} ${val}|" "$sshd_config" > "$tmp"
    cat "$tmp" > "$sshd_config"
    rm -f "$tmp"
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

# 4) validate
sshd -t || { echo "trust: sshd config validation failed — NOT reloading" >&2; exit 1; }

# 5) check the directives actually took effect (an earlier Include/drop-in or a
#    Match block can shadow what we just wrote).
eff=$(sshd -T 2>/dev/null | tr 'A-Z' 'a-z' || true)
if [ -n "$eff" ]; then
  printf '%s\n' "$eff" | grep -q "^trustedusercakeys $ca_store$" \
    || echo "trust: WARNING — effective TrustedUserCAKeys is not $ca_store; check Include/Match blocks in $sshd_config" >&2
  printf '%s\n' "$eff" | grep -q "^authorizedprincipalsfile $princ_dir/" \
    || echo "trust: WARNING — effective AuthorizedPrincipalsFile is not $princ_dir/%u; check Include/Match blocks in $sshd_config" >&2
fi

# 6) reload. Never fatal: the config on disk is already correct, and a host we
#    could not signal simply picks it up on its next sshd start.
if [ "$(uname -s)" = Darwin ]; then
  # launchd socket-activates sshd per connection, so each new connection reads
  # the config afresh — there is nothing to reload.
  echo "trust: macOS — sshd is launchd-activated, config applies to new connections"
elif command -v systemctl >/dev/null 2>&1; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
    || echo "trust: WARNING — could not reload sshd; restart it to apply" >&2
elif command -v rc-service >/dev/null 2>&1; then
  rc-service sshd reload 2>/dev/null \
    || echo "trust: WARNING — could not reload sshd; restart it to apply" >&2
elif command -v service >/dev/null 2>&1; then
  service ssh reload 2>/dev/null || service sshd reload 2>/dev/null \
    || echo "trust: WARNING — could not reload sshd; restart it to apply" >&2
else
  pid=$(cat /var/run/sshd.pid 2>/dev/null || pgrep -o sshd 2>/dev/null || true)
  if [ -n "$pid" ]; then kill -HUP "$pid"
  else echo "trust: WARNING — no sshd process found to signal; config applies on next start" >&2; fi
fi
echo "trust: done"
`)
	return b.String()
}

// shQuote single-quotes a string for safe embedding in a bash script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
