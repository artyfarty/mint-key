# Spec — the `mintk` Go binary

Design/build brief for `mintk`. It began as a rewrite of an earlier bash `mint` script
(now removed); see [design.md](design.md) for the model and behaviour. `mintk` has been
validated end-to-end (mint a cert via the YubiKey agent → ssh into a host); the
implementation status is at the end of this doc.

## Goal & name

A single static Go binary that issues short-lived, scope-limited OpenSSH user
certificates from a YubiKey-held CA, manages its scopes, keeps the Windows cert store
sane across YubiKey swaps, and enrolls hosts to trust the CA.

- **Binary name: `mintk`** (`mint` collides with the Mint-lang compiler, which also
  installs `mint`).
- Generic / public-safe: **no** real hostnames, IPs, CA keys, or principal names in the
  repo. Real values live in the operator's config outside the repo.

## Config — YAML at `~/.config/mint-key/`

Move off the old bash location (`~/.config/mint/config`, shell-sourced). New home:
`~/.config/mint-key/config.yaml` (resolve `$MINTK_CONFIG` override first, then this).
The CA public key and throwaway session keys also live under `~/.config/mint-key/` and
`~/.ssh/sessions/` respectively.

Schema (fields mirror the bash config vars):

```yaml
ca_pub: ~/.config/mint-key/ca.pub      # CA public key (identifies the CA in agent/token modes)
mode: agent                            # agent | token | software | wsl-delegate
sessions_dir: ~/.ssh/sessions          # throwaway per-scope keys + minted certs
source_address: ""                     # optional -O source-address=... lock (empty = off)

# agent mode (recommended; YubiKey exposed to the ssh-agent, e.g. via WinCryptSSHAgent)
ca_cert_cn: ssh-user-ca-mintkey        # the CA cert subject CN — used by `clean`

# token mode (local PKCS#11, YubiKey attached to this machine)
ykcs11: ""                             # path; auto-detect libykcs11/opensc-pkcs11 if empty

# software mode (testing only)
ca_key: ""                             # CA private key file

# windows helpers (WSL): ykman.exe for `clean`
win_ykman: "/mnt/c/Program Files/Yubico/YubiKey Manager CLI/ykman.exe"

scopes:
  - name: example-host
    principal: host-example
    ttl: 8h
  - name: general
    principal: general
    ttl: 24h
```

Ship `config.example.yaml` with placeholders; never commit a real one.

## Dependencies (match wg-hop's versions — already vetted, no <3-day packages)

- `github.com/spf13/cobra v1.10.2` — command tree
- `github.com/charmbracelet/huh v1.0.0` — interactive forms for `scopes edit`
- `gopkg.in/yaml.v3 v3.0.1` — config

Pin exactly; mirror wg-hop's stack so it builds with the same toolchain (Go 1.25).

## Commands (cobra; mirror wg-hop's structure & `edit` UX)

### `mintk init`
Interactive bootstrap of `~/.config/mint-key/config.yaml` for a new machine: pick a
signing mode, **import the CA public key** (autodetect — inserted YubiKey via
`ssh-keygen -D <pkcs11>`, then the ssh-agent via `ssh-add -L`, then paste/file), write it
to `~/.config/mint-key/ca.pub`, and optionally set `scopes_file` (cloning the scopes git
repo if given a URL). Refuses to clobber an existing config without `--force`.

### `mintk doctor`
Read-only prerequisite check (replaces the old `install.sh check`): OpenSSH tools +
version (`-U` needs ≥7.6), the CA public key (+ fingerprint), and the pieces the
configured mode needs — agent reachable with the CA loaded / a PKCS#11 module readable /
software key file / wsl-delegate Windows paths — plus the scopes file. Exits non-zero on a
failed required check. Works without a config (checks common + both backends, nudges to
`mintk init`).

### `mintk key <scope> [<ttl>]`
Mint a cert for `<scope>` (default ttl from the scope). Port the bash signing modes:

- **agent** (`mode: agent`): verify the CA key (matching `ca_pub`) is in the ssh-agent;
  `ssh-keygen -U -s ca_pub -I <id> -n <principal> -V +<ttl> -z <serial> [-O source-address] key.pub`
  — the agent (YubiKey) signs; PIN dialog + tap happen on the Windows side. On failure,
  print the agent-refused hint (stale cert from a swapped YubiKey → plug the right card
  or `mintk clean`). This is the validated path. See design.md "Agent mode".
- **token** (`mode: token`): `ssh-keygen -s ca_pub -D <pkcs11> …` (local YubiKey).
- **software** (`mode: software`): `ssh-keygen -s ca_key …` (testing only).
- Ensure a throwaway ed25519 key at `sessions_dir/<scope>`; the private key never leaves
  this host. After signing, `ssh-add -t <ttl> <key>` into the agent (best-effort).
- Detect WSL (`/proc/version` contains microsoft/wsl) where it affects behaviour.

Prefer driving `ssh-keygen` as a subprocess (same flags as bash) over reimplementing
cert signing in Go — the agent/PKCS#11 paths are battle-tested via `ssh-keygen`.

### `mintk scopes list | add | delete | edit | pull | push`
CRUD over `scopes` in the YAML.
- `list` — table of name / principal / ttl.
- `add <name> <principal> [<ttl>]` and `delete <name>` — non-interactive edits.
- `edit` — **interactive huh-based editor like wg-hop's `editCmd`/`runEditConfig`**:
  pick a scope to edit, or add/delete, accumulate changes, write the YAML on exit.
  (wg-hop uses charmbracelet/huh forms — mirror that look/flow.)
- `pull` / `push` — when `scopes_file` is set (see below), `git pull --ff-only` /
  `git add+commit+push` the scopes repo, for sharing the scope list across machines.

**Shared scopes (`scopes_file`):** the scope list (alias → principal → ttl) can live in a
separate YAML, typically a private git repo, so it travels across machines. When set, the
`scopes` block in `config.yaml` is ignored; scope edits read/write `scopes_file` instead.
The host↔principal/deploy mapping is intentionally *not* synced (it stays in `~/.ssh/config`
and the operator's head) — only the principal/alias catalogue is shared.

### `mintk clean`
Windows-cert-store hygiene for the WSL+Windows-agent path. Multiple YubiKeys carrying
the same CA key each enroll a cert (identical pubkey) into `CurrentUser\My`; the agent
can then try a container whose card isn't plugged → "agent refused operation". `clean`:
purge every `CurrentUser\My` cert whose subject matches `ca_cert_cn`
(`Get-ChildItem Cert:\CurrentUser\My | Where Subject -like … | Remove-Item` via
`powershell.exe`), then **prompt the user to unplug + re-plug** the YubiKey they want —
Windows' Certificate Propagation re-enrolls only its (linked) cert. (Port the bash
`clean_store`.) Gate on WSL.

### `mintk clean-keys`
Local cleanup of minted identities (distinct from `clean`, which is the Windows
cert-store command). Removes every throwaway per-scope key and minted cert under
`sessions_dir` — the `mintk key` output. The private keys there never leave the
host and are re-created on the next `mintk key`, so wiping them only forces a
fresh tap/sign; useful for tidy-up or before handing a machine off. Prompts for
confirmation (default No); `-y`/`--yes` skips the prompt for scripts, and is
required when stdin isn't a terminal. Leaves the `sessions_dir` itself in place.

### `mintk secret …`
The secret-grant subsystem — cert minting's shape applied to credentials. Subcommands
`init` / `grant` / `run` / `path` / `list` / `revoke` / `print` / `edit` / `rm` / `pull` /
`push` / `sweep` (plus a hidden `_reap` the wipers re-exec). `secret init` mirrors
`mintk init` — interactive, merges into an existing config, autodetects the age/plugin
binaries (resolving `%USERPROFILE%` under WSL), reads the card's identities and asks which
**slot** to use, and uses/clones/creates the blob repo. It **never writes to the YubiKey**:
generating an identity in a retired slot stays a separate, deliberate command. Kept in `mintk` rather than a separate
binary because it shares the config, path/WSL helpers, git sync and `doctor`; it is
self-contained in `secret.go` / `secretage.go` / `secretgrant.go`. Configured under a
`secrets:` block; absent from a cert-only config. Full design, decisions and platform
quirks: [secrets.md](secrets.md).

### `mintk deploy <scope> user@host`
"ssh-copy-id for the CA": enroll a host to trust the CA + accept the scope's principal,
using the operator's current SSH access to the host. Port the repo's `trust-ca` logic,
run remotely (needs sudo on the host):
1. `ssh user@host` and, via sudo: append `ca_pub` to `/etc/ssh/trusted-user-ca-keys.pub`
   (dedup), ensure `sshd_config` has `TrustedUserCAKeys` + `AuthorizedPrincipalsFile
   /etc/ssh/auth_principals/%u`, append the scope's `principal` to
   `/etc/ssh/auth_principals/<login-user>`, `sshd -t` then reload.
2. Idempotent; report what changed.
Stream the CA pubkey + a small remote script over the SSH session (don't depend on the
repo's bash `trust-ca` being present on the host).

Extra behaviour (implemented):
- **Alias-aware target:** `user@host` *or* a `~/.ssh/config` alias — resolved via
  `ssh -G <target>` to the effective login user + hostname (the login user is what the
  principal is appended to in `auth_principals/`).
- **Interactive sudo:** the enroll step runs over `ssh -t` (a PTY), so `sudo` can prompt
  for a password on the terminal; the script is read from a staged file, not stdin, so
  the prompt isn't consumed.
- **~/.ssh/config wiring:** unless `--no-ssh-config`, add/edit `Host <alias>` with
  `IdentityFile <sessions_dir>/<scope>` + `IdentitiesOnly yes` so `ssh <alias>` uses the
  minted cert and nothing else. Idempotent; existing `HostName`/`User`/other directives
  in the block are preserved.
- **Bootstrap identity:** `-i`/`--identity <file>` is passed straight to the `ssh`
  invocations that connect to the target (`ssh -i <file> -o IdentitiesOnly=yes`), for
  authenticating with a chosen key — e.g. a password/bootstrap key when the cert isn't
  trusted yet. It affects only the enrollment connection, not the staged trust script.

### CLI behaviour (all commands)
When a command is invoked with the wrong number/shape of positional arguments or an
unknown flag, `mintk` prints that command's full help (not just a one-line error) before
the error. Implemented in `main.go`: a recursive wrapper over each command's `Args`
validator, plus a root `FlagErrorFunc` (inherited by subcommands) for flag-parse errors.
`SilenceUsage`/`SilenceErrors` stay on so *runtime* errors (bad config, signing failures)
don't dump usage.

## Platform notes (hard-won — carry into the implementation)

From design.md / the build log: native Win32 `ssh-keygen` has no PKCS#11; Git-Bash
(Cygwin) `ssh-keygen` crashes loading a native PKCS#11 DLL; usbipd detaches the key from
Windows. The **validated path is agent + `ssh-keygen -U`**: YubiKey → minidriver/CNG →
WinCryptSSHAgent on the `openssh-ssh-agent` pipe → npiperelay bridge → WSL agent →
`ssh-keygen -U`. The YubiKey Smart Card Minidriver is required (CNG won't expose ECDSA
otherwise) and the slot-9c cert must be in `CurrentUser\My` (re-plug after installing the
minidriver). `mintk` targets this path; `clean` handles the multi-card collision.

## Install

`make` builds the binary; `make install` puts it in `$(PREFIX)/bin` (default
`/usr/local`). Then `mintk doctor` checks prerequisites (per platform / per mode) and
`mintk init` creates the config (importing the CA from the YubiKey). The earlier bash
`mint`, its `~/.config/mint/` config, and the `install.sh` bootstrap have been removed;
there is no migration path.

## Done when

`mintk scopes edit` manages scopes; `mintk key <scope>` mints via the YubiKey agent and
`ssh <host>` logs in with the cert; `mintk clean` recovers after a YubiKey swap;
`mintk deploy <scope> user@host` makes a fresh host accept the cert. Cross-platform build
(Linux/macOS/WSL); generic/public-safe.

## Status (implementation)

The Go binary is implemented at repo root (`go build -o mintk .`, module `mintk`,
Go 1.25 toolchain, cobra/huh/yaml pinned to wg-hop's versions). Layout: `main.go`
(cobra root), `config.go` (YAML + `~`-expansion + `$MINTK_CONFIG` + external `scopes_file`
load/save), `init.go` (`mintk init` bootstrap + CA import), `key.go` (all four signing
modes + agent fingerprint check + agent-refused hint), `doctor.go` (`mintk doctor`
prerequisite checks), `scopes.go` (list/add/delete + huh `edit` loop + git pull/push),
`clean.go`, `cleankeys.go` (`mintk clean-keys` — wipe `sessions_dir` with confirm/`-y`),
`deploy.go` (streams an idempotent trust script over SSH, sudo via `ssh -t`, `-i` bootstrap
identity, alias resolution via `ssh -G`), `sshconfig.go` (add/edit `Host` blocks; unit-tested in
`sshconfig_test.go`), `platform.go` (WSL/PKCS#11/path helpers), `prompt.go` (huh helpers).
`config.example.yaml` ships placeholders; the `Makefile` builds/installs. The secret-grant
subsystem adds `secret.go` (command tree, consumption paths, `edit`), `secretage.go` (blob
repo + the age client's per-OS card-access modes), `secretgrant.go` (tmpfs runtime dir,
grant records, the independent wiper, `sweep`), `secretinit.go` (`secret init`: read-only
card queries, binary autodetection, repo setup) and `secret_test.go`.

- **Validated:** the agent (`-U`) path end-to-end on the WSL+Windows setup (mint via the
  YubiKey agent → `ssh` into a host) — `mintk` is in daily use. Plus software-mode
  end-to-end (scopes CRUD → `key` signs → `ssh-keygen -L` shows the right
  principal/validity), ttl validation, unknown-scope errors, `clean` WSL gating, the
  `~/.ssh/config` editor (`go test`), `go vet`/`gofmt` clean.
- **Not yet hardware-validated:** the token (PKCS#11) path and `deploy` against a live
  host — these need the YubiKey-on-this-machine / a target host in the loop (see
  [prerequisites.md](prerequisites.md)).
- **Secret grants — validated:** the full lifecycle in `software` mode against a real `age`
  (grant burst → `list`/`path`/`run` env injection + exit-status passthrough → `revoke` →
  `edit` create/modify/no-op/empty-refusal → `rm` → git commits), both wiper paths firing
  with no `mintk` process alive (systemd transient timer and the detached reaper), the
  sweep of expired grants / orphaned plaintext / a `SIGKILL`ed edit workspace, the signal
  wipe, and the non-tmpfs refusal plus its opt-out. The Windows-interop plugin lookup that
  `mode: wsl-windows` depends on is covered by an opt-in test
  (`MINTK_TEST_WIN_PLUGIN_DIR=<dir> go test -run Interop`), verified here.
- **The `wsl-windows` pipeline — validated** against the real Windows `age.exe` v1.3.1 run
  from WSL through interop: `doctor`, encrypt (`secret edit` → armoured blob → git commit)
  and decrypt (`secret grant` → tmpfs) all end-to-end, with a payload carrying CRLF, a lone
  CR and NUL bytes coming back **byte-for-byte identical** — the stdin/stdout pipe mangles
  nothing. Run with an X25519 identity, so the plugin and card are the one piece still
  unproven from inside `mintk`.
- **Not yet hardware-validated:** a decrypt through `age-plugin-yubikey` against the card
  (the plugin lookup mechanism itself is covered by the opt-in interop test), and the
  interactive walkthrough of `secret init` — its huh prompts can't be driven from a script,
  the same way `mintk init` and `scopes edit` can't. Its non-interactive guard rails, the
  `--list`/`--identity` parsers and the Windows binary autodetection (`where.exe` +
  `%USERPROFILE%` globbing, verified finding a winget-installed `age.exe`) were exercised
  here.
- The earlier bash `mint`, its `~/.config/mint/` config, and the `trust-ca` helper have
  been removed.
