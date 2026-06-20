# Spec — rewrite `mint` (bash) as a Go binary `mintk`

Implementation brief for a focused build. The current **bash `mint`** in the repo root is
the working reference implementation — read it and [design.md](design.md) for exact
behaviour; this doc specifies the Go rewrite. Keep the bash version until the Go one is
validated end-to-end (mint a cert via the YubiKey agent → ssh into a host).

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

### `mintk scopes list | add | delete | edit`
CRUD over `scopes` in the YAML.
- `list` — table of name / principal / ttl.
- `add <name> <principal> [<ttl>]` and `delete <name>` — non-interactive edits.
- `edit` — **interactive huh-based editor like wg-hop's `editCmd`/`runEditConfig`**:
  pick a scope to edit, or add/delete, accumulate changes, write the YAML on exit.
  (wg-hop uses charmbracelet/huh forms — mirror that look/flow.)

### `mintk clean`
Windows-cert-store hygiene for the WSL+Windows-agent path. Multiple YubiKeys carrying
the same CA key each enroll a cert (identical pubkey) into `CurrentUser\My`; the agent
can then try a container whose card isn't plugged → "agent refused operation". `clean`:
purge every `CurrentUser\My` cert whose subject matches `ca_cert_cn`
(`Get-ChildItem Cert:\CurrentUser\My | Where Subject -like … | Remove-Item` via
`powershell.exe`), then **prompt the user to unplug + re-plug** the YubiKey they want —
Windows' Certificate Propagation re-enrolls only its (linked) cert. (Port the bash
`clean_store`.) Gate on WSL.

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

## Platform notes (hard-won — carry into the implementation)

From design.md / the build log: native Win32 `ssh-keygen` has no PKCS#11; Git-Bash
(Cygwin) `ssh-keygen` crashes loading a native PKCS#11 DLL; usbipd detaches the key from
Windows. The **validated path is agent + `ssh-keygen -U`**: YubiKey → minidriver/CNG →
WinCryptSSHAgent on the `openssh-ssh-agent` pipe → npiperelay bridge → WSL agent →
`ssh-keygen -U`. The YubiKey Smart Card Minidriver is required (CNG won't expose ECDSA
otherwise) and the slot-9c cert must be in `CurrentUser\My` (re-plug after installing the
minidriver). `mintk` targets this path; `clean` handles the multi-card collision.

## Migration & compat

- One-time: read the old bash config if present and offer to write `config.yaml`.
- Don't break the working bash `mint` — leave it in the repo until `mintk` is validated;
  then update README to point at `mintk`, and the installer (the prereq/installer task)
  to build/install `mintk` into `/usr/local/bin`.

## Done when

`mintk scopes edit` manages scopes; `mintk key <scope>` mints via the YubiKey agent and
`ssh <host>` logs in with the cert; `mintk clean` recovers after a YubiKey swap;
`mintk deploy <scope> user@host` makes a fresh host accept the cert. Cross-platform build
(Linux/macOS/WSL); generic/public-safe.
