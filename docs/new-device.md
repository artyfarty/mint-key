# Onboarding a new client device

How to bring `mintk` up on a fresh machine so that `mintk key <scope>` mints a cert and
you can SSH with it. This stitches together the per-platform [prerequisites](prerequisites.md)
into one procedure. Everything here is generic — substitute your own scope names, scopes
repo, and PKCS#11 paths.

> A "client device" is anything you *mint from*. It needs the CA **public** key + a way to
> reach the CA **private** key (a YubiKey, via the ssh-agent or PKCS#11). It does **not**
> need the CA private key on disk. Making a host *accept* certs is a separate step — see
> [Host side](#host-side).

## 0. Pick the signing mode for this machine

| Mode | When | What reaches the CA |
| --- | --- | --- |
| `token` | YubiKey plugs **into this machine** (Linux, macOS) | local PKCS#11 module (`libykcs11` / OpenSC) |
| `agent` | YubiKey lives on **Windows**, you mint from **WSL** | the Windows ssh-agent over the WSL bridge |
| `wsl-delegate` | WSL, signing via the Windows `ssh-keygen` + PKCS#11 | Windows `ssh-keygen -D` |
| `software` | **testing only** — CA key in a file | never use for real access |

Install the matching prerequisites first — see [prerequisites.md](prerequisites.md)
(`token`: a PKCS#11 module + `pcscd`; `agent`: the YubiKey minidriver →
WinCryptSSHAgent → the WSL agent bridge).

## 1. Install the binary

```sh
git clone <this-repo> && cd mint-key
make install                 # → $PREFIX/bin/mintk  (PREFIX=/usr/local by default)
#   make PREFIX=~/.local install   # if you can't write /usr/local
mintk --version
```

`make` needs Go (the `Makefile` sets `GOTOOLCHAIN=auto`, so an older `go` fetches the
required toolchain). On Windows you mint from inside WSL, so build it there.

## 2. Bootstrap the config

```sh
mintk init
```

Interactive: pick the signing **mode**, import the **CA public key** (from an inserted
YubiKey via PKCS#11, from the ssh-agent, or pasted / from a file), and optionally point at
a **shared scopes file** (a private git repo) so your scope list travels with you. It
writes `~/.config/mint-key/config.yaml` (override location with `$MINTK_CONFIG`).

The mode prompt defaults to the mode recommended for this machine. In the CA picker,
candidates read off a YubiKey are tagged with their **PIV slot** (e.g. `(PIV slot 9C)`)
when `ykman` can resolve it — handy because via `libykcs11` every key otherwise shows the
same module-path comment. The CA lives in **slot 9C** throughout these docs, so a 9C
candidate is pre-selected; verify the fingerprint matches your `ca.pub` before accepting.

Prefer to do it by hand? Copy [`config.example.yaml`](../config.example.yaml) to
`~/.config/mint-key/config.yaml` and fill in `mode`, `ca_pub`, and either `scopes_file`
or an inline `scopes:` list. For `token` mode set `ykcs11` if autodetection misses your
module path.

## 3. Sync your scopes (if you keep them in a git repo)

```sh
mintk scopes pull            # git pull the shared scopes file
mintk scopes list            # confirm your scopes are present
```

The scopes repo is reached over SSH/HTTPS like any git remote — this machine needs a git
credential the repo host accepts. If your git identity rides the *same* YubiKey (a PIV
auth key registered with the git host), pin it for that host in `~/.ssh/config` via
`PKCS11Provider` + `IdentityFile <that-pubkey>` + `IdentitiesOnly yes`, and `scopes pull`
authenticates straight off the token.

## 4. Validate

```sh
mintk doctor                 # read-only; checks OpenSSH, the CA pubkey, and the
                             # pieces your mode needs. Must be all-green.
```

Fix anything it flags (usually a missing PKCS#11 module, a `pcscd` not running, or — in
`agent` mode — the CA key not visible to `ssh-add -l`) before continuing.

## 5. First cert

```sh
mintk key <scope>            # PIN + tap → cert in ~/.ssh/sessions/<scope>-cert.pub
ssh <host>                   # the host block uses IdentityFile ~/.ssh/sessions/<scope>
```

The tap is on **issuance**, once per scope per lifetime — SSH then needs no hardware until
the cert expires.

## Per-platform notes

- **Linux / macOS (`token`):** the YubiKey must be plugged into *this* box; minting prompts
  for the PIN (and a touch, per slot policy) on this machine. macOS routes PKCS#11 through
  Apple's `ssh-apple-pkcs11`, which **prompts for the PIN even for a no-PIN slot** — so
  PIN-gated operations can't be driven over a non-interactive SSH session; run them at a
  real terminal. `pcscd` on a headless box may need `pcscd --disable-polkit`.
- **Windows + WSL (`agent`):** the validated path — minidriver + WinCryptSSHAgent serving
  the CNG key on the OpenSSH pipe + the `socat`/`npiperelay` bridge into WSL. Verify with
  `ssh-add -l` (the CA key's fingerprint must match `ssh-keygen -lf ca.pub`). See
  [prerequisites.md → Windows + WSL](prerequisites.md#windows--wsl--agent-mode-the-validated-path).

## SSH config hygiene

Set `AddKeysToAgent no` and pin each cert-reached host with
`IdentityFile ~/.ssh/sessions/<scope>` + `IdentitiesOnly yes`. `mintk deploy` writes these
blocks for you. Without `IdentitiesOnly`, a YubiKey-only agent gets "fished" and SSH dies
with `Too many authentication failures`.

## Multi-YubiKey gotcha

If several cards hold the same CA key, signing can fail with **"agent refused operation"**
when the agent picks a card that isn't plugged. Fix: `mintk clean` (purge the stale certs),
then re-plug the card you want.

## Host side

A new client only *mints* certs. For a target host to *accept* them it must trust the CA
and list your scope's principal — `mintk deploy <scope> user@host` does this over SSH
(streams `ca.pub` + a small enrollment script; needs sudo on the host). Details and the
manual form: [prerequisites.md → Host side](prerequisites.md#host-side-to-accept-the-certs).
Routers (RouterOS) don't accept OpenSSH user certs — they stay on their own key/password
model.
