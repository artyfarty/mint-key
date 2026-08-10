# mint-key

Issue **short-lived, scope-limited OpenSSH user certificates** from a CA whose private
key lives on a **YubiKey**. One tap authorizes a scope for a session; SSH then needs no
further taps until the cert expires. `mintk` is a thin, auditable wrapper around
`ssh-keygen -s`.

```
$ mintk key example-host
mintk: signing example-host  principal=host-example  +8h  [agent CA — tap to sign]
       (tap the blinking YubiKey)
mintk: minted.
        Type: ecdsa-cert ... user certificate
        Principals: host-example
        Valid: from ... to ...
$ ssh some-host            # works for 8h, no further taps
```

## Why certificates (vs. plain keys)

- **The CA is the only precious thing, and it stays in hardware.** Hosts trust the CA
  public key (`TrustedUserCAKeys`); they keep **no per-user `authorized_keys`**.
- **Access is time-boxed.** A cert is valid for hours, then it's dead — nothing to
  revoke, nothing to clean up on the hosts.
- **Scope = principal.** A cert carries a principal (e.g. `host-example`); a host only
  honours certs whose principal it lists. One CA, many narrowly-scoped certs.
- **The tap is on issuance, not on connection.** The CA (on the YubiKey) is touched
  once to sign the day's cert; the cert + a throwaway user key then do the SSH-ing with
  no hardware in the loop. (Putting the *user* key on the YubiKey instead would tap
  every connection — the opposite of what we want.)

## Install

Requires OpenSSH (`ssh-keygen`, `ssh-add`) and a Go toolchain to build. For hardware
mode you also need the YubiKey reachable via the ssh-agent (agent mode) or the Yubico
PKCS#11 module `libykcs11` (token mode). See [docs/prerequisites.md](docs/prerequisites.md).

```
git clone <this-repo> ~/work/mint-key
cd ~/work/mint-key
make                  # build ./mintk
sudo make install     # install to /usr/local/bin (PREFIX=~/.local for a user install)
```

Then check the machine has everything minting needs, and create your config:

```
mintk doctor          # prerequisite check (OpenSSH, CA, agent/PKCS#11 per mode)
mintk init            # bootstrap config — import the CA from your YubiKey
```

`make check` runs `mintk doctor` too.

### Prerequisites by hand — macOS

macOS already ships OpenSSH and a PC/SC stack (no `pcscd` to run), so for token mode you
only add the YubiKey tooling via [Homebrew](https://brew.sh) and a Go toolchain:

```
brew install go                       # to build ./mintk
brew install ykman                    # YubiKey slot management (ykman)
brew install yubico-piv-tool          # Yubico PKCS#11 module (libykcs11)
# or, alternatively:
brew install opensc                   # OpenSC PKCS#11 module (opensc-pkcs11.so)
```

The PKCS#11 module lands under Homebrew's prefix — Apple Silicon
`/opt/homebrew/lib/libykcs11.dylib` (Intel `/usr/local/lib/libykcs11.dylib`), or
`…/lib/opensc-pkcs11.so` for OpenSC. `mintk` autodetects these paths; if yours differs,
set `ykcs11` in your config. Then run `mintk doctor` to confirm everything's in place.

`mintk` is portable: any machine with `ssh-keygen` + access to the CA (agent or token) and
your `ca.pub` + config can issue certs — the authority travels on the YubiKey, the machine
is never "trusted."

## First-time setup on a machine

```
mintk init
```

Interactively writes `~/.config/mint-key/config.yaml`: picks a signing mode, **imports the
CA public key from your inserted YubiKey** (via PKCS#11 — or the ssh-agent, or a
file/paste), and optionally points at a shared scopes file (see below). It won't overwrite
an existing config (use `--force` to recreate).

## Usage

```
mintk init                           # bootstrap config (import CA from the YubiKey)
mintk doctor                         # check prerequisites are in place
mintk key <scope> [<ttl>]            # issue/refresh a cert for <scope> into the agent
mintk scopes list                    # list configured scopes
mintk scopes add <name> <principal> [<ttl>]
mintk scopes edit                    # interactive editor
mintk scopes pull | push             # sync the shared scopes file via git
mintk clean                          # (WSL+agent) recover after swapping YubiKeys
mintk clean-keys [-y]                # wipe minted session keys+certs from sessions_dir
mintk deploy <scope> user@host       # enroll a host to trust the CA + accept the scope
mintk deploy <scope> host -i <key>   #   ...authenticating to the host with a chosen key
mintk secret grant <scope> [<ttl>]   # (optional subsystem) grant a credential — see below
```

Pass the wrong arguments (or an unknown flag) to any command and `mintk` prints that
command's full help.

Scopes, principals, default lifetimes, the signing mode, CA location and the PKCS#11 path
are all set in your config (`~/.config/mint-key/config.yaml`, or `$MINTK_CONFIG`); see
[`config.example.yaml`](config.example.yaml). Nothing host-specific is baked into the code.

### Sharing scopes across machines

The scope list (alias → principal → ttl) is the one thing worth keeping in sync. Point
`scopes_file` at a YAML in a **private git repo**:

```yaml
scopes_file: ~/work/mint-scopes/scopes.yaml
```

Then `mintk scopes add/edit/delete` write that file, and `mintk scopes pull` / `push` sync
it via git. Which principal you actually use for which host stays local (your `~/.ssh/config`
and your memory) — only the principal/alias catalogue travels.

## Host side

To let a host accept your certs, enroll it once — this is "ssh-copy-id for the CA". Using
your existing SSH access (sudo on the host), it appends `ca.pub` to the host's trusted CA
keys and adds the scope's principal to the login user's `AuthorizedPrincipalsFile`:

```
mintk deploy example-host user@host
```

It also adds/updates `Host <host>` in your `~/.ssh/config` with `IdentityFile` (the minted
cert) + `IdentitiesOnly yes`, so `ssh <host>` just works (skip with `--no-ssh-config`).
The target may be a `~/.ssh/config` alias.

## Secret grants — the same idea, for credentials

An optional sibling subsystem: `mintk secret` applies the tap-once-then-work model to
*credentials* instead of hosts. Secrets are **age-encrypted blobs, one per scope**, in a
git repo (so the hosting server can never read them). One tap decrypts a scope onto
**tmpfs** for a bounded time; an **independent wiper** destroys it at TTL, and the consumer
reads a file rather than the card.

```
mintk secret init                             # set it up: mode, age+plugin, slot, repo
mintk secret grant registry deploy-token 4h   # one tap covers the burst
mintk secret run registry -- docker push …    # env injection, nothing in scrollback
mintk secret list                             # what's granted, how long is left
mintk secret revoke --all
mintk secret edit registry                    # decrypt → $EDITOR (tmpfs) → encrypt → commit
```

It cannot reuse the ssh-agent bridge that carries CA signing — the agent protocol only
signs, it has no decrypt operation — so on Windows+WSL the age client runs on the Windows
side, where the card is natively reachable, and only plaintext crosses into WSL (no usbipd,
no pcscd). Because the store is end-to-end encrypted, **per-read auditing is impossible by
construction**. Grants are Linux/WSL-only for now (they need tmpfs).

Everything — blob repo, scope→blob mapping, TTLs, plugin paths, per-OS card access — is
config-driven; `mintk secret init` writes that block interactively and can clone or create
the blob repo for you. Like `mintk init`, it only ever *reads* the YubiKey. See
[docs/secrets.md](docs/secrets.md).

## Setting up the CA on a YubiKey

See [docs/yubikey-piv-setup.md](docs/yubikey-piv-setup.md). In short: generate the CA
keypair offline, import the private key into a YubiKey PIV slot with `PIN`+`touch`
policy, distribute the single `ca.pub` to hosts, seal an offline backup of the private
key. Hardware mode never lets the CA private key touch a working disk again.

## Security notes

- A live cert sits in your agent for its lifetime — keep lifetimes tight on sensitive
  scopes, mint only the scopes in play, and consider `source_address` locking.
- This repo is **generic tooling**. Your real CA, hostnames, and principals stay in
  your private config — never commit them here.
