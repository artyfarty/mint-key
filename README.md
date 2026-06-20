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
./install.sh                 # checks prereqs, builds mintk → /usr/local/bin, seeds config
```

`./install.sh` is the guided path; the pieces are also available individually:
`./install.sh check` (prerequisite "doctor"), `./install.sh deps` (OS packages),
`./install.sh build` (build + install the binary), `./install.sh config` (write a starter
config from the example).

Just want the binary? Use the Makefile:

```
make                  # build ./mintk
sudo make install     # install to /usr/local/bin (PREFIX=~/.local for a user install)
make check            # run the prerequisite doctor
```

`mintk` is portable: any machine with `ssh-keygen` + access to the CA (agent or token) and
your `ca.pub` + config can issue certs — the authority travels on the YubiKey, the machine
is never "trusted."

## Usage

```
mintk key <scope> [<ttl>]            # issue/refresh a cert for <scope> into the agent
mintk scopes list                    # list configured scopes
mintk scopes add <name> <principal> [<ttl>]
mintk scopes edit                    # interactive editor
mintk clean                          # (WSL+agent) recover after swapping YubiKeys
mintk deploy <scope> user@host       # enroll a host to trust the CA + accept the scope
```

Scopes, principals, default lifetimes, the signing mode, CA location and the PKCS#11 path
are all set in your config (`~/.config/mint-key/config.yaml`, or `$MINTK_CONFIG`); see
[`config.example.yaml`](config.example.yaml). Nothing host-specific is baked into the code.

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
