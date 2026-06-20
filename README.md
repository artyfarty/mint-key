# mint-key

Issue **short-lived, scope-limited OpenSSH user certificates** from a CA whose private
key lives on a **YubiKey**. One tap authorizes a scope for a session; SSH then needs no
further taps until the cert expires. A thin, auditable wrapper around `ssh-keygen -s`.

```
$ mint example-host
mint: signing example-host  principal=host-example  valid=+8h  [YubiKey — tap to sign]
       (tap the blinking YubiKey)
mint: minted.
        Type: ed25519-cert ... user certificate
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

Requires OpenSSH (`ssh-keygen`, `ssh-add`) and — for hardware mode — the Yubico
PKCS#11 module (`libykcs11`, from `yubico-piv-tool` / `ykman`).

```
git clone <this-repo> ~/mint-key
ln -s ~/mint-key/mint ~/.local/bin/mint          # or add the repo to PATH
cp ~/mint-key/mint.conf.example ~/.config/mint/config   # then edit it
```

`mint` is portable: any machine with `ssh-keygen` + `libykcs11` + your `ca.pub` and
config can issue certs — the authority travels on the YubiKey, the machine is never
"trusted." See [docs/](docs/index.md).

## Usage

```
mint <scope> [hours]      # issue/refresh a cert for <scope> into the agent
mint --list               # list configured scopes
```

Scopes, principals, default lifetimes, CA location and the PKCS#11 path are all set in
your config (see `mint.conf.example`). Nothing host-specific is baked into the code.

## Host side

On each target host, once, trust the CA and declare which principals a login user
accepts:

```
sudo ./trust-ca /path/to/ca.pub <login-user> host-example general
```

## Setting up the CA on a YubiKey

See [docs/yubikey-piv-setup.md](docs/yubikey-piv-setup.md). In short: generate the CA
keypair offline, import the private key into a YubiKey PIV slot with `PIN`+`touch`
policy, distribute the single `ca.pub` to hosts, seal an offline backup of the private
key. Hardware mode never lets the CA private key touch a working disk again.

## Security notes

- A live cert sits in your agent for its lifetime — keep lifetimes tight on sensitive
  scopes, mint only the scopes in play, and consider `SOURCE_ADDRESS` locking.
- This repo is **generic tooling**. Your real CA, hostnames, and principals stay in
  your private config — never commit them here.
