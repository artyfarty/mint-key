# Design — how mint-key works

## The SSH certificate model

An OpenSSH **user certificate** is a user's public key plus metadata — an identity
string, a list of **principals**, a validity window, and options (e.g.
`source-address`) — all signed by a **CA**. A host configured to trust the CA
(`TrustedUserCAKeys`) accepts any cert the CA signed, provided it hasn't expired and one
of its principals is accepted for the login user (`AuthorizedPrincipalsFile`). No
per-user `authorized_keys` entry is needed on the host.

```
   CA private key (on YubiKey)
            │  ssh-keygen -s  (tap)
            ▼
  throwaway user key ──► user certificate { principals=[scope], valid=+Nh } 
            │
            ▼  ssh (no tap)
        target host  ── trusts CA, accepts the cert's principal ──► login
```

## Scopes are principals; the host is the gatekeeper

A "scope" in your config maps to a **principal** string baked into the cert. A host only
honours a principal it lists in `AuthorizedPrincipalsFile`. So:

- the CA signs whatever principal you ask for, but
- a cert only opens a host if that host opted into the principal.

This means minting can never grant reach a host hasn't agreed to — the trust decision
lives on the host, not in the issuance step. Creating a new scope is therefore a
host-side edit (list the principal), not a CA operation: no tap, no key handling.

## Why the tap is on issuance, not connection

The precious key is the **CA** key, and it stays on the YubiKey. The per-scope **user**
key is a throwaway on disk. So the YubiKey is touched once — when the CA *signs* a
cert — and never again for the SSH connections that cert authorizes. That yields
"tap once, then work the session." (The alternative — a user key resident on the
YubiKey — would require a tap on every connection.)

A minted cert + its key are loaded into the `ssh-agent` with a lifetime matching the
cert (`ssh-add -t`), so they auto-expire from the agent too.

## Issuance flow (`mint <scope> [hours]`)

1. Resolve `<scope>` → `(principal, default-hours)` from config.
2. Ensure a throwaway `ed25519` key for the scope exists under `SESSIONS_DIR`.
3. `ssh-keygen -s <CA> [-D <pkcs11>] -I <id> -n <principal> -V +<h>h [-O source-address=…]
   <scope>.pub` → **this is the tap** (hardware mode).
4. `ssh-add -t <h>h` the key+cert into the agent.

CA backends (signing modes, auto-selected from config):
- **Token (hardware):** `-s ca.pub -D <pkcs11>` — CA private key on the YubiKey, reached
  by a local PKCS#11 module (libykcs11 / opensc-pkcs11). Best when the YubiKey is on the
  same machine that runs `mint` (Linux/macOS, or WSL with the key passed through).
- **Agent (`CA_AGENT=1`):** `-s ca.pub -U` — the CA key lives in the `ssh-agent`;
  ssh-keygen signs *through the agent*. This is the clean answer when the YubiKey is on a
  **Windows** host and `mint` runs in **WSL**: expose the YubiKey to a Windows SSH agent
  (e.g. WinCryptSSHAgent, reading PIV via Windows' native smartcard stack), bridge that
  agent into WSL, and sign with `-U` — no usbipd, no Cygwin, no local PKCS#11. Windows
  keeps the YubiKey; only the signature crosses the bridge (the YubiKey taps).
- **Software (testing only):** `-s ca` — a CA private key file. Validate the end-to-end
  pipeline before importing to hardware; never for anything real.

### Platform note (Windows + WSL)

Why the agent mode exists: native Win32 OpenSSH `ssh-keygen` has **no PKCS#11** (`-D`),
and the Git-Bash (Cygwin) `ssh-keygen`, while it *has* PKCS#11, **crashes loading a
native Windows PKCS#11 DLL**. WSL's own `ssh-keygen` has PKCS#11 but can't see a
Windows-attached YubiKey without usbipd (which detaches it from Windows). The
agent-`-U` path sidesteps all of that. (A `wsl-delegate` mode that shells out to the
Windows ssh-keygen also exists in the script but is unreliable for exactly the Cygwin
reason above.)

## Threat model & residual risk

- **Lost/stolen cert+key:** usable only until it expires, only for its principal's
  hosts, and (if set) only from `SOURCE_ADDRESS`. Tight lifetimes on sensitive scopes
  bound the damage.
- **Compromised minting host while a cert is live:** the attacker gets that scope for
  the remaining lifetime. Mitigate by minting only the scopes in active use, keeping
  sensitive scopes short, and running the agent in a constrained environment.
- **Lost YubiKey:** depends on how the CA is held (one imported key across devices vs.
  N independent CA keys). With a single imported key, treat loss as "rotate the CA"
  (new key, re-distribute the one `ca.pub`). PIN + touch policy buys time. Keep an
  offline sealed backup of the CA private key for rotation/recovery.
- **Revocation:** expiry is the primary mechanism; for early revocation use a KRL
  (`ssh-keygen -k`) distributed to hosts, or drop/rotate the CA.

## Non-targets

- **Hosts that don't speak OpenSSH user certs** (e.g. some appliance SSH stacks, and
  Git hosting like GitHub/Gitea which authenticate *registered keys*) are out of scope
  — they need their own key/identity handling, not this CA.
