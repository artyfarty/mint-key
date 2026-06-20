# Docs index — mint-key

Read the relevant doc here **before** planning work, and keep this index in sync when
you add, rename, or remove docs.

| Document | What it covers |
| --- | --- |
| [design.md](design.md) | How the tool works: the SSH-CA model, scopes/principals, the issuance flow, the tap-once-per-scope property, and the threat model. |
| [yubikey-piv-setup.md](yubikey-piv-setup.md) | Putting the CA private key on a YubiKey PIV slot (generate offline → import → policies → distribute `ca.pub` → seal backup), and the software-CA test mode. |
| [mintk-go-spec.md](mintk-go-spec.md) | **Build brief:** rewrite the bash `mint` as a Go binary `mintk` — YAML config in `~/.config/mint-key/`, cobra + huh, commands `key`/`scopes (list/add/delete/edit)`/`clean`/`deploy`. Implement from here in a focused session. |

## Conventions

- One doc per topic. Record hard-won knowledge: PKCS#11 paths per OS, touch/PIN policy
  gotchas, ssh-agent behaviour, OpenSSH version quirks.
- Keep everything **generic** — no real hostnames, IPs, principals, or keys. Those
  belong in the operator's private config, never in this public repo.
