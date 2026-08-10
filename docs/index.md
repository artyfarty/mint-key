# Docs index — mint-key

Read the relevant doc here **before** planning work, and keep this index in sync when
you add, rename, or remove docs.

| Document | What it covers |
| --- | --- |
| [design.md](design.md) | How the tool works: the SSH-CA model, scopes/principals, the issuance flow, the tap-once-per-scope property, and the threat model. |
| [secrets.md](secrets.md) | **Secret grants** — scoped, time-limited access to *credentials* (`mintk secret`): age blobs in a git repo, why the ssh-agent bridge can't carry them, the per-OS card-access modes, tmpfs grants + the independent wiper, consumption paths, and the design decisions with their reasoning. |
| [yubikey-piv-setup.md](yubikey-piv-setup.md) | Putting the CA private key on a YubiKey PIV slot (generate offline → import → policies → distribute `ca.pub` → seal backup), and the software-CA test mode. |
| [prerequisites.md](prerequisites.md) | What must be installed/configured for `mintk` to work, per platform (token mode on Linux/macOS; the Windows+WSL agent path: minidriver, WinCryptSSHAgent, the agent bridge), host-side trust, gotchas. What `mintk doctor` checks. |
| [new-device.md](new-device.md) | Step-by-step **onboarding of a new client device**: pick mode → install the binary → `mintk init` → `scopes pull` → `doctor` → first `mintk key` (→ optional `mintk secret init`). Per-platform notes, SSH-config hygiene, the multi-YubiKey gotcha, and the host-side pointer. |
| [mintk-go-spec.md](mintk-go-spec.md) | **Design/build brief** for the `mintk` binary — YAML config in `~/.config/mint-key/`, cobra + huh, commands `interactive`/`key`/`secret`/`scopes (list/add/delete/edit)`/`clean`/`clean-keys`/`deploy`, plus the implementation status. |

## Conventions

- One doc per topic. Record hard-won knowledge: PKCS#11 paths per OS, touch/PIN policy
  gotchas, ssh-agent behaviour, OpenSSH version quirks.
- Keep everything **generic** — no real hostnames, IPs, principals, or keys. Those
  belong in the operator's private config, never in this public repo.
