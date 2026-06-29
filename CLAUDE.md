# mint-key

A small, portable Go CLI (`mintk`) that issues **short-lived, scope-limited OpenSSH user
certificates** by signing them with a CA private key held on a **YubiKey** (reached via
the ssh-agent or PKCS#11) — a thin, auditable wrapper around `ssh-keygen -s`. Tap the
YubiKey once to authorize a scope for a session; SSH then needs no further taps until the
cert expires.

> **Visibility:** Public

## What this is (and isn't)

- It is the generic **tooling**: the `mintk` binary (commands `init` / `doctor` / `key` /
  `scopes` / `clean` / `clean-keys` / `deploy`), a `Makefile`, an example config, and docs explaining the
  model.
- It is **not** anyone's deployment. Real CA keys, real hostnames/principals, and real
  configs live **outside this repo** (in the operator's private config / secret store).
  This repo ships only placeholders.

## Directives

- All configuration (CA key location, PKCS#11 library path, scope→principal mapping,
  source-address, etc.) **must** come from a config file, never hardcoded. Ship
  `config.example.yaml` with generic placeholders; the real config lives at
  `~/.config/mint-key/config.yaml` (or `$MINTK_CONFIG`) outside the repo.
- **Read `docs/` before planning** — start from `docs/index.md`.
- **Update `docs/` before committing** — keep the index in sync; record quirks
  (PKCS#11 paths per OS, touch/PIN policy gotchas, agent behaviour) as they're found.
- **Language** — all committed artifacts are in **English**. Conversation may be in any
  language.

## Public-project rules

- This is a **public** project (mirrored to GitHub with public visibility).
- **Never expose personal data** in any committed file: IP addresses, hostnames, domain
  names of personal infra, API keys/tokens/passwords, real CA public *or* private keys,
  real principal names, asset/user IDs, or paths that reveal personal info. Use generic
  placeholders in examples. Treat everything committed as world-readable.
- A `LICENSE` file (MIT) is present; keep it accurate.
- **Keep it generic** is the load-bearing rule here: a reviewer cloning this repo must
  learn *how the tool works*, never *anything about the operator's network*.

## Sibling-project initialization

- If you create a **sibling project** (anything at `../<name>` outside this repo), give
  it the same baseline before writing substantial code: its own `CLAUDE.md` (purpose,
  directives, visibility), a `docs/` folder with an index, and an initialized git repo
  with a sensible `.gitignore`. Decide and record visibility first, and apply matching
  precautions (keep personal data / internal hostnames out of anything public).
