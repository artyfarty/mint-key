# Secret grants — scoped, time-limited access to credentials

The sibling of cert minting. Same shape, different payload: instead of signing a cert
that opens hosts for a while, a **grant** decrypts one credential and parks it where a
consumer can read it for a while.

```
mintk secret grant <scope> [<ttl>]
  → one YubiKey interaction (PIN if needed + one touch)
  → decrypt that scope's blob
  → plaintext on tmpfs, mode 0600
  → an expiry, enforced by an independent wiper
```

After the grant, the consumer reads a **file**, not the card. The tap *is* the grant —
that is the whole point, and nothing in the design should let you route around it.

## Storage model: age blobs in a git repo

Secrets live as **age-encrypted blobs, one per scope**, in a git repo:

```
<secrets repo>/
  secrets/<scope>.age      one armoured age blob per scope
  recipients.txt           optional: one age recipient per line
```

The repo is end-to-end encrypted, so **the hosting server can never read it** — push it
anywhere you like. The direct consequence, stated plainly rather than glossed: **per-read
auditing is impossible by construction.** The store sees blobs being fetched, never a
secret being used. If you need "who read what, when", you need a server that can read
your secrets, which is the thing this design refuses to build.

Scopes are **blobs, not keys**. Nothing here needs one PIV slot per scope: the PIV PIN is
applet-wide, so a second no-touch slot would unlock together with the first anyway and buy
nothing. Separate slots only earn their place when the *policies* differ — e.g. a
`touch always` tier where every single use costs a physical tap. There is room for that
(it is a second identity + a second set of blobs); it isn't built.

## Why the mechanism is unusual

The obvious implementation — reuse the ssh-agent bridge that already carries CA signing —
**cannot work**: the ssh-agent protocol only signs. It has no decrypt operation, so an
age identity cannot ride it. That is not a limitation of the bridge; it is what the
protocol is.

So the card is reached a different way, and the platform split mirrors the CA `mode:`
rather than special-casing anything:

| `secrets.mode` | How the card is reached |
| --- | --- |
| `native` | `age` + `age-plugin-yubikey` run on this machine and talk to the card through PC/SC (`pcscd`). Linux/macOS with the YubiKey attached here. |
| `wsl-windows` | WSL runs the **Windows** `age.exe` through WSL interop. The card stays on Windows, where the minidriver reaches it natively. **No usbipd, no pcscd in WSL.** Only the plaintext crosses back over a pipe. |
| `software` | A plain age X25519 identity file. Testing only — no hardware, no tap. |

`wsl-windows` works because `/proc/sys/fs/binfmt_misc/WSLInterop` lets Linux execute
Windows binaries directly. Ciphertext goes in on the child's **stdin** and plaintext comes
back on its **stdout**, so no path has to be translated for the Windows client and — the
part that matters — **plaintext never touches an NTFS filesystem.** stderr is passed
through, so the touch prompt is visible.

## TTL is enforced by an independent wiper

A consuming wrapper that checks the deadline before reading would be theatre: anyone
already on the box can read the tmpfs file directly and ignore any such check. So the
deadline is enforced by something that isn't the consumer and isn't the granting shell:

1. **A transient systemd user timer** (`systemd-run --user --on-active=<ttl>`), which
   outlives the shell, the terminal and `mintk` itself.
2. **Fallback: a detached reaper** — `mintk` re-executes itself in a new session, sleeps,
   and wipes. Survives the terminal; not a `kill -9`.
3. **Backstop: `mintk secret sweep`** — wipes anything past its deadline, any plaintext
   with no grant record behind it, and any `secret edit` workspace whose process is gone.
   Every `secret` command runs it first, so an expired grant is destroyed before any
   command can look at it, whether or not its own wiper ever fired.

If no wiper can be armed at all, the grant is **destroyed rather than left unwatched**.

The wiper reads **no config** — it takes the runtime dir as an argument. A systemd `--user`
unit runs in the user manager's environment and inherits nothing from your shell (not
`$MINTK_CONFIG`, not anything else), and a wiper that can't find its config is a wiper that
never fires.

Grants live on **real tmpfs** (`$XDG_RUNTIME_DIR/mint-key` by default), verified by reading
the filesystem type out of `/proc/self/mountinfo`. That is what makes "grants die on
reboot" free rather than aspirational, and keeps plaintext off any disk that could later be
imaged. A non-tmpfs runtime dir is refused unless you set `allow_non_tmpfs: true`.

Layout under the runtime dir (mode 0700 throughout):

```
secrets/<scope>        plaintext, mode 0600
grants/<scope>.json    scope, deadline, serial, which wiper is armed
edit/<scope>.<pid>/    `secret edit` workspace
```

Every grant carries a **serial**. A wiper only destroys the grant it was armed for, so a
timer left over from an earlier grant can't wipe the one that replaced it.

## Consumption: never stdout by default

Printing a secret puts it in your terminal scrollback — and in the transcript of any agent
that ran the command. So the default paths don't print:

```
mintk secret run <scope> [<scope>...] -- <command> [args...]
mintk secret path <scope>
```

`run` gives the child `$MINTK_SECRET_<SCOPE>` pointing at the granted file (plus
`$MINTK_SECRET_FILE` when there's exactly one scope), and for scopes marked `format: env`
it parses the blob's `KEY=VALUE` lines and injects them as environment variables. Scopes
that aren't granted yet are granted first, and the child's exit status is passed through
unchanged.

`mintk secret print <scope>` is the escape hatch. It exists, it is never on the default
path, and it asks for confirmation when stdout is a terminal.

Both the file and an injected environment are readable by anything running as **this user**
(`/proc/<pid>/environ` is no more private than a 0600 file). A grant bounds *time*, not who
on the box can look — the same bargain a minted cert sitting in your agent makes.

## Managing secrets: `secret edit`

```
mintk secret edit <scope> [--push]
```

Decrypts the blob into a 0700 workspace **on tmpfs**, opens `$EDITOR` on it, re-encrypts
the result to the configured recipients, writes the blob **atomically** (temp file +
rename, so a crash can't truncate the blob where a secret used to be) and commits just that
file. Editing a scope that doesn't exist creates it.

Plaintext left behind on a crash is handled at four levels: the workspace is wiped on
normal exit; on `SIGINT`/`SIGTERM`/`SIGHUP`; by the next command's sweep, which drops any
workspace whose owning process is gone; and by a reboot, because it is tmpfs. Files are
zeroed before being unlinked — on tmpfs that rewrites the actual pages.

Editing a scope that is currently granted **revokes the grant**, since the live plaintext
is now a stale value with a valid-looking deadline.

## Commands

```
mintk secret init [--force]                           # set up the subsystem on a machine
mintk secret grant <scope>... [<ttl>] [--ttl <ttl>]   # the tap
mintk secret run <scope>... -- <cmd> [args...]        # exec wrapper + env injection
mintk secret path <scope>                             # the path, never the secret
mintk secret list                                     # scopes + which are granted
mintk secret revoke <scope>... | --all                # wipe now
mintk secret print <scope> [-y]                       # escape hatch
mintk secret edit <scope> [--push]                    # decrypt → $EDITOR → encrypt → commit
mintk secret rm <scope> [-y] [--push]
mintk secret pull | push                              # git sync the blob repo
mintk secret sweep                                    # wipe expired/orphaned/abandoned
```

### Grant several scopes at once

A touch policy of `cached` (15 s) serves a whole burst from **one tap**:

```
mintk secret grant registry deploy-token database 4h
```

A decrypt failure **aborts the burst** instead of moving on to the next scope, and is never
retried automatically. See the PIN warning below for why that matters.

## Setting it up: `mintk secret init`

```
mintk secret init [--force]
```

Interactive bootstrap of the `secrets:` block, mirroring `mintk init`:

1. **Card access mode** — recommends `wsl-windows` under WSL, `native` elsewhere.
2. **`age` + `age-plugin-yubikey`** — found on PATH natively. Under `wsl-windows` it asks
   Windows itself (`where.exe`, so anything on the Windows PATH is found however it was
   installed), then globs the usual install locations — winget's `Links` shim dir, scoop,
   chocolatey, `Program Files`, `Downloads` — one level deep so unpacked release zips are
   caught. You pick the *binary*; for the plugin what's stored is its **directory**,
   because that directory has to be a real PATH entry.

   Nothing found? The prompt is pre-filled with where the thing *would* be once installed,
   and the install hint is printed: `winget install FiloSottile.age`. The plugin is **not**
   packaged — it's a manual download, and the prompt pre-fills next to age, since both
   usually end up in the same place.
3. **The identity** — lists the age identities on the inserted YubiKey
   (`age-plugin-yubikey --list`) with each slot's **name and PIN/touch policy**, so you can
   tell apart identities you made for other purposes. You pick the **slot**; it writes that
   slot's identity stub to a file (`\r` stripped — see the CRLF gotcha) and warns if the
   policies aren't the ones a one-tap burst needs. Under `wsl-windows` the default location
   is on the Windows side, so the client that reads it needs no path translation.

   Note the output format: `--list` prints each identity as a **block** of `# Key: Value`
   comment lines followed by the recipient on its own line — not one line per identity.
4. **The blob repo** — uses an existing git repo, **clones** one from a URL, or **creates**
   one with `git init`; also accepts a plain directory, saying plainly that `pull`/`push`
   and auto-commit then won't work.
5. **Recipients** — seeds `recipients.txt` with the card's recipient and asks for
   break-glass recipients, then commits it.
6. **Default TTL**, and a check that grants would land on tmpfs.

It merges into an existing config, so a machine that already mints certs just gains the
block; it refuses to overwrite an existing `secrets:` block without `--force`. Rewriting
the config drops any comments you added to it — it says so before doing it.

**It never writes to the YubiKey.** Like `mintk init`, it only reads the card. Creating an
age identity in a retired slot stays a deliberate, separate step (see below), because
`--generate` on a filled slot is not something a setup wizard should be able to do to you.

## Config

All of it, like the CA config, lives outside this repo. Placeholders are in
[`config.example.yaml`](../config.example.yaml):

```yaml
secrets:
  mode: wsl-windows            # native | wsl-windows | software
  repo: ~/work/mint-secrets    # git repo holding the blobs
  dir: secrets                 # blob subdir inside the repo
  identity: /mnt/c/Users/<you>/.age/identity.txt
  age: /mnt/c/Users/<you>/age-tools/age.exe
  plugin_dir: /mnt/c/Users/<you>/age-tools           # must be a real PATH entry
  recipients_file: recipients.txt
  default_ttl: 8h
  runtime_dir: ""              # default: $XDG_RUNTIME_DIR/mint-key (tmpfs)
  scopes:
    - name: example-service
      ttl: 1h
      format: env              # env | opaque
```

Scopes are **discovered from the repo** — every `<name>.age` in the blob dir is usable
without being declared. A `scopes:` entry only adds policy (lifetime, consumption format, a
non-default filename). That way the catalogue travels with the (private) repo instead of
having to be mirrored into every machine's config.

The `identity` file is an age **plugin stub**: it names the card and slot, and contains no
key material. Keeping it on the Windows side under `wsl-windows` is fine and avoids path
translation entirely.

Recipients should include a **break-glass X25519 recipient** whose identity is in your
offline backup, not only the YubiKey. A YubiKey plugin recipient means every re-encryption
needs the plugin binary present (though not the card); losing the only card that can
decrypt means losing every blob.

## Creating the age identity on the card

Do this **before** `mintk secret init`, which only reads what's already there. Put the age
identity in a PIV **retired** slot, leaving `9c` to the CA — the plugin numbers the twenty
retired slots `1`–`20` (PIV `82`–`95`):

```
age-plugin-yubikey --generate --slot <1-20> --pin-policy once --touch-policy cached
```

`--pin-policy once` + `--touch-policy cached` is what makes a multi-scope burst cost one
tap. Under WSL run the **Windows** binary for this, so the identity belongs to the card as
Windows sees it.

Then `mintk secret init` picks that slot up, and `mintk doctor` checks the rest of the
wiring.

## Gotchas — each of these costs an hour if you rediscover it

- **The PIV PIN is applet-wide.** The same PIN protects the CA signing slot. Three wrong
  entries block the applet and kill `mintk key` along with your secrets. `mintk` therefore
  **never auto-retries a PIN** and aborts a burst on the first failure.
- **A prepended PATH does not reach a Windows child.** WSL interop hands the child the
  *Windows* PATH and drops whatever you put in front of the Linux one. The lever that works
  is `WSLENV=PATH/l`, which makes interop translate our PATH as a path list, so a
  `/mnt/c/...` entry arrives as `C:\...`. `mintk` sets this itself.
- **…but `/l` translates every entry.** Linux entries become `\\wsl.localhost\...` UNC
  paths — including a directory holding a *Linux* `age-plugin-yubikey`, which the Windows
  client would find and fail to execute. `mintk` passes the plugin dir plus only the
  Windows-backed (`/mnt/...`) entries.
- **age refuses a plugin resolved through `.`** — "cannot run executable found relative to
  current directory". The plugin's directory has to be a real PATH entry.
- **Windows binaries emit CRLF.** An identity file captured without stripping `\r` fails
  with `unknown identity type`. `mintk` strips `\r` from captured *text* and never from
  ciphertext or plaintext.
- **`cmd /k` leaves a console alive** after the command. Any interactive window has to exit
  by itself — no `pause`.
- **A touch is required per decrypt**, served from the 15 s cache. Hence bursts.
- **PIN longevity is not reliable and must not be depended on.** Measured: still valid at
  ~6 min, gone at ~7 — but force-killed processes in between plausibly reset the card
  session, and the two causes were never separated. The design sidesteps the question by
  touching the card exactly once per grant. Don't build anything that assumes the PIN is
  still cached.
- **PIN survives a process boundary.** A second, separate decrypt did not re-prompt — which
  is what makes a multi-process burst practical at all.

Validated with `age` v1.3.1 + `age-plugin-yubikey` v0.5.1 (Windows x86_64) against a
YubiKey 5.7.x, age identity in a PIV retired slot, PIN policy `once`, touch policy `cached`.

## Decisions, and why

**Subcommands of `mintk`, not a separate binary.** Grants share the config file, the
`~`-expansion and path helpers, the WSL detection and Windows-path translation, the git
sync pattern, the prompts and `doctor`. A second binary would duplicate all of it to
separate two things the operator does in one breath. The subsystem is self-contained in
`secret.go` / `secretage.go` / `secretgrant.go`, so splitting it out later is mechanical.

**One whole age blob per scope, not sops.** sops with age recipients gives readable diffs,
which is genuinely attractive. It was rejected on measured behaviour: plugin pubkeys in
`creation_rules` break editing, touch prompts are silent under sops (you sit there watching
a hung process), and PIN policy `once` degrades into a prompt on *every* decrypt, because
the plugin only lives as long as the age client and sops starts a fresh one per file. That
last point undoes the property the whole design is built on. Nothing found since changes
this; if sops fixes the plugin lifetime, revisit. Blobs are **armoured**, so the repo stays
text-only even though the diffs are opaque either way.

**`edit` decrypts to tmpfs, never to the repo working tree.** The workspace is on tmpfs
with a 0700 dir, wiped on exit, on signals, by the next sweep, and by reboot; the blob is
written atomically so a crash mid-encrypt can't destroy the previous value.

**Linux/WSL only for v1.** macOS has no `/run/user/<uid>` and no tmpfs by default. Rather
than quietly writing plaintext to an APFS file and calling it a grant, `mintk` refuses a
non-tmpfs runtime dir. macOS users can attach a RAM disk (`hdiutil attach -nomount
ram://…` + `diskutil erasevolume`) and point `runtime_dir` at it — that path is
**untested**, and there is no auto-detection for it. Everything else (`edit`, the repo,
`list`) works anywhere age does.

## Threat model

- **Grant live on a compromised box:** the attacker gets that scope until it expires —
  same-uid access is same-uid access. Keep sensitive scopes short; grant only what's in
  play.
- **Blob repo leaked / hosting host compromised:** nothing is readable without the card (or
  the break-glass identity). This is the property worth having.
- **Lost YubiKey:** every blob must be re-encrypted to a new identity. This is why the
  break-glass recipient exists. There is no revocation of a blob someone already copied —
  rotate the *secret*, not the key.
- **Reboot / crash:** grants die with tmpfs. Blobs are unaffected.
- **Audit:** none per read, by construction. See above.
