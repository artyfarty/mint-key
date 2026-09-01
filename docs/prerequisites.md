# Prerequisites — what `mintk` needs to work

What must be installed/configured before `mintk key <scope>` can sign a cert with a
YubiKey-held CA and you can SSH in with it. Generic; substitute your own paths/names.
This is the reference for the installer to check + offer to install.

## Common (all platforms)

- **OpenSSH** client: `ssh-keygen`, `ssh-add`, `ssh` — and (for agent mode) a running
  `ssh-agent`. `ssh-keygen` must support `-U` (CA key in an agent) — OpenSSH ≥ 7.6.
- **The CA on a YubiKey PIV slot** (e.g. 9c), with a **certificate in that slot**. The
  cert is required even when you only use the key for signing: PKCS#11 modules and
  Windows CNG only expose a slot's key if a cert is present. Generate a self-signed one:
  `ykman piv certificates generate --subject "CN=<your-ca-cn>" --valid-days 36500 9c <pub.pem>`.
- **`ca.pub`** (the CA public key, OpenSSH format) available to `mintk` and distributed to
  the hosts you want to reach (see "Host side").
- Recommended: `ykman` (YubiKey Manager) for slot management.

## Linux / macOS — token mode (YubiKey attached to this machine)

- **A PKCS#11 module:** Yubico `libykcs11` (`yubico-piv-tool`) **or** OpenSC
  `opensc-pkcs11.so` (`opensc`). `mintk` autodetects common paths; else set it in config.
- **`pcscd`** running (PC/SC daemon) so the module can reach the card. On a headless box
  it may need `pcscd --disable-polkit` (polkit denies PC/SC over SSH sessions).
- Sign path: `ssh-keygen -s ca.pub -D <module> …` (PIN + touch on the YubiKey).

## Windows + WSL — agent mode (the validated path)

The YubiKey lives on Windows; `mintk` runs in WSL. Native Win32 `ssh-keygen` has **no
PKCS#11**, and Git-Bash (Cygwin) `ssh-keygen` **crashes** loading a native PKCS#11 DLL,
so signing goes through the **ssh-agent** (`ssh-keygen -U`) instead. Pieces:

1. **YubiKey Smart Card Minidriver** (Yubico) installed on Windows — the inbox driver
   won't expose an **ECDSA** PIV key to CNG. After installing it, **unplug + re-plug** the
   YubiKey so Certificate Propagation enrolls the slot-9c cert into `CurrentUser\My`
   (verify: `certutil -scinfo` shows the cert under "Microsoft Smart Card Key Storage
   Provider"; the cert is in `Cert:\CurrentUser\My` with `HasPrivateKey = True`).
2. **WinCryptSSHAgent** on Windows — serves the CNG/smartcard key as an SSH agent on the
   `\\.\pipe\openssh-ssh-agent` named pipe. To own that pipe, **stop the native Windows
   `ssh-agent` service** (`Stop-Service ssh-agent; Set-Service ssh-agent -StartupType
   Manual`). Bonus: the agent then holds only the YubiKey key, not on-disk god-keys.
3. **WSL agent bridge** — `SSH_AUTH_SOCK` in WSL points (via `socat` + `npiperelay.exe`)
   at the Windows `openssh-ssh-agent` pipe, so WSL sees the YubiKey key. Verify:
   `ssh-add -l` in WSL lists the CA key (fingerprint matches `ca.pub`).
4. **WSL OpenSSH** with `-U` support (Ubuntu's is fine).
5. For `mintk clean`: Windows `ykman.exe` + `certutil.exe` + `powershell.exe` reachable
   from WSL via interop.

Set `~/.ssh/config` to `AddKeysToAgent no` and pin homelab hosts with
`IdentityFile … + IdentitiesOnly yes`, so (a) on-disk keys aren't re-added to the
agent and (b) the now-YubiKey-only agent isn't "fished" (`Too many authentication
failures`).

### Gotchas

- **Multi-YubiKey, same CA key:** each card enrolls a cert with an identical public key
  into `CurrentUser\My`; the agent may then sign with a container whose card isn't
  plugged → **"agent refused operation"**. Fix: `mintk clean` (purge those certs) then
  re-plug the card you want — propagation re-enrolls only its (linked) cert.
- **usbipd** (USB passthrough to WSL) works but **detaches the key from Windows** — avoid;
  the agent path keeps the YubiKey usable by Windows.

## Secret grants (optional subsystem — `mintk secret`)

Only needed if you use [secret grants](secrets.md); cert minting doesn't touch any of it.

- **`age`** and **`age-plugin-yubikey`**, installed where the card is reachable:
  - Linux/macOS (`mode: native`): both on this machine, plus `pcscd` running.
  - Windows+WSL (`mode: wsl-windows`): both on the **Windows** side, run from WSL through
    interop (`/proc/sys/fs/binfmt_misc/WSLInterop` enabled). No usbipd, no pcscd in WSL.
    The plugin's directory must be a real PATH entry — a plugin resolved through `.` is
    refused by age.

    `age` is packaged: `winget install FiloSottile.age` (the shim lands in
    `%LOCALAPPDATA%\Microsoft\WinGet\Links`, which is on PATH). **`age-plugin-yubikey`
    is not** — download the Windows build and unpack it somewhere stable yourself.
    `mintk secret init` autodetects both (asking Windows via `where.exe`, then the usual
    install locations) and pre-fills the prompt with the winget path when age isn't
    installed yet.
- **An age identity in a PIV retired slot** (`82`–`95`, leaving `9c` to the CA), created
  with `--pin-policy once --touch-policy cached` so a multi-scope grant costs one tap.
- **A git repo of age blobs** and the recipients they're encrypted to.
- **A tmpfs runtime dir** — `$XDG_RUNTIME_DIR` (i.e. `/run/user/<uid>`) by default. Grants
  are Linux/WSL-only for v1; macOS has no such directory.
- Optional but recommended: **`systemd --user`**, so TTLs are enforced by transient timers
  rather than the fallback reaper process.

`mintk doctor` checks all of this when a `secrets:` block is present.

**Careful:** the PIV PIN is applet-wide — the same PIN protects the CA signing slot, so
three wrong entries block cert minting too.

## Host side (to accept the certs)

Each target host must trust the CA and accept your scope's principal:

```
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub      # contains ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u     # lists principals per login user
```
plus the scope's `principal` in `/etc/ssh/auth_principals/<login-user>`, then reload sshd.
`mintk deploy <scope> user@host` does this over SSH (streams the CA pubkey + a small
enrollment script; sudo on the host).

**Bootstrapping a host with no key on it:** `mintk deploy <scope> user@host --password`
authenticates with the account password (`PubkeyAuthentication=no` for that one
connection), so you don't have to `ssh-copy-id` a key by hand first. The whole enrollment
travels on a single SSH connection — the script is passed inside the remote command as a
quoted here-doc rather than over stdin — so you authenticate exactly once and the PTY
stays free for `sudo`'s prompt.

**Routers excluded:** RouterOS doesn't accept OpenSSH user certs — those stay on their
own key/password model.

### The login name you type is not necessarily `%u`

`AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u` expands `%u` to the account's
**canonical** passwd name (`getpwnam()`'s `pw_name`) — not to the name you happened to
type. Where the directory service accepts aliases, the two differ, and the file has to be
named after the canonical one or sshd reads a path that doesn't exist:

```
debug1: trying authorized principals file /etc/ssh/auth_principals/<canonical>
Certificate does not contain an authorized principal
```

macOS is where this bites: an account carries several OpenDirectory `RecordName`s (the
short name plus an Apple-ID-derived one), so `ssh someothername@host` authenticates fine
while `pw_name` stays the short name. `mintk deploy` resolves the target with `id -un`
before writing the principals file and says so when the two differ. Symptom if you hit it
by hand: the client offers the cert, the server never explains why, and you fall back to a
password prompt.

### Host-side quirks (macOS targets)

Verified against macOS 15.7 (Sequoia), OpenSSH 9.9p2:

- **Nothing to reload.** `sshd` is *launchd socket-activated*: there is no listener
  process (`pgrep sshd` finds nothing — connections show up as `sshd-session`), and every
  new connection re-reads the config. `systemctl`/`service` don't exist either, so the
  enrollment script skips the reload on Darwin instead of trying to `kill -HUP` a PID
  that isn't there. (A `kill -HUP ""` under `set -e` is exactly what used to abort the
  deploy after the config had already been written.)
- **BSD `sed`.** `sed -i -E …` on macOS consumes `-E` as the backup suffix. The script
  never uses `sed -i`; it rewrites through `mktemp` and copies back, which also preserves
  the file's mode and owner.
- **`Include /etc/ssh/sshd_config.d/*` comes first.** macOS ships that include near the
  top of `sshd_config` (with a `100-macos.conf` drop-in), and sshd takes the *first*
  value of most keywords — a drop-in could shadow the directives appended at the bottom.
  The script therefore verifies the *effective* config with `sshd -T` afterwards and warns
  if `TrustedUserCAKeys`/`AuthorizedPrincipalsFile` didn't take.
- Remote Login must be on (System Settings → General → Sharing), and the login user must
  be an admin (for `sudo`).

### Keep `ca.pub` to exactly one line

sshd's key-file parser **stops at the first line it can't read**, so every CA listed after
a junk line silently stops being trusted. Junk gets into a `ca.pub` easily — a captured
command's output can carry a terminal-title escape, a paste can bring blank lines — and
`deploy` used to copy the file verbatim onto every host. It now sends only the first line
that actually parses as a public key, scrubs unparsable lines out of the host's CA store,
and `mintk doctor` warns when the local `ca.pub` holds more than the key.

To inspect one: `awk '{print NR": "length($0)}' ~/.config/mint-key/ca.pub` (expect a
single line), and `sed -n 2p ca.pub | cat -v` to make any escape sequence visible.

## Quick verification

```
ssh-add -l                       # CA key present, fingerprint == ssh-keygen -lf ca.pub
mint key <scope>                 # PIN + tap → cert in ~/.ssh/sessions/<scope>-cert.pub
ssh -i ~/.ssh/sessions/<scope> <host>   # logs in via the cert
```
