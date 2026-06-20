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

## Host side (to accept the certs)

Each target host must trust the CA and accept your scope's principal:

```
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub      # contains ca.pub
AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u     # lists principals per login user
```
plus the scope's `principal` in `/etc/ssh/auth_principals/<login-user>`, then reload sshd.
`mintk deploy <scope> user@host` does this over SSH (streams the CA pubkey + a small
enrollment script; sudo on the host).

**Routers excluded:** RouterOS doesn't accept OpenSSH user certs — those stay on their
own key/password model.

## Quick verification

```
ssh-add -l                       # CA key present, fingerprint == ssh-keygen -lf ca.pub
mint key <scope>                 # PIN + tap → cert in ~/.ssh/sessions/<scope>-cert.pub
ssh -i ~/.ssh/sessions/<scope> <host>   # logs in via the cert
```
