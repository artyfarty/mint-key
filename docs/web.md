# `mintk web` — the browser UI

`mintk web` serves the day-to-day surface of `mintk i` to a browser **on the same
machine**. The CLI stays the primary tool. The browser is better at one thing: showing
the whole picture at once and letting you act on any part of it with a single click.

```
mintk web                 # serve on web.listen (default localhost:7537), open the browser
mintk web --no-open       # just print the URL
mintk web --listen localhost:9000
mintk web enroll          # one-time link to register a YubiKey (works against a running server)
mintk web service install # run it as a systemd user unit (Linux / WSL)
```

If the server is already running (the unit, another terminal), `mintk web` just opens
the browser on it.

The page is unlocked with a **tap on a registered YubiKey**; see [Login](#login-a-tap-on-the-yubikey).

It runs in the foreground until Ctrl-C, or as a systemd user unit; see
[Running it as a service](#running-it-as-a-service).

## What it shows

- **Layout**: on a screen 1280 px or wider, the tabs and tree take the left column and Live + Activity sit in a 400 px sidebar. On a narrower screen it is one column: Live, then the tabs, then Activity. A scope row with a live cert or grant is tinted (green, amber when it expires soon).
- **Live**: every minted cert and secret grant that is still valid, soonest expiry first,
  with a live countdown and a bar for the share of the lifetime that's left. A card turns
  amber when under 15 minutes or 10% of its lifetime remain. Each card offers *Re-mint* /
  *Re-grant* and *×* (forget the cert / revoke the grant).
- **Certs** (the main tab): the full [scope-group tree](mintk-go-spec.md#scope-groups),
  expanded, with every scope's principal, state and remaining time. *Mint* signs with the
  scope's default lifetime. To use a different one, type it into the row's lifetime box
  and press *Mint* or Enter. Type in the filter (`/` focuses it) to search names,
  principals and group paths. When only one scope matches, Enter mints it. Groups
  collapse with a click, and the collapsed set is remembered per browser.
- **Secrets**: the secret scopes with their grant state. *Grant* / *Revoke* / per-grant
  lifetime work the same way as on the Certs tab.
- **Manage scopes**: add a scope or a group, change a scope's default lifetime, move a
  scope to another group, rename/move a group, delete an empty group. Every change is
  written straight to the scopes file (or the config), as `mintk i` does.
- **Clean up**: wipe `sessions_dir` (`clean-keys`) and revoke every live grant.
- **Keys**: the registered security keys (name, algorithm, last use). Register another,
  or remove one. The last key can't be removed. **Lock** in the header ends the session.
- **Activity**: the transcript of every action this tab ran, the same text the terminal
  would have shown (signing line, `ssh-keygen` output, the cert summary).

The page polls the state every 4 s and runs the countdowns itself between polls. Several
tabs can be open: a running action shows up as a banner in all of them.

### Deliberately not in the browser

- **Creating or editing secrets.** That needs the plaintext. In the terminal it goes
  `$EDITOR` → tmpfs. In a browser it would sit in the page's memory, the DOM and maybe a
  form-restore cache. `mintk secret edit <name>` stays the only way.
- **Changing a principal or deleting a scope.** Same rule as `mintk i`: those stay in
  `mintk scopes edit` / `delete`, where they're harder to hit by accident. The API has no
  field for them, and an unknown field is a 400.

### Extra over `mintk i`

- **Forget** (*×* on a cert): `ssh-add -d` the scope's key, then delete its key, `.pub`
  and cert. This is the per-scope version of `clean-keys`.

## How actions run

Every action calls the same code the CLI runs: `runKey`, `runSecretGrant`,
`runCleanKeys`, and the scope edits in `scopeops.go`, which `mintk i` shares. The only
plumbing added is `output.go`. The action code writes to `outW`/`errW` instead of
`os.Stdout`/`os.Stderr`, and the server points both at a buffer for the length of one
action. Child processes (`ssh-keygen`, `age`) are captured the same way. Terminal escapes
are stripped before the text goes to the page.

**One action at a time.** Every card or file operation takes one mutex. A second request
while one runs gets **409** with the running action's label. It is refused, not queued: a
queued mint would ask for a tap nobody expects any more.

**The YubiKey prompts** behave as in the terminal, because the same processes run:

| mode | tap | PIN |
|---|---|---|
| `agent` (WSL + Windows agent) | physical | the Windows agent's own dialog |
| `software` | none | none |
| `token`, `wsl-delegate` | physical | read from a **tty**: asked in the terminal running `mintk web` (the page shows a note) |
| secret grant, `wsl-windows` | physical | the console window `decryptViaConsole` already opens |
| secret grant, `native` | physical | the age plugin's prompt in the terminal running `mintk web` |

The tty-PIN modes therefore need `mintk web` running in a visible terminal. Bridging
those prompts into the browser (`SSH_ASKPASS` → the server → the page) is possible.
It's left out on purpose: carrying a PIV PIN over HTTP into a browser is a step down
from a native prompt, and the recommended `agent` path doesn't need it.

Every scope edit loads the config fresh, applies one change and saves, so whatever the
CLI wrote in the meantime is kept. Config and scopes-file writes are atomic (temp file
+ rename, through a symlink if the file is one), so a reader never sees a half-written
file even with the CLI and the browser both writing.

## Login: a tap on the YubiKey

The UI is unlocked with **WebAuthn (FIDO2)** on a registered YubiKey: one touch, no PIN,
no password, no token in a URL.

- **Non-resident credentials.** Nothing is stored on the key. The credential ID wraps
  the private key, and the server keeps the IDs and public keys in
  `web-credentials.json` next to the config (0600; `web.credentials_file` overrides).
  So a login is a touch with no FIDO2 PIN, and no resident-key slot (25 on a YubiKey 5)
  is used. A discoverable "passkey" would need a FIDO2 PIN and buys nothing here: the
  server already knows which credentials to ask for.
- **The first key** is registered through a one-time link that the terminal prints
  (`/enroll?t=…`, valid 15 minutes). `mintk web` prints it by itself while no key is
  registered, and `mintk web enroll` prints one on demand (a new key, or recovery after losing
  them all). The link becomes a short-lived cookie, and the registration tap also
  unlocks. A link registers one key, then closes. **Later keys** can be added from the
  Keys tab of an unlocked session.
- **Login**: the page asks for a challenge (random, single-use, valid 2 minutes). The
  browser has the key sign it, the server verifies the signature against the stored
  public key, and a session cookie is set (`web.session_ttl`, default 12h). A server
  restart ends every session; the next visit asks for a tap again.
- **What the server verifies**: `clientDataJSON` (type, challenge, origin
  `http://localhost:<port>`, not cross-origin), `authenticatorData` (RP ID hash of
  `localhost`, the user-presence flag, a signature counter that must advance when the
  key keeps one) and the ES256 / Ed25519 signature. At registration it checks the same,
  plus that the credential ID in `authenticatorData` matches. It takes the public key
  from the browser's `getPublicKey()` as SPKI DER, so there is no CBOR parser and no
  dependency: `crypto/ecdsa`, `crypto/ed25519`, `crypto/x509`. Attestation is `none`,
  because the enrollment link (or an unlocked session) is what authorizes a new key.
- **Roaming keys only**: registration asks for `authenticatorAttachment:
  cross-platform`, so the browser offers the YubiKey rather than Windows Hello or
  Touch ID.
- **FIDO2 is not PIV.** They are separate applets. A FIDO2 mistake can never block the
  PIV applet, and so never the CA signing slot. A PIV signature as the login would have
  had that risk. It also wouldn't bind to the browser: any local process could have
  asked for it.

### Why localhost and not 127.0.0.1

A WebAuthn relying-party ID must be a domain, not an IP. So the origin is
`http://localhost:<port>`, which browsers treat as a secure context. A page opened as
`127.0.0.1` / `[::1]` is redirected there; the API answers only to `localhost`. A
credential is bound to the RP ID, not the port, so changing the port keeps the
registered keys.

With `listen: localhost:<port>` (the default) the server binds **both** `127.0.0.1` and
`::1`: a Windows browser resolving `localhost` tries `::1` first, and WSL forwards
whichever the server listens on.

## Security model

The server can change scopes without a tap, and it can trigger a mint that you might
tap for out of habit. So it must be reachable by **you, from your browser**, and by
nothing else: not by another local user, not by another machine, and not by a web page
open in the same browser.

| threat | defence |
|---|---|
| another machine | the listener must be a loopback address. `0.0.0.0`, a LAN IP or a hostname other than `localhost` are refused at start-up |
| another local user / process | it can reach the port (WSL forwards it to all of Windows), but without a registered key it can't unlock. Registering a key needs the one-time link from the terminal or an unlocked session |
| a web page in the same browser (CSRF) | the session cookie is `HttpOnly; SameSite=Strict`. Every API call must also carry `X-Mintk: 1`, which a cross-origin page can't add without a CORS preflight. Mutations must be `application/json`, which a plain HTML form can't send, and must carry `Origin: http://localhost:<port>` |
| cross-origin XHR / fetch | no `Access-Control-Allow-*` header is ever sent. Every `OPTIONS` preflight gets 403, so the browser never sends the real request. `Sec-Fetch-Site` must be `same-origin` when present |
| phishing for the tap | a WebAuthn signature carries its origin and is checked against ours; a signature made for another site is useless here |
| DNS rebinding (`evil.example` → 127.0.0.1) | `Host` must be exactly `localhost:<port>`; anything else gets 421 (or, for a page load by IP, a redirect to localhost) |
| injected markup | the page builds all DOM from data with `textContent`, never `innerHTML`. The CSP allows only our own scripts and styles (`default-src 'none'; script-src 'self'; …; frame-ancestors 'none'`) |
| clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |

Notes:

- The page shell (`/`, `/static/*`) is served without a session: it holds no data. It
  asks `/api/auth/status` and shows the unlock or enrollment screen.
- Cookies aren't port-scoped, so the cookies are named `mintk_session_<port>` and
  `mintk_enroll_<port>`. Two servers, or another localhost app, can't clobber them.
- The browser is opened with `wslview` when present, else `explorer.exe <url>`
  (`cmd.exe /c start` would need quoting that doesn't survive the WSL→Windows boundary).
- No external requests: no CDN, no fonts, no framework. `go:embed` serves three static
  files (`web/index.html`, `web/static/app.js`, `web/static/style.css`) plus an icon.
  There is no build step and no npm.

## Running it as a service

`mintk web service install` writes `~/.config/systemd/user/mintk-web.service` (running
`mintk web --no-open` from the installed binary), then enables and starts it. `status`
shows it, `uninstall` removes it, and the logs are in `journalctl --user -u
mintk-web.service`. `make install` restarts a running unit, so a rebuilt binary is
picked up. Linux and WSL only for now. Under WSL it needs `[boot] systemd=true` in
`/etc/wsl.conf`, and the unit runs whenever the distro does.

Two things make the unit simple:

- **No token to hand out.** The UI is unlocked by a YubiKey tap, so a service that
  starts unattended has nothing to print or persist.
- **The agent socket is only dialled when an action runs.** Each mint spawns
  `ssh-keygen` / `ssh-add`, which connect to `SSH_AUTH_SOCK` at that moment. So the unit
  only needs the socket's *path*. `install` bakes the current `SSH_AUTH_SOCK` into the
  unit (plus `MINTK_CONFIG` if set). It doesn't have to start after whatever creates
  the socket: on the WSL setup a login shell starts the `socat` + `npiperelay` bridge
  on a fixed path, and it only has to be up by the first mint. A per-session socket
  (`/tmp/ssh-…`) gets a warning, because the unit would keep a dead path. Re-run
  `install` when the binary or the socket moves.

**Enrolling against a running server.** The one-time enrollment token lives in
`$XDG_RUNTIME_DIR/mint-key/web-enroll.json` (0600, tmpfs), not in the server's memory.
`mintk web enroll` writes it, and the server reads it when the link is opened. That's
how a key gets added to the unit's server without a control channel. It's no new
privilege: whoever can write that file can already edit `web-credentials.json`. A new
`enroll` replaces an unused link, a registration consumes it, and a reboot clears it.

Validated on WSL2: from a unit, the agent socket answers (`ssh-add -l`) and Windows
interop works (`cmd.exe`, which the `wsl-windows` secret grants need). The unit serves on
both loopbacks. `mintk web` next to it just opens the browser, `enroll` reaches it, and
`make install` restarts it.

## Config

```yaml
web:
  listen: localhost:7537          # loopback only; --listen overrides
  session_ttl: 12h                # how long one tap keeps the UI unlocked
  # credentials_file: ~/.config/mint-key/web-credentials.json   # the default: next to the config
```

## Testing it without a YubiKey

Use a `software`-mode config in a scratch dir, and unset `SSH_AUTH_SOCK` so the test
keys never reach your real agent:

```sh
ssh-keygen -q -t ed25519 -N '' -f /tmp/mt/ca
# config: mode: software, ca_key: /tmp/mt/ca, ca_pub: /tmp/mt/ca.pub, sessions_dir: /tmp/mt/sessions
MINTK_CONFIG=/tmp/mt/config.yaml SSH_AUTH_SOCK= mintk web --listen localhost:47537
```

**Validated on hardware:** `agent` mode on WSL2. The Windows browser reaches the WSL
listener through localhost forwarding. A mint from the page goes through the YubiKey tap,
and the cert lands in the agent and shows up in Live. The YubiKey login works on the same setup: enrollment through
the one-time link from the Windows browser (via `localhost` forwarding into WSL)
registers an ES256 FIDO2 credential, and later visits unlock with a tap (the signature counter advances on each login).

`web_test.go` covers the request gate (every row of the table above), the 409-while-busy
refusal and scope edits through the API. `webauthn_test.go` runs enrollment and login
against a software FIDO2 key, and checks that each of these is refused: a bad
signature, a wrong origin, a replayed challenge, an unregistered key, a counter going
backwards, a reused enrollment link, and deleting the last key. During development the UI was also driven headlessly (Chromium over
CDP): click-to-mint, the busy banner, the activity log and filter-then-Enter, plus the
whole login loop against Chromium's **virtual WebAuthn authenticator** (enroll →
non-resident credential → unlocked → Lock → tap → unlocked → reload keeps the session).

## Not yet

- **macOS autostart**: a launchd agent, the counterpart of `web service`.
- **PIN prompts in the browser** for the tty-PIN modes (see above). Possible, but
  deliberately not done.
