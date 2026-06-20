# Setting up the CA on a YubiKey (PIV)

Goal: the CA **private** key lives in a YubiKey PIV slot, requires a touch (and PIN) to
sign, and never sits on a working disk again. Hosts trust only the CA **public** key.

> Commands below are generic. Tools: `ssh-keygen` (OpenSSH), `ykman` (YubiKey Manager)
> or `yubico-piv-tool`, and `libykcs11` (the Yubico PKCS#11 module). Paths/slots are
> examples — adapt to your setup. Do the key-generation step **offline**.

## 1. Generate the CA keypair (offline)

```
ssh-keygen -t ecdsa -b 384 -f ca -C "ssh-user-ca" -N ''
#   -> ca       (private — to be imported into the YubiKey, then sealed offline)
#   -> ca.pub   (public  — distribute to hosts; safe to share)
```

(ECDSA P-384 imports cleanly into PIV slot `9c`. ed25519 PIV import support varies by
YubiKey firmware; check before choosing it.)

## 2. Import the private key into a PIV slot, with policies

Slot `9c` ("Digital Signature") requires the PIN once per session; set touch policy so
each signature needs a tap:

```
ykman piv keys import --pin-policy once --touch-policy always 9c ca
#   (or: yubico-piv-tool -a import-key -s 9c --pin-policy=once --touch-policy=always -i ca)
```

Repeat for each YubiKey that should hold the CA (import the *same* `ca` file into each),
or generate independent CA keys per device and trust all their `ca.pub`s — a deliberate
trade-off (single identity + simpler trust vs. per-device revocation). Document which
you chose in your private notes.

## 3. Seal the offline backup, wipe the working copy

The `ca` private key still exists as a file. Encrypt it to your offline backup (e.g.
`age`/hardware-backed recipients) — this is both your break-glass and the source for
adding/rotating a device — then securely remove the plaintext:

```
age -R ~/.config/age/recipients.txt -o ca.age ca   # example; use your own recipients
shred -u ca      # (or platform equivalent)
```

Keep `ca.pub` around (it's public).

## 4. Distribute `ca.pub` to hosts

On each target host (see `trust-ca` in the repo root):

```
sudo ./trust-ca ca.pub <login-user> <principal> [<principal> ...]
```

## 5. Point `mint` at the token

In your config (`~/.config/mint/config`):

```
CA_PUB="$HOME/.config/mint/ca.pub"
# YKCS11="/path/to/libykcs11.{so,dylib,dll}"   # only if autodetect misses it
```

`libykcs11` locations differ by OS — Linux: `/usr/lib/.../libykcs11.so`; macOS:
`…/libykcs11.dylib` (Homebrew `yubico-piv-tool`); Windows: under the Yubico PIV Tool
install. `mint` autodetects common paths; override with `YKCS11` if needed.

## Software test mode (before hardware)

To validate the whole pipeline without a token, point `mint` at a software CA key and
swap to the token afterwards:

```
ssh-keygen -t ed25519 -f ca-test -N ''        # throwaway test CA
# in config:  CA_KEY="$HOME/.../ca-test"       # takes precedence over CA_PUB/YKCS11
sudo ./trust-ca ca-test.pub <login-user> <principal>
mint <scope>                                   # signs in software, no tap
```

Delete the test CA and its trust once you've cut over to the YubiKey.
