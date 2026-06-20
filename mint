#!/usr/bin/env bash
#
# mint — issue a short-lived, scope-limited OpenSSH user certificate.
#
# Signs a throwaway per-scope user key with a CA. The CA private key normally lives
# on a YubiKey (PIV slot, reached over PKCS#11), so signing requires a physical tap;
# a software CA key file is also supported for testing. The resulting certificate is
# loaded into the ssh-agent with a matching lifetime, so SSH needs no further taps
# until it expires.
#
# Signing modes (auto-selected):
#   software       CA_KEY set            — a CA private key file (testing only)
#   wsl-delegate   in WSL + WIN_YKCS11   — YubiKey is on the Windows host; sign via
#                                          the Windows ssh-keygen + Windows PKCS#11
#                                          (native Win32 ssh-keygen has no PKCS#11 and
#                                          WSL can't see the YubiKey without usbipd)
#   token          CA_PUB + YKCS11       — local PKCS#11 (YubiKey attached here)
#
# Usage:
#   mint <scope> [hours]
#   mint --list                 # list configured scopes
#
# Config (first found wins):  $MINT_CONFIG  |  ./mint.conf  |  ~/.config/mint/config
# See mint.conf.example for the format. This repo ships only placeholders — the real
# config (real CA path, real scope→principal mapping) lives outside the repo.

set -euo pipefail
prog=${0##*/}
die() { printf '%s: %s\n' "$prog" "$*" >&2; exit 1; }

in_wsl()   { grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; }
# MSYS/Cygwin path form for Git-Bash tools (they choke on C:\ backslash args):
# /mnt/c/x -> /c/x ; leave already-MSYS or other paths untouched.
to_winpath() { case "$1" in /mnt/[a-z]/*) printf '/%s' "${1#/mnt/}";; *) printf '%s' "$1";; esac; }

# --- locate + load config -------------------------------------------------------
config=${MINT_CONFIG:-}
if [ -z "$config" ]; then
  for c in "./mint.conf" "$HOME/.config/mint/config" "$HOME/.mint.conf"; do
    [ -f "$c" ] && { config=$c; break; }
  done
fi
[ -n "$config" ] && [ -f "$config" ] || die "no config found (set MINT_CONFIG, or create ~/.config/mint/config — see mint.conf.example)"
# shellcheck disable=SC1090
. "$config"

SESSIONS_DIR=${SESSIONS_DIR:-$HOME/.ssh/sessions}
: "${CA_PUB:=}"; : "${CA_KEY:=}"; : "${YKCS11:=}"; : "${SOURCE_ADDRESS:=}"
: "${CA_AGENT:=}"
: "${WIN_SSH_KEYGEN:=}"; : "${WIN_YKCS11:=}"; : "${WIN_STAGE:=}"
command -v scope_def >/dev/null 2>&1 || die "config defines no scope_def() function (see mint.conf.example)"

detect_ykcs11() {
  local p
  for p in \
    /usr/lib/x86_64-linux-gnu/libykcs11.so /usr/lib/libykcs11.so \
    /usr/local/lib/libykcs11.so /usr/local/lib/libykcs11.dylib \
    /opt/homebrew/lib/libykcs11.dylib \
    /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so \
    /usr/local/lib/opensc-pkcs11.so /opt/homebrew/lib/opensc-pkcs11.so; do
    [ -e "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

list_scopes() {
  printf 'configured scopes (from %s):\n' "$config"
  if command -v scope_list >/dev/null 2>&1; then scope_list; else
    printf '  (define scope_list() in the config to enumerate)\n'
  fi
}

[ "${1:-}" = "--list" ] && { list_scopes; exit 0; }

scope=${1:-} ; [ -n "$scope" ] || die "usage: $prog <scope> [hours]   (or --list)"
def=$(scope_def "$scope") || die "unknown scope '$scope' (try: $prog --list)"
principal=${def%% *}
def_hours=${def##* }
hours=${2:-$def_hours}
case "$hours" in (*[!0-9]*|'') die "hours must be an integer, got '$hours'";; esac

# --- ensure a throwaway per-scope user key (private key stays here) --------------
mkdir -p "$SESSIONS_DIR"; chmod 700 "$SESSIONS_DIR"
key="$SESSIONS_DIR/$scope"
[ -f "$key" ] || ssh-keygen -q -t ed25519 -N '' -C "mint-$scope" -f "$key"

# --- common cert metadata -------------------------------------------------------
id="${USER:-user}-${scope}-$(date +%Y%m%dT%H%M%S)"
serial=$(date +%s)
src=()
[ -n "$SOURCE_ADDRESS" ] && src=(-O "source-address=$SOURCE_ADDRESS")

# --- sign, by mode --------------------------------------------------------------
if [ -n "$CA_KEY" ]; then
  [ -f "$CA_KEY" ] || die "CA_KEY '$CA_KEY' not found"
  printf '%s: signing %s  principal=%s  +%sh  [software CA]\n' "$prog" "$scope" "$principal" "$hours"
  ssh-keygen -s "$CA_KEY" -I "$id" -n "$principal" -V "+${hours}h" -z "$serial" "${src[@]}" "$key.pub"

elif [ "$CA_AGENT" = 1 ]; then
  # CA private key lives in the ssh-agent (e.g. a YubiKey exposed to the agent via a
  # Windows agent bridge). ssh-keygen -U signs the cert through the agent — no local
  # PKCS#11, no Cygwin: the agent performs the signature (and the YubiKey taps).
  [ -n "$CA_PUB" ] && [ -f "$CA_PUB" ] || die "set CA_PUB to your CA public key (agent mode)"
  ssh-add -l 2>/dev/null | grep -qF "$(ssh-keygen -lf "$CA_PUB" | awk '{print $2}')" \
    || die "CA key not present in the ssh-agent (load it / start the agent bridge)"
  printf '%s: signing %s  principal=%s  +%sh  [agent CA — tap to sign]\n' "$prog" "$scope" "$principal" "$hours"
  ssh-keygen -U -s "$CA_PUB" -I "$id" -n "$principal" -V "+${hours}h" -z "$serial" "${src[@]}" "$key.pub"

elif [ -n "$WIN_YKCS11" ] && in_wsl; then
  # YubiKey on the Windows host: sign via Windows ssh-keygen + Windows PKCS#11.
  # The private key never leaves WSL; only the public key crosses out, cert comes back.
  [ -n "$CA_PUB" ] && [ -f "$CA_PUB" ] || die "set CA_PUB to your CA public key (wsl-delegate mode)"
  [ -n "$WIN_SSH_KEYGEN" ] && [ -x "$WIN_SSH_KEYGEN" ] || die "set WIN_SSH_KEYGEN to the Windows ssh-keygen.exe (e.g. Git-Bash's)"
  [ -n "$WIN_STAGE" ] || die "set WIN_STAGE to a Windows-readable staging dir (e.g. /mnt/c/Users/<you>/.mint)"
  mkdir -p "$WIN_STAGE"
  cp "$CA_PUB" "$WIN_STAGE/$scope.ca.pub"
  cp "$key.pub" "$WIN_STAGE/$scope.pub"
  win_ca=$(to_winpath "$WIN_STAGE/$scope.ca.pub")
  win_pub=$(to_winpath "$WIN_STAGE/$scope.pub")
  printf '%s: signing %s  principal=%s  +%sh  [WSL→Windows YubiKey — PIN + tap]\n' "$prog" "$scope" "$principal" "$hours"
  "$WIN_SSH_KEYGEN" -s "$win_ca" -D "$WIN_YKCS11" -I "$id" -n "$principal" -V "+${hours}h" -z "$serial" "${src[@]}" "$win_pub"
  [ -f "$WIN_STAGE/$scope-cert.pub" ] || die "Windows signing produced no cert at $WIN_STAGE/$scope-cert.pub"
  cp "$WIN_STAGE/$scope-cert.pub" "$key-cert.pub"
  rm -f "$WIN_STAGE/$scope.ca.pub" "$WIN_STAGE/$scope.pub" "$WIN_STAGE/$scope-cert.pub"

else
  [ -n "$CA_PUB" ] && [ -f "$CA_PUB" ] || die "set CA_PUB (token mode) or CA_KEY (software mode)"
  [ -n "$YKCS11" ] || YKCS11=$(detect_ykcs11) || die "could not find a PKCS#11 module; set YKCS11"
  [ -e "$YKCS11" ] || die "YKCS11 '$YKCS11' not found"
  printf '%s: signing %s  principal=%s  +%sh  [YubiKey — PIN + tap]\n' "$prog" "$scope" "$principal" "$hours"
  ssh-keygen -s "$CA_PUB" -D "$YKCS11" -I "$id" -n "$principal" -V "+${hours}h" -z "$serial" "${src[@]}" "$key.pub"
fi

# --- load into the agent with a matching lifetime -------------------------------
if ssh-add -l >/dev/null 2>&1 || [ $? -eq 1 ]; then
  ssh-add -t "${hours}h" "$key" >/dev/null 2>&1 || ssh-add "$key" >/dev/null 2>&1 || \
    printf '%s: note — could not add to agent (no agent?); cert at %s-cert.pub\n' "$prog" "$key"
fi

printf '%s: minted.\n' "$prog"
ssh-keygen -L -f "$key-cert.pub" | sed -n '2,9p'
