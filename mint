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
command -v scope_def >/dev/null 2>&1 || die "config defines no scope_def() function (see mint.conf.example)"

# --- locate the PKCS#11 module if token mode and YKCS11 unset --------------------
detect_ykcs11() {
  local p
  for p in \
    /usr/lib/x86_64-linux-gnu/libykcs11.so /usr/lib/libykcs11.so \
    /usr/local/lib/libykcs11.so /usr/local/lib/libykcs11.dylib \
    /opt/homebrew/lib/libykcs11.dylib \
    "/c/Program Files/Yubico/Yubico PIV Tool/bin/libykcs11.dll"; do
    [ -e "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

list_scopes() {
  # scope_def must `echo "<principal> <hours>"` for a known scope, else return non-zero.
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

# --- choose CA backend -----------------------------------------------------------
sign=()
if [ -n "$CA_KEY" ]; then
  [ -f "$CA_KEY" ] || die "CA_KEY '$CA_KEY' not found"
  sign=(-s "$CA_KEY")                       # software CA (testing)
else
  [ -n "$CA_PUB" ] || die "set CA_PUB (token mode) or CA_KEY (software mode) in config"
  [ -f "$CA_PUB" ] || die "CA_PUB '$CA_PUB' not found"
  if [ -z "$YKCS11" ]; then YKCS11=$(detect_ykcs11) || die "could not find libykcs11; set YKCS11 in config"; fi
  [ -e "$YKCS11" ] || die "YKCS11 '$YKCS11' not found"
  sign=(-s "$CA_PUB" -D "$YKCS11")          # CA private key on the YubiKey
fi

# --- ensure a throwaway per-scope user key --------------------------------------
mkdir -p "$SESSIONS_DIR"; chmod 700 "$SESSIONS_DIR"
key="$SESSIONS_DIR/$scope"
[ -f "$key" ] || ssh-keygen -q -t ed25519 -N '' -C "mint-$scope" -f "$key"

# --- build cert options + sign (THE TAP, in token mode) -------------------------
id="${USER:-user}-${scope}-$(date +%Y%m%dT%H%M%S)"
serial=$(date +%s)
opts=(-I "$id" -n "$principal" -V "+${hours}h" -z "$serial")
[ -n "$SOURCE_ADDRESS" ] && opts+=(-O "source-address=$SOURCE_ADDRESS")

printf '%s: signing %s  principal=%s  valid=+%sh%s\n' \
  "$prog" "$scope" "$principal" "$hours" \
  "$([ -n "$CA_KEY" ] && echo '  [software CA]' || echo '  [YubiKey — tap to sign]')"
ssh-keygen "${sign[@]}" "${opts[@]}" "$key.pub"

# --- load into the agent with a matching lifetime -------------------------------
if ssh-add -l >/dev/null 2>&1 || [ $? -eq 1 ]; then
  ssh-add -t "${hours}h" "$key" >/dev/null 2>&1 || ssh-add "$key" >/dev/null 2>&1 || \
    printf '%s: note — could not add to agent (no agent?); cert at %s-cert.pub\n' "$prog" "$key"
fi

printf '%s: minted.\n' "$prog"
ssh-keygen -L -f "$key-cert.pub" | sed -n '2,9p'
