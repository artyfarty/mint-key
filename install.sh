#!/usr/bin/env bash
#
# install.sh — build/install `mintk` and check that the prerequisites for minting
# are in place. Generic and public-safe: it configures the tool, never anyone's
# CA, hostnames, or principals. See docs/prerequisites.md for the full checklist.
#
# Usage:
#   ./install.sh                 # check prereqs, build+install mintk, set up config
#   ./install.sh check           # only run the prerequisite checks (a "doctor")
#   ./install.sh deps            # offer to install OS-level dependencies
#   ./install.sh build           # build + install the binary only
#   ./install.sh config          # set up the config from the example template
#
# Flags: --prefix DIR (default /usr/local/bin), --yes (no prompts), --help.

# No `set -e`: this installer is conditional-heavy (lots of `[ ] && …`, confirm,
# optional checks). Critical steps (build/install) handle errors explicitly.
set -uo pipefail

PREFIX="/usr/local/bin"
ASSUME_YES=0
ACTION="all"

# --- pretty output --------------------------------------------------------------
if [ -t 1 ]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$C_ERR" "$C_OFF" "$*"; }
info() { printf '%s\n' "$*"; }
hdr()  { printf '\n%s== %s ==%s\n' "$C_DIM" "$*" "$C_OFF"; }
have() { command -v "$1" >/dev/null 2>&1; }

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  printf '%s [y/N] ' "$1"
  read -r ans </dev/tty || return 1
  case "$ans" in y|Y|yes|YES) return 0;; *) return 1;; esac
}

# --- platform -------------------------------------------------------------------
REPO_DIR=$(cd "$(dirname "$0")" && pwd)
OS=$(uname -s)
IS_WSL=0
grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && IS_WSL=1
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/mint-key"
CONFIG="$CONFIG_DIR/config.yaml"

platform_label() {
  if [ "$IS_WSL" = 1 ]; then echo "WSL (Windows host)"; else echo "$OS"; fi
}

# --- argument parsing -----------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    check|deps|build|config|all) ACTION="$1" ;;
    --prefix) PREFIX="$2"; shift ;;
    --prefix=*) PREFIX="${1#--prefix=}" ;;
    --yes|-y) ASSUME_YES=1 ;;
    --help|-h)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) bad "unknown argument: $1"; exit 2 ;;
  esac
  shift
done

# --- read the active mode from config (if any) ----------------------------------
# Best-effort: just grep the scalar so checks can be mode-aware without a parser.
config_mode() {
  [ -f "$CONFIG" ] || { echo ""; return; }
  sed -nE 's/^[[:space:]]*mode:[[:space:]]*([a-z-]+).*/\1/p' "$CONFIG" | head -1
}
config_value() { # config_value <key>
  [ -f "$CONFIG" ] || return 1
  sed -nE "s/^[[:space:]]*$1:[[:space:]]*(.*)/\1/p" "$CONFIG" | head -1 | sed 's/^"//; s/"$//'
}
expand_tilde() { case "$1" in "~"/*) printf '%s' "$HOME/${1#\~/}";; *) printf '%s' "$1";; esac; }

# ================================================================================
# checks
# ================================================================================
CHECK_FAILS=0
check_common() {
  hdr "Common (platform: $(platform_label))"
  local missing=0
  for c in ssh ssh-keygen ssh-add; do
    if have "$c"; then ok "$c found"; else bad "$c missing — install OpenSSH client"; missing=1; fi
  done
  # ssh-keygen -U (CA key in agent) needs OpenSSH >= 7.6
  if have ssh; then
    local ver
    ver=$(ssh -V 2>&1 | sed -nE 's/.*OpenSSH_([0-9]+\.[0-9]+).*/\1/p')
    if [ -n "$ver" ]; then
      awk -v v="$ver" 'BEGIN{split(v,a,"."); exit !(a[1]>7 || (a[1]==7 && a[2]>=6))}' \
        && ok "OpenSSH $ver (supports ssh-keygen -U)" \
        || { warn "OpenSSH $ver is old; -U (agent CA) needs >= 7.6"; }
    fi
  fi
  [ "$missing" = 1 ] && CHECK_FAILS=$((CHECK_FAILS+1))
}

check_ca() {
  hdr "CA public key"
  local capub
  capub=$(config_value ca_pub || true)
  if [ -z "$capub" ]; then warn "ca_pub not set in $CONFIG (set it after config setup)"; return; fi
  capub=$(expand_tilde "$capub")
  if [ -f "$capub" ]; then
    ok "ca.pub present: $capub"
    have ssh-keygen && info "    $(ssh-keygen -lf "$capub" 2>/dev/null || echo '(could not fingerprint)')"
  else
    bad "ca.pub not found at $capub"; CHECK_FAILS=$((CHECK_FAILS+1))
  fi
}

check_agent_mode() {
  hdr "Agent mode (ssh-keygen -U through an agent)"
  if ! have ssh-add; then bad "ssh-add missing"; CHECK_FAILS=$((CHECK_FAILS+1)); return; fi
  if [ -z "${SSH_AUTH_SOCK:-}" ]; then
    bad "SSH_AUTH_SOCK is unset — no agent reachable (start the agent bridge)"; CHECK_FAILS=$((CHECK_FAILS+1)); return
  fi
  ok "SSH_AUTH_SOCK=$SSH_AUTH_SOCK"
  if ssh-add -l >/dev/null 2>&1; then
    local capub fp
    capub=$(config_value ca_pub || true); capub=$(expand_tilde "${capub:-}")
    if [ -n "$capub" ] && [ -f "$capub" ] && have ssh-keygen; then
      fp=$(ssh-keygen -lf "$capub" 2>/dev/null | awk '{print $2}')
      if [ -n "$fp" ] && ssh-add -l 2>/dev/null | grep -qF "$fp"; then
        ok "CA key is loaded in the agent"
      else
        bad "CA key NOT in the agent — plug in a CA YubiKey / start the bridge (or run 'mintk clean')"
        CHECK_FAILS=$((CHECK_FAILS+1))
      fi
    else
      warn "can't verify the CA is in the agent (ca_pub not set/found yet)"
    fi
  else
    bad "agent not responding to ssh-add -l"; CHECK_FAILS=$((CHECK_FAILS+1))
  fi
  if [ "$IS_WSL" = 1 ]; then
    info "    ${C_DIM}WSL: needs WinCryptSSHAgent + an npiperelay/socat bridge — see docs/prerequisites.md${C_OFF}"
  fi
}

check_token_mode() {
  hdr "Token mode (local PKCS#11)"
  local found=""
  for p in \
    /usr/lib/x86_64-linux-gnu/libykcs11.so /usr/lib/libykcs11.so \
    /usr/local/lib/libykcs11.so /usr/local/lib/libykcs11.dylib /opt/homebrew/lib/libykcs11.dylib \
    /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so /usr/lib/opensc-pkcs11.so \
    /usr/local/lib/opensc-pkcs11.so /opt/homebrew/lib/opensc-pkcs11.so \
    /Library/OpenSC/lib/opensc-pkcs11.so; do
    [ -e "$p" ] && { found="$p"; break; }
  done
  if [ -n "$found" ]; then ok "PKCS#11 module: $found"; else
    bad "no PKCS#11 module (install yubico-piv-tool/libykcs11 or opensc) — './install.sh deps'"
    CHECK_FAILS=$((CHECK_FAILS+1))
  fi
  if [ "$OS" = "Linux" ]; then
    if pgrep -x pcscd >/dev/null 2>&1; then ok "pcscd running"; else warn "pcscd not running (needed to reach the card)"; fi
  fi
}

run_checks() {
  info "mintk prerequisite check — $(platform_label)"
  check_common
  check_ca
  local mode; mode=$(config_mode)
  case "$mode" in
    agent)        check_agent_mode ;;
    token)        check_token_mode ;;
    software)     hdr "Software mode"; warn "software CA (testing only) — set ca_key in $CONFIG" ;;
    wsl-delegate) hdr "wsl-delegate"; warn "signs via Windows ssh-keygen + Windows PKCS#11 — see docs/prerequisites.md" ;;
    "")           warn "no config yet; checking both common backends"; check_agent_mode; check_token_mode ;;
    *)            warn "unknown mode '$mode' in config" ;;
  esac
  hdr "Result"
  if [ "$CHECK_FAILS" = 0 ]; then ok "all required checks passed"; else
    bad "$CHECK_FAILS check group(s) need attention — see docs/prerequisites.md"
  fi
}

# ================================================================================
# deps
# ================================================================================
install_deps() {
  hdr "OS dependencies"
  local pkgs_apt="opensc yubico-piv-tool pcscd socat age yubikey-manager"
  local pkgs_brew="opensc yubico-piv-tool socat age ykman"
  if have apt-get; then
    info "Debian/Ubuntu packages: $pkgs_apt"
    info "  (opensc/yubico-piv-tool → PKCS#11; socat → WSL agent bridge; age → CA backup; ykman → slot mgmt)"
    if confirm "Install via apt-get (sudo)?"; then
      sudo apt-get update && sudo apt-get install -y $pkgs_apt
      ok "apt packages installed"
    else info "skipped."; fi
  elif have brew; then
    info "Homebrew packages: $pkgs_brew"
    if confirm "Install via brew?"; then
      brew install $pkgs_brew && ok "brew packages installed"
    else info "skipped."; fi
  else
    warn "no apt-get or brew — install the PKCS#11 module / socat / age manually (see docs/prerequisites.md)"
  fi
  if [ "$IS_WSL" = 1 ]; then
    info "${C_DIM}WSL agent path also needs Windows-side pieces (Smart Card Minidriver,${C_OFF}"
    info "${C_DIM}WinCryptSSHAgent, npiperelay) — those are manual; see docs/prerequisites.md.${C_OFF}"
  fi
}

# ================================================================================
# build + install binary
# ================================================================================
build_install() {
  hdr "Build mintk"
  if ! have go; then
    bad "Go toolchain not found — install Go (>= 1.25) then re-run './install.sh build'"
    return 1
  fi
  info "go build (GOTOOLCHAIN=auto fetches Go 1.25 if needed)..."
  if ! ( cd "$REPO_DIR" && GOTOOLCHAIN=auto go build -o mintk . ); then
    bad "go build failed"; return 1
  fi
  ok "built $REPO_DIR/mintk"

  hdr "Install to $PREFIX"
  local dest="$PREFIX/mintk"
  mkdir -p "$PREFIX" 2>/dev/null || sudo mkdir -p "$PREFIX"
  if [ -w "$PREFIX" ]; then
    install -m 755 "$REPO_DIR/mintk" "$dest" || { bad "install failed"; return 1; }
  else
    info "  (sudo needed to write $PREFIX)"
    sudo install -m 755 "$REPO_DIR/mintk" "$dest" || { bad "install failed"; return 1; }
  fi
  ok "installed $dest"
  have mintk && info "    $(command -v mintk)"
}

# ================================================================================
# config setup
# ================================================================================
setup_config() {
  hdr "Config"
  if [ -f "$CONFIG" ]; then ok "config exists: $CONFIG (leaving as-is)"; return; fi
  info "no config yet — the best way to create one is the interactive bootstrap:"
  info "    ${C_DIM}mintk init${C_OFF}   (picks a mode, imports the CA from your YubiKey, sets up scopes)"
  if confirm "Write a starter config from the example template instead?"; then
    mkdir -p "$CONFIG_DIR"
    cp "$REPO_DIR/config.example.yaml" "$CONFIG"
    chmod 600 "$CONFIG"
    ok "wrote $CONFIG — edit it (ca_pub, mode, scopes) before minting"
  else
    info "skipped — run 'mintk init' when ready."
  fi
}

# ================================================================================
# main
# ================================================================================
case "$ACTION" in
  check)  run_checks; exit $CHECK_FAILS ;;
  deps)   install_deps ;;
  build)  build_install ;;
  config) setup_config ;;
  all)
    run_checks
    hdr "Install"
    if confirm "Build and install mintk to $PREFIX?"; then build_install; fi
    setup_config
    hdr "Next steps"
    info "  1) mintk init             # bootstrap config: import the CA from your YubiKey"
    info "  2) mintk scopes list      # (or 'mintk scopes add' / 'mintk scopes edit')"
    info "  3) mintk key <scope>      # mint (tap the YubiKey)"
    info "  4) mintk deploy <scope> user@host   # enroll a host"
    info "  Re-run './install.sh check' anytime to re-verify prerequisites."
    ;;
esac
