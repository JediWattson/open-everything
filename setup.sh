#!/usr/bin/env bash
# setup.sh — one-shot environment setup for open-everything.
#
#   ./setup.sh              full setup: venv, pip deps, JDK, Ghidra
#   ./setup.sh --check      verify the environment, install nothing
#   ./setup.sh --with-model also pre-download the embedding model (~3 GB)
#
# Idempotent: anything already in place is reported and skipped.

set -euo pipefail
cd "$(dirname "$0")"

CHECK_ONLY=0
WITH_MODEL=0
for arg in "$@"; do
  case "$arg" in
    -c|--check)      CHECK_ONLY=1 ;;
    -m|--with-model) WITH_MODEL=1 ;;
    -h|--help)       sed -n '4,6p' "$0"; exit 0 ;;
    *) echo "unknown flag: $arg (try --help)" >&2; exit 2 ;;
  esac
done

VENV=.venv
FAILED=0
IS_MAC=0
[ "$(uname -s)" = "Darwin" ] && IS_MAC=1

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*" >&2; }
need() { warn "MISSING: $*"; FAILED=1; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ -n "${OE_HOME:-}" ] && printf '%s' "/$OE_HOME" | grep -q '/\.'; then
  warn "OE_HOME=$OE_HOME has a hidden path element — Ghidra's ProjectLocator will reject it"
fi

# --- python >= 3.11 ----------------------------------------------------------
say "python >= 3.11"
PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if have "$c" && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    PY="$c"; break
  fi
done

if [ -z "$PY" ]; then
  if [ "$CHECK_ONLY" = 1 ]; then
    need "python >= 3.11"
  elif [ "$IS_MAC" = 1 ] && have brew; then
    brew install python@3.13 || need "brew install python@3.13 failed"
    PY="$(brew --prefix python@3.13 2>/dev/null)/bin/python3.13"
    [ -x "$PY" ] || PY=python3.13
  else
    need "python >= 3.11 (brew install python@3.13, or your distro's python3.11+)"
  fi
else
  ok "$("$PY" --version 2>&1) ($PY)"
fi

# --- virtualenv + pip --------------------------------------------------------
say "virtualenv"
if [ -x "$VENV/bin/python" ]; then
  ok "$VENV exists"
elif [ "$CHECK_ONLY" = 1 ]; then
  need "$VENV missing"
elif [ -n "$PY" ]; then
  "$PY" -m venv "$VENV" \
    || need "venv creation failed (debian/ubuntu: apt install python3-venv)"
fi

if [ -x "$VENV/bin/python" ]; then
  if [ "$CHECK_ONLY" = 1 ]; then
    if [ -x "$VENV/bin/oe" ]; then ok "oe installed"; else need "oe not installed in $VENV"; fi
  else
    say "pip install -e \".[dev,llm]\""
    "$VENV/bin/pip" install -qU pip
    "$VENV/bin/pip" install -q -e ".[dev,llm]"
    ok "installed into $VENV"
  fi
fi

# --- JDK (Ghidra needs 17+) ---------------------------------------------------
say "java (JDK 17+)"
have_java() {
  if [ "$IS_MAC" = 1 ]; then
    /usr/libexec/java_home >/dev/null 2>&1 && return 0
    # keg-only brew openjdk isn't registered with java_home
    local d
    for d in /opt/homebrew/opt/openjdk* /usr/local/opt/openjdk*; do
      [ -e "$d" ] && return 0
    done
    return 1
  fi
  have java
}

if have_java; then
  ok "JDK found"
elif [ "$CHECK_ONLY" = 1 ]; then
  need "JDK 17+"
elif [ "$IS_MAC" = 1 ]; then
  if have brew; then
    brew install openjdk@21 && ok "openjdk@21 installed" || need "brew install openjdk@21 failed"
  else
    need "JDK 17+ — install Homebrew and 'brew install openjdk@21'"
  fi
elif have apt-get; then
  sudo apt-get update && sudo apt-get install -y default-jdk || need "JDK install failed"
elif have dnf; then
  sudo dnf install -y java-21-openjdk-devel || need "JDK install failed"
elif have pacman; then
  sudo pacman -S --noconfirm jdk-openjdk || need "JDK install failed"
else
  need "JDK 17+ — install OpenJDK with your package manager"
fi

# --- Ghidra ------------------------------------------------------------------
say "ghidra"

# Reuse the app's own discovery (env var, brew libexec, ~/​**/ghidra*_PUBLIC…)
# so this check can never drift from what oe actually sees.
find_ghidra() {
  if [ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ -e "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then
    printf '%s\n' "$GHIDRA_INSTALL_DIR"; return 0
  fi
  for d in /opt/homebrew/opt/ghidra/libexec /usr/local/opt/ghidra/libexec; do
    [ -e "$d/support/analyzeHeadless" ] && { printf '%s\n' "$d"; return 0; }
  done
  if [ -x "$VENV/bin/python" ]; then
    "$VENV/bin/python" -c 'from openeverything import config
g = config.find_ghidra_install()
print(g or "")'
  fi
}

# Latest official release zip, checksum-verified when the API exposes a digest.
# Used on Linux only — the official zip ships no macOS decompiler natives.
install_ghidra_zip() {
  have curl || { need "curl is required to download Ghidra"; return; }
  local tools="${OE_HOME:-$HOME/open-everything}/tools"
  local json meta url digest zip dir
  mkdir -p "$tools"
  say "fetching latest Ghidra release"
  json="$(curl -fsSL https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest)" \
    || { need "could not reach the GitHub releases API"; return; }
  meta="$(printf '%s' "$json" | "$VENV/bin/python" -c '
import json, sys
zips = [a for a in json.load(sys.stdin)["assets"] if a["name"].endswith(".zip")]
a = zips[0]
print(a["browser_download_url"])
print(a.get("digest") or "")' 2>/dev/null)"
  { read -r url; read -r digest; } <<<"$meta"
  [ -n "$url" ] || { need "no ghidra zip asset in the latest release"; return; }
  zip="$tools/$(basename "$url")"
  say "downloading $(basename "$zip")"
  curl -fSL --progress-bar -o "$zip" "$url" || { need "ghidra download failed"; return; }
  case "$digest" in
    sha256:*)
      if [ "$(shasum -a 256 "$zip" | awk '{print $1}')" != "${digest#sha256:}" ]; then
        rm -f "$zip"; need "ghidra zip sha256 mismatch"; return
      fi
      ok "sha256 verified" ;;
  esac
  say "unpacking into $tools"
  if have unzip; then
    unzip -q -o "$zip" -d "$tools"
  else
    "$VENV/bin/python" -m zipfile -e "$zip" "$tools"
  fi
  dir="$(ls -d "$tools"/ghidra_*_PUBLIC 2>/dev/null | sort | tail -1)"
  [ -n "$dir" ] || { need "ghidra_*_PUBLIC missing after unzip"; return; }
  ok "ghidra: $dir"
}

GH="$(find_ghidra || true)"
if [ -n "$GH" ]; then
  ok "ghidra: $GH"
elif [ "$CHECK_ONLY" = 1 ]; then
  [ -x "$VENV/bin/python" ] || warn "$VENV missing — ghidra search limited to env/brew paths"
  need "ghidra (run ./setup.sh, or set GHIDRA_INSTALL_DIR)"
elif [ "$IS_MAC" = 1 ]; then
  if have brew; then
    # formula, not cask — the bottle builds the macOS decompiler natives
    brew install ghidra && ok "ghidra installed via brew" || need "brew install ghidra failed"
  else
    need "ghidra — install Homebrew and 'brew install ghidra'.
          (the official release zip has no macOS decompiler natives)"
  fi
elif [ -x "$VENV/bin/python" ]; then
  install_ghidra_zip
else
  need "ghidra"
fi

# Re-check: a custom OE_HOME outside ~ won't be hit by the home-dir search.
GH="$(find_ghidra || true)"
if [ -z "$GH" ] && [ "$CHECK_ONLY" = 0 ] && [ "$FAILED" = 0 ]; then
  need "ghidra installed but not discoverable — set GHIDRA_INSTALL_DIR"
fi

# --- optional: embedding model ------------------------------------------------
if [ "$WITH_MODEL" = 1 ] && [ "$CHECK_ONLY" = 0 ] && [ -x "$VENV/bin/python" ]; then
  say "embedding model (first download is ~3 GB)"
  "$VENV/bin/python" -c 'from openeverything.embed import Embedder; Embedder()' \
    && ok "model cached" || need "model download failed"
fi

# --- report -------------------------------------------------------------------
echo
[ -x "$VENV/bin/oe" ] && { "$VENV/bin/oe" doctor || true; echo; }

if [ "$FAILED" = 1 ]; then
  warn "setup incomplete — fix the items above and re-run ./setup.sh"
  exit 1
fi
say "ready — try:  $VENV/bin/oe ingest /bin/ls"
