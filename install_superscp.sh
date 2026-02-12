#!/usr/bin/env bash
# MIT No Attribution License (MIT-0)
#
# Copyright (c) 2026 Scott Morrison
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
# THE USE OR OTHER DEALINGS IN THE SOFTWARE.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_FILE="${1:-$SCRIPT_DIR/superscp.py}"

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "Source file not found: $SOURCE_FILE" >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Cannot detect Linux distribution: /etc/os-release not readable" >&2
  exit 1
fi

source /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"

choose_install_dir() {
  case "$DISTRO_ID" in
    termux)
      if [[ -n "${PREFIX:-}" ]]; then
        printf '%s\n' "$PREFIX/bin"
      else
        printf '%s\n' "$HOME/.local/bin"
      fi
      ;;
    nixos)
      printf '%s\n' "$HOME/.local/bin"
      ;;
    *)
      printf '%s\n' "/usr/local/bin"
      ;;
  esac
}

INSTALL_DIR="$(choose_install_dir)"
TARGET="$INSTALL_DIR/superscp"

use_sudo=false
if [[ "$INSTALL_DIR" == /usr/* || "$INSTALL_DIR" == /opt/* ]]; then
  if [[ ! -w "$INSTALL_DIR" ]]; then
    use_sudo=true
  fi
fi

if [[ "$use_sudo" == true ]] && ! command -v sudo >/dev/null 2>&1; then
  echo "Need elevated permissions to write $INSTALL_DIR, but sudo is not available." >&2
  exit 1
fi

if [[ "$use_sudo" == true ]]; then
  sudo mkdir -p "$INSTALL_DIR"
  sudo install -m 0755 "$SOURCE_FILE" "$TARGET"
else
  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$SOURCE_FILE" "$TARGET"
fi

echo "Installed superscp to: $TARGET"
echo "Detected distro: $DISTRO_ID${DISTRO_LIKE:+ (like: $DISTRO_LIKE)}"

case "$INSTALL_DIR" in
  "$HOME"/*)
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
      echo "Note: $INSTALL_DIR is not currently in PATH."
      echo "Add this to your shell profile: export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
    ;;
esac
