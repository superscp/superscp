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
VERSION_FILE="$SCRIPT_DIR/VERSION"

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "Source file not found: $SOURCE_FILE" >&2
  exit 1
fi

# Read the canonical version from the VERSION file.
if [[ -f "$VERSION_FILE" ]]; then
  SUPERSCP_VERSION="$(tr -d '[:space:]' < "$VERSION_FILE")"
else
  echo "Warning: VERSION file not found at $VERSION_FILE; version will not be stamped." >&2
  SUPERSCP_VERSION=""
fi

# Detect the running distro so we can pick the right package manager
# and install location later.

DISTRO_ID="unknown"
DISTRO_LIKE=""

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  DISTRO_ID="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
elif [[ "$(uname)" == "Darwin" ]]; then
  DISTRO_ID="macos"
fi

# Figure out whether we can elevate with sudo.  We try a no-password
# check first; if that fails we still set has_sudo=true because the
# user may be prompted later.

has_sudo=false
if command -v sudo >/dev/null 2>&1; then
  if sudo -n true 2>/dev/null; then
    has_sudo=true
  else
    echo "Note: sudo available but may require a password."
    has_sudo=true
  fi
fi

# Pick the install directory.  Prefer /usr/local/bin for system-wide
# visibility; fall back to ~/.local/bin when we can't write there.

choose_install_dir() {
  case "$DISTRO_ID" in
    termux)
      if [[ -n "${PREFIX:-}" ]]; then
        printf '%s\n' "$PREFIX/bin"
      else
        printf '%s\n' "$HOME/.local/bin"
      fi
      return
      ;;
    nixos)
      printf '%s\n' "$HOME/.local/bin"
      return
      ;;
  esac

  local sys_dir="/usr/local/bin"

  if [[ -w "$sys_dir" ]]; then
    printf '%s\n' "$sys_dir"
    return
  fi

  if [[ "$has_sudo" == true ]]; then
    printf '%s\n' "$sys_dir"
    return
  fi

  printf '%s\n' "$HOME/.local/bin"
}

INSTALL_DIR="$(choose_install_dir)"
TARGET="$INSTALL_DIR/superscp"

# Copy the script into the chosen directory with executable permissions.

install_binary() {
  if [[ -w "$INSTALL_DIR" ]] || [[ -w "$(dirname "$INSTALL_DIR")" ]]; then
    mkdir -p "$INSTALL_DIR"
    install -m 0755 "$SOURCE_FILE" "$TARGET"
    return 0
  fi

  if [[ "$has_sudo" == true ]]; then
    sudo mkdir -p "$INSTALL_DIR"
    sudo install -m 0755 "$SOURCE_FILE" "$TARGET"
    return 0
  fi

  # Neither writable nor sudoable; fall back to user-local directory.
  local fallback="$HOME/.local/bin"
  mkdir -p "$fallback"
  install -m 0755 "$SOURCE_FILE" "$fallback/superscp"
  INSTALL_DIR="$fallback"
  TARGET="$fallback/superscp"
  return 0
}

install_binary

# Stamp the version string into the installed copy.  The source file
# contains a @@VERSION@@ placeholder; we substitute it here so the
# binary reports the correct version without needing the VERSION file.
if [[ -n "$SUPERSCP_VERSION" ]]; then
  stamp_version() {
    local target="$1"
    if [[ -w "$target" ]]; then
      sed -i "s/@@VERSION@@/$SUPERSCP_VERSION/g" "$target"
    elif [[ "$has_sudo" == true ]]; then
      sudo sed -i "s/@@VERSION@@/$SUPERSCP_VERSION/g" "$target"
    else
      echo "Warning: cannot write to $target; version not stamped." >&2
    fi
  }
  stamp_version "$TARGET"
fi

echo "Installed superscp to: $TARGET"
echo "Detected distro: $DISTRO_ID${DISTRO_LIKE:+ (like: $DISTRO_LIKE)}"

# Install paramiko (optional).  When available, superscp can use native
# SFTP channels instead of forking scp subprocesses.  We try the system
# package manager first, then pip system-wide, then pip --user.

PY_CMD=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    PY_CMD="$candidate"
    break
  fi
done

paramiko_installed=false

install_paramiko_pkg() {
  # Try the distro package manager so we don't need pip at all.
  case "$DISTRO_ID" in
    ubuntu|debian|linuxmint|pop)
      if [[ "$has_sudo" == true ]]; then
        echo "Installing python3-paramiko via apt..."
        if sudo apt-get install -y python3-paramiko >/dev/null 2>&1; then
          return 0
        fi
      fi
      ;;
    fedora)
      if [[ "$has_sudo" == true ]]; then
        echo "Installing python3-paramiko via dnf..."
        if sudo dnf install -y python3-paramiko >/dev/null 2>&1; then
          return 0
        fi
      fi
      ;;
    centos|rhel|almalinux|rocky)
      if [[ "$has_sudo" == true ]]; then
        echo "Installing python3-paramiko via yum..."
        if sudo yum install -y python3-paramiko >/dev/null 2>&1; then
          return 0
        fi
      fi
      ;;
    arch|manjaro)
      if [[ "$has_sudo" == true ]]; then
        echo "Installing python-paramiko via pacman..."
        if sudo pacman -S --noconfirm python-paramiko >/dev/null 2>&1; then
          return 0
        fi
      fi
      ;;
    opensuse*|sles)
      if [[ "$has_sudo" == true ]]; then
        echo "Installing python3-paramiko via zypper..."
        if sudo zypper install -y python3-paramiko >/dev/null 2>&1; then
          return 0
        fi
      fi
      ;;
    macos)
      # No system package available; pip handles macOS below.
      ;;
  esac
  return 1
}

install_paramiko_pip() {
  [[ -z "$PY_CMD" ]] && return 1

  # On macOS, Homebrew Python's site-packages is user-writable and
  # sudo pip is blocked by SIP, so try plain pip before --user.
  if [[ "$DISTRO_ID" == "macos" ]]; then
    if "$PY_CMD" -m pip install "paramiko>=2.7" >/dev/null 2>&1; then
      return 0
    fi
    if "$PY_CMD" -m pip install --user "paramiko>=2.7" >/dev/null 2>&1; then
      return 0
    fi
    # Try pip3 directly (some macOS setups only expose pip3).
    if command -v pip3 >/dev/null 2>&1; then
      if pip3 install "paramiko>=2.7" >/dev/null 2>&1; then
        return 0
      fi
      if pip3 install --user "paramiko>=2.7" >/dev/null 2>&1; then
        return 0
      fi
    fi
    return 1
  fi

  # Linux / other: try system-wide via sudo, then user-local.
  if [[ "$has_sudo" == true ]]; then
    if sudo "$PY_CMD" -m pip install "paramiko>=2.7" >/dev/null 2>&1; then
      return 0
    fi
  fi

  if "$PY_CMD" -m pip install --user "paramiko>=2.7" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

if [[ -n "$PY_CMD" ]]; then
  # Check if paramiko is already importable.
  if "$PY_CMD" -c "import paramiko" 2>/dev/null; then
    echo "paramiko already available - native SFTP transport enabled."
    paramiko_installed=true
  else
    echo "Attempting to install paramiko for native SFTP support..."
    if install_paramiko_pkg; then
      paramiko_installed=true
    elif install_paramiko_pip; then
      paramiko_installed=true
    fi
  fi
fi

if [[ "$paramiko_installed" == true ]]; then
  echo "paramiko installed - superscp will use native SFTP transport."
else
  echo "Note: paramiko not installed (optional). superscp will use scp subprocess."
  echo "      Install later with: pip install paramiko"
fi

# If we installed to a user-local directory, remind the user to add
# it to PATH if it isn't there already.

case "$INSTALL_DIR" in
  "$HOME"/*)
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
      echo ""
      echo "Note: $INSTALL_DIR is not in PATH."
      echo "Add to your shell profile:"
      echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
    ;;
esac
