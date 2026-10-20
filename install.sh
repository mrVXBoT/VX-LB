#!/bin/bash
set -euo pipefail
umask 022

echo "=========================================================="
echo "      VX LB — Network Load Balancer & Tunnel Platform     "
echo "             Fast Automated One-Line Installer            "
echo "=========================================================="

as_root() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    elif command -v sudo &>/dev/null; then
        sudo "$@"
    else
        echo "[-] Root privileges are required. Run this installer as root or with sudo." >&2
        return 1
    fi
}

install_system_packages() {
    echo "[+] Installing system prerequisites (Python 3, venv, git, curl)..."
    if command -v apt-get &>/dev/null; then
        as_root apt-get update -y
        as_root apt-get install -y python3 python3-venv python3-pip git curl
    elif command -v dnf &>/dev/null; then
        as_root dnf install -y python3 python3-pip git curl
    elif command -v yum &>/dev/null; then
        as_root yum install -y python3 python3-pip git curl
    elif command -v pacman &>/dev/null; then
        as_root pacman -Sy --noconfirm python python-virtualenv git curl
    else
        echo "[-] Unsupported package manager. Please install Python 3 with venv/pip, git, and curl manually." >&2
        return 1
    fi
}

# 1. Determine execution context (local clone vs remote one-liner curl | bash)
DETECTED_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    CANDIDATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
    if [ -f "$CANDIDATE_DIR/main.py" ]; then
        DETECTED_DIR="$CANDIDATE_DIR"
    fi
fi

REPO_URL="https://github.com/mrVXBoT/VX-LB.git"

if [ -n "$DETECTED_DIR" ]; then
    SCRIPT_DIR="$DETECTED_DIR"
    echo "[*] Running installation from local directory: $SCRIPT_DIR"
    cd "$SCRIPT_DIR"
else
    INSTALL_DIR="/opt/vx-lb"
    echo "[+] Remote one-line installation detected."
    echo "[+] Target installation directory: $INSTALL_DIR"

    if ! command -v git &>/dev/null || ! command -v python3 &>/dev/null; then
        install_system_packages
    fi

    if [ -d "$INSTALL_DIR/.git" ]; then
        echo "[*] Existing installation found in $INSTALL_DIR. Updating to latest release..."
        cd "$INSTALL_DIR"
        # Untracked runtime data is preserved; tracked files are reset to upstream state.
        as_root git fetch origin main
        if ! as_root git pull --ff-only origin main; then
            echo "[!] Local changes detected. Resetting tracked files to latest release (user data preserved)..."
            as_root git reset --hard origin/main
        fi
        as_root git submodule update --init --recursive 2>/dev/null || true
    else
        echo "[+] Cloning VX-LB repository into $INSTALL_DIR..."
        as_root mkdir -p "$(dirname "$INSTALL_DIR")"
        as_root git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    SCRIPT_DIR="$INSTALL_DIR"
fi

# 2. Ensure Python runtime & virtual environment
if ! command -v python3 &>/dev/null; then
    install_system_packages
fi

VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -d "$VENV_DIR" ] || [ ! -x "$VENV_DIR/bin/python" ]; then
    echo "[+] Initializing Python virtual environment at $VENV_DIR..."
    if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
        if ! python3 -m venv --without-pip --system-site-packages "$VENV_DIR" 2>/dev/null; then
            install_system_packages
            python3 -m venv "$VENV_DIR" || python3 -m venv --without-pip --system-site-packages "$VENV_DIR"
        fi
    fi
fi
PYTHON="$VENV_DIR/bin/python"

# 3. Install Python dependencies
echo "[+] Checking and installing Python dependencies..."
if [ -x "$VENV_DIR/bin/pip" ]; then
    "$VENV_DIR/bin/pip" install -q --upgrade pip 2>/dev/null || true
    "$VENV_DIR/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt" || true
elif command -v pip3 &>/dev/null; then
    pip3 install -q -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || true
fi
"$PYTHON" -c 'import rich, paramiko, pydantic, yaml'

# 4. Setup directories, permissions & global command
echo "[+] Setting directory permissions & binary execution bits..."
mkdir -p "$SCRIPT_DIR/data"
chmod 700 "$SCRIPT_DIR/data"
find "$SCRIPT_DIR/data" -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null || true

chmod +x "$SCRIPT_DIR/scripts/bp-conn-monitor.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/daemon.py"
chmod +x "$SCRIPT_DIR/main.py"
chmod +x "$SCRIPT_DIR/run.sh"
chmod +x "$SCRIPT_DIR/vx-lb"
chmod +x "$SCRIPT_DIR"/bin/*/* 2>/dev/null || true

# Global command link: 'vx-lb' accessible system-wide
if [ -w "/usr/local/bin" ] || [ "$EUID" -eq 0 ]; then
    ln -sf "$SCRIPT_DIR/vx-lb" /usr/local/bin/vx-lb
    echo "✅ Global command linked: /usr/local/bin/vx-lb"
elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    sudo ln -sf "$SCRIPT_DIR/vx-lb" /usr/local/bin/vx-lb
    echo "✅ Global command linked: /usr/local/bin/vx-lb"
else
    mkdir -p "$HOME/.local/bin"
    ln -sf "$SCRIPT_DIR/vx-lb" "$HOME/.local/bin/vx-lb"
    echo "✅ User command linked: $HOME/.local/bin/vx-lb"
fi

# 5. Setup Systemd Watchdog Service
SERVICE_NAME="ld-bp-watchdog"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ -f "$SCRIPT_DIR/systemd/ld-bp-watchdog.service" ]; then
    CAN_INSTALL_SERVICE=0
    if [ "$EUID" -eq 0 ]; then
        CAN_INSTALL_SERVICE=1
    elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
        CAN_INSTALL_SERVICE=2
    fi

    if [ "$CAN_INSTALL_SERVICE" -gt 0 ]; then
        echo "[+] Configuring background watchdog systemd service..."
        SERVICE_TMP="$(mktemp)"
        trap 'rm -f "$SERVICE_TMP"' EXIT
        "$PYTHON" - "$SCRIPT_DIR" "$SERVICE_TMP" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
template = (root / "systemd/ld-bp-watchdog.service").read_text()
Path(sys.argv[2]).write_text(template.replace("%WORKING_DIR%", str(root)))
PY

        if [ "$CAN_INSTALL_SERVICE" -eq 1 ]; then
            if cp "$SERVICE_TMP" "$SERVICE_FILE" 2>/dev/null; then
                systemctl daemon-reload 2>/dev/null || true
                systemctl enable --now "${SERVICE_NAME}.service" 2>/dev/null || true
                echo "✅ Systemd service installed and started: ${SERVICE_NAME}.service"
            fi
        elif [ "$CAN_INSTALL_SERVICE" -eq 2 ]; then
            if sudo cp "$SERVICE_TMP" "$SERVICE_FILE" 2>/dev/null; then
                sudo systemctl daemon-reload 2>/dev/null || true
                sudo systemctl enable --now "${SERVICE_NAME}.service" 2>/dev/null || true
                echo "✅ Systemd service installed and started: ${SERVICE_NAME}.service"
            else
                echo "ℹ️  Systemd service setup skipped (can be registered later via sudo)."
            fi
        fi
    else
        echo "ℹ️  Systemd service registration requires sudo/root (optional for standalone CLI)."
    fi
fi

echo ""
echo "=========================================================="
echo "🎉 VX-LB platform installed successfully!"
echo "=========================================================="
echo ""
echo "Quick Commands:"
echo "  • Launch the interactive management panel (CLI):"
echo "      vx-lb"
echo ""
echo "  • Start the web dashboard in the background (port 8088):"
echo "      vx-lb --web"
echo ""
echo "  • Set the web panel password:"
echo "      vx-lb --set-web-password"
echo ""
echo "  • Check the Watchdog background service status:"
echo "      sudo systemctl status ${SERVICE_NAME}"
echo "=========================================================="
echo ""

# Launch CLI automatically if running in an interactive terminal
if [ -t 0 ] && [ -t 1 ]; then
    read -t 15 -rp "Launch the VX-LB panel now? [Y/n] " LAUNCH_CHOICE || LAUNCH_CHOICE="n"
    echo ""
    if [[ "$LAUNCH_CHOICE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        exec "$SCRIPT_DIR/vx-lb"
    fi
fi
