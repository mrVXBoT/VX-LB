#!/bin/bash
set -euo pipefail
umask 022
export PYTHONDONTWRITEBYTECODE=1

OFFLINE_MODE="${VX_LB_OFFLINE:-0}"
UPDATE=0
CHECK_ONLY=0
NO_SERVICE=0
for arg in "$@"; do
    case "$arg" in
        --offline) OFFLINE_MODE=1 ;;
        --update) UPDATE=1 ;;
        --check) CHECK_ONLY=1 ;;
        --no-service) NO_SERVICE=1 ;;
        --help|-h)
            echo "Usage: bash install.sh [--offline | --update] [--check] [--no-service]"
            echo "Local installs use the verified offline payload automatically."
            echo "--update fetches main explicitly; --offline forbids package/repository downloads."
            echo "--check verifies payload and dependency resolution without installing."
            echo "VX_LB_INSTALL_DIR sets the bootstrap destination (default /opt/vx-lb)."
            echo "VX_LB_BIN_DIR sets the command link directory."
            exit 0 ;;
        *) echo "Unknown option: $arg (see --help)" >&2; exit 2 ;;
    esac
done
if [ "$OFFLINE_MODE" = 1 ] && [ "$UPDATE" = 1 ]; then
    echo "--offline and --update cannot be combined." >&2
    exit 2
fi
if [ "$CHECK_ONLY" = 1 ] && [ "$UPDATE" = 1 ]; then
    echo "--check does not update files; run --update separately." >&2
    exit 2
fi

echo "=========================================================="
echo "             VX LB — Automated Installer                  "
echo "=========================================================="

as_root() {
    if [ "$EUID" -eq 0 ]; then "$@"
    elif command -v sudo &>/dev/null; then sudo "$@"
    else echo "Root or sudo is required for system package installation." >&2; return 1
    fi
}
reexec_as_root() {
    local installer_path="$1"
    shift
    as_root env VX_LB_OFFLINE="$OFFLINE_MODE" \
        VX_LB_BIN_DIR="${VX_LB_BIN_DIR:-}" VX_LB_INSTALL_DIR="$INSTALL_DIR" \
        bash "$installer_path" "$@"
}

install_system_packages() {
    if [ "$OFFLINE_MODE" = 1 ] || [ "$CHECK_ONLY" = 1 ]; then
        echo "Python 3 with venv is required. Install OS prerequisites before going offline." >&2
        return 1
    fi
    if command -v apt-get &>/dev/null; then
        as_root apt-get update
        as_root apt-get install -y python3 python3-venv git ca-certificates
    elif command -v dnf &>/dev/null; then
        as_root dnf install -y python3 python3-pip git ca-certificates
    elif command -v yum &>/dev/null; then
        as_root yum install -y python3 python3-pip git ca-certificates
    elif command -v pacman &>/dev/null; then
        as_root pacman -S --needed --noconfirm python git ca-certificates
    else
        echo "Install Python 3 with venv and git using your OS package manager." >&2
        return 1
    fi
}

DETECTED_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    CANDIDATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$CANDIDATE_DIR/main.py" ]; then DETECTED_DIR="$CANDIDATE_DIR"; fi
fi
INSTALL_DIR="${VX_LB_INSTALL_DIR:-/opt/vx-lb}"
if [ -z "$DETECTED_DIR" ] && [ -f "$INSTALL_DIR/main.py" ]; then
    DETECTED_DIR="$INSTALL_DIR"
fi

if [ -z "$DETECTED_DIR" ]; then
    if [ "$OFFLINE_MODE" = 1 ] || [ "$CHECK_ONLY" = 1 ]; then
        echo "A local VX-LB directory is required. Transfer and extract the offline kit first." >&2
        exit 1
    fi
    if ! command -v git &>/dev/null || ! command -v python3 &>/dev/null; then
        install_system_packages
    fi
    echo "[+] Downloading application and offline payload to $INSTALL_DIR..."
    as_root git clone https://github.com/mrVXBoT/VX-LB.git "$INSTALL_DIR"
    # Use the downloaded installer, including any newer validation logic.
    if [ -w "$INSTALL_DIR" ]; then
        exec bash "$INSTALL_DIR/install.sh" "$@"
    fi
    reexec_as_root "$INSTALL_DIR/install.sh" "$@"
    exit $?
fi
SCRIPT_DIR="$(cd "$DETECTED_DIR" && pwd)"
cd "$SCRIPT_DIR"

# A bootstrap rerun may find an installation created by root on the first run.
# Preflight remains readable without sudo; mutations need the installation owner.
if [ "$CHECK_ONLY" = 0 ] && { [ ! -w "$SCRIPT_DIR" ] || { [ -d "$SCRIPT_DIR/.venv" ] && [ ! -w "$SCRIPT_DIR/.venv" ]; }; }; then
    if [ "$EUID" -eq 0 ]; then
        echo "Installation directory or .venv is not writable: $SCRIPT_DIR" >&2
        exit 1
    fi
    reexec_as_root "$SCRIPT_DIR/install.sh" "$@"
    exit $?
fi

if [ "$UPDATE" = 1 ] && [ "${VX_LB_UPDATE_APPLIED:-0}" != 1 ]; then
    if [ ! -d .git ]; then
        echo "Archive installations cannot git-update. Transfer a newer kit to a separate directory." >&2
        exit 1
    fi
    if ! command -v git &>/dev/null || ! command -v python3 &>/dev/null; then install_system_packages; fi
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "Tracked local changes found; commit or save them before --update. Nothing was reset." >&2
        exit 1
    fi
    git pull --ff-only origin main
    export VX_LB_UPDATE_APPLIED=1
    exec bash "$SCRIPT_DIR/install.sh" "$@"
fi

# Once a local payload exists, all dependency operations stay offline. A missing
# or corrupt payload fails with diagnostics instead of falling back to a network.
OFFLINE_MODE=1
if ! command -v python3 &>/dev/null; then install_system_packages; fi
python3 -c 'import venv' || { echo "Python venv support is required before offline installation." >&2; exit 1; }
python3 "$SCRIPT_DIR/scripts/verify_offline_payload.py"
PIP_WHEEL=("$SCRIPT_DIR"/wheelhouse/pip-*.whl)
if [ "${#PIP_WHEEL[@]}" != 1 ] || [ ! -f "${PIP_WHEEL[0]}" ]; then
    echo "Exactly one bundled pip wheel is required. Rebuild the wheelhouse." >&2
    exit 1
fi
# Execute bundled pip directly; OS pip/ensurepip and downloads are unnecessary.
# -S prevents build-host or system packages from satisfying the preflight.
PYTHONPATH="${PIP_WHEEL[0]}" PIP_CONFIG_FILE=/dev/null python3 -S -m pip --isolated install \
    --dry-run --ignore-installed --target "$SCRIPT_DIR/.venv" --no-index --only-binary=:all: --disable-pip-version-check \
    --find-links "$SCRIPT_DIR/wheelhouse" -r "$SCRIPT_DIR/requirements.txt" \
    -r "$SCRIPT_DIR/requirements-offline.lock"
if [ "$CHECK_ONLY" = 1 ]; then
    echo "[+] Offline preflight passed; no installation changes made."
    exit 0
fi

VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -x "$VENV_DIR/bin/python" ]; then
    echo "[+] Creating isolated Python environment..."
    if ! python3 -m venv --without-pip "$VENV_DIR"; then
        echo "Python venv support is missing. Install your OS python3-venv package first." >&2
        exit 1
    fi
fi
if [ -f "$VENV_DIR/pyvenv.cfg" ] && grep -qi 'include-system-site-packages *= *true' "$VENV_DIR/pyvenv.cfg"; then
    echo "Existing .venv uses system packages. Move it aside and rerun for an isolated offline installation." >&2
    exit 1
fi
PYTHON="$VENV_DIR/bin/python"
# Reject a copied/incompatible environment before it can use incompatible wheels.
"$PYTHON" "$SCRIPT_DIR/scripts/verify_offline_payload.py"
PYTHONPATH="${PIP_WHEEL[0]}" PIP_CONFIG_FILE=/dev/null "$PYTHON" -m pip --isolated install \
    --no-index --only-binary=:all: --disable-pip-version-check \
    --find-links "$SCRIPT_DIR/wheelhouse" -r "$SCRIPT_DIR/requirements.txt" \
    -r "$SCRIPT_DIR/requirements-offline.lock"
"$PYTHON" -m pip --isolated check
"$PYTHON" -c 'import rich, paramiko, pydantic, yaml, qrcode, nacl, cryptography'

# 4. Setup directories, permissions & global command
echo "[+] Setting directory permissions & binary execution bits..."
mkdir -p "$SCRIPT_DIR/data"
chmod 700 "$SCRIPT_DIR/data"
find "$SCRIPT_DIR/data" -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null || true

chmod +x "$SCRIPT_DIR/scripts/vxlb-conn-monitor.py" 2>/dev/null || true
chmod +x "$SCRIPT_DIR/daemon.py"
chmod +x "$SCRIPT_DIR/main.py"
chmod +x "$SCRIPT_DIR/run.sh"
chmod +x "$SCRIPT_DIR/vx-lb"
chmod +x "$SCRIPT_DIR"/bin/*/* 2>/dev/null || true

# A custom bin directory allows an unprivileged installation or isolated checks.
BIN_DIR="${VX_LB_BIN_DIR:-/usr/local/bin}"
if [ -n "${VX_LB_BIN_DIR:-}" ] || [ -w "$BIN_DIR" ] || [ "$EUID" -eq 0 ]; then
    mkdir -p "$BIN_DIR"
    ln -sf "$SCRIPT_DIR/vx-lb" "$BIN_DIR/vx-lb"
elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
    sudo ln -sf "$SCRIPT_DIR/vx-lb" "$BIN_DIR/vx-lb"
else
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    ln -sf "$SCRIPT_DIR/vx-lb" "$BIN_DIR/vx-lb"
fi
echo "[+] Command linked: $BIN_DIR/vx-lb (directory must be on PATH)"

# 5. Setup Systemd Watchdog Service
SERVICE_NAME="vx-lb-watchdog"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ "$NO_SERVICE" -eq 0 ] && command -v systemctl &>/dev/null && [ -d /run/systemd/system ] && [ -f "$SCRIPT_DIR/systemd/vx-lb-watchdog.service" ]; then
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
template = (root / "systemd/vx-lb-watchdog.service").read_text()
Path(sys.argv[2]).write_text(template.replace("%WORKING_DIR%", str(root)))
PY

        if [ "$CAN_INSTALL_SERVICE" -eq 1 ]; then
            cp "$SERVICE_TMP" "$SERVICE_FILE"
            if [ -f "$SERVICE_FILE" ]; then
                systemctl daemon-reload
                systemctl enable --now "${SERVICE_NAME}.service"
                if [ "$UPDATE" = 1 ]; then systemctl restart "${SERVICE_NAME}.service"; fi
                echo "✅ Systemd service installed and started: ${SERVICE_NAME}.service"
            fi
        elif [ "$CAN_INSTALL_SERVICE" -eq 2 ]; then
            if sudo cp "$SERVICE_TMP" "$SERVICE_FILE" 2>/dev/null; then
                sudo systemctl daemon-reload
                sudo systemctl enable --now "${SERVICE_NAME}.service"
                if [ "$UPDATE" = 1 ]; then sudo systemctl restart "${SERVICE_NAME}.service"; fi
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
echo "[+] Offline application dependencies and engine depot verified."
echo "[!] Remote nodes still need their OS tools, kernel support and engine libraries."
echo "[!] WireGuard tools are OS packages and are not included in this kit."
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
