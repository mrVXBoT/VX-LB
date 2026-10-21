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
            echo "NO_COLOR disables colors; non-terminal output has no animation."
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

# Self-contained UI: also available when this file runs via curl/process substitution.
UI_TTY=0
UI_COLOR=0
if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ]; then UI_TTY=1; fi
if [ "$UI_TTY" = 1 ] && [ -z "${NO_COLOR+x}" ]; then UI_COLOR=1; fi
UI_RESET='' UI_CYAN='' UI_GREEN='' UI_RED='' UI_DIM=''
if [ "$UI_COLOR" = 1 ]; then
    UI_RESET=$'\033[0m' UI_CYAN=$'\033[36m' UI_GREEN=$'\033[32m'
    UI_RED=$'\033[31m' UI_DIM=$'\033[2m'
fi
UI_LOG='' UI_TASK='' UI_SPINNER='' UI_STAGE='' UI_RENDERER=''
ui_message() {
    printf '  %s[ %-7s ]%s %s\n' "$UI_CYAN" "$1" "$UI_RESET" "$2"
}
ui_banner() {
    if [ "${VX_LB_INSTALL_BANNER:-0}" != 1 ]; then
        printf '\n  %sVX / LB%s   INSTALLER\n' "$UI_CYAN" "$UI_RESET"
        printf '  %sOffline-ready tunnel platform%s\n\n' "$UI_DIM" "$UI_RESET"
        export VX_LB_INSTALL_BANNER=1
    fi
}
ui_stop_spinner() {
    if [ -n "$UI_SPINNER" ]; then
        kill "$UI_SPINNER" 2>/dev/null || true
        wait "$UI_SPINNER" 2>/dev/null || true
        UI_SPINNER=''
        printf '\r\033[2K\033[?25h'
    fi
}
ui_cleanup() {
    local rc=$?
    trap - EXIT
    ui_stop_spinner
    if [ -n "$UI_TASK" ]; then
        kill "$UI_TASK" 2>/dev/null || true
        wait "$UI_TASK" 2>/dev/null || true
    fi
    if [ "$rc" -ne 0 ] && [ -n "$UI_LOG" ]; then
        printf '\n  %s[ failed  ]%s %s (exit %s)\n' "$UI_RED" "$UI_RESET" "${UI_STAGE:-Installation}" "$rc" >&2
        tail -n 12 "$UI_LOG" >&2
        printf '\n  Full installation log: %s\n' "$UI_LOG" >&2
    fi
    exit "$rc"
}
trap ui_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ui_init_log() {
    if [ -z "$UI_LOG" ]; then
        UI_LOG="$(mktemp "${TMPDIR:-/tmp}/vx-lb-install.XXXXXXXX.log")"
        chmod 600 "$UI_LOG"
        ui_message log "$UI_LOG"
    fi
}
ui_spin() {
    # numbers_5 (cliloaders.com), adapted to VX-LB branding, 80ms per frame.
    local frames=('000000' 'V01010' 'VX0101' 'VX-010' 'VX-L01' 'VX-LB0' 'VX-LB ' 'VX-LB ' 'VX-LB ' 'VX-LB0' 'VX-L01' 'VX-010' 'VX0101' 'V01010' '010101')
    local frame width
    width="${COLUMNS:-80}"
    [[ "$width" =~ ^[0-9]+$ ]] || width=80
    [ "$width" -gt 20 ] || width=20
    printf '\033[?25l'
    while :; do
        for frame in "${frames[@]}"; do
            printf '\r\033[2K  %s%s%s  %.*s' "$UI_CYAN" "$frame" "$UI_RESET" "$((width - 12))" "$UI_STAGE"
            sleep 0.08
        done
    done
}
run_step() {
    local label="$1" started=$SECONDS rc=0
    shift
    ui_init_log
    # sudo must prompt in the foreground before command output is redirected.
    case "${1:-}" in
        as_root|install_system_packages)
            if [ "$EUID" -ne 0 ] && command -v sudo &>/dev/null; then sudo -v; fi ;;
    esac
    UI_STAGE="$label"
    printf '\n--- %s ---\n' "$label" >> "$UI_LOG"
    if [ "$UI_TTY" = 1 ]; then ui_spin & UI_SPINNER=$!
    else ui_message working "$label"; fi
    # A separate job lets signals restore the terminal while a command is running.
    # Keep errexit enabled here so failures inside multi-command steps propagate.
    ( trap - EXIT INT TERM; set -e; "$@" ) >> "$UI_LOG" 2>&1 &
    UI_TASK=$!
    wait "$UI_TASK" || rc=$?
    UI_TASK=''
    ui_stop_spinner
    if [ "$rc" -ne 0 ]; then return "$rc"; fi
    if [ -z "$UI_RENDERER" ] || ! node "$UI_RENDERER" done "$label" "$((SECONDS - started))"; then
        printf '  %s[ done    ]%s %s %s(%ss)%s\n' "$UI_GREEN" "$UI_RESET" "$label" "$UI_DIM" "$((SECONDS - started))" "$UI_RESET"
    fi
    UI_STAGE=''
}
ui_banner

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
        VX_LB_INSTALL_BANNER="${VX_LB_INSTALL_BANNER:-0}" \
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
REQUIRED_PAYLOAD=("main.py" "scripts/verify_offline_payload.py" "requirements.txt")
is_complete_install() {
    local d="$1"
    [ -d "$d" ] || return 1
    local f
    for f in "${REQUIRED_PAYLOAD[@]}"; do
        [ -f "$d/$f" ] || return 1
    done
    return 0
}
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    CANDIDATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if is_complete_install "$CANDIDATE_DIR"; then DETECTED_DIR="$CANDIDATE_DIR"; fi
fi
INSTALL_DIR="${VX_LB_INSTALL_DIR:-/opt/vx-lb}"
# Piped offline/check invocations can select an already transferred kit.
if [ -z "$DETECTED_DIR" ] && { [ "$OFFLINE_MODE" = 1 ] || [ "$CHECK_ONLY" = 1 ]; } && is_complete_install "$INSTALL_DIR"; then
    DETECTED_DIR="$INSTALL_DIR"
fi

if [ -z "$DETECTED_DIR" ]; then
    if [ "$OFFLINE_MODE" = 1 ] || [ "$CHECK_ONLY" = 1 ]; then
        echo "A local VX-LB directory is required. Transfer and extract the offline kit first." >&2
        exit 1
    fi
    if ! command -v git &>/dev/null || ! command -v python3 &>/dev/null; then
        run_step "Install OS prerequisites" install_system_packages
    fi
    if [ -e "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR/.git" ]; then
        # An earlier attempt may have left a partial directory; refuse to
        # silently overwrite it.
        echo "$INSTALL_DIR exists but is not a VX-LB checkout. Remove it or set VX_LB_INSTALL_DIR." >&2
        exit 1
    fi
    if [ -d "$INSTALL_DIR/.git" ]; then
        run_step "Fetch application update" as_root git -C "$INSTALL_DIR" fetch origin main
        run_step "Apply application update" as_root git -C "$INSTALL_DIR" reset --hard origin/main
    else
        run_step "Download application and offline payload" as_root git clone https://github.com/mrVXBoT/VX-LB.git "$INSTALL_DIR"
    fi
    # Use the downloaded installer, including any newer validation logic.
    if [ -w "$INSTALL_DIR" ]; then
        exec bash "$INSTALL_DIR/install.sh" "$@"
    fi
    reexec_as_root "$INSTALL_DIR/install.sh" "$@"
    exit $?
fi
SCRIPT_DIR="$(cd "$DETECTED_DIR" && pwd)"
cd "$SCRIPT_DIR"
# The checked-in bundle needs no npm install or network. Unsupported/missing
# Node and narrow terminals use the self-contained Bash renderer.
UI_BUNDLE="$SCRIPT_DIR/scripts/installer-ui/renderer.bundle.mjs"
if command -v node &>/dev/null && [ -f "$UI_BUNDLE" ] &&
    { [ "$UI_TTY" = 0 ] || [ "${COLUMNS:-80}" -ge 76 ] 2>/dev/null; } &&
    node "$UI_BUNDLE" probe >/dev/null 2>&1; then
    UI_RENDERER="$UI_BUNDLE"
    node "$UI_RENDERER" plan "$SCRIPT_DIR" || UI_RENDERER=''
fi

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
    if ! command -v git &>/dev/null || ! command -v python3 &>/dev/null; then run_step "Install OS prerequisites" install_system_packages; fi
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "Tracked local changes found; commit or save them before --update. Nothing was reset." >&2
        exit 1
    fi
    run_step "Update application" git pull --ff-only origin main
    export VX_LB_UPDATE_APPLIED=1
    exec bash "$SCRIPT_DIR/install.sh" "$@"
fi

# Once a local payload exists, all dependency operations stay offline. A missing
# or corrupt payload fails with diagnostics instead of falling back to a network.
OFFLINE_MODE=1
if ! command -v python3 &>/dev/null; then run_step "Install OS prerequisites" install_system_packages; fi
python3 -c 'import venv' || { echo "Python venv support is required before offline installation." >&2; exit 1; }
run_step "Verify offline wheels and engine depot" python3 "$SCRIPT_DIR/scripts/verify_offline_payload.py"
PIP_WHEEL=("$SCRIPT_DIR"/wheelhouse/pip-*.whl)
if [ "${#PIP_WHEEL[@]}" != 1 ] || [ ! -f "${PIP_WHEEL[0]}" ]; then
    echo "Exactly one bundled pip wheel is required. Rebuild the wheelhouse." >&2
    exit 1
fi
# Execute bundled pip directly; OS pip/ensurepip and downloads are unnecessary.
# -S prevents build-host or system packages from satisfying the preflight.
run_step "Check offline dependency resolution" env PYTHONPATH="${PIP_WHEEL[0]}" PIP_CONFIG_FILE=/dev/null python3 -S -m pip --isolated install \
    --dry-run --ignore-installed --target "$SCRIPT_DIR/.venv" --no-index --only-binary=:all: --disable-pip-version-check \
    --find-links "$SCRIPT_DIR/wheelhouse" -r "$SCRIPT_DIR/requirements.txt" \
    -r "$SCRIPT_DIR/requirements-offline.lock"
if [ "$CHECK_ONLY" = 1 ]; then
    ui_message success "Offline preflight passed; no installation changes made."
    exit 0
fi

VENV_DIR="$SCRIPT_DIR/.venv"
if [ ! -x "$VENV_DIR/bin/python" ]; then
    run_step "Create isolated Python environment" python3 -m venv --without-pip "$VENV_DIR"
fi
if [ -f "$VENV_DIR/pyvenv.cfg" ] && grep -qi 'include-system-site-packages *= *true' "$VENV_DIR/pyvenv.cfg"; then
    echo "Existing .venv uses system packages. Move it aside and rerun for an isolated offline installation." >&2
    exit 1
fi
PYTHON="$VENV_DIR/bin/python"
# Reject a copied/incompatible environment before it can use incompatible wheels.
run_step "Verify Python environment compatibility" "$PYTHON" "$SCRIPT_DIR/scripts/verify_offline_payload.py"
run_step "Install bundled Python dependencies" env PYTHONPATH="${PIP_WHEEL[0]}" PIP_CONFIG_FILE=/dev/null "$PYTHON" -m pip --isolated install \
    --no-index --only-binary=:all: --disable-pip-version-check \
    --find-links "$SCRIPT_DIR/wheelhouse" -r "$SCRIPT_DIR/requirements.txt" \
    -r "$SCRIPT_DIR/requirements-offline.lock"
run_step "Check installed dependencies" "$PYTHON" -m pip --isolated check
run_step "Verify application imports" "$PYTHON" -c 'import rich, paramiko, pydantic, yaml, qrcode, nacl, cryptography'

# 4. Setup directories, permissions & global command
setup_permissions() {
    mkdir -p "$SCRIPT_DIR/data"
    chmod 700 "$SCRIPT_DIR/data"
    find "$SCRIPT_DIR/data" -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null || true

    chmod +x "$SCRIPT_DIR/scripts/vxlb-conn-monitor.py" 2>/dev/null || true
    chmod +x "$SCRIPT_DIR/daemon.py"
    chmod +x "$SCRIPT_DIR/main.py"
    chmod +x "$SCRIPT_DIR/run.sh"
    chmod +x "$SCRIPT_DIR/vx-lb"
    chmod +x "$SCRIPT_DIR"/bin/*/* 2>/dev/null || true

}
run_step "Set application permissions" setup_permissions

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
ui_message command "$BIN_DIR/vx-lb (directory must be on PATH)"


# 5. Setup Systemd services (watchdog + optional web dashboard)
install_unit() {
    local unit_name="$1" template="$2"
    local target="/etc/systemd/system/${unit_name}.service"
    local tmp
    tmp="$(mktemp)"
    "$PYTHON" - "$SCRIPT_DIR" "$template" "$tmp" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
template = (root / sys.argv[2]).read_text()
out = template.replace('"%WORKING_DIR%"', str(root)).replace("%WORKING_DIR%", str(root))
Path(sys.argv[3]).write_text(out)
PY
    if [ "$CAN_INSTALL_SERVICE" -eq 1 ]; then
        cp "$tmp" "$target"
    else
        sudo cp "$tmp" "$target"
    fi
    rm -f "$tmp"
}

setup_services() {
    if [ "$NO_SERVICE" -eq 0 ] && command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        CAN_INSTALL_SERVICE=0
        if [ "$EUID" -eq 0 ]; then
            CAN_INSTALL_SERVICE=1
        elif command -v sudo &>/dev/null && sudo -n true 2>/dev/null; then
            CAN_INSTALL_SERVICE=2
        fi

        if [ "$CAN_INSTALL_SERVICE" -gt 0 ]; then
            if [ -f "$SCRIPT_DIR/systemd/vx-lb-watchdog.service" ]; then
                echo "[+] Configuring background watchdog systemd service..."
                install_unit "vx-lb-watchdog" "systemd/vx-lb-watchdog.service"
                if [ "$CAN_INSTALL_SERVICE" -eq 1 ]; then
                    systemctl daemon-reload
                    systemctl enable --now vx-lb-watchdog.service
                    if [ "$UPDATE" = 1 ]; then systemctl restart vx-lb-watchdog.service; fi
                else
                    sudo systemctl daemon-reload
                    sudo systemctl enable --now vx-lb-watchdog.service
                    if [ "$UPDATE" = 1 ]; then sudo systemctl restart vx-lb-watchdog.service; fi
                fi
                echo "✅ Systemd service installed and started: vx-lb-watchdog.service"
            fi

            # Register the web dashboard unit so the panel survives reboot. It is
            # enabled for the next boot; it is started immediately only when the
            # operator starts it via `vx-lb --web`.
            if [ -f "$SCRIPT_DIR/systemd/vx-lb-web.service" ]; then
                install_unit "vx-lb-web" "systemd/vx-lb-web.service"
                if [ "$CAN_INSTALL_SERVICE" -eq 1 ]; then
                    systemctl daemon-reload
                    systemctl enable vx-lb-web.service
                    if [ "$UPDATE" = 1 ]; then systemctl try-restart vx-lb-web.service || true; fi
                else
                    sudo systemctl daemon-reload
                    sudo systemctl enable vx-lb-web.service
                    if [ "$UPDATE" = 1 ]; then sudo systemctl try-restart vx-lb-web.service || true; fi
                fi
                echo "✅ Systemd service registered (enabled, starts on next boot): vx-lb-web.service"
            fi
        else
            echo "ℹ️  Systemd service registration requires sudo/root (optional for standalone CLI)."
        fi
    fi

}
if [ "$NO_SERVICE" = 1 ]; then
    ui_message skipped "Background services (--no-service)"
elif ! command -v systemctl &>/dev/null || [ ! -d /run/systemd/system ]; then
    ui_message skipped "Background services (systemd is unavailable)"
elif [ "$EUID" -ne 0 ] && ! { command -v sudo &>/dev/null && sudo -n true 2>/dev/null; }; then
    ui_message skipped "Background services (requires root/sudo)"
else
    run_step "Configure background services" setup_services
fi

if [ -n "$UI_RENDERER" ]; then
    node "$UI_RENDERER" success "$SCRIPT_DIR" "$BIN_DIR/vx-lb" "$UI_LOG" || ui_message success "VX-LB installed successfully"
else
    printf '\n  %sVX-LB installed successfully%s\n\n' "$UI_GREEN" "$UI_RESET"
    printf '  %-28s %s\n' 'Management panel' 'vx-lb' 'Web dashboard (port 8088)' 'vx-lb --web' 'Set dashboard password' 'vx-lb --set-web-password' 'Watchdog status' 'sudo systemctl status vx-lb-watchdog'
    printf '\n  Installation: %s\n  Full log: %s\n' "$SCRIPT_DIR" "$UI_LOG"
fi
ui_message note "Remote nodes need OS tools, kernel support and engine libraries."
ui_message note "WireGuard OS packages are not included in the offline kit."
printf '\n'

# Launch CLI automatically if running in an interactive terminal
if [ -t 0 ] && [ -t 1 ]; then
    read -t 15 -rp "  Launch the VX-LB panel now? [y/N] " LAUNCH_CHOICE || LAUNCH_CHOICE="n"
    echo ""
    if [[ "$LAUNCH_CHOICE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        exec "$SCRIPT_DIR/vx-lb"
    fi
fi
