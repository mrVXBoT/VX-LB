#!/bin/bash
# Build a verified archive from an explicit runtime allowlist (never runtime data).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT="${1:-${VXLB_OFFLINE_OUT:-/tmp/vxlb-offline.tar.gz}}"
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
case "$OUT" in
    "$ROOT"/dist/*|"$ROOT"/build/*) ;;
    "$ROOT"/*)
        echo "Inside the checkout, output must be under dist/ or build/." >&2; exit 2 ;;
esac
python3 scripts/verify_offline_payload.py --all-targets
# Check the dependency closure for all supported targets using bundled pip.
PIP_WHEEL=("$ROOT"/wheelhouse/pip-*.whl)
PYTHONPATH="${PIP_WHEEL[0]}" python3 - <<'PY'
from scripts.build_wheelhouse import ARCHES, PYTHONS, ROOT, target_args
import os
import subprocess
import sys
for arch in ARCHES:
    for version in PYTHONS:
        subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'install',
                        '--dry-run', '--ignore-installed', '--target', str(ROOT / '.resolve-only'), '--no-index',
                        '--disable-pip-version-check', '--find-links', str(ROOT / 'wheelhouse'),
                        '-r', str(ROOT / 'requirements.txt'),
                        '-r', str(ROOT / 'requirements-offline.lock'),
                        *target_args(arch, version)], check=True,
                       env={**os.environ, 'PIP_CONFIG_FILE': '/dev/null'})
PY
# No .git, .venv, inventory, credentials, local configs or arbitrary untracked
# top-level files. The archive includes the empty data directory only at install.
TMP="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
tar --exclude='__pycache__' --exclude='*.pyc' \
    -czf "$TMP" \
    main.py daemon.py vx-lb run.sh install.sh requirements.txt \
    requirements-offline.lock offline-manifest.json \
    core web bin wheelhouse scripts systemd README.md docs banner.png vx-lb-logo-assets
chmod 644 "$TMP"
mv "$TMP" "$OUT"
(cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "[+] Verified kit: $OUT"
echo "[+] Checksum: $OUT.sha256"
echo "Transfer both files, then:"
echo "  sha256sum -c $(basename "$OUT").sha256"
echo "  mkdir -p /opt/vx-lb"
echo "  tar -xzf $(basename "$OUT") -C /opt/vx-lb"
echo "  bash /opt/vx-lb/install.sh"
