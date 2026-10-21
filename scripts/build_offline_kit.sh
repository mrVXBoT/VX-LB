#!/bin/bash
# Build a self-contained VX-LB offline kit tarball for air-gapped deployment.
# The archive contains code, the verified binary depot (bin/), and the Python
# wheelhouse — everything needed to run `install.sh --offline` on a host with
# no internet access beyond Python 3 + systemd.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${1:-${VXLB_OFFLINE_OUT:-/tmp/vxlb-offline.tar.gz}}"

echo "[+] Verifying offline depot before packaging..."
python3 scripts/verify_offline_depot.py x86_64 aarch64

echo "[+] Building $OUT ..."
tar --exclude='./.git' \
    --exclude='./.venv' \
    --exclude='./data' \
    --exclude='./__pycache__' \
    --exclude='./**/__pycache__' \
    --exclude='./.pytest_cache' \
    --exclude='./node_modules' \
    --exclude='./vxlb-offline*.tar.gz' \
    --exclude='./.claude' \
    -czf "$OUT" .

echo "[+] Kit ready:"
ls -lh "$OUT"
echo ""
echo "Deploy on an offline host:"
echo "  scp $(basename "$OUT") root@SERVER:/root/"
echo "  ssh root@SERVER 'mkdir -p /opt/vx-lb && tar -xzf /root/vxlb-offline.tar.gz -C /opt/vx-lb && bash /opt/vx-lb/install.sh --offline'"
