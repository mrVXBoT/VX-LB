#!/usr/bin/env python3
"""Verify the local offline binary depot against the pinned manifest."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.dependency_manifest import PLATFORM_DEPENDENCIES, verify_file_sha256
from core.nfqws2_profiles import VERSION as NFQWS2_VERSION, ARCHIVE_SHA256 as NFQWS2_ARCHIVE_SHA256

DEPOT_ENGINES = (
    "backpack", "waterwall", "paqet", "slipstream", "slipstream-server",
    "xray", "trusttunnel", "backhaul", "frp", "frpc", "rathole", "gost", "hysteria2",
)

# Packet-engine archives that must exist for strict-offline NFQWS2 installs;
# missing files fail preflight instead of reaching for ARCHIVE_URL at deploy
# time. Archives are arch-pinned by nfqws2_profiles, not the manifest.
DEPOT_ARCHIVES = (
    ("nfqws2", f"zapret2-{NFQWS2_VERSION}.tar.gz", NFQWS2_ARCHIVE_SHA256),
)
ALIASES = {
    "slipstream": ("slipstream-client",),
    "slipstream-server": ("slipstream-server",),
    "waterwall": ("Waterwall",),
    "paqet": ("paqet",),
    "backpack": ("backpack",),
    "xray": ("xray",),
    "trusttunnel": ("trusttunnel",),
    "backhaul": ("backhaul",),
    "frp": ("frps",),
    "frpc": ("frpc",),
    "rathole": ("rathole",),
    "gost": ("gost",),
    "hysteria2": ("hysteria",),
}


def main() -> int:
    failures = []
    required_archs = sys.argv[1:] or ["x86_64"]
    unknown = set(required_archs) - {'x86_64', 'aarch64'}
    if unknown:
        print(f"Unsupported depot architectures: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 1
    for name in DEPOT_ENGINES:
        manifest = PLATFORM_DEPENDENCIES[name]
        for arch in required_archs:
            info = manifest.architectures.get(arch)
            if info is None:
                failures.append(f"missing manifest entry {name}/{arch}")
                continue
            expected = info.get("sha256")
            candidates = ALIASES.get(name, (manifest.executable_name,))
            paths = [os.path.join(ROOT, "bin", arch, candidate) for candidate in candidates]
            present = next((path for path in paths if os.path.isfile(path)), None)
            if not present:
                failures.append(f"missing {name}/{arch} ({manifest.executable_name})")
            elif not expected or not info.get("is_verified"):
                failures.append(f"unverified {present}")
            elif not verify_file_sha256(present, expected):
                failures.append(f"checksum mismatch {present}")
            else:
                print(f"OK {name}/{arch}: {os.path.relpath(present, ROOT)}")

    # Packet-engine archives are pinned to a specific arch by their profile
    # constants, not by the per-engine manifest.
    for label, filename, expected_sha in DEPOT_ARCHIVES:
        path = os.path.join(ROOT, "bin", "x86_64", filename)
        if not os.path.isfile(path):
            failures.append(f"missing {label} archive bin/x86_64/{filename}")
            continue
        if not expected_sha or not verify_file_sha256(path, expected_sha):
            failures.append(f"checksum mismatch {os.path.relpath(path, ROOT)}")
        else:
            print(f"OK {label}/x86_64: {os.path.relpath(path, ROOT)}")

    if failures:
        print("Offline depot is incomplete:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
