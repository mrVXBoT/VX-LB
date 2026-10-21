#!/usr/bin/env python3
"""Verify the local offline binary depot against the pinned manifest."""
import os
import platform
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from core.dependency_manifest import PLATFORM_DEPENDENCIES, verify_file_sha256

ALIASES = {
    "slipstream": ("slipstream-client",),
    "slipstream-server": ("slipstream-server",),
    "waterwall": ("Waterwall",),
    "paqet": ("paqet",),
    "backpack": ("backpack",),
}

DEPOT_ENGINES = (
    "backpack", "waterwall", "paqet", "slipstream", "slipstream-server",
    "xray", "trusttunnel", "backhaul", "frp", "frpc", "rathole", "gost", "hysteria2",
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
    for name in DEPOT_ENGINES:
        manifest = PLATFORM_DEPENDENCIES[name]
        for arch in required_archs:
            info = manifest.architectures.get(arch)
            if info is None:
                print(f"-- {name}/{arch}: no manifest entry, skipping")
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
    if failures:
        print("Offline depot is incomplete:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
