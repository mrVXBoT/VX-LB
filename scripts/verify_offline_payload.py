#!/usr/bin/env python3
"""Validate wheel integrity, supported host, and the bundled engine depot."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify(root=ROOT, check_host=True):
    manifest = json.loads((root / 'offline-manifest.json').read_text())
    if manifest.get('schema') != 1 or not manifest.get('wheels'):
        raise ValueError('Invalid offline manifest; rebuild with scripts/build_wheelhouse.py')
    if set(manifest.get('inputs', {})) != {'requirements.txt', 'requirements-offline.lock'}:
        raise ValueError('Offline manifest must cover both requirements files')
    for name, digest in manifest['inputs'].items():
        if name not in ('requirements.txt', 'requirements-offline.lock'):
            raise ValueError(f'Unexpected manifest input: {name}')
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'{name} changed; rebuild wheelhouse and manifest')
    actual = {p.name for p in (root / 'wheelhouse').glob('*.whl')}
    if actual != set(manifest['wheels']):
        raise ValueError('Wheelhouse files differ from manifest; rebuild the payload')
    for name, digest in manifest['wheels'].items():
        if Path(name).name != name or not name.endswith('.whl'):
            raise ValueError(f'Invalid wheel name: {name}')
        if hashlib.sha256((root / 'wheelhouse' / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f'Wheel checksum mismatch: {name}')
    if check_host:
        version = f'{sys.version_info.major}.{sys.version_info.minor}'
        arch = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(platform.machine().lower(), platform.machine().lower())
        libc, libc_version = platform.libc_ver()
        if (sys.platform != 'linux' or platform.python_implementation().lower() != manifest['implementation']
                or version not in manifest['python'] or arch not in manifest['architectures']):
            raise ValueError(f'Unsupported offline host: {sys.platform}/{arch}/Python {version}. '
                             f"Supported: Linux CPython {', '.join(manifest['python'])}; x86_64/aarch64")
        if libc != 'glibc' or tuple(map(int, libc_version.split('.'))) < tuple(map(int, manifest['glibc_min'].split('.'))):
            raise ValueError(f"Offline wheels require glibc >= {manifest['glibc_min']}; found {libc} {libc_version}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all-targets', action='store_true', help='Verify payload integrity without requiring a supported build host')
    args = parser.parse_args()
    try:
        manifest = verify(check_host=not args.all_targets)
        subprocess.run([sys.executable, str(ROOT / 'scripts/verify_offline_depot.py'),
                        *manifest['architectures']], check=True)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f'Offline preflight failed: {exc}', file=sys.stderr)
        return 1
    print(f"Offline payload verified: {len(manifest['wheels'])} wheels; engine depot for both architectures.")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
