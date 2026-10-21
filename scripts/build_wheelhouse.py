#!/usr/bin/env python3
"""Fetch binary-only dependencies for every supported offline host; pin checksums.

Run with a recent pip in a build environment with internet access. No source
builds or dependencies from the build host are used.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ARCHES = ('x86_64', 'aarch64')
PYTHONS = ('3.10', '3.11', '3.12', '3.13', '3.14')


def target_args(arch, version):
    return ['--implementation', 'cp', '--python-version', version,
            '--platform', f'manylinux_2_34_{arch}',
            '--platform', f'manylinux_2_28_{arch}',
            '--platform', f'manylinux_2_17_{arch}',
            '--platform', f'manylinux2014_{arch}', '--only-binary=:all:']


def main():
    wheels = ROOT / 'wheelhouse'
    wheels.mkdir(exist_ok=True)
    for arch in ARCHES:
        for version in PYTHONS:
            subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'download',
                            '--dest', str(wheels), '-r', str(ROOT / 'requirements-offline.lock'),
                            *target_args(arch, version)], check=True)
    # Validate each dependency closure against application requirements as well
    # as the pins. Dry-run is offline and ignores packages installed on the builder.
    for arch in ARCHES:
        for version in PYTHONS:
            subprocess.run([sys.executable, '-m', 'pip', '--isolated', 'install',
                            '--dry-run', '--ignore-installed', '--target', str(ROOT / '.resolve-only'), '--no-index',
                            '--find-links', str(wheels), '-r', str(ROOT / 'requirements.txt'),
                            '-r', str(ROOT / 'requirements-offline.lock'),
                            *target_args(arch, version)], check=True)
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(wheels.glob('*.whl'))}
    manifest = {'schema': 1, 'implementation': 'cpython', 'python': list(PYTHONS),
                'architectures': list(ARCHES), 'glibc_min': '2.34',
                'inputs': {n: hashlib.sha256((ROOT / n).read_bytes()).hexdigest()
                           for n in ('requirements.txt', 'requirements-offline.lock')},
                'wheels': files}
    (ROOT / 'offline-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Validated 10 targets; recorded {len(files)} wheel checksums.')


if __name__ == '__main__':
    main()
