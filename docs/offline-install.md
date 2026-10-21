# Offline installation and outage readiness

The normal one-line installer clones the application, engine depot and Python
wheelhouse while internet access is available. Once downloaded, installation and
reinstallation use local wheels only. A local `install.sh` automatically uses the
offline payload; it never silently switches to PyPI or an OS package manager.

## Supported application hosts

- Linux, x86_64 or aarch64 (ARM64).
- CPython 3.10 through 3.14, with the standard `venv` module.
- glibc 2.34 or newer; Alpine/musl is not supported by this wheelhouse.
- Enough free space for the unpacked depot and a virtual environment.
- systemd is required for the watchdog service and remote managed services;
  the CLI can be installed without starting a local watchdog.

For example, Ubuntu 22.04/24.04 and Debian 12/13 meet the glibc requirement when
using a supported Python. An older distribution or Python needs a separately
built and tested payload. Wheel compatibility is not determined by CPU alone.

Prepare OS Python/venv packages **before** disconnecting the host. Neither Git,
curl, OS pip nor ensurepip is needed when installing a transferred kit: the
installer creates a venv without pip and bootstraps pip from its verified wheel.

## Existing installations

```bash
bash /opt/vx-lb/install.sh --check   # Read-only payload and dependency preflight
bash /opt/vx-lb/install.sh          # Install/reinstall locally without downloads
bash /opt/vx-lb/install.sh --offline # Same, with explicit no-download intent
bash /opt/vx-lb/install.sh --update  # Explicit online fast-forward from main
```

`--update` requires a clean tracked working tree. It never resets local changes
or divergent history. Archive installations must be replaced with a newer kit,
preferably extracted into a separate directory; preserve `data/` separately.
`--offline` and `--update` cannot be combined. The one-line bootstrap still needs
internet access to obtain the script and repository on a fresh host.

## Build and transfer a kit

From a trusted, reviewed checkout with the checked-in payload:

```bash
bash scripts/build_offline_kit.sh /tmp/vxlb-offline.tar.gz
```

The builder verifies wheel and binary checksums, resolves dependencies for all
ten Python/CPU combinations without an index, and packages an explicit runtime
allowlist. It excludes inventory, credentials, `.git`, virtual environments and
unrelated top-level files. It writes a SHA-256 sidecar. Transfer both files to the
target using a reachable machine, SCP on a private network, or removable storage.

```bash
sha256sum -c vxlb-offline.tar.gz.sha256
mkdir -p /opt/vx-lb
# Extract into a new/empty directory, not over an unrelated installation.
tar -xzf vxlb-offline.tar.gz -C /opt/vx-lb
bash /opt/vx-lb/install.sh --check
bash /opt/vx-lb/install.sh
```

The kit does not include live inventory. Keep a separate protected backup of
`data/` for recovery. Checksums detect corruption; obtain the kit and checksum
from a trusted channel. They do not establish publisher authenticity by themselves.

For an unprivileged installation or a host without systemd:

```bash
VX_LB_BIN_DIR="$HOME/.local/bin" bash /path/to/vx-lb/install.sh --no-service
```

Add the chosen command directory to `PATH`. `VX_LB_INSTALL_DIR` overrides the
one-line bootstrap destination; `VX_LB_OFFLINE=1` enforces offline mode.

## What outage readiness covers

A successful installation verifies the Python application payload and the pinned
engine depot for both CPU architectures. Existing deployments and engine uploads
over a reachable SSH connection use the bundled binaries. This does not make
Cloudflare API calls, DNS resolution or remote SSH possible across an unavailable
network. It also does not prove every transport works on every kernel or distro.

BackPack installation uses the same local-only path for the adapter, legacy
pools and TUN runtime. A working installed executable is kept. New uploads must
match the architecture's pinned SHA-256. Missing/corrupt local payloads,
unsupported CPUs, failed uploads and failed execution checks return an error;
they never trigger a download from the upstream BackPack repository. An upstream
repository disappearing therefore does not remove our stored binaries. This is
binary redistribution, not a source mirror or fork.

Remote nodes still need appropriate system tools (for example iproute2 and
firewall tools), service management, kernel modules/capabilities and any dynamic
libraries required by the selected engine. WireGuard needs distro-specific
WireGuard tools; `.deb`/`.rpm` packages are not included. Prepare and test each
remote node and the actual chosen transport while connectivity is available.

## Refreshing the payload

In a build environment with network access and recent pip:

```bash
# Edit pins deliberately; this downloads binary wheels for all ten targets.
python3 scripts/build_wheelhouse.py
bash scripts/build_offline_kit.sh /tmp/vxlb-offline.tar.gz
```

`requirements-offline.lock` pins the entire Python closure, including bootstrap
pip. `offline-manifest.json` records SHA-256 hashes of every wheel and both input
requirements files. Changed requirements, missing wheels, unexpected wheels or
corruption fail preflight. The builder also checks application requirements
against the pins. Never edit a hash to hide a failed check.

The `Offline installation` workflow installs the archive twice and launches the
CLI with Docker networking disabled for CPython 3.10–3.14 on amd64 and arm64.
Version tags attach the kit and checksum to a draft GitHub Release only after all
matrix installations pass. Publishing that release remains a separate step.
