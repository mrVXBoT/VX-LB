<p align="center">
  <img src="banner.png" alt="VX LB" width="100%">
</p>

# VX LB

VX LB manages tunnel endpoints on Iran and Kharej servers through a Python CLI and a Persian web dashboard. It deploys remote services over SSH, monitors node health, and updates Cloudflare DNS records for failover and scheduled IP rotation.

## Features

- Server inventory, pool creation, node addition and removal, and transport changes.
- Background jobs with checkpoints and rollback support.
- Cloudflare profiles, zone discovery, per-record controls, and scheduled DNS rotation.
- Health checks using tunnel probes, connection telemetry, and watchdog consensus.
- A Persian RTL dashboard with password authentication and login rate limiting.

Transport profiles include BackPack, HTTP-based tunnels, kernel tunnels, WireGuard, WaterWall, Slipstream, and spoof/desynchronization modes. Availability and support status vary by engine; inspect the registry before deploying:

```bash
vx-lb --list-capabilities
```

Experimental engines require an explicit override for production use. VXLAN itself provides no encryption or authentication; use a separate cryptographic layer where needed. External notification delivery is not implemented; notification calls report that nothing was sent.

## Installation

Run on a Linux host with root access or sudo:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mrVXBoT/VX-LB/main/install.sh)
```

The installer prepares the Python environment, installs the application in `/opt/vx-lb`, and creates the `vx-lb` command. It configures the watchdog service when systemd and the required permissions are available.

The installer shows named stages, a VX-LB `numbers_5` animation, elapsed times,
and a compact command summary. Detailed command output is saved in a private
`/tmp/vx-lb-install.*.log` file; failures show the last lines and the full log path.
Redirected output uses static messages, and `NO_COLOR=1` disables colors.
A bundled `@poppinss/cliui` renderer is used when a compatible Node.js runtime is
already available; the Bash interface works without Node or npm, including offline.

To install from a local checkout instead:

```bash
git clone https://github.com/mrVXBoT/VX-LB.git
cd VX-LB
./install.sh
./run.sh
```

Local installation now automatically uses the verified offline payload. For an
existing installation, rerun `bash /opt/vx-lb/install.sh` without downloads; use
`--update` explicitly to fetch newer code. `--check` verifies offline readiness
without installing. Fresh one-line installation still requires internet access.

For installation during an outage, transfer a prebuilt kit and its checksum,
extract into an empty directory, and run `bash install.sh`. See the
[offline installation guide](docs/offline-install.md) for supported Python/CPU
combinations, kit building, recovery, and OS prerequisites.

## Usage

```bash
vx-lb                         # Open the management CLI
vx-lb --set-web-password       # Set the dashboard password
vx-lb --web                    # Start the dashboard in the background
sudo systemctl status vx-lb-watchdog
```

If node cleanup fails because a server was decommissioned, the failed removal
shows **حذف از پنل بدون پاک‌سازی** (remove from the panel without cleanup). After
confirmation this removes pool membership without SSH or DNS changes. Unverified
cleanup details are retained server-side under `pending_node_cleanup`; remote
services, DNS records and resource reservations still require separate review.

The dashboard normally listens on `127.0.0.1:8088`. For remote access, forward the port over SSH:

```bash
ssh -L 8088:127.0.0.1:8088 root@YOUR_SERVER
```

Then open `http://127.0.0.1:8088` locally. `VX_LB_WEB_HOST` changes the bind address; protect the dashboard with a firewall if exposing it beyond localhost. `VX_LB_WEB_PASSWORD` can bootstrap the password on first run.

## Project layout

| Path | Purpose |
| --- | --- |
| `main.py` | Interactive CLI and command-line entry points |
| `daemon.py` | Watchdog and scheduled DNS rotation |
| `core/` | Deployment adapters, storage, health checks, jobs, and dashboard API |
| `web/` | Dashboard HTML, JavaScript, styles, and assets |
| `bin/` | Engine binaries for remote deployment; see [binary depot](bin/README.md) |
| `scripts/` | Binary packaging, connection monitoring, and lab helpers |
| `systemd/` | Watchdog service template |
| `tests/` | Regression tests and network lab scripts |
| `data/` | Local inventory, credentials, logs, and locks |

Inventory writes are atomic and use file locking with backup generations. DNS and pool mutations use separate locks to coordinate the CLI, dashboard, and watchdog.

## Development and tests

From a checkout, create a virtual environment and install the dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
```

The dashboard's JavaScript test harness requires Node.js:

```bash
node tests/test_web_client.cjs
```

Network lab scripts are separate from the regression suite. Review each script's prerequisites and target hosts before running it.

## Data and dependencies

`data/` stores SSH credentials and Cloudflare tokens. Keep runtime data out of Git, restrict the directory to mode `0700` and files to `0600`, and rotate any credentials that were committed.

Some transports require root or `CAP_NET_RAW` on remote nodes. Deploy and test them only on infrastructure you are authorized to operate.

The bundled VICI client retains its upstream source and license information in [core/vendor/vici/UPSTREAM.md](core/vendor/vici/UPSTREAM.md). Branding assets are in [vx-lb-logo-assets/](vx-lb-logo-assets/).
