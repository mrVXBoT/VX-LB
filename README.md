<p align="center">
  <img src="banner.png" alt="VX LB" width="100%">
</p>

<p align="center">
  <strong>Control plane for Iran and Kharej tunnels.</strong><br>
  A Python CLI and a Persian dashboard deploy the tunnel, watch the nodes, and move Cloudflare DNS when a path fails.
</p>

<p align="center">
  <a href="docs/wiki/Home.md"><strong>راهنمای فارسی</strong></a>
  &nbsp;·&nbsp;
  <a href="docs/wiki/Installation.md">نصب</a>
  &nbsp;·&nbsp;
  <a href="docs/wiki/Quickstart.md">اولین استخر</a>
  &nbsp;·&nbsp;
  <a href="docs/wiki/Panel.md">پنل</a>
  &nbsp;·&nbsp;
  <a href="docs/wiki/Troubleshooting.md">رفع خطا</a>
</p>

The Persian guide is the operator manual: every dashboard profile, Cloudflare, private links, monitoring, recovery, and backups. This page is the project overview. A name in the capability registry is not the same thing as a profile the dashboard can deploy. Disabled packet profiles stay out of the catalog below.

## Install

On a Linux host with root or sudo:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/mrVXBoT/VX-LB/main/install.sh)
```

The installer builds the Python environment, installs the application in `/opt/vx-lb`, and adds the `vx-lb` command. It enables the watchdog when systemd and the required permissions are present.

From a local checkout:

```bash
git clone https://github.com/mrVXBoT/VX-LB.git
cd VX-LB
./install.sh
./run.sh
```

A local install uses the verified offline payload. On an existing install, `bash /opt/vx-lb/install.sh` does not download; pass `--update` to fetch newer code. `--check` only reports whether the offline payload is ready. The one-line install still needs network access.

The installer prints named stages, a timer, and a short command summary. The full command log stays in a private `/tmp/vx-lb-install.*.log`. `NO_COLOR=1` turns color off. A bundled renderer is used when Node.js is already installed; the Bash interface does not need Node.

To install during an outage, copy a prebuilt kit and its checksum into an empty directory and run `bash install.sh`. The [offline guide](docs/offline-install.md) lists the supported Python and CPU combinations.

## Operate

```bash
vx-lb                    # management CLI
vx-lb --set-web-password # dashboard password
vx-lb --web              # dashboard on 127.0.0.1:8088
vx-lb --list-capabilities
sudo systemctl status vx-lb-watchdog
```

Reach the dashboard from another machine by forwarding the port:

```bash
ssh -L 8088:127.0.0.1:8088 root@YOUR_SERVER
```

Then open `http://127.0.0.1:8088`. `VX_LB_WEB_HOST` changes the bind address; firewall it if it is not localhost. `VX_LB_WEB_PASSWORD` can set the first password.

The dashboard creates pools, adds and removes nodes, and changes the tunnel with a checkpointed job. A failed removal can be dropped from the panel without SSH cleanup; the leftover remote resources stay recorded for a later review. DNS updates and pool changes use separate locks so the CLI, the dashboard, and the watchdog do not write the inventory at the same time.

## Tunnel catalog

These are the families the dashboard offers. The client publishes a TCP port on the Iran node unless a profile says otherwise. The carrier between Iran and Kharej is chosen with the profile.

| Engine | Profiles in the dashboard | Carrier | Guide |
| --- | --- | --- | --- |
| BackPack | TCP, Stealth (Noise), PCK, KCP, WSS, QUIC | The selected BackPack transport | [BackPack](docs/wiki/BackPack.md) |
| WaterWall | HalfDuplex, Reverse, Trojan, Bgp4, Reality | WaterWall protocol chain | [WaterWall](docs/wiki/WaterWall.md) |
| GOST | Thirteen profiles: Shadowsocks, obfs4, gRPC, SSH, KCP, Web-Tunnel, QUIC | The selected GOST chain. The published port stays TCP | [GOST](docs/wiki/GOST.md) |
| FRP | TCP, UDP, TCP + UDP | Reverse proxy. The published port stays TCP; UDP mode also forwards UDP | [FRP](docs/wiki/FRP.md) |
| Hedioum | SOCKS5, TUN, Gateway | Mimic pool. The published port is a raw TCP forward | [Hedioum](docs/wiki/Hedioum.md) |
| Rathole | TCP, TLS, Noise, WebSocket | The selected Rathole carrier. The forwarded service is separate | [Rathole](docs/wiki/Rathole.md) |
| Paqet | Port forwarding | KCP over raw packets. Presets: normal, fast, fast2, fast3 | [Paqet](docs/wiki/Paqet.md) |
| Candy-Spoof | One tunnel | Spoofed source address, SOCKS5 on Iran | [Candy-Spoof](docs/wiki/Candy-Spoof.md) |
| ParsaKSH | One tunnel | ICMP, ICMPv6, UDP, or TCP-SYN | [ParsaKSH](docs/wiki/ParsaKSH.md) |
| Kernel | WireGuard, TUN, GRE + IPsec, GRE6, IP6IP6, VXLAN, VXLAN + IPsec, DC6, Geneve + IPsec | A kernel interface on the selected encapsulation | [Kernel tunnels](docs/wiki/Kernel-Tunnels.md) |
| Web and DNS | WebSocket, HTTP CONNECT, HTTPS CONNECT, Slipstream | The selected application or DNS carrier | [Web and DNS](docs/wiki/Web-and-DNS.md) |
| Packet profiles | Five experimental profiles | A managed packet path. The other registry names are disabled | [Packet profiles](docs/wiki/Packet-Profiles.md) |

Encryption is a property of the profile, not of the family. Plain BackPack TCP, plain Rathole TCP, raw VXLAN, GRE6, IP6IP6, and DC6 do not encrypt on their own. Paqet and the spoof tunnels need raw packet access. Read the linked guide before choosing a profile for production. Experimental engines need an explicit production override.

## Also in the dashboard

- Server inventory, pool creation, node membership, and transport changes with rollback.
- Cloudflare profiles, zone discovery, per-record controls, failover, and scheduled IP rotation.
- Health from tunnel probes, connection telemetry, and watchdog consensus.
- Persian RTL interface, password login, and login rate limiting.

External notification delivery is not implemented. Notification calls report that nothing was sent.

## Layout

| Path | Role |
| --- | --- |
| `main.py` | CLI entry point |
| `daemon.py` | Watchdog and scheduled DNS rotation |
| `core/` | Deploy adapters, inventory, health, jobs, and the dashboard API |
| `web/` | Dashboard HTML, JavaScript, and styles |
| `bin/` | Binaries uploaded to the servers. See [bin/README.md](bin/README.md) |
| `scripts/` | Packaging and lab helpers |
| `systemd/` | Watchdog unit |
| `tests/` | Regression tests and network labs |
| `data/` | Inventory, credentials, logs, and locks. Not for Git |
| `docs/wiki/` | Persian operator guide |

Inventory writes are atomic, locked, and kept for a few backup generations.

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
node tests/test_web_client.cjs
```

Network lab scripts are outside the regression suite. Read each script before pointing it at a host.

## Secrets and privileges

`data/` holds SSH passwords and Cloudflare tokens. Keep it at mode `0700`, the files at `0600`, and rotate anything that was ever committed.

Some transports need root or `CAP_NET_RAW` on the remote nodes. Deploy them only on machines you are allowed to operate.

The bundled VICI client keeps its upstream license in [core/vendor/vici/UPSTREAM.md](core/vendor/vici/UPSTREAM.md). Branding files live in [vx-lb-logo-assets/](vx-lb-logo-assets/). Publishing notes for the Persian guide are in [docs/wiki/Maintainers.md](docs/wiki/Maintainers.md).
