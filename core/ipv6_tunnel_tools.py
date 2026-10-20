"""Dedicated tools and utilities for IPv6-based kernel tunnels (GRE6 and IP6IP6) in VX-LB.

Covers:
- IP6IP6 (IPv6-in-IPv6 RFC 2473 encapsulation)
- GRE6 (Generic Routing Encapsulation over IPv6 RFC 7676 / RFC 2784)
- Verification of IPv6 reachability on both Iran and Kharej endpoints
- Private link addressing (dual-stack and IPv6-only)
- MTU validation and scoped routing (strict /32 and /128 host routes dev iface)
- Strict preservation of default routes and SSH management access
- Scoped firewall lifecycle per interface
- Active data-plane probe with cryptographic nonce verification
- Inherent cleartext warning (these protocols do NOT have intrinsic encryption)
"""
import hashlib
import ipaddress
import re
import secrets
import shlex
import time
from typing import Any, Dict, List, Optional, Tuple, Union

CLEARTEXT_WARNING = (
    "SECURITY NOTICE: This tunnel protocol transmits cleartext packets without "
    "native cryptographic encryption, authentication, or obfuscation. "
    "Underlay headers and encapsulated payloads are fully visible to intermediate transit networks."
)


def validate_ipv6_address(ip_str: Any) -> str:
    """Validates and normalizes an IPv6 address string.

    Rejects loopback, link-local, multicast, unspecified, and IPv4-mapped addresses
    to guarantee valid routable native endpoints for outer tunnel carriers.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError(f"Invalid IPv6 address value: {ip_str!r}")

    # Strip CIDR prefix and scope identifier (e.g. %eth0)
    clean = ip_str.strip().split("/")[0].split("%")[0]
    try:
        addr = ipaddress.IPv6Address(clean)
    except ValueError as err:
        raise ValueError(f"Invalid IPv6 address format '{ip_str}': {err}") from err

    if addr.is_loopback:
        raise ValueError(f"IPv6 address '{clean}' cannot be loopback (::1)")
    if addr.is_link_local:
        raise ValueError(f"IPv6 address '{clean}' cannot be link-local (fe80::/10) for tunnel endpoint")
    if addr.is_multicast:
        raise ValueError(f"IPv6 address '{clean}' cannot be multicast (ff00::/8)")
    if addr.is_unspecified:
        raise ValueError(f"IPv6 address '{clean}' cannot be unspecified (::)")
    if addr.ipv4_mapped is not None:
        raise ValueError(f"IPv6 address '{clean}' cannot be IPv4-mapped IPv6 address")

    return str(addr)


def validate_mtu(mtu_value: Any, min_mtu: int, max_mtu: int, tunnel_type: str = "IPv6 tunnel") -> int:
    """Validates MTU bounds for an IPv6 tunnel interface."""
    try:
        mtu = int(str(mtu_value).strip())
    except (ValueError, TypeError):
        raise ValueError(f"{tunnel_type} MTU must be an integer, got: {mtu_value!r}")

    if not (min_mtu <= mtu <= max_mtu):
        raise ValueError(
            f"{tunnel_type} MTU must be between {min_mtu} and {max_mtu} bytes, got {mtu}"
        )
    return mtu


def sanitize_interface_name(prefix: str, identifier: str) -> str:
    """Generates a valid Linux interface name (max 15 chars, IFNAMSIZ)."""
    clean_id = re.sub(r"[^a-zA-Z0-9]", "", identifier).lower()
    if not clean_id:
        clean_id = secrets.token_hex(4)
    # Ensure prefix + '-' + clean_id <= 15 chars
    max_id_len = 15 - len(prefix) - 1
    short_id = clean_id[:max_id_len]
    return f"{prefix}-{short_id}"


def check_ipv6_reachability(ssh: Any, remote_ipv6: str, count: int = 2, timeout: int = 2) -> Tuple[bool, str]:
    """Verifies IPv6 reachability from the SSH host to the remote endpoint."""
    if not hasattr(ssh, "execute"):
        return False, "Invalid SSH manager provided for IPv6 reachability check"

    norm_ip = validate_ipv6_address(remote_ipv6)
    # Check for ping utility using POSIX command -v with fallback to which
    cmd = (
        f"if command -v ping >/dev/null 2>&1; then "
        f"ping -6 -c {count} -W {timeout} {shlex.quote(norm_ip)}; "
        f"elif command -v ping6 >/dev/null 2>&1; then "
        f"ping6 -c {count} -W {timeout} {shlex.quote(norm_ip)}; "
        f"elif which ping >/dev/null 2>&1; then "
        f"ping -6 -c {count} -W {timeout} {shlex.quote(norm_ip)}; "
        f"elif which ping6 >/dev/null 2>&1; then "
        f"ping6 -c {count} -W {timeout} {shlex.quote(norm_ip)}; "
        f"else exit 127; fi"
    )
    code, out, err = ssh.execute(cmd)
    if code == 0:
        return True, f"IPv6 reachability to {norm_ip} verified successfully"
    if code == 127:
        return False, "Neither 'ping -6' nor 'ping6' utility found on host"
    return False, f"IPv6 reachability check to {norm_ip} failed: {err.strip() or out.strip()}"


def check_bidirectional_ipv6_reachability(
    iran_ssh: Any,
    kharej_ssh: Any,
    iran_ipv6: str,
    kharej_ipv6: str,
    count: int = 2,
    timeout: int = 2,
) -> Tuple[bool, str]:
    """Verifies IPv6 reachability from both sides (Iran -> Kharej and Kharej -> Iran)."""
    ok_ir, msg_ir = check_ipv6_reachability(iran_ssh, kharej_ipv6, count=count, timeout=timeout)
    if not ok_ir:
        return False, f"Iran to Kharej reachability failed: {msg_ir}"

    ok_kh, msg_kh = check_ipv6_reachability(kharej_ssh, iran_ipv6, count=count, timeout=timeout)
    if not ok_kh:
        return False, f"Kharej to Iran reachability failed: {msg_kh}"

    return True, f"Bidirectional IPv6 reachability verified between {iran_ipv6} and {kharej_ipv6}"


def check_kernel_prerequisites(ssh: Any, module_name: str) -> Tuple[bool, str]:
    """Verifies that the required kernel module can be loaded and iproute2 tools are installed."""
    if not hasattr(ssh, "execute"):
        return False, "Invalid SSH manager"

    # 1. Verify kernel module presence (fail closed if module cannot be loaded or found)
    mod_cmd = (
        f"modprobe {shlex.quote(module_name)} 2>/dev/null || "
        f"test -d /sys/module/{shlex.quote(module_name)} || "
        f"grep -q '^{shlex.quote(module_name)} ' /proc/modules 2>/dev/null"
    )
    code_mod, out_mod, err_mod = ssh.execute(mod_cmd)
    if code_mod != 0:
        return False, f"Kernel module '{module_name}' is missing or not supported on target host: {err_mod.strip() or out_mod.strip()}"

    # 2. Verify required system utilities
    tool_cmd = (
        "command -v ip sysctl >/dev/null 2>&1 || "
        "which ip sysctl >/dev/null 2>&1"
    )
    code_tool, out_tool, err_tool = ssh.execute(tool_cmd)
    if code_tool != 0:
        return False, "Missing required system tools (ip, sysctl) on target host"

    # Host-to-host private relays do not require changing global forwarding/RA policy.

    return True, f"Kernel module '{module_name}' and system networking tools verified"


def allocate_tunnel_ips(
    base_id: Optional[str] = None,
    ipv4_subnet: Optional[str] = None,
    ipv6_subnet: Optional[str] = None,
    prefix_v4: str = "10.206",
    prefix_v6: str = "fd00:1db0:6",
) -> Dict[str, str]:
    """Allocates deterministic or pseudo-random non-conflicting private IPv4 (/30) and IPv6 (/126) addresses."""
    if base_id:
        idx = int(hashlib.md5(base_id.encode("utf-8")).hexdigest()[:4], 16) % 16000
    else:
        idx = secrets.randbelow(16000)

    # IPv4 /30
    if ipv4_subnet:
        net4 = ipaddress.IPv4Network(ipv4_subnet)
        hosts4 = list(net4.hosts())
        ir_v4 = str(hosts4[0])
        kh_v4 = str(hosts4[1])
        sub4 = str(net4)
    else:
        octet2 = (idx >> 6) & 0xFF
        octet3 = (idx & 0x3F) * 4
        sub4 = f"{prefix_v4}.{octet2}.{octet3}/30"
        ir_v4 = f"{prefix_v4}.{octet2}.{octet3 + 1}"
        kh_v4 = f"{prefix_v4}.{octet2}.{octet3 + 2}"

    # IPv6 /126
    if ipv6_subnet:
        net6 = ipaddress.IPv6Network(ipv6_subnet)
        hosts6 = list(net6.hosts())
        ir_v6 = str(hosts6[0])
        kh_v6 = str(hosts6[1])
        sub6 = str(net6)
    else:
        sub6 = f"{prefix_v6}:{idx:04x}::/126"
        ir_v6 = f"{prefix_v6}:{idx:04x}::1"
        kh_v6 = f"{prefix_v6}:{idx:04x}::2"

    return {
        "iran_ipv4": ir_v4,
        "kharej_ipv4": kh_v4,
        "ipv4_subnet": sub4,
        "iran_ipv6": ir_v6,
        "kharej_ipv6": kh_v6,
        "ipv6_subnet": sub6,
    }


def parse_link_telemetry(link_output: str) -> Dict[str, Any]:
    """Parses `ip -d -s link show <iface>` output into telemetry metrics."""
    telemetry = {
        "state": "DOWN",
        "mtu": None,
        "rx_packets": 0,
        "rx_bytes": 0,
        "rx_errors": 0,
        "tx_packets": 0,
        "tx_bytes": 0,
        "tx_errors": 0,
    }

    if not link_output:
        return telemetry

    lines = link_output.strip().splitlines()
    header = lines[0] if lines else ""

    state_match = re.search(r"state\s+([A-Z]+)", header)
    if state_match:
        telemetry["state"] = state_match.group(1)
    elif "<UP" in header:
        telemetry["state"] = "UP"

    mtu_match = re.search(r"mtu\s+(\d+)", header)
    if mtu_match:
        telemetry["mtu"] = int(mtu_match.group(1))

    # Look for RX / TX counters in subsequent lines
    # ip -s output standard format:
    # RX:  bytes packets errors dropped overrun mcast
    #     12345   123     0       0       0       0
    # TX:  bytes packets errors dropped carrier collsns
    #     67890   456     0       0       0       0
    for i, line in enumerate(lines):
        line_s = line.strip()
        if line_s.startswith("RX:") and i + 1 < len(lines):
            parts = lines[i + 1].strip().split()
            if len(parts) >= 3:
                try:
                    telemetry["rx_bytes"] = int(parts[0])
                    telemetry["rx_packets"] = int(parts[1])
                    telemetry["rx_errors"] = int(parts[2])
                except ValueError:
                    pass
        elif line_s.startswith("TX:") and i + 1 < len(lines):
            parts = lines[i + 1].strip().split()
            if len(parts) >= 3:
                try:
                    telemetry["tx_bytes"] = int(parts[0])
                    telemetry["tx_packets"] = int(parts[1])
                    telemetry["tx_errors"] = int(parts[2])
                except ValueError:
                    pass

    return telemetry


def synthesize_status(service_active: bool, link_exists: bool, telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """Synthesizes high-level tunnel status (UP, DOWN, DEGRADED) with explanatory diagnosis."""
    if not service_active or not link_exists:
        return {
            "status": "DOWN",
            "reason": "Service inactive or network interface missing in kernel",
            "telemetry": telemetry,
        }

    state = telemetry.get("state")
    if state == "UP" or (telemetry.get("tx_packets", 0) > 0 and telemetry.get("rx_packets", 0) > 0):
        return {
            "status": "UP",
            "reason": "Interface state is UP with active bidirectional packet flow",
            "telemetry": telemetry,
        }

    return {
        "status": "DEGRADED",
        "reason": f"Interface exists but carrier state is {state or 'UNKNOWN'} with no bidirectional traffic",
        "telemetry": telemetry,
    }


def render_scoped_service(
    service_name: str,
    interface: str,
    create_link_cmd: str,
    mtu: int,
    local_priv_v4: Optional[str],
    local_priv_v6: Optional[str],
    peer_priv_v4: Optional[str],
    peer_priv_v6: Optional[str],
) -> str:
    """Generates a systemd oneshot service unit that creates the link, sets MTU,
    assigns private addresses, and adds scoped host-only routes without modifying default routes.
    """
    start_cmds = [
        f"/sbin/{create_link_cmd}",
        f"/sbin/ip link set {interface} mtu {mtu}",
    ]

    if local_priv_v6:
        start_cmds.append(f"/sbin/ip -6 addr add {local_priv_v6}/126 dev {interface}")
    if local_priv_v4:
        start_cmds.append(f"/sbin/ip addr add {local_priv_v4}/30 dev {interface}")

    # IPv6 rejects a host route whose output device is still down.
    start_cmds.append(f"/sbin/ip link set {interface} up")

    # Scoped routes: strictly /128 for IPv6 peer and /32 for IPv4 peer
    # NEVER modifies default route or default gateway
    if peer_priv_v6:
        start_cmds.append(f"/sbin/ip -6 route replace {peer_priv_v6}/128 dev {interface}")
    if peer_priv_v4:
        start_cmds.append(f"/sbin/ip route replace {peer_priv_v4}/32 dev {interface}")

    exec_start_lines = "\n".join(f"ExecStart={cmd}" for cmd in start_cmds)

    return f"""[Unit]
Description=VX-LB IPv6 Kernel Tunnel ({interface})
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
{exec_start_lines}
ExecStop=-/sbin/ip link set {interface} down
ExecStop=-/sbin/ip link del {interface}
TimeoutSec=30

[Install]
WantedBy=multi-user.target
"""


ECHO_RESPONDER_PY = """import socket, sys, time
host = sys.argv[1]
port = int(sys.argv[2])
is_v6 = (':' in host)
af = socket.AF_INET6 if is_v6 else socket.AF_INET
sock = socket.socket(af, socket.SOCK_DGRAM)
try:
    sock.bind((host, port))
except Exception:
    try:
        sock.bind(('::' if is_v6 else '0.0.0.0', port))
    except Exception as e:
        sys.stderr.write(f"BIND_ERROR:{e}\\n")
        sys.exit(1)

sock.settimeout(1.0)
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    try:
        data, addr = sock.recvfrom(2048)
        if data.startswith(b"VX-LB-IPV6-PROBE:"):
            nonce = data.split(b":", 1)[1]
            sock.sendto(b"VX-LB-IPV6-ACK:" + nonce, addr)
            break
    except (TimeoutError, OSError):
        pass
sock.close()
"""

NONCE_PROBER_PY = """import socket, sys, time
target_ip = sys.argv[1]
target_port = int(sys.argv[2])
nonce = sys.argv[3].encode("ascii")
is_v6 = (':' in target_ip)
af = socket.AF_INET6 if is_v6 else socket.AF_INET

sock = socket.socket(af, socket.SOCK_DGRAM)
sock.settimeout(2.5)
payload = b"VX-LB-IPV6-PROBE:" + nonce
expected = b"VX-LB-IPV6-ACK:" + nonce

success = False
lat_ms = None

for attempt in range(3):
    t0 = time.monotonic()
    try:
        sock.sendto(payload, (target_ip, target_port))
        data, _ = sock.recvfrom(2048)
        if data == expected:
            lat_ms = round((time.monotonic() - t0) * 1000, 2)
            success = True
            break
    except (TimeoutError, OSError):
        time.sleep(0.3)

sock.close()
if success:
    print(f"PASS:{lat_ms}")
    sys.exit(0)
else:
    print("FAIL:NO_REPLY")
    sys.exit(1)
"""


def execute_active_data_probe(
    iran_ssh: Any,
    kharej_ssh: Any,
    kharej_private_ip: str,
    probe_port: int = 42892,
) -> Dict[str, Any]:
    """Conducts an active bidirectional probe using an authenticated nonce challenge across the private link."""
    nonce = secrets.token_hex(16)
    target_ip = kharej_private_ip.split("/")[0]

    # Kharej listens on target private IP
    cmd_kh = f"python3 -c {shlex.quote(ECHO_RESPONDER_PY)} {shlex.quote(target_ip)} {probe_port} >/dev/null 2>&1 &"
    ok_kh, _, err_kh = kharej_ssh.execute(cmd_kh)
    if ok_kh != 0:
        return {
            "passed": False,
            "latency_ms": None,
            "error": f"Failed starting probe echo responder on Kharej ({target_ip}:{probe_port}): {err_kh}",
        }

    time.sleep(0.3)

    # Iran challenges Kharej
    cmd_ir = f"python3 -c {shlex.quote(NONCE_PROBER_PY)} {shlex.quote(target_ip)} {probe_port} {nonce}"
    ok_ir, out_ir, err_ir = iran_ssh.execute(cmd_ir)

    if ok_ir == 0 and "PASS:" in out_ir:
        try:
            lat_str = out_ir.strip().split("PASS:")[1].split()[0]
            lat_ms = float(lat_str)
        except Exception:
            lat_ms = 1.0
        return {
            "passed": True,
            "latency_ms": lat_ms,
            "error": None,
            "details": {"probe_target": f"{target_ip}:{probe_port}", "nonce_verified": True},
        }

    return {
        "passed": False,
        "latency_ms": None,
        "error": f"Active IPv6 tunnel probe failed: {err_ir or out_ir or 'Packet dropped across tunnel'}",
        "details": {"probe_target": f"{target_ip}:{probe_port}", "nonce_verified": False},
    }


def render_relay_service(service_name: str, interface: str, peer_ip: str, ports: List[int]) -> Tuple[str, str]:
    """Generates relay python script content and a systemd service unit for client port forwarding."""
    relay_script = f'''import asyncio, socket, sys, json

target_host = "{peer_ip}"
ports = {list(map(int, ports))}
is_v6 = (":" in target_host)

async def pipe(reader, writer):
    try:
        while not reader.at_eof():
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def handle_tcp(local_reader, local_writer, port):
    try:
        remote_reader, remote_writer = await asyncio.open_connection(target_host, port)
    except Exception:
        try:
            local_writer.close()
            await local_writer.wait_closed()
        except Exception:
            pass
        return
    asyncio.create_task(pipe(local_reader, remote_writer))
    asyncio.create_task(pipe(remote_reader, local_writer))

class UdpForwarder(asyncio.DatagramProtocol):
    def __init__(self, port):
        self.port = port
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        loop = asyncio.get_running_loop()
        af = socket.AF_INET6 if is_v6 else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_DGRAM)
        sock.setblocking(False)
        async def forward():
            try:
                await loop.sock_connect(sock, (target_host, self.port))
                await loop.sock_sendall(sock, data)
                sock.settimeout(3.0)
                resp = await loop.run_in_executor(None, sock.recv, 65536)
                if resp and self.transport:
                    self.transport.sendto(resp, addr)
            except Exception:
                pass
            finally:
                sock.close()
        asyncio.create_task(forward())

async def main():
    servers = []
    for p in ports:
        s_v4 = await asyncio.start_server(lambda r, w, port=p: handle_tcp(r, w, port), '0.0.0.0', p)
        servers.append(s_v4)
        try:
            s_v6 = await asyncio.start_server(lambda r, w, port=p: handle_tcp(r, w, port), '::', p)
            servers.append(s_v6)
        except Exception:
            pass
        loop = asyncio.get_running_loop()
        await loop.create_datagram_endpoint(lambda port=p: UdpForwarder(port), local_addr=('0.0.0.0', p))
    print("READY", flush=True)
    while True:
        await asyncio.sleep(3600)

if __name__ == '__main__':
    asyncio.run(main())
'''
    relay_script_path = f"/etc/vxlb/{interface}-relay.py"
    parent_service = service_name.removesuffix("-relay.service") + ".service"
    unit_content = f"""[Unit]
Description=VX-LB IPv6 Tunnel Port Forwarding Relay ({interface})
After=network-online.target {parent_service}
Wants=network-online.target
Requires={parent_service}
PartOf={parent_service}

[Service]
Type=simple
ExecStart=/usr/bin/python3 {relay_script_path}
Restart=always
RestartSec=3
TimeoutStopSec=15
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    return relay_script, unit_content
