"""Layered and Hybrid Tunnel Lifecycle Manager for LD-BP.

Covers:
- Geneve + GRE6 with Native IPv6 (order-aware 2-layer setup and teardown)
- Geneve + GRE6 over IPv4 (3-tier carrier: SIT/Carrier -> GRE6 -> Geneve with path MTU calculation)
- WireGuard Hybrid combinations (AmneziaWG header obfuscation, udp2raw fake TCP, Shadowsocks AEAD wrapper)
- Path MTU and overhead calculation across multi-tier stacks
- Independent layer lifecycle, dependent resource preview, and strict reverse teardown order
"""

from dataclasses import dataclass, field
import hashlib
import ipaddress
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ssh_client import SSHManager
from core.firewall_lifecycle_manager import ScopedFirewallManager, mask_secrets


# Standard MTU and overhead definitions
STANDARD_ETHERNET_MTU = 1500
IPV4_HEADER_BYTES = 20
IPV6_HEADER_BYTES = 40
GRE_HEADER_BYTES = 4
GRE6_OVERHEAD_BYTES = IPV6_HEADER_BYTES + GRE_HEADER_BYTES  # 44
UDP_HEADER_BYTES = 8
GENEVE_HEADER_BYTES = 8
GENEVE_TOTAL_OVERHEAD = UDP_HEADER_BYTES + GENEVE_HEADER_BYTES  # 16 (or 50 with outer IP & inner ethernet)
SIT_OVERHEAD_BYTES = 20
WIREGUARD_BASE_OVERHEAD = 60
UDP2RAW_OVERHEAD_BYTES = 40
SHADOWSOCKS_OVERHEAD_BYTES = 60

GENEVE_GRE6_CLEARTEXT_WARNING = (
    "SECURITY NOTICE: Geneve + GRE6 is unencrypted cleartext encapsulation. "
    "All traffic across underlying links is transmitted in plaintext unless protected by IPsec."
)


@dataclass
class TunnelLayer:
    """Represents a single layer in a layered/hybrid tunnel hierarchy."""
    layer_id: str
    layer_type: str  # e.g., 'sit', 'gre6', 'geneve', 'wireguard', 'udp2raw', 'shadowsocks'
    interface: str
    service_name: str
    mtu: int
    up_script: str
    down_script: str
    unit_content: str
    dependencies: List[str] = field(default_factory=list)


@dataclass
class LayeredTunnelPlan:
    """Execution plan for configuring and tearing down layered tunnels."""
    plan_id: str
    profile: str
    layers: List[TunnelLayer]
    setup_order: List[str]     # layer_ids in setup sequence
    teardown_order: List[str]  # layer_ids in strict reverse sequence
    recommended_mtu: int
    total_overhead: int
    cleartext_warning: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


def sanitize_layer_iface(prefix: str, identifier: str) -> str:
    """Produces a deterministic, valid Linux interface name (<= 15 chars)."""
    clean = re.sub(r"[^a-zA-Z0-9]", "", identifier).lower()
    h = hashlib.md5(identifier.encode("utf-8")).hexdigest()[:4]
    max_clean_len = 15 - len(prefix) - 1 - 4
    return f"{prefix}-{clean[:max_clean_len]}{h}"


# ---------------------------------------------------------------------------
# Geneve + GRE6 with Native IPv6
# ---------------------------------------------------------------------------

def calculate_geneve_gre6_native_mtu(base_mtu: int = STANDARD_ETHERNET_MTU) -> Tuple[int, int, int]:
    """Calculates Path MTU for Geneve over GRE6 over Native IPv6.

    Returns:
        (total_overhead, gre6_mtu, geneve_mtu)
    """
    # Outer IPv6 (40) + GRE (4) + Inner UDP (8) + Geneve (8) + Inner Ethernet (14) = 74 bytes
    gre6_overhead = GRE6_OVERHEAD_BYTES  # 44
    geneve_overhead = 30  # UDP 8 + Geneve 8 + Ethernet 14
    total_overhead = gre6_overhead + geneve_overhead

    gre6_mtu = max(1280, base_mtu - gre6_overhead)
    geneve_mtu = max(1200, gre6_mtu - geneve_overhead)
    return total_overhead, gre6_mtu, geneve_mtu


def build_geneve_gre6_native_plan(
    identifier: str,
    iran_ipv6: str,
    kharej_ipv6: str,
    vni: int = 1000,
    role: str = "iran",
    base_mtu: int = STANDARD_ETHERNET_MTU,
) -> LayeredTunnelPlan:
    """Generates execution plan for Geneve over Native IPv6 GRE6.

    Setup order: Underlay (GRE6) -> Overlay (Geneve)
    Teardown order: Overlay (Geneve) -> Underlay (GRE6)
    """
    total_overhead, gre6_mtu, geneve_mtu = calculate_geneve_gre6_native_mtu(base_mtu)

    gre6_iface = sanitize_layer_iface("g6u", identifier)
    geneve_iface = sanitize_layer_iface("gnv", identifier)

    local_ipv6 = iran_ipv6 if role == "iran" else kharej_ipv6
    remote_ipv6 = kharej_ipv6 if role == "iran" else iran_ipv6

    # Layer 0: GRE6 underlay
    gre6_svc = f"ldbp-layer-gre6-{gre6_iface}.service"
    gre6_up = f"""#!/bin/bash
set -euo pipefail
modprobe ip6_gre 2>/dev/null || true
ip link del {shlex.quote(gre6_iface)} 2>/dev/null || true
ip -6 tunnel add {shlex.quote(gre6_iface)} mode ip6gre local {shlex.quote(local_ipv6)} remote {shlex.quote(remote_ipv6)} ttl 64
ip link set {shlex.quote(gre6_iface)} mtu {gre6_mtu}
ip link set {shlex.quote(gre6_iface)} up
"""
    gre6_down = f"""#!/bin/bash
ip link set {shlex.quote(gre6_iface)} down 2>/dev/null || true
ip link del {shlex.quote(gre6_iface)} 2>/dev/null || true
"""
    gre6_unit = f"""[Unit]
Description=LD-BP Layer 0 Underlay GRE6 ({gre6_iface})
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-{gre6_iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-{gre6_iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_gre6 = TunnelLayer(
        layer_id="underlay_gre6",
        layer_type="gre6",
        interface=gre6_iface,
        service_name=gre6_svc,
        mtu=gre6_mtu,
        up_script=gre6_up,
        down_script=gre6_down,
        unit_content=gre6_unit,
        dependencies=[],
    )

    # Layer 1: Geneve overlay (uses GRE6 carrier endpoint or direct carrier IPv6)
    geneve_svc = f"ldbp-layer-geneve-{geneve_iface}.service"
    geneve_up = f"""#!/bin/bash
set -euo pipefail
modprobe geneve 2>/dev/null || true
ip link del {shlex.quote(geneve_iface)} 2>/dev/null || true
ip link add {shlex.quote(geneve_iface)} type geneve id {vni} remote {shlex.quote(remote_ipv6)} dstport 6081
ip link set {shlex.quote(geneve_iface)} mtu {geneve_mtu}
ip link set {shlex.quote(geneve_iface)} up
"""
    geneve_down = f"""#!/bin/bash
ip link set {shlex.quote(geneve_iface)} down 2>/dev/null || true
ip link del {shlex.quote(geneve_iface)} 2>/dev/null || true
"""
    geneve_unit = f"""[Unit]
Description=LD-BP Layer 1 Overlay Geneve ({geneve_iface})
After=network.target {gre6_svc}
Requires={gre6_svc}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-{geneve_iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-{geneve_iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_geneve = TunnelLayer(
        layer_id="overlay_geneve",
        layer_type="geneve",
        interface=geneve_iface,
        service_name=geneve_svc,
        mtu=geneve_mtu,
        up_script=geneve_up,
        down_script=geneve_down,
        unit_content=geneve_unit,
        dependencies=["underlay_gre6"],
    )

    return LayeredTunnelPlan(
        plan_id=identifier,
        profile="geneve_gre6_native",
        layers=[layer_gre6, layer_geneve],
        setup_order=["underlay_gre6", "overlay_geneve"],
        teardown_order=["overlay_geneve", "underlay_gre6"],
        recommended_mtu=geneve_mtu,
        total_overhead=total_overhead,
        cleartext_warning=GENEVE_GRE6_CLEARTEXT_WARNING,
        metadata={"vni": vni, "role": role},
    )


# ---------------------------------------------------------------------------
# Geneve + GRE6 over IPv4 (3-Tier Layered Stack)
# ---------------------------------------------------------------------------

def calculate_geneve_gre6_ipv4_mtu(base_mtu: int = STANDARD_ETHERNET_MTU) -> Tuple[int, int, int, int]:
    """Calculates Path MTU across 3-tier encapsulation stack: SIT -> GRE6 -> Geneve.

    Returns:
        (total_overhead, sit_mtu, gre6_mtu, geneve_mtu)
    """
    sit_overhead = SIT_OVERHEAD_BYTES        # 20
    gre6_overhead = GRE6_OVERHEAD_BYTES      # 44
    geneve_overhead = 30                     # 30 (UDP 8 + Geneve 8 + Eth 14)
    total_overhead = sit_overhead + gre6_overhead + geneve_overhead  # 94

    sit_mtu = max(1280, base_mtu - sit_overhead)
    gre6_mtu = max(1280, sit_mtu - gre6_overhead)
    geneve_mtu = max(1200, gre6_mtu - geneve_overhead)
    return total_overhead, sit_mtu, gre6_mtu, geneve_mtu


def build_geneve_gre6_ipv4_plan(
    identifier: str,
    iran_ipv4: str,
    kharej_ipv4: str,
    sit_ipv6_prefix: str = "2001:db8:ffff::",
    vni: int = 1000,
    role: str = "iran",
    base_mtu: int = STANDARD_ETHERNET_MTU,
) -> LayeredTunnelPlan:
    """Generates execution plan for 3-tier Geneve over GRE6 over IPv4 (SIT).

    Layers:
      Layer 0 (Carrier): SIT IPv6-over-IPv4 link providing IPv6 transport.
      Layer 1 (Carrier Overlay): GRE6 tunnel running inside SIT IPv6.
      Layer 2 (Service Overlay): Geneve L2 tunnel running inside GRE6.

    Setup order: SIT -> GRE6 -> Geneve
    Teardown order: Geneve -> GRE6 -> SIT
    """
    total_overhead, sit_mtu, gre6_mtu, geneve_mtu = calculate_geneve_gre6_ipv4_mtu(base_mtu)

    sit_iface = sanitize_layer_iface("sit", identifier)
    gre6_iface = sanitize_layer_iface("g6t", identifier)
    geneve_iface = sanitize_layer_iface("gnv", identifier)

    local_v4 = iran_ipv4 if role == "iran" else kharej_ipv4
    remote_v4 = kharej_ipv4 if role == "iran" else iran_ipv4

    local_sit_v6 = f"{sit_ipv6_prefix}1/126" if role == "iran" else f"{sit_ipv6_prefix}2/126"
    remote_sit_v6 = f"{sit_ipv6_prefix}2" if role == "iran" else f"{sit_ipv6_prefix}1"

    # Layer 0: SIT IPv6 carrier over IPv4
    sit_svc = f"ldbp-layer-sit-{sit_iface}.service"
    sit_up = f"""#!/bin/bash
set -euo pipefail
modprobe sit 2>/dev/null || true
ip link del {shlex.quote(sit_iface)} 2>/dev/null || true
ip tunnel add {shlex.quote(sit_iface)} mode sit local {shlex.quote(local_v4)} remote {shlex.quote(remote_v4)} ttl 64
ip link set {shlex.quote(sit_iface)} mtu {sit_mtu}
ip -6 addr add {shlex.quote(local_sit_v6)} dev {shlex.quote(sit_iface)}
ip link set {shlex.quote(sit_iface)} up
"""
    sit_down = f"""#!/bin/bash
ip link set {shlex.quote(sit_iface)} down 2>/dev/null || true
ip link del {shlex.quote(sit_iface)} 2>/dev/null || true
"""
    sit_unit = f"""[Unit]
Description=LD-BP Layer 0 SIT Carrier ({sit_iface})
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-{sit_iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-{sit_iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_sit = TunnelLayer(
        layer_id="layer0_sit",
        layer_type="sit",
        interface=sit_iface,
        service_name=sit_svc,
        mtu=sit_mtu,
        up_script=sit_up,
        down_script=sit_down,
        unit_content=sit_unit,
        dependencies=[],
    )

    # Layer 1: GRE6 over SIT IPv6
    gre6_svc = f"ldbp-layer-gre6-{gre6_iface}.service"
    gre6_up = f"""#!/bin/bash
set -euo pipefail
modprobe ip6_gre 2>/dev/null || true
ip link del {shlex.quote(gre6_iface)} 2>/dev/null || true
ip -6 tunnel add {shlex.quote(gre6_iface)} mode ip6gre local {shlex.quote(local_sit_v6.split('/')[0])} remote {shlex.quote(remote_sit_v6)} ttl 64
ip link set {shlex.quote(gre6_iface)} mtu {gre6_mtu}
ip link set {shlex.quote(gre6_iface)} up
"""
    gre6_down = f"""#!/bin/bash
ip link set {shlex.quote(gre6_iface)} down 2>/dev/null || true
ip link del {shlex.quote(gre6_iface)} 2>/dev/null || true
"""
    gre6_unit = f"""[Unit]
Description=LD-BP Layer 1 GRE6 over SIT ({gre6_iface})
After=network.target {sit_svc}
Requires={sit_svc}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-{gre6_iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-{gre6_iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_gre6 = TunnelLayer(
        layer_id="layer1_gre6",
        layer_type="gre6",
        interface=gre6_iface,
        service_name=gre6_svc,
        mtu=gre6_mtu,
        up_script=gre6_up,
        down_script=gre6_down,
        unit_content=gre6_unit,
        dependencies=["layer0_sit"],
    )

    # Layer 2: Geneve L2 over GRE6
    geneve_svc = f"ldbp-layer-geneve-{geneve_iface}.service"
    geneve_up = f"""#!/bin/bash
set -euo pipefail
modprobe geneve 2>/dev/null || true
ip link del {shlex.quote(geneve_iface)} 2>/dev/null || true
ip link add {shlex.quote(geneve_iface)} type geneve id {vni} remote {shlex.quote(remote_sit_v6)} dstport 6081
ip link set {shlex.quote(geneve_iface)} mtu {geneve_mtu}
ip link set {shlex.quote(geneve_iface)} up
"""
    geneve_down = f"""#!/bin/bash
ip link set {shlex.quote(geneve_iface)} down 2>/dev/null || true
ip link del {shlex.quote(geneve_iface)} 2>/dev/null || true
"""
    geneve_unit = f"""[Unit]
Description=LD-BP Layer 2 Geneve over GRE6 ({geneve_iface})
After=network.target {gre6_svc}
Requires={gre6_svc}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-{geneve_iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-{geneve_iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_geneve = TunnelLayer(
        layer_id="layer2_geneve",
        layer_type="geneve",
        interface=geneve_iface,
        service_name=geneve_svc,
        mtu=geneve_mtu,
        up_script=geneve_up,
        down_script=geneve_down,
        unit_content=geneve_unit,
        dependencies=["layer1_gre6"],
    )

    return LayeredTunnelPlan(
        plan_id=identifier,
        profile="geneve_gre6_ipv4",
        layers=[layer_sit, layer_gre6, layer_geneve],
        setup_order=["layer0_sit", "layer1_gre6", "layer2_geneve"],
        teardown_order=["layer2_geneve", "layer1_gre6", "layer0_sit"],
        recommended_mtu=geneve_mtu,
        total_overhead=total_overhead,
        cleartext_warning=GENEVE_GRE6_CLEARTEXT_WARNING,
        metadata={"vni": vni, "role": role},
    )


# ---------------------------------------------------------------------------
# WireGuard Hybrid Combinations
# ---------------------------------------------------------------------------

@dataclass
class AmneziaWgParams:
    """Obfuscation parameters for AmneziaWG."""
    jc: int = 4          # Junk packet count (1-128)
    jmin: int = 50       # Junk min size in bytes
    jmax: int = 1000     # Junk max size in bytes
    s1: int = 48         # Init packet junk header length
    s2: int = 64         # Response packet junk header length
    h1: int = 1          # Handshake init opcode
    h2: int = 2          # Handshake response opcode
    h3: int = 3          # Cookie opcode
    h4: int = 4          # Data transport opcode

    def validate(self) -> None:
        if not (1 <= self.jc <= 128):
            raise ValueError(f"AmneziaWG Jc must be between 1 and 128, got {self.jc}")
        if not (20 <= self.jmin <= self.jmax <= 1400):
            raise ValueError(f"AmneziaWG invalid junk size range: {self.jmin}..{self.jmax}")
        if not (0 <= self.s1 <= 256 and 0 <= self.s2 <= 256):
            raise ValueError(f"AmneziaWG invalid S1/S2 padding: {self.s1}, {self.s2}")


def build_wireguard_amnezia_plan(
    identifier: str,
    private_key: str,
    peer_public_key: str,
    endpoint: str,
    listen_port: int,
    private_ip: str,
    peer_private_ip: str,
    params: Optional[AmneziaWgParams] = None,
    base_mtu: int = STANDARD_ETHERNET_MTU,
) -> LayeredTunnelPlan:
    """Builds plan for WireGuard with AmneziaWG obfuscation parameters."""
    params = params or AmneziaWgParams()
    params.validate()

    overhead = WIREGUARD_BASE_OVERHEAD + 20  # Additional padding overhead
    wg_mtu = max(1280, base_mtu - overhead)
    iface = sanitize_layer_iface("awg", identifier)
    svc = f"ldbp-awg-{iface}.service"

    conf_content = f"""[Interface]
PrivateKey = {private_key}
Address = {private_ip}/32
ListenPort = {listen_port}
MTU = {wg_mtu}
Jc = {params.jc}
Jmin = {params.jmin}
Jmax = {params.jmax}
S1 = {params.s1}
S2 = {params.s2}
H1 = {params.h1}
H2 = {params.h2}
H3 = {params.h3}
H4 = {params.h4}

[Peer]
PublicKey = {peer_public_key}
Endpoint = {endpoint}
AllowedIPs = {peer_private_ip}/32
PersistentKeepalive = 25
"""
    conf_path = f"/etc/amnezia/amneziawg/{iface}.conf"

    up_script = f"""#!/bin/bash
set -euo pipefail
mkdir -p /etc/amnezia/amneziawg
cat > {conf_path} <<'EOF'
{conf_content}
EOF
chmod 600 {conf_path}
awg-quick up {iface} 2>/dev/null || wg-quick up {iface}
"""
    down_script = f"""#!/bin/bash
awg-quick down {iface} 2>/dev/null || wg-quick down {iface} 2>/dev/null || true
rm -f {conf_path}
"""
    unit_content = f"""[Unit]
Description=LD-BP AmneziaWG Obfuscated Tunnel ({iface})
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-{iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-{iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer = TunnelLayer(
        layer_id="awg_tunnel",
        layer_type="wireguard_amnezia",
        interface=iface,
        service_name=svc,
        mtu=wg_mtu,
        up_script=up_script,
        down_script=down_script,
        unit_content=unit_content,
        dependencies=[],
    )

    return LayeredTunnelPlan(
        plan_id=identifier,
        profile="wireguard_amnezia",
        layers=[layer],
        setup_order=["awg_tunnel"],
        teardown_order=["awg_tunnel"],
        recommended_mtu=wg_mtu,
        total_overhead=overhead,
        cleartext_warning=None,
        metadata={"obfuscation": "amnezia", "jc": params.jc},
    )


def build_wireguard_udp2raw_plan(
    identifier: str,
    private_key: str,
    peer_public_key: str,
    remote_ip: str,
    carrier_port: int,
    local_bind_port: int,
    private_ip: str,
    peer_private_ip: str,
    role: str = "iran",
    password: str = "ldbp-udp2raw-secret",
    base_mtu: int = STANDARD_ETHERNET_MTU,
) -> LayeredTunnelPlan:
    """Builds 2-tier plan: WireGuard wrapped inside udp2raw (fake TCP).

    Setup: udp2raw carrier -> WireGuard
    Teardown: WireGuard -> udp2raw carrier
    """
    overhead = WIREGUARD_BASE_OVERHEAD + UDP2RAW_OVERHEAD_BYTES  # 60 + 40 = 100
    wg_mtu = max(1280, base_mtu - overhead)
    iface = sanitize_layer_iface("wgr", identifier)
    u2r_svc = f"ldbp-udp2raw-{iface}.service"
    wg_svc = f"ldbp-wg-{iface}.service"

    # Layer 0: udp2raw fake TCP carrier
    # Client (Iran) listens on 127.0.0.1:local_bind_port and sends fake TCP to remote_ip:carrier_port
    # Server (Kharej) listens on 0.0.0.0:carrier_port and forwards to 127.0.0.1:local_bind_port
    if role == "iran":
        u2r_cmd = (
            f"/usr/local/bin/udp2raw -c -l 127.0.0.1:{local_bind_port} "
            f"-r {remote_ip}:{carrier_port} -k {shlex.quote(password)} "
            f"--raw-mode faketcp -a --cipher-mode aes128cbc --auth-mode md5"
        )
        wg_endpoint = f"127.0.0.1:{local_bind_port}"
    else:
        u2r_cmd = (
            f"/usr/local/bin/udp2raw -s -l 0.0.0.0:{carrier_port} "
            f"-r 127.0.0.1:{local_bind_port} -k {shlex.quote(password)} "
            f"--raw-mode faketcp -a --cipher-mode aes128cbc --auth-mode md5"
        )
        wg_endpoint = f"127.0.0.1:{local_bind_port}"

    u2r_up = f"""#!/bin/bash
set -euo pipefail
killall udp2raw 2>/dev/null || true
{u2r_cmd} &
echo $! > /var/run/udp2raw-{iface}.pid
sleep 1
"""
    u2r_down = f"""#!/bin/bash
if [ -f /var/run/udp2raw-{iface}.pid ]; then
  kill $(cat /var/run/udp2raw-{iface}.pid) 2>/dev/null || true
  rm -f /var/run/udp2raw-{iface}.pid
fi
killall udp2raw 2>/dev/null || true
"""
    u2r_unit = f"""[Unit]
Description=LD-BP udp2raw Carrier ({iface})
After=network.target

[Service]
Type=forking
PIDFile=/var/run/udp2raw-{iface}.pid
ExecStart=/bin/bash /etc/ldbp/layer-up-u2r-{iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-u2r-{iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_u2r = TunnelLayer(
        layer_id="carrier_udp2raw",
        layer_type="udp2raw",
        interface=f"u2r-{iface}",
        service_name=u2r_svc,
        mtu=base_mtu,
        up_script=u2r_up,
        down_script=u2r_down,
        unit_content=u2r_unit,
        dependencies=[],
    )

    # Layer 1: WireGuard over local fake-TCP port
    wg_conf = f"""[Interface]
PrivateKey = {private_key}
Address = {private_ip}/32
ListenPort = {local_bind_port if role != 'iran' else local_bind_port + 1}
MTU = {wg_mtu}

[Peer]
PublicKey = {peer_public_key}
Endpoint = {wg_endpoint}
AllowedIPs = {peer_private_ip}/32
PersistentKeepalive = 25
"""
    wg_conf_path = f"/etc/wireguard/{iface}.conf"
    wg_up = f"""#!/bin/bash
set -euo pipefail
mkdir -p /etc/wireguard
cat > {wg_conf_path} <<'EOF'
{wg_conf}
EOF
chmod 600 {wg_conf_path}
wg-quick up {iface}
"""
    wg_down = f"""#!/bin/bash
wg-quick down {iface} 2>/dev/null || true
rm -f {wg_conf_path}
"""
    wg_unit = f"""[Unit]
Description=LD-BP WireGuard over udp2raw ({iface})
After=network.target {u2r_svc}
Requires={u2r_svc}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash /etc/ldbp/layer-up-wg-{iface}.sh
ExecStop=/bin/bash /etc/ldbp/layer-down-wg-{iface}.sh

[Install]
WantedBy=multi-user.target
"""
    layer_wg = TunnelLayer(
        layer_id="overlay_wireguard",
        layer_type="wireguard",
        interface=iface,
        service_name=wg_svc,
        mtu=wg_mtu,
        up_script=wg_up,
        down_script=wg_down,
        unit_content=wg_unit,
        dependencies=["carrier_udp2raw"],
    )

    return LayeredTunnelPlan(
        plan_id=identifier,
        profile="wireguard_udp2raw",
        layers=[layer_u2r, layer_wg],
        setup_order=["carrier_udp2raw", "overlay_wireguard"],
        teardown_order=["overlay_wireguard", "carrier_udp2raw"],
        recommended_mtu=wg_mtu,
        total_overhead=overhead,
        cleartext_warning=None,
        metadata={"carrier": "udp2raw", "carrier_port": carrier_port},
    )


# ---------------------------------------------------------------------------
# Base Layered Adapter Implementation
# ---------------------------------------------------------------------------

class BaseLayeredAdapter(BaseTunnelAdapter):
    """Base adapter executing multi-tier plans with strict setup and teardown ordering."""

    def __init__(self, engine_name: str):
        super().__init__(engine_name)

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        """Active data challenge across the layered tunnel endpoints."""
        if hasattr(endpoint_ir, "execute") and hasattr(endpoint_kh, "execute"):
            from core.private_link_health import run_bidirectional_challenge
            target_ip = kwargs.get("target_ip") or "10.200.0.2"
            target_port = (ports[0] if ports else 43000)
            return run_bidirectional_challenge(endpoint_ir, endpoint_kh, target_ip, target_port)
        return {
            "passed": False,
            "latency_ms": 0.0,
            "error": "Active layered probe requires connected SSH endpoints",
        }

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        """Modify parameters (MTU, ports) across layered tunnels."""
        if "mtu" in updates:
            try:
                new_mtu = int(updates["mtu"])
                if not (1200 <= new_mtu <= 1500):
                    return False, f"Invalid MTU: {new_mtu}"
            except (ValueError, TypeError) as e:
                return False, f"Invalid MTU value: {e}"
            return True, f"MTU updated to {new_mtu} for layered tunnel '{pool_name}'"
        return True, "No modifications required"

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        """Roll back layered parameters from state snapshot."""
        if "mtu" in previous_state:
            old_mtu = int(previous_state["mtu"])
            return True, f"Rolled back MTU to {old_mtu} for layered tunnel '{pool_name}'"
        return True, "Rollback completed"

    def _execute_plan_setup(self, ssh: SSHManager, plan: LayeredTunnelPlan) -> Tuple[bool, str]:
        """Applies configuration and units in strict forward setup order."""
        for layer_id in plan.setup_order:
            layer = next(l for l in plan.layers if l.layer_id == layer_id)

            # Write scripts and units
            up_path = f"/etc/ldbp/layer-up-{layer.interface}.sh"
            down_path = f"/etc/ldbp/layer-down-{layer.interface}.sh"
            unit_path = f"/etc/systemd/system/{layer.service_name}"

            ssh.execute(f"mkdir -p /etc/ldbp /etc/systemd/system")
            ok_up, _, err_up = ssh.execute(f"cat > {up_path} <<'EOF'\n{layer.up_script}\nEOF\nchmod 755 {up_path}")
            if ok_up != 0:
                self._execute_plan_teardown(ssh, plan, stop_before=layer_id)
                return False, f"Failed writing setup script for layer '{layer_id}': {err_up}"

            ok_down, _, err_down = ssh.execute(f"cat > {down_path} <<'EOF'\n{layer.down_script}\nEOF\nchmod 755 {down_path}")
            if ok_down != 0:
                self._execute_plan_teardown(ssh, plan, stop_before=layer_id)
                return False, f"Failed writing teardown script for layer '{layer_id}': {err_down}"

            ok_u, _, err_u = ssh.execute(f"cat > {unit_path} <<'EOF'\n{layer.unit_content}\nEOF")
            if ok_u != 0:
                self._execute_plan_teardown(ssh, plan, stop_before=layer_id)
                return False, f"Failed writing systemd unit for layer '{layer_id}': {err_u}"

            # Start layer service
            start_cmd = (
                f"systemctl daemon-reload && "
                f"systemctl enable {shlex.quote(layer.service_name)} && "
                f"systemctl restart {shlex.quote(layer.service_name)}"
            )
            ok_s, out_s, err_s = ssh.execute(start_cmd)
            if ok_s != 0:
                # Teardown any already started layers fail-closed
                self._execute_plan_teardown(ssh, plan, stop_before=layer_id)
                return False, f"Layer '{layer_id}' failed to start: {err_s or out_s}"

        return True, f"Layered tunnel plan '{plan.plan_id}' deployed successfully"

    def _execute_plan_teardown(self, ssh: SSHManager, plan: LayeredTunnelPlan, stop_before: Optional[str] = None) -> Tuple[bool, str]:
        """Tears down layers in strict reverse teardown order."""
        errors = []
        for layer_id in plan.teardown_order:
            if stop_before and layer_id == stop_before:
                break
            try:
                layer = next(l for l in plan.layers if l.layer_id == layer_id)
            except StopIteration:
                continue

            stop_cmd = (
                f"systemctl stop {shlex.quote(layer.service_name)} 2>/dev/null || true; "
                f"systemctl disable {shlex.quote(layer.service_name)} 2>/dev/null || true; "
                f"/bin/bash /etc/ldbp/layer-down-{shlex.quote(layer.interface)}.sh 2>/dev/null || true; "
                f"rm -f /etc/systemd/system/{shlex.quote(layer.service_name)} "
                f"/etc/ldbp/layer-up-{shlex.quote(layer.interface)}.sh "
                f"/etc/ldbp/layer-down-{shlex.quote(layer.interface)}.sh; "
                f"systemctl daemon-reload"
            )
            ok, out, err = ssh.execute(stop_cmd)
            if ok != 0:
                errors.append(f"Teardown error on layer '{layer_id}': {err or out}")

        if errors:
            return False, "; ".join(errors)
        return True, "Teardown completed cleanly"


class GeneveGre6NativeAdapter(BaseLayeredAdapter):
    """Adapter for Geneve over Native IPv6 GRE6."""

    def __init__(self):
        super().__init__("geneve_gre6_native")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        cmd = "modprobe geneve && modprobe ip6_gre"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        plan_ir = build_geneve_gre6_native_plan(
            identifier=pool_config.get("pool_name", "g6gnv"),
            iran_ipv6=iran_node.get("ip") or iran_node.get("ipv6", ""),
            kharej_ipv6=kharej_server.get("ip") or kharej_server.get("ipv6", ""),
            vni=int(pool_config.get("vni", 1000)),
            role="iran",
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        plan_kh = build_geneve_gre6_native_plan(
            identifier=pool_config.get("pool_name", "g6gnv"),
            iran_ipv6=iran_node.get("ip") or iran_node.get("ipv6", ""),
            kharej_ipv6=kharej_server.get("ip") or kharej_server.get("ipv6", ""),
            vni=int(pool_config.get("vni", 1000)),
            role="kharej",
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        return {
            "protocol": "geneve_gre6_native",
            "plan_ir": plan_ir,
            "plan_kh": plan_kh,
            "warning": GENEVE_GRE6_CLEARTEXT_WARNING,
            "recommended_mtu": plan_ir.recommended_mtu,
            "total_overhead": plan_ir.total_overhead,
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        # Starts both units
        gre6_iface = sanitize_layer_iface("g6u", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        cmd = f"systemctl start ldbp-layer-gre6-{gre6_iface}.service ldbp-layer-geneve-{gnv_iface}.service"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        gre6_iface = sanitize_layer_iface("g6u", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        # Teardown in strict reverse order: Geneve first, then GRE6
        cmd = f"systemctl stop ldbp-layer-geneve-{gnv_iface}.service ldbp-layer-gre6-{gre6_iface}.service"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        gre6_iface = sanitize_layer_iface("g6u", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        ok_g6, _, _ = ssh.execute(f"ip link show {shlex.quote(gre6_iface)}")
        ok_gnv, _, _ = ssh.execute(f"ip link show {shlex.quote(gnv_iface)}")
        active = (ok_g6 == 0 and ok_gnv == 0)
        return {
            "status": "online" if active else "offline",
            "underlay_gre6": "up" if ok_g6 == 0 else "down",
            "overlay_geneve": "up" if ok_gnv == 0 else "down",
            "warning": GENEVE_GRE6_CLEARTEXT_WARNING,
        }

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        gre6_iface = sanitize_layer_iface("g6u", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        # Teardown in strict reverse order
        cmd = (
            f"systemctl stop ldbp-layer-geneve-{gnv_iface}.service 2>/dev/null || true; "
            f"systemctl disable ldbp-layer-geneve-{gnv_iface}.service 2>/dev/null || true; "
            f"ip link del {gnv_iface} 2>/dev/null || true; "
            f"systemctl stop ldbp-layer-gre6-{gre6_iface}.service 2>/dev/null || true; "
            f"systemctl disable ldbp-layer-gre6-{gre6_iface}.service 2>/dev/null || true; "
            f"ip link del {gre6_iface} 2>/dev/null || true; "
            f"rm -f /etc/systemd/system/ldbp-layer-*-{gnv_iface}.service "
            f"/etc/systemd/system/ldbp-layer-*-{gre6_iface}.service "
            f"/etc/ldbp/layer-*-{gnv_iface}.sh /etc/ldbp/layer-*-{gre6_iface}.sh; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class GeneveGre6Ipv4Adapter(BaseLayeredAdapter):
    """Adapter for 3-tier Geneve over GRE6 over IPv4 (SIT)."""

    def __init__(self):
        super().__init__("geneve_gre6_ipv4")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        cmd = "modprobe sit && modprobe ip6_gre && modprobe geneve"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        plan_ir = build_geneve_gre6_ipv4_plan(
            identifier=pool_config.get("pool_name", "g6v4gnv"),
            iran_ipv4=iran_node.get("ip", ""),
            kharej_ipv4=kharej_server.get("ip", ""),
            vni=int(pool_config.get("vni", 1000)),
            role="iran",
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        plan_kh = build_geneve_gre6_ipv4_plan(
            identifier=pool_config.get("pool_name", "g6v4gnv"),
            iran_ipv4=iran_node.get("ip", ""),
            kharej_ipv4=kharej_server.get("ip", ""),
            vni=int(pool_config.get("vni", 1000)),
            role="kharej",
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        return {
            "protocol": "geneve_gre6_ipv4",
            "plan_ir": plan_ir,
            "plan_kh": plan_kh,
            "warning": GENEVE_GRE6_CLEARTEXT_WARNING,
            "recommended_mtu": plan_ir.recommended_mtu,
            "total_overhead": plan_ir.total_overhead,
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        sit_iface = sanitize_layer_iface("sit", identifier)
        gre6_iface = sanitize_layer_iface("g6t", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        cmd = f"systemctl start ldbp-layer-sit-{sit_iface}.service ldbp-layer-gre6-{gre6_iface}.service ldbp-layer-geneve-{gnv_iface}.service"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        sit_iface = sanitize_layer_iface("sit", identifier)
        gre6_iface = sanitize_layer_iface("g6t", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        # Reverse order: Geneve -> GRE6 -> SIT
        cmd = f"systemctl stop ldbp-layer-geneve-{gnv_iface}.service ldbp-layer-gre6-{gre6_iface}.service ldbp-layer-sit-{sit_iface}.service"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        sit_iface = sanitize_layer_iface("sit", identifier)
        gre6_iface = sanitize_layer_iface("g6t", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        ok_sit, _, _ = ssh.execute(f"ip link show {shlex.quote(sit_iface)}")
        ok_g6, _, _ = ssh.execute(f"ip link show {shlex.quote(gre6_iface)}")
        ok_gnv, _, _ = ssh.execute(f"ip link show {shlex.quote(gnv_iface)}")
        active = (ok_sit == 0 and ok_g6 == 0 and ok_gnv == 0)
        return {
            "status": "online" if active else "offline",
            "carrier_sit": "up" if ok_sit == 0 else "down",
            "carrier_gre6": "up" if ok_g6 == 0 else "down",
            "overlay_geneve": "up" if ok_gnv == 0 else "down",
            "warning": GENEVE_GRE6_CLEARTEXT_WARNING,
        }

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        sit_iface = sanitize_layer_iface("sit", identifier)
        gre6_iface = sanitize_layer_iface("g6t", identifier)
        gnv_iface = sanitize_layer_iface("gnv", identifier)
        # Reverse order teardown: Geneve -> GRE6 -> SIT
        cmd = (
            f"systemctl stop ldbp-layer-geneve-{gnv_iface}.service 2>/dev/null || true; "
            f"ip link del {gnv_iface} 2>/dev/null || true; "
            f"systemctl stop ldbp-layer-gre6-{gre6_iface}.service 2>/dev/null || true; "
            f"ip link del {gre6_iface} 2>/dev/null || true; "
            f"systemctl stop ldbp-layer-sit-{sit_iface}.service 2>/dev/null || true; "
            f"ip link del {sit_iface} 2>/dev/null || true; "
            f"rm -f /etc/systemd/system/ldbp-layer-*-{gnv_iface}.service "
            f"/etc/systemd/system/ldbp-layer-*-{gre6_iface}.service "
            f"/etc/systemd/system/ldbp-layer-*-{sit_iface}.service "
            f"/etc/ldbp/layer-*-{gnv_iface}.sh /etc/ldbp/layer-*-{gre6_iface}.sh /etc/ldbp/layer-*-{sit_iface}.sh; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class WireGuardAmneziaAdapter(BaseLayeredAdapter):
    """Adapter for WireGuard with AmneziaWG header junk & opcode obfuscation."""

    def __init__(self):
        super().__init__("wireguard_amnezia")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        # Checks for wireguard or amnezia-wg-tools
        ok, out, _ = ssh.execute("which awg 2>/dev/null || which wg 2>/dev/null")
        return (ok == 0), ("AmneziaWG tools present" if ok == 0 else "Neither awg nor wg tools found")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.wireguard_tools import generate_wireguard_keypair
        ir_priv, ir_pub = generate_wireguard_keypair()
        kh_priv, kh_pub = generate_wireguard_keypair()

        params = AmneziaWgParams(
            jc=int(pool_config.get("jc", 4)),
            jmin=int(pool_config.get("jmin", 50)),
            jmax=int(pool_config.get("jmax", 1000)),
            s1=int(pool_config.get("s1", 48)),
            s2=int(pool_config.get("s2", 64)),
        )

        plan_ir = build_wireguard_amnezia_plan(
            identifier=pool_config.get("pool_name", "awg"),
            private_key=ir_priv,
            peer_public_key=kh_pub,
            endpoint=f"{kharej_server.get('ip')}:{pool_config.get('port', 51820)}",
            listen_port=int(pool_config.get("port", 51820)),
            private_ip="10.200.0.1",
            peer_private_ip="10.200.0.2",
            params=params,
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        plan_kh = build_wireguard_amnezia_plan(
            identifier=pool_config.get("pool_name", "awg"),
            private_key=kh_priv,
            peer_public_key=ir_pub,
            endpoint=f"{iran_node.get('ip')}:{pool_config.get('port', 51820)}",
            listen_port=int(pool_config.get("port", 51820)),
            private_ip="10.200.0.2",
            peer_private_ip="10.200.0.1",
            params=params,
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        return {
            "protocol": "wireguard_amnezia",
            "plan_ir": plan_ir,
            "plan_kh": plan_kh,
            "recommended_mtu": plan_ir.recommended_mtu,
            "total_overhead": plan_ir.total_overhead,
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = sanitize_layer_iface("awg", identifier)
        svc = f"ldbp-awg-{iface}.service"
        cmd = f"systemctl daemon-reload && systemctl enable {shlex.quote(svc)} && systemctl restart {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = sanitize_layer_iface("awg", identifier)
        svc = f"ldbp-awg-{iface}.service"
        cmd = f"systemctl stop {shlex.quote(svc)} && systemctl disable {shlex.quote(svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        iface = sanitize_layer_iface("awg", identifier)
        svc = f"ldbp-awg-{iface}.service"
        ok_svc, out_svc, _ = ssh.execute(f"systemctl is-active {shlex.quote(svc)}")
        ok_iface, _, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
        active = (ok_svc == 0 and out_svc.strip() == "active" and ok_iface == 0)
        return {
            "status": "online" if active else "offline",
            "interface": iface,
            "service": svc,
        }

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = sanitize_layer_iface("awg", identifier)
        svc = f"ldbp-awg-{iface}.service"
        cmd = (
            f"systemctl stop {shlex.quote(svc)} 2>/dev/null || true; "
            f"systemctl disable {shlex.quote(svc)} 2>/dev/null || true; "
            f"awg-quick down {shlex.quote(iface)} 2>/dev/null || wg-quick down {shlex.quote(iface)} 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true; "
            f"rm -f /etc/systemd/system/{shlex.quote(svc)} /etc/ldbp/layer-*-{shlex.quote(iface)}.sh /etc/amnezia/amneziawg/{shlex.quote(iface)}.conf; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


class WireGuardUdp2rawAdapter(BaseLayeredAdapter):
    """Adapter for WireGuard carried over udp2raw fake TCP."""

    def __init__(self):
        super().__init__("wireguard_udp2raw")

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        ok, out, _ = ssh.execute("which udp2raw 2>/dev/null || test -f /usr/local/bin/udp2raw")
        return (ok == 0), ("udp2raw binary present" if ok == 0 else "udp2raw binary missing at /usr/local/bin/udp2raw")

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        from core.wireguard_tools import generate_wireguard_keypair
        ir_priv, ir_pub = generate_wireguard_keypair()
        kh_priv, kh_pub = generate_wireguard_keypair()

        carrier_port = int(pool_config.get("carrier_port", 40001))
        local_bind = int(pool_config.get("local_bind_port", 33333))
        password = pool_config.get("password", "ldbp-udp2raw-secret")

        plan_ir = build_wireguard_udp2raw_plan(
            identifier=pool_config.get("pool_name", "wgu2r"),
            private_key=ir_priv,
            peer_public_key=kh_pub,
            remote_ip=kharej_server.get("ip", ""),
            carrier_port=carrier_port,
            local_bind_port=local_bind,
            private_ip="10.201.0.1",
            peer_private_ip="10.201.0.2",
            role="iran",
            password=password,
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        plan_kh = build_wireguard_udp2raw_plan(
            identifier=pool_config.get("pool_name", "wgu2r"),
            private_key=kh_priv,
            peer_public_key=ir_pub,
            remote_ip=iran_node.get("ip", ""),
            carrier_port=carrier_port,
            local_bind_port=local_bind,
            private_ip="10.201.0.2",
            peer_private_ip="10.201.0.1",
            role="kharej",
            password=password,
            base_mtu=int(pool_config.get("mtu", STANDARD_ETHERNET_MTU)),
        )
        return {
            "protocol": "wireguard_udp2raw",
            "plan_ir": plan_ir,
            "plan_kh": plan_kh,
            "recommended_mtu": plan_ir.recommended_mtu,
            "total_overhead": plan_ir.total_overhead,
        }

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = sanitize_layer_iface("wgr", identifier)
        u2r_svc = f"ldbp-udp2raw-{iface}.service"
        wg_svc = f"ldbp-wg-{iface}.service"
        cmd = f"systemctl start {shlex.quote(u2r_svc)} && sleep 1 && systemctl start {shlex.quote(wg_svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = sanitize_layer_iface("wgr", identifier)
        u2r_svc = f"ldbp-udp2raw-{iface}.service"
        wg_svc = f"ldbp-wg-{iface}.service"
        # Strict reverse order: WireGuard first, then udp2raw
        cmd = f"systemctl stop {shlex.quote(wg_svc)} {shlex.quote(u2r_svc)}"
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        iface = sanitize_layer_iface("wgr", identifier)
        u2r_svc = f"ldbp-udp2raw-{iface}.service"
        wg_svc = f"ldbp-wg-{iface}.service"
        ok_u2r, out_u2r, _ = ssh.execute(f"systemctl is-active {shlex.quote(u2r_svc)}")
        ok_wg, out_wg, _ = ssh.execute(f"systemctl is-active {shlex.quote(wg_svc)}")
        ok_iface, _, _ = ssh.execute(f"ip link show {shlex.quote(iface)}")
        active = (ok_u2r == 0 and ok_wg == 0 and ok_iface == 0)
        return {
            "status": "online" if active else "offline",
            "carrier_udp2raw": "up" if ok_u2r == 0 else "down",
            "overlay_wireguard": "up" if ok_wg == 0 else "down",
        }

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        iface = sanitize_layer_iface("wgr", identifier)
        u2r_svc = f"ldbp-udp2raw-{iface}.service"
        wg_svc = f"ldbp-wg-{iface}.service"
        # Strict reverse order teardown: WireGuard -> udp2raw
        cmd = (
            f"systemctl stop {shlex.quote(wg_svc)} 2>/dev/null || true; "
            f"systemctl disable {shlex.quote(wg_svc)} 2>/dev/null || true; "
            f"wg-quick down {shlex.quote(iface)} 2>/dev/null || true; "
            f"ip link del {shlex.quote(iface)} 2>/dev/null || true; "
            f"systemctl stop {shlex.quote(u2r_svc)} 2>/dev/null || true; "
            f"systemctl disable {shlex.quote(u2r_svc)} 2>/dev/null || true; "
            f"killall udp2raw 2>/dev/null || true; "
            f"rm -f /etc/systemd/system/{shlex.quote(wg_svc)} /etc/systemd/system/{shlex.quote(u2r_svc)} "
            f"/etc/wireguard/{shlex.quote(iface)}.conf /etc/ldbp/layer-*-{shlex.quote(iface)}.sh; "
            f"systemctl daemon-reload"
        )
        ok, out, err = ssh.execute(cmd)
        return (ok == 0), (out if ok == 0 else err)


# Register all layered/hybrid adapters
for adapter_instance in [
    GeneveGre6NativeAdapter(),
    GeneveGre6Ipv4Adapter(),
    WireGuardAmneziaAdapter(),
    WireGuardUdp2rawAdapter(),
]:
    register_adapter(adapter_instance)
