"""Unified Layer and Composition Data Model for VX-LB.

Refactor pool data modeling to explicitly separate:
1. Network Layer (L3/Overlay routing: direct, GRE, IP6IP6, VXLAN, Geneve, WireGuard, Slipstream DNS)
2. Encryption Layer (Security: None, IPsec AES-256-GCM, Noise Curve25519, TLS 1.3, KCP AES, PSK)
3. Camouflage Layer (Obfuscation: None, XHTTP/TLS, WebSocket/TLS, Raw TCP spoofing, DNS Delegation)

Maintains 100% backward compatibility with legacy monolithic transport definitions (e.g. 'gre_xhttp', 'geneve_ipsec').
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any
import copy
import logging

logger = logging.getLogger("vxlb.composition_schema")


@dataclass
class NetworkLayerSpec:
    type: str  # direct, gre_ipv4, gre_ipv6, ip6ip6, vxlan, geneve, wireguard, slipstream
    overlay_family: str = "ipv4"  # ipv4, ipv6, dual
    mtu: int = 1400
    vni: Optional[int] = None
    port: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EncryptionLayerSpec:
    type: str  # none, ipsec, noise, tls13, kcp, psk
    cipher: Optional[str] = None
    has_psk: bool = False
    rekey_interval_s: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CamouflageLayerSpec:
    type: str  # none, xhttp_grpc, wss, raw_tcp_kcp, dns_delegation
    domain: Optional[str] = None
    sni: Optional[str] = None
    resolvers: List[str] = field(default_factory=list)
    rate_limit: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedComposition:
    engine: str
    network: NetworkLayerSpec
    encryption: EncryptionLayerSpec
    camouflage: CamouflageLayerSpec

    def to_dict(self) -> dict:
        d = asdict(self)
        d["transport"] = d["network"]
        return d


def deconstruct_legacy_pool(pool: dict) -> UnifiedComposition:
    """Deconstruct an existing pool dictionary (v0, v1, v2) into a structured 3-layer composition."""
    transport = str(pool.get("transport", "")).lower()
    engine = str(pool.get("engine", "")).lower() or transport
    camo_dict = pool.get("camouflage", {}) or {}

    # Defaults
    net_type = "direct"
    net_family = "ipv4"
    net_mtu = int(pool.get("mtu") or pool.get("wireguard_mtu") or pool.get("geneve_mtu") or pool.get("vxlan_mtu") or pool.get("gre_mtu") or pool.get("gre6_mtu") or pool.get("ip6ip6_mtu") or 1400)
    net_vni = pool.get("vni")
    net_port = pool.get("tunnel_port") or pool.get("dst_port")

    enc_type = "none"
    enc_cipher = None
    enc_psk = False

    cam_type = "none"
    cam_domain = pool.get("domain") or camo_dict.get("domain") or camo_dict.get("server_name")
    cam_resolvers = pool.get("resolvers") or camo_dict.get("resolvers") or []

    # Map known transports to 3 layers
    if transport in ("gre_xhttp",):
        net_type = "gre_ipv4"
        enc_type = "tls13"
        enc_cipher = "TLS_AES_128_GCM_SHA256"
        cam_type = "xhttp_grpc"
    elif transport in ("xhttp",):
        net_type = "direct"
        enc_type = "tls13"
        enc_cipher = "TLS_AES_128_GCM_SHA256"
        cam_type = "xhttp_grpc"
    elif transport in ("gre",):
        net_type = "gre_ipv4"
        enc_type = "ipsec"
        enc_cipher = "AES_GCM_16_256"
        cam_type = "none"
    elif transport in ("gre6",):
        net_type = "gre_ipv6"
        net_family = "ipv6"
        enc_type = "none"
        cam_type = "none"
    elif transport in ("ip6ip6",):
        net_type = "ip6ip6"
        net_family = "ipv6"
        enc_type = "none"
        cam_type = "none"
    elif transport in ("geneve_ipsec",):
        net_type = "geneve"
        enc_type = "ipsec"
        enc_cipher = "AES_GCM_16_256"
        cam_type = "none"
    elif transport in ("geneve",):
        net_type = "geneve"
        enc_type = "none"
        cam_type = "none"
    elif transport in ("vxlan",):
        net_type = "vxlan"
        enc_type = "none"
        cam_type = "none"
    elif transport in ("wireguard",):
        net_type = "wireguard"
        enc_type = "noise"
        enc_cipher = "ChaCha20Poly1305"
        enc_psk = bool(pool.get("enable_psk") or pool.get("has_psk"))
        cam_type = "none"
    elif transport in ("waterwall",):
        net_type = "direct"
        enc_type = "tls13"
        enc_cipher = "TLS_AES_128_GCM_SHA256"
        cam_type = "xhttp_grpc"
    elif transport in ("slipstream",):
        net_type = "slipstream"
        enc_type = "tls13" if pool.get("slipstream_security") else "none"
        cam_type = "dns_delegation"
        cam_resolvers = pool.get("resolvers") or ["1.1.1.1:53", "8.8.8.8:53"]
    elif transport in ("wss",):
        net_type = "direct"
        enc_type = "tls13"
        cam_type = "wss"
    elif transport in ("quic",):
        net_type = "direct"
        enc_type = "tls13"
        cam_type = "none"
    elif transport in ("kcp", "stealth", "pck", "tcp"):
        net_type = "direct"
        enc_type = "none"
        cam_type = "none"

    return UnifiedComposition(
        engine=engine,
        network=NetworkLayerSpec(
            type=net_type,
            overlay_family=net_family,
            mtu=net_mtu,
            vni=int(net_vni) if net_vni else None,
            port=int(net_port) if net_port else None,
        ),
        encryption=EncryptionLayerSpec(
            type=enc_type,
            cipher=enc_cipher,
            has_psk=enc_psk,
        ),
        camouflage=CamouflageLayerSpec(
            type=cam_type,
            domain=cam_domain,
            resolvers=cam_resolvers,
            rate_limit=int(pool["rate_limit"]) if pool.get("rate_limit") and (transport != "slipstream" or int(pool.get("slipstream_runtime_version", 1)) >= 2) else None,
        ),
    )


def validate_composition(comp: UnifiedComposition) -> Tuple[bool, str]:
    """Validate layer cross-compatibility and safety rules."""
    # 1. Plain GRE on public IPv4 without IPsec or XHTTP is strictly blocked for new configs (Audit item 3.2)
    if comp.network.type == "gre_ipv4" and comp.encryption.type == "none" and comp.camouflage.type == "none":
        return False, "Raw unencrypted GRE on public IPv4 is forbidden without IPsec or XHTTP encapsulation."

    # 2. XHTTP camouflage requires TLS 1.3 encryption
    if comp.camouflage.type == "xhttp_grpc" and comp.encryption.type != "tls13":
        return False, "XHTTP camouflage requires TLS 1.3 encryption layer."

    # 3. DNS delegation camouflage requires a non-empty domain
    if comp.camouflage.type == "dns_delegation" and not comp.camouflage.domain:
        return False, "Slipstream DNS delegation requires a delegated domain name."

    # 4. Geneve VNI range validation if specified
    if comp.network.type == "geneve" and comp.network.vni is not None:
        if not (1 <= comp.network.vni <= 16777215):
            return False, f"Geneve VNI {comp.network.vni} must be between 1 and 16777215."

    # 5. VXLAN VNI range validation if specified
    if comp.network.type == "vxlan" and comp.network.vni is not None:
        if not (1 <= comp.network.vni <= 16777215):
            return False, f"VXLAN VNI {comp.network.vni} must be between 1 and 16777215."

    return True, "Composition is valid."
