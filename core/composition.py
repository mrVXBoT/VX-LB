"""Unified Layer and Composition Data Model for VX-LB.

Explicitly separate:
1. Transport Layer (L2/L3/L4/L7 overlay/carrier network)
2. Encryption Layer (ipsec, tls, wireguard, noise, none)
3. Camouflage Layer (xhttp, waterwall, dns_subdomain, stealth, pck, wss, none)

Provides:
- TransportLayer, EncryptionLayer, CamouflageLayer, PoolComposition dataclasses.
- validate_composition: Cross-layer compatibility and security verification.
- Bi-directional translation between legacy monolithic strings and PoolComposition.
- infer_composition_from_pool: Derives structured 3-layer composition for any pool record.
- get_available_compositions: Introspection catalog of supported profiles and schemas.
"""

from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any, Tuple, Union
import logging

logger = logging.getLogger("vxlb.composition")

VALID_TRANSPORT_TYPES = {
    "tcp", "udp", "gre", "vxlan", "geneve", "wireguard", "ip6ip6", "gre6", "dns", "raw_tcp", "tun", "dc6", "http", "https",
    "fake-sni", "split-tls", "hop-ttl-injection", "tcp-state-desync", "l7-header-mutation",
    # Aliases
    "gre_ipv4", "gre_ipv6", "direct"
}

VALID_LAYERS = {"L2", "L3", "L4", "L7"}

VALID_ENCRYPTION_TYPES = {
    "none", "ipsec", "tls", "wireguard", "noise",
    # Aliases
    "tls13", "kcp", "psk"
}

VALID_CAMOUFLAGE_TYPES = {
    "none", "xhttp", "waterwall", "dns_subdomain", "stealth", "pck", "wss",
    # Aliases
    "xhttp_grpc", "raw_tcp_kcp", "dns_delegation"
}


@dataclass
class TransportLayer:
    type: str  # tcp, udp, gre, vxlan, geneve, wireguard, ip6ip6, gre6, dns, raw_tcp
    layer: str  # L2, L3, L4, L7
    mtu: int
    vni: Optional[int] = None
    interface: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransportLayer":
        if not isinstance(data, dict):
            raise ValueError(f"Expected dict for TransportLayer, got {type(data).__name__}")
        return cls(
            type=str(data.get("type", "tcp")),
            layer=str(data.get("layer", "L4")),
            mtu=int(data.get("mtu", 1500)),
            vni=int(data["vni"]) if data.get("vni") is not None else None,
            interface=str(data["interface"]) if data.get("interface") is not None else None,
        )


@dataclass
class EncryptionLayer:
    type: str  # none, ipsec, tls, wireguard, noise
    cipher: Optional[str] = None
    auth_mode: Optional[str] = None
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptionLayer":
        if not isinstance(data, dict):
            raise ValueError(f"Expected dict for EncryptionLayer, got {type(data).__name__}")
        enc_type = str(data.get("type", "none"))
        default_enabled = False if enc_type.lower() in ("none", "", "null") else True
        enabled = bool(data.get("enabled", default_enabled))
        return cls(
            type=enc_type,
            cipher=str(data["cipher"]) if data.get("cipher") is not None else None,
            auth_mode=str(data["auth_mode"]) if data.get("auth_mode") is not None else None,
            enabled=enabled,
        )


@dataclass
class CamouflageLayer:
    type: str  # none, xhttp, waterwall, dns_subdomain, stealth, pck, wss
    mode: Optional[str] = None
    domain: Optional[str] = None
    rate_limit: Optional[int] = None
    resolvers: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CamouflageLayer":
        if not isinstance(data, dict):
            raise ValueError(f"Expected dict for CamouflageLayer, got {type(data).__name__}")
        res = data.get("resolvers")
        if res is not None and not isinstance(res, list):
            res = list(res)
        return cls(
            type=str(data.get("type", "none")),
            mode=str(data["mode"]) if data.get("mode") is not None else None,
            domain=str(data["domain"]) if data.get("domain") is not None else None,
            rate_limit=int(data["rate_limit"]) if data.get("rate_limit") is not None else None,
            resolvers=res,
        )


@dataclass
class PoolComposition:
    transport: TransportLayer
    encryption: EncryptionLayer
    camouflage: CamouflageLayer

    @property
    def network(self) -> TransportLayer:
        """Backward compatibility alias for network layer."""
        return self.transport

    def to_dict(self) -> Dict[str, Any]:
        t_dict = self.transport.to_dict()
        e_dict = self.encryption.to_dict()
        c_dict = self.camouflage.to_dict()
        return {
            "transport": t_dict,
            "encryption": e_dict,
            "camouflage": c_dict,
            "network": t_dict,  # Backward compatibility alias
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PoolComposition":
        if not isinstance(data, dict):
            raise ValueError(f"Expected dict for PoolComposition, got {type(data).__name__}")
        t_data = data.get("transport") or data.get("network") or {}
        e_data = data.get("encryption") or {}
        c_data = data.get("camouflage") or {}
        return cls(
            transport=TransportLayer.from_dict(t_data),
            encryption=EncryptionLayer.from_dict(e_data),
            camouflage=CamouflageLayer.from_dict(c_data),
        )


def validate_composition(comp: Union[PoolComposition, Dict[str, Any]]) -> Tuple[bool, str]:
    """Validate layer cross-compatibility, security and MTU boundaries.
    
    Returns:
        (valid: bool, message: str)
    """
    if isinstance(comp, dict):
        try:
            comp_obj = PoolComposition.from_dict(comp)
        except Exception as e:
            return False, f"Invalid composition format: {e}"
    elif isinstance(comp, PoolComposition):
        comp_obj = comp
    else:
        return False, f"Expected PoolComposition or dict, got {type(comp).__name__}"

    t = comp_obj.transport
    e = comp_obj.encryption
    c = comp_obj.camouflage

    # 1. MTU bounds check: min standard IP packet size is 576, jumbo frames max 9000
    if not isinstance(t.mtu, int) or t.mtu < 576 or t.mtu > 9000:
        return False, f"Invalid MTU {t.mtu}: must be between 576 and 9000 bytes."

    # 2. Layer bounds check
    if t.layer not in VALID_LAYERS:
        return False, f"Unsupported transport layer '{t.layer}'. Must be one of {sorted(VALID_LAYERS)}."

    # 3. Transport type check
    if t.type not in VALID_TRANSPORT_TYPES:
        return False, f"Unsupported transport type '{t.type}'."

    # 4. Security check: Reject raw unencrypted L3 on public networks (e.g. GRE without IPsec or XHTTP)
    if t.type in ("gre", "gre_ipv4") and e.type == "none" and c.type in ("none", ""):
        return False, "Raw unencrypted GRE on public networks is rejected: requires IPsec or TLS/XHTTP encapsulation."

    # 5. Overlay VNI bounds check (24-bit VNI: 1 to 16,777,215)
    if t.type in ("vxlan", "geneve") and t.vni is not None:
        if not (1 <= t.vni <= 16777215):
            return False, f"Overlay VNI {t.vni} out of range (must be 1 to 16,777,215)."

    # 6. Camouflage consistency checks
    if c.type in ("dns_subdomain", "dns_delegation") and not c.domain:
        return False, "DNS camouflage requires a valid delegated domain."

    if c.type in ("xhttp", "xhttp_grpc") and e.type not in ("tls", "tls13"):
        return False, "XHTTP camouflage requires TLS encryption layer."

    return True, "Composition is valid."


def legacy_transport_to_composition(transport: str, **kwargs) -> PoolComposition:
    """Convert legacy monolithic transport string into structured PoolComposition."""
    tr = (transport or "").strip().lower()
    
    # Defaults
    t_type = "tcp"
    t_layer = "L4"
    t_mtu = kwargs.get("mtu") or 1500
    t_vni = kwargs.get("vni")
    t_iface = kwargs.get("interface")

    e_type = "none"
    e_cipher = kwargs.get("cipher")
    e_auth = kwargs.get("auth_mode")
    e_enabled = False

    c_type = "none"
    c_mode = kwargs.get("mode")
    c_domain = kwargs.get("domain")
    c_rate = kwargs.get("rate_limit")
    c_res = kwargs.get("resolvers")

    if tr in ("gre_xhttp",):
        t_type = "gre"
        t_layer = "L3"
        t_mtu = kwargs.get("gre_mtu") or kwargs.get("mtu") or 1360
        e_type = "tls"
        e_cipher = e_cipher or "tls13"
        e_auth = e_auth or "sni"
        e_enabled = True
        c_type = "xhttp"
        c_mode = c_mode or "xhttp_grpc"
    elif tr in ("xhttp",):
        t_type = "tcp"
        t_layer = "L7"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "tls"
        e_cipher = e_cipher or "tls13"
        e_auth = e_auth or "sni"
        e_enabled = True
        c_type = "xhttp"
        c_mode = c_mode or "xhttp_grpc"
    elif tr in ("gre", "gre_ipv4"):
        t_type = "gre"
        t_layer = "L3"
        t_mtu = kwargs.get("gre_mtu") or kwargs.get("mtu") or 1280
        e_type = "ipsec"
        e_cipher = e_cipher or "aes_gcm_256"
        e_auth = e_auth or "psk"
        e_enabled = True
        c_type = "none"
    elif tr in ("geneve_ipsec",):
        t_type = "geneve"
        t_layer = "L2"
        t_mtu = kwargs.get("geneve_mtu") or kwargs.get("mtu") or 1280
        t_vni = t_vni or 1000
        e_type = "ipsec"
        e_cipher = e_cipher or "aes_gcm_256"
        e_auth = e_auth or "psk"
        e_enabled = True
        c_type = "none"
    elif tr in ("geneve",):
        t_type = "geneve"
        t_layer = "L2"
        t_mtu = kwargs.get("geneve_mtu") or kwargs.get("mtu") or 1450
        t_vni = t_vni or 1000
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("geneve_gre6", "geneve_gre6_native"):
        t_type = "geneve"
        t_layer = "L2"
        t_mtu = kwargs.get("geneve_mtu") or kwargs.get("mtu") or 1376
        t_vni = t_vni or 1000
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("geneve_gre6_ipv4",):
        t_type = "geneve"
        t_layer = "L2"
        t_mtu = kwargs.get("geneve_mtu") or kwargs.get("mtu") or 1358
        t_vni = t_vni or 1000
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("wireguard_amnezia",):
        t_type = "wireguard"
        t_layer = "L3"
        t_mtu = kwargs.get("wireguard_mtu") or kwargs.get("mtu") or 1380
        e_type = "wireguard"
        e_cipher = e_cipher or "chacha20poly1305"
        e_auth = e_auth or "pubkey"
        e_enabled = True
        c_type = "stealth"
        c_mode = "amnezia_junk"
    elif tr in ("wireguard_udp2raw",):
        t_type = "wireguard"
        t_layer = "L3"
        t_mtu = kwargs.get("wireguard_mtu") or kwargs.get("mtu") or 1360
        e_type = "wireguard"
        e_cipher = e_cipher or "chacha20poly1305"
        e_auth = e_auth or "pubkey"
        e_enabled = True
        c_type = "stealth"
        c_mode = "faketcp_udp2raw"
    elif tr in ("vxlan",):
        t_type = "vxlan"
        t_layer = "L2"
        t_mtu = kwargs.get("vxlan_mtu") or kwargs.get("mtu") or 1280
        t_vni = t_vni or 1000
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("dc6",):
        t_type = "dc6"
        t_layer = "L3"
        t_mtu = kwargs.get("dc6_mtu") or kwargs.get("mtu") or 1280
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("http", "https", "fake-sni", "split-tls", "hop-ttl-injection", "tcp-state-desync", "l7-header-mutation"):
        t_type = tr
        t_layer = "L7"
        t_mtu = 1400
        e_type = "tls"
        e_cipher = "tls13"
        e_auth = "mutual_tls"
        e_enabled = True
        c_type = "none"
    elif tr in ("tun",):
        t_type = "tun"
        t_layer = "L3"
        t_mtu = kwargs.get("tun_mtu") or kwargs.get("mtu") or 1280
        e_type = "noise"
        e_auth = "psk"
        e_enabled = True
        c_type = "none"
    elif tr in ("wireguard",):
        t_type = "wireguard"
        t_layer = "L3"
        t_mtu = kwargs.get("wireguard_mtu") or kwargs.get("mtu") or 1280
        e_type = "wireguard"
        e_cipher = e_cipher or "chacha20poly1305"
        e_auth = e_auth or "pubkey"
        e_enabled = True
        c_type = "none"
    elif tr in ("waterwall",):
        t_type = "tcp"
        t_layer = "L7"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "tls"
        e_cipher = e_cipher or "tls13"
        e_auth = e_auth or "sni"
        e_enabled = True
        c_type = "waterwall"
        c_mode = c_mode or "vless_mux"
    elif tr in ("slipstream",):
        t_type = "dns"
        t_layer = "L7"
        t_mtu = kwargs.get("mtu") or 1200
        e_type = "tls" if kwargs.get("mutual_tls") else "none"
        e_cipher = "tls13" if kwargs.get("mutual_tls") else None
        e_auth = "mutual_tls" if kwargs.get("mutual_tls") else None
        e_enabled = bool(kwargs.get("mutual_tls"))
        c_type = "dns_subdomain"
        c_mode = c_mode or "delegated_ns"
        c_res = c_res or ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]
        c_rate = int(kwargs["rate_limit"]) if kwargs.get("dns_qps_enforced") and kwargs.get("rate_limit") else None
    elif tr in ("gre6", "gre_ipv6"):
        t_type = "gre6"
        t_layer = "L3"
        t_mtu = kwargs.get("gre6_mtu") or kwargs.get("mtu") or 1280
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("ip6ip6",):
        t_type = "ip6ip6"
        t_layer = "L3"
        t_mtu = kwargs.get("ip6ip6_mtu") or kwargs.get("mtu") or 1280
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("wss",):
        t_type = "tcp"
        t_layer = "L7"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "tls"
        e_cipher = e_cipher or "tls13"
        e_enabled = True
        c_type = "wss"
    elif tr in ("stealth",):
        t_type = "tcp"
        t_layer = "L4"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "none"
        e_enabled = False
        c_type = "stealth"
    elif tr in ("pck",):
        t_type = "tcp"
        t_layer = "L4"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "none"
        e_enabled = False
        c_type = "pck"
    elif tr in ("udp",):
        t_type = "udp"
        t_layer = "L4"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "none"
        e_enabled = False
        c_type = "none"
    elif tr in ("kcp", "quic"):
        t_type = "udp"
        t_layer = "L4"
        t_mtu = kwargs.get("mtu") or 1400
        e_type = "tls" if tr == "quic" else "none"
        e_enabled = True if tr == "quic" else False
        c_type = "none"
    else:  # backpack or generic
        t_type = "tcp"
        t_layer = "L4"
        t_mtu = kwargs.get("mtu") or 1500
        e_type = "none"
        e_enabled = False
        c_type = "none"

    return PoolComposition(
        transport=TransportLayer(
            type=t_type,
            layer=t_layer,
            mtu=int(t_mtu),
            vni=int(t_vni) if t_vni is not None else None,
            interface=str(t_iface) if t_iface is not None else None,
        ),
        encryption=EncryptionLayer(
            type=e_type,
            cipher=e_cipher,
            auth_mode=e_auth,
            enabled=e_enabled,
        ),
        camouflage=CamouflageLayer(
            type=c_type,
            mode=c_mode,
            domain=c_domain,
            rate_limit=int(c_rate) if c_rate is not None else None,
            resolvers=c_res,
        ),
    )


def composition_to_legacy_string(comp: Union[PoolComposition, Dict[str, Any]]) -> str:
    """Convert structured PoolComposition back to canonical legacy transport string."""
    if isinstance(comp, dict):
        comp = PoolComposition.from_dict(comp)

    t = comp.transport
    e = comp.encryption
    c = comp.camouflage

    if t.type in ("http","https","tun","dc6","fake-sni","split-tls","hop-ttl-injection","tcp-state-desync","l7-header-mutation"):
        return t.type
    if t.type == "dns" or c.type in ("dns_subdomain", "dns_delegation"):
        return "slipstream"
    if t.type in ("gre", "gre_ipv4"):
        if c.type in ("xhttp", "xhttp_grpc") or e.type in ("tls", "tls13"):
            return "gre_xhttp"
        return "gre"
    if t.type == "geneve":
        if e.type == "ipsec":
            return "geneve_ipsec"
        return "geneve"
    if t.type == "vxlan":
        return "vxlan"
    if t.type == "wireguard" or e.type == "wireguard":
        return "wireguard"
    if c.type == "waterwall":
        return "waterwall"
    if c.type in ("xhttp", "xhttp_grpc"):
        return "xhttp"
    if c.type == "wss":
        return "wss"
    if c.type == "pck":
        return "pck"
    if c.type == "stealth":
        return "stealth"
    if t.type in ("gre6", "gre_ipv6"):
        return "gre6"
    if t.type == "ip6ip6":
        return "ip6ip6"
    if t.type == "udp":
        return "udp"
    if t.type == "tcp":
        return "tcp"

    return "backpack"


def infer_composition_from_pool(pool: dict) -> Dict[str, Any]:
    """Construct the 3-layer composition dictionary for any existing pool."""
    if not isinstance(pool, dict):
        return legacy_transport_to_composition("backpack").to_dict()

    # If pool already has a valid composition dict, parse and return it
    if "composition" in pool and isinstance(pool["composition"], dict):
        try:
            return PoolComposition.from_dict(pool["composition"]).to_dict()
        except Exception:
            pass

    transport = pool.get("transport") or pool.get("engine") or "backpack"

    # Gather parameters
    params: Dict[str, Any] = {"mutual_tls": bool(pool.get("slipstream_security")), "dns_qps_enforced": int(pool.get("slipstream_runtime_version", 1)) >= 2}
    
    # MTU extraction
    for mtu_key in ("mtu", "gre_mtu", "geneve_mtu", "vxlan_mtu", "wireguard_mtu", "gre6_mtu", "ip6ip6_mtu"):
        if pool.get(mtu_key):
            try:
                params[mtu_key] = int(pool[mtu_key])
            except (ValueError, TypeError):
                pass

    if "mtu" not in params:
        for k in ("gre_mtu", "geneve_mtu", "vxlan_mtu", "wireguard_mtu", "gre6_mtu", "ip6ip6_mtu"):
            if k in params:
                params["mtu"] = params[k]
                break

    # VNI extraction
    if pool.get("vni") is not None:
        try:
            params["vni"] = int(pool["vni"])
        except (ValueError, TypeError):
            pass

    # Camouflage extraction
    camo = pool.get("camouflage")
    if isinstance(camo, dict):
        if camo.get("mode"):
            params["mode"] = camo["mode"]
        if camo.get("server_name"):
            params["domain"] = camo["server_name"]
        if camo.get("domain"):
            params["domain"] = camo["domain"]
        if camo.get("resolvers"):
            params["resolvers"] = camo["resolvers"]
        if camo.get("rate_limit"):
            params["rate_limit"] = camo["rate_limit"]
    elif isinstance(camo, str) and camo.strip():
        params["mode"] = camo.strip()

    if pool.get("domain") and "domain" not in params:
        params["domain"] = pool["domain"]
    if pool.get("resolvers") and "resolvers" not in params:
        params["resolvers"] = pool["resolvers"]
    if pool.get("rate_limit") and "rate_limit" not in params:
        params["rate_limit"] = pool["rate_limit"]

    # Check node-specific details if pool-level params missing
    nodes = pool.get("nodes")
    if isinstance(nodes, list) and nodes:
        first_node = nodes[0]
        if isinstance(first_node, dict):
            for eng_key in ("geneve", "vxlan", "wireguard", "gre", "gre6", "ip6ip6", "waterwall"):
                cfg = first_node.get(eng_key)
                if isinstance(cfg, dict):
                    if "vni" not in params and cfg.get("vni") is not None:
                        try:
                            params["vni"] = int(cfg["vni"])
                        except (ValueError, TypeError):
                            pass
                    if "interface" not in params and cfg.get("interface"):
                        params["interface"] = cfg["interface"]
                    if "mtu" not in params and cfg.get("mtu") is not None:
                        try:
                            params["mtu"] = int(cfg["mtu"])
                        except (ValueError, TypeError):
                            pass
                    if "cipher" not in params and cfg.get("cipher"):
                        params["cipher"] = cfg["cipher"]

    # Build composition
    comp = legacy_transport_to_composition(transport, **params)
    return comp.to_dict()


def get_available_compositions() -> List[Dict[str, Any]]:
    """Return catalog of supported compositions and schema definitions for introspection."""
    catalog = [
        {
            "id": "gre",
            "name": "GRE IPv4 + IPsec",
            "description": "Encrypted Layer 3 point-to-point tunnel using IPsec AES-GCM.",
            "layer": "L3",
            "security": "ipsec",
            "composition": legacy_transport_to_composition("gre").to_dict(),
            "schema": {
                "transport": {"type": "gre", "layer": "L3", "default_mtu": 1400},
                "encryption": {"type": "ipsec", "cipher": "aes_gcm_256", "auth_mode": "psk"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "gre_xhttp",
            "name": "GRE inside XHTTP",
            "description": "Encapsulated GRE L3 tunnel disguised inside TLS 1.3 XHTTP/gRPC carrier.",
            "layer": "L3",
            "security": "tls",
            "composition": legacy_transport_to_composition("gre_xhttp").to_dict(),
            "schema": {
                "transport": {"type": "gre", "layer": "L3", "default_mtu": 1360},
                "encryption": {"type": "tls", "cipher": "tls13", "auth_mode": "sni"},
                "camouflage": {"type": "xhttp", "mode": "xhttp_grpc"}
            }
        },
        {
            "id": "geneve_ipsec",
            "name": "Geneve + IPsec",
            "description": "Overlay L2 Geneve tunnel with IPsec AES-GCM encryption.",
            "layer": "L2",
            "security": "ipsec",
            "composition": legacy_transport_to_composition("geneve_ipsec").to_dict(),
            "schema": {
                "transport": {"type": "geneve", "layer": "L2", "default_mtu": 1400, "default_vni": 1000},
                "encryption": {"type": "ipsec", "cipher": "aes_gcm_256", "auth_mode": "psk"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "geneve",
            "name": "Geneve Overlay",
            "description": "Unencrypted Geneve Layer 2 overlay for private interconnects.",
            "layer": "L2",
            "security": "none",
            "composition": legacy_transport_to_composition("geneve").to_dict(),
            "schema": {
                "transport": {"type": "geneve", "layer": "L2", "default_mtu": 1450, "default_vni": 1000},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "vxlan",
            "name": "VXLAN Overlay",
            "description": "Layer 2 VXLAN overlay across Iran and Kharej nodes.",
            "layer": "L2",
            "security": "none",
            "composition": legacy_transport_to_composition("vxlan").to_dict(),
            "schema": {
                "transport": {"type": "vxlan", "layer": "L2", "default_mtu": 1450, "default_vni": 1000},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "wireguard",
            "name": "WireGuard",
            "description": "Kernel-based Layer 3 tunnel with Curve25519 and ChaCha20-Poly1305.",
            "layer": "L3",
            "security": "wireguard",
            "composition": legacy_transport_to_composition("wireguard").to_dict(),
            "schema": {
                "transport": {"type": "wireguard", "layer": "L3", "default_mtu": 1420},
                "encryption": {"type": "wireguard", "cipher": "chacha20poly1305", "auth_mode": "pubkey"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "slipstream",
            "name": "Slipstream DNS Tunnel",
            "description": "Emergency fallback L7 tunnel operating over delegated DNS subdomains.",
            "layer": "L7",
            "security": "mutual_tls",
            "composition": legacy_transport_to_composition("slipstream", mutual_tls=True).to_dict(),
            "schema": {
                "transport": {"type": "dns", "layer": "L7", "default_mtu": 1200},
                "encryption": {"type": "tls", "cipher": "tls13", "auth_mode": "mutual_tls"},
                "camouflage": {"type": "dns_subdomain", "mode": "delegated_ns", "required": ["domain"]}
            }
        },
        {
            "id": "waterwall",
            "name": "WaterWall",
            "description": "Userspace proxy tunnel with VLESS/TLS/Mux routing.",
            "layer": "L7",
            "security": "tls",
            "composition": legacy_transport_to_composition("waterwall").to_dict(),
            "schema": {
                "transport": {"type": "tcp", "layer": "L7", "default_mtu": 1500},
                "encryption": {"type": "tls", "cipher": "tls13", "auth_mode": "sni"},
                "camouflage": {"type": "waterwall", "mode": "vless_mux"}
            }
        },
        {
            "id": "gre6",
            "name": "GRE6 (IPv6)",
            "description": "Layer 3 IPv6 GRE encapsulation over pure IPv6 networks.",
            "layer": "L3",
            "security": "none",
            "composition": legacy_transport_to_composition("gre6").to_dict(),
            "schema": {
                "transport": {"type": "gre6", "layer": "L3", "default_mtu": 1400},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "ip6ip6",
            "name": "IP6IP6 (IPv6)",
            "description": "Direct IPv6-in-IPv6 tunnel over IPv6 networks.",
            "layer": "L3",
            "security": "none",
            "composition": legacy_transport_to_composition("ip6ip6").to_dict(),
            "schema": {
                "transport": {"type": "ip6ip6", "layer": "L3", "default_mtu": 1420},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "tcp",
            "name": "Direct TCP",
            "description": "Standard direct TCP forwarding.",
            "layer": "L4",
            "security": "none",
            "composition": legacy_transport_to_composition("tcp").to_dict(),
            "schema": {
                "transport": {"type": "tcp", "layer": "L4", "default_mtu": 1500},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "pck",
            "name": "BackPack PCK",
            "description": "BackPack raw TCP carrier with PCK obfuscation.",
            "layer": "L4",
            "security": "none",
            "composition": legacy_transport_to_composition("pck").to_dict(),
            "schema": {
                "transport": {"type": "tcp", "layer": "L4", "default_mtu": 1500},
                "encryption": {"type": "none"},
                "camouflage": {"type": "pck"}
            }
        },
        {
            "id": "geneve_gre6_native",
            "name": "Geneve + GRE6 Native IPv6",
            "description": "Layer 2 Geneve overlay running over Native IPv6 GRE6 carrier (3.17).",
            "layer": "L2",
            "security": "none",
            "composition": legacy_transport_to_composition("geneve_gre6_native").to_dict(),
            "schema": {
                "transport": {"type": "geneve", "layer": "L2", "default_mtu": 1376, "default_vni": 1000},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "geneve_gre6_ipv4",
            "name": "Geneve + GRE6 over IPv4 (SIT)",
            "description": "3-tier stack: SIT carrier -> GRE6 -> Geneve L2 overlay (3.18).",
            "layer": "L2",
            "security": "none",
            "composition": legacy_transport_to_composition("geneve_gre6_ipv4").to_dict(),
            "schema": {
                "transport": {"type": "geneve", "layer": "L2", "default_mtu": 1358, "default_vni": 1000},
                "encryption": {"type": "none"},
                "camouflage": {"type": "none"}
            }
        },
        {
            "id": "wireguard_amnezia",
            "name": "WireGuard + AmneziaWG Obfuscation",
            "description": "WireGuard with header junk padding and custom handshake opcodes (3.23).",
            "layer": "L3",
            "security": "wireguard",
            "composition": legacy_transport_to_composition("wireguard_amnezia").to_dict(),
            "schema": {
                "transport": {"type": "wireguard", "layer": "L3", "default_mtu": 1380},
                "encryption": {"type": "wireguard", "cipher": "chacha20poly1305", "auth_mode": "pubkey"},
                "camouflage": {"type": "stealth", "mode": "amnezia_junk"}
            }
        },
        {
            "id": "wireguard_udp2raw",
            "name": "WireGuard + udp2raw Fake TCP",
            "description": "WireGuard encapsulated inside raw fake TCP packets to bypass UDP blocking (3.23).",
            "layer": "L3",
            "security": "wireguard",
            "composition": legacy_transport_to_composition("wireguard_udp2raw").to_dict(),
            "schema": {
                "transport": {"type": "wireguard", "layer": "L3", "default_mtu": 1360},
                "encryption": {"type": "wireguard", "cipher": "chacha20poly1305", "auth_mode": "pubkey"},
                "camouflage": {"type": "stealth", "mode": "faketcp_udp2raw"}
            }
        }
    ]
    return catalog
