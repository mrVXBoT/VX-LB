"""13 Advanced Transports Engine (VX-LB Suite).

Transport profiles:
1. tcp: Raw TCP / Noise-Framed TCP (Low overhead, Nodelay, BBR)
2. ws: Plaintext WebSocket over TCP (RFC 6455, Early Data)
3. wss: WebSocket Secure over TLS 1.3 (Browser fingerprint, CDN-compatible)
4. http: HTTP/1.1 Chunked / h2c (Corporate header obfuscation)
5. https: HTTP/2 Multiplexed over TLS (RFC 9113)
6. tun: Linux Kernel Virtual L3 TUN (/dev/net/tun with TCPMSS clamp)
7. xhttp: Xray SplitHTTP (Decoupled GET/POST with X-Padding)
8. xhttps: XHTTP over TLS 1.3 / REALITY with xmux
9. dc6: Direct Connect IPv6 Carrier (ip6gre / sit / ip6ip6)
10. nova: Next-Gen Obfuscated Hybrid (QUIC/H3 + Port Hopping, TLS ClientHello Slicing)

Includes kernel-based telemetry via direct Linux kernel struct tcp_info extraction.
"""
from dataclasses import dataclass, field, asdict
import hmac
import hashlib
import json
import logging
import os
import secrets
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("vxlb.transports_13")

# Category Identifiers
CAT_WEB_STREAM = "web_stream"
CAT_KCP_ACCELERATOR = "kcp_accelerator"
CAT_L3_CARRIER = "l3_carrier"
CAT_ANTI_CENSORSHIP = "anti_censorship"

CATEGORY_TITLES = {
    CAT_WEB_STREAM: "استاندارد و استریم وب (Standard & Web)",
    CAT_KCP_ACCELERATOR: "شتاب‌دهنده و گیمینگ (Loss-Resilient & Gaming)",
    CAT_L3_CARRIER: "حامل‌های لایه ۳ کرنل (Kernel L3 Carriers)",
    CAT_ANTI_CENSORSHIP: "استتار و ضدسانسور پیشرفته (Anti-Censorship)",
}

@dataclass
class TransportSpecification:
    id: str
    display_name: str
    display_name_fa: str
    category: str
    category_title_fa: str
    layer: str
    underlying_protocol: str
    reference_core: str
    header_overhead_bytes: int
    dpi_resistance: str  # کم, متوسط, خوب, عالی, حداکثری
    recommended_use: str
    min_mtu: int
    max_mtu: int
    default_mtu: int
    kernel_modules: List[str]
    requires_encryption: bool
    encryption_type: str
    supports_fec: bool = False
    supports_padding: bool = False
    supports_xmux: bool = False
    supports_port_hopping: bool = False
    sysctl_recommendations: Dict[str, Any] = field(default_factory=dict)
    default_parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


TRANSPORTS_13_CATALOG: Dict[str, TransportSpecification] = {
    # 01) tcp
    "tcp": TransportSpecification(
        id="tcp",
        display_name="Standard TCP",
        display_name_fa="تی‌سی‌پی استاندارد / نویز",
        category=CAT_WEB_STREAM,
        category_title_fa=CATEGORY_TITLES[CAT_WEB_STREAM],
        layer="L4",
        underlying_protocol="Raw TCP Stream (RFC 9293) / Noise_NK",
        reference_core="Rathole / GOST / BackPack",
        header_overhead_bytes=20,
        dpi_resistance="کم",
        recommended_use="سرورهای بدون اختلال پورت با نیاز به کمترین مصرف CPU و تأخیر پایه",
        min_mtu=1200,
        max_mtu=1500,
        default_mtu=1420,
        kernel_modules=["tcp_bbr"],
        requires_encryption=False,
        encryption_type="none",
        sysctl_recommendations={
            "net.ipv4.tcp_congestion_control": "bbr",
            "net.core.default_qdisc": "fq",
            "net.ipv4.tcp_nodelay": 1,
            "net.ipv4.tcp_quickack": 1,
        },
        default_parameters={"nodelay": True, "quickack": True, "congestion": "bbr"},
    ),
    # 02) ws
    "ws": TransportSpecification(
        id="ws",
        display_name="WebSocket (Plaintext)",
        display_name_fa="وب‌سوکت خام (RFC 6455)",
        category=CAT_WEB_STREAM,
        category_title_fa=CATEGORY_TITLES[CAT_WEB_STREAM],
        layer="L7",
        underlying_protocol="TCP / HTTP/1.1 Upgrade WebSocket",
        reference_core="gorilla/websocket / tokio-tungstenite",
        header_overhead_bytes=14,
        dpi_resistance="کم",
        recommended_use="استفاده پشت ریورس‌پروکسی‌ها، وب‌سرورهای داخلی و سناریوهای شبکه محلی",
        min_mtu=1200,
        max_mtu=1500,
        default_mtu=1400,
        kernel_modules=[],
        requires_encryption=False,
        encryption_type="none",
        default_parameters={
            "path": "/ws",
            "permessage_deflate": False,
            "early_data": True,
            "max_early_data": 2560,
        },
    ),
    # 03) wss
    "wss": TransportSpecification(
        id="wss",
        display_name="WebSocket + TLS 1.3",
        display_name_fa="وب‌سوکت امن (WSS + uTLS)",
        category=CAT_WEB_STREAM,
        category_title_fa=CATEGORY_TITLES[CAT_WEB_STREAM],
        layer="L7",
        underlying_protocol="TCP / TLS 1.3 / WebSocket (RFC 8446 + RFC 6455)",
        reference_core="uTLS / BackPack / Xray",
        header_overhead_bytes=45,
        dpi_resistance="خوب",
        recommended_use="عبور مطمئن از CDN (کلودفلر، آروان) با شبیه‌سازی اثرانگشت مرورگر کروم",
        min_mtu=1200,
        max_mtu=1500,
        default_mtu=1380,
        kernel_modules=[],
        requires_encryption=True,
        encryption_type="tls",
        default_parameters={
            "path": "/wss",
            "server_name": "",
            "utls_fingerprint": "chrome",
            "ciphers": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
            "session_resumption": True,
        },
    ),
    # 04) http
    "http": TransportSpecification(
        id="http", display_name="HTTP/1.1 CONNECT + mTLS", display_name_fa="اچ‌تی‌تی‌پی CONNECT با احراز هویت دوطرفه",
        category=CAT_WEB_STREAM, category_title_fa=CATEGORY_TITLES[CAT_WEB_STREAM], layer="L7",
        underlying_protocol="HTTP/1.1 CONNECT / inner TLS1.3 TCP/UDP framing", reference_core="VX-LB stdlib HTTP CONNECT / OpenSSL",
        header_overhead_bytes=80, dpi_resistance="آزمایشی؛ بدون تقلید اثر انگشت مرورگر",
        recommended_use="حامل CONNECT با هویت اختصاصی mTLS؛ آزمون TCP/UDP پیش از فعال‌شدن؛ بدون ادعای HTTP/2 یا استتار مرورگر",
        min_mtu=1200, max_mtu=1500, default_mtu=1400, kernel_modules=[],
        requires_encryption=True, encryption_type="tls",
        default_parameters={"http_version": "1.1", "method": "CONNECT", "mutual_tls": True},
    ),
    # 05) https
    "https": TransportSpecification(
        id="https", display_name="HTTPS CONNECT + mTLS", display_name_fa="اچ‌تی‌تی‌پی‌اس CONNECT با گواهی اختصاصی",
        category=CAT_WEB_STREAM, category_title_fa=CATEGORY_TITLES[CAT_WEB_STREAM], layer="L7",
        underlying_protocol="TLS1.3 / HTTP/1.1 CONNECT / inner mTLS TCP/UDP framing", reference_core="VX-LB stdlib HTTP CONNECT / OpenSSL",
        header_overhead_bytes=80, dpi_resistance="آزمایشی؛ بدون تقلید اثر انگشت مرورگر",
        recommended_use="حامل CONNECT با هویت اختصاصی mTLS؛ آزمون TCP/UDP پیش از فعال‌شدن؛ بدون ادعای HTTP/2 یا استتار مرورگر",
        min_mtu=1200, max_mtu=1500, default_mtu=1400, kernel_modules=[],
        requires_encryption=True, encryption_type="tls",
        default_parameters={"http_version": "1.1", "method": "CONNECT", "mutual_tls": True},
    ),
    # 06) tun
    "tun": TransportSpecification(
        id="tun",
        display_name="Linux Kernel L3 TUN",
        display_name_fa="تانل کرنلی لایه ۳ (/dev/net/tun)",
        category=CAT_L3_CARRIER,
        category_title_fa=CATEGORY_TITLES[CAT_L3_CARRIER],
        layer="L3",
        underlying_protocol="Linux IFF_TUN over UDP/Noise",
        reference_core="Linux drivers/net/tun.c / BackPack L3",
        header_overhead_bytes=80,
        dpi_resistance="وابسته به Carrier",
        recommended_use="مسیریابی کامل پکت‌های IP بدون اثر منفی TCP-over-TCP و سربار لایه اپلیکیشن",
        min_mtu=1200,
        max_mtu=1420,
        default_mtu=1280,
        kernel_modules=["tun", "xt_TCPMSS"],
        requires_encryption=True,
        encryption_type="noise",
        default_parameters={
            "interface_name": "tun_vxlb",
            "clamp_mss": True,
            "txqueuelen": 4096,
            "carrier": "udp",
        },
    ),
    # 11) dc6
    "dc6": TransportSpecification(
        id="dc6",
        display_name="Direct Connect IPv6 Carrier",
        display_name_fa="حامل مستقیم IPv6 دیتاسنتر (DC6)",
        category=CAT_L3_CARRIER,
        category_title_fa=CATEGORY_TITLES[CAT_L3_CARRIER],
        layer="L3",
        underlying_protocol="Linux Kernel ip6gre / ip6ip6 / sit",
        reference_core="Linux ip6_tunnel / iproute2",
        header_overhead_bytes=40,
        dpi_resistance="بدون استتار یا رمزنگاری",
        recommended_use="لینک خصوصی بدون رمزنگاری؛ GRE6/IP6IP6 روی IPv6 عمومی یا SIT روی IPv4 عمومی؛ نیازمند آزمون مسیر",
        min_mtu=1280,
        max_mtu=1440,
        default_mtu=1280,
        kernel_modules=["ip6_tunnel", "ip6_gre", "sit", "xt_TCPMSS"],
        requires_encryption=False,
        encryption_type="none",
        default_parameters={
            "carrier_type": "ip6gre",
            "encaplimit": "none",
            "mss_clamp": 1220,
            "remote_ipv6": "",
        },
    ),
}

def get_transport_spec(transport_id: str) -> Optional[TransportSpecification]:
    """Retrieve the specification of a transport by ID."""
    if not transport_id:
        return None
    tid = str(transport_id).lower().strip()
    return TRANSPORTS_13_CATALOG.get(tid)

def is_13_transport(transport_id: str) -> bool:
    """Return True if the given transport is one of the 13 advanced transports."""
    return str(transport_id).lower().strip() in TRANSPORTS_13_CATALOG

def list_transports_by_category() -> Dict[str, Dict[str, Any]]:
    """Return catalog partitioned by category for UI menus and documentation."""
    result: Dict[str, Dict[str, Any]] = {}
    for cat_id, cat_title in CATEGORY_TITLES.items():
        specs = [s.to_dict() for s in TRANSPORTS_13_CATALOG.values() if s.category == cat_id]
        result[cat_id] = {
            "category_id": cat_id,
            "title_fa": cat_title,
            "transports": specs,
        }
    return result

def validate_transport_params(transport_id: str, params: Optional[dict] = None) -> Tuple[bool, str, dict]:
    """Validates parameters for the specified transport, applying safe defaults."""
    spec = get_transport_spec(transport_id)
    if not spec:
        return False, f"ترنسپورت ناشناخته '{transport_id}'", {}

    merged = dict(spec.default_parameters)
    if params and isinstance(params, dict):
        merged.update(params)

    # MTU bounds check
    mtu = int(merged.get("mtu") or spec.default_mtu)
    if mtu < spec.min_mtu or mtu > spec.max_mtu:
        return (
            False,
            f"MTU نامعتبر برای {spec.display_name}. بازهٔ مجاز: {spec.min_mtu} تا {spec.max_mtu}",
            {},
        )
    merged["mtu"] = mtu

    # Protocol-specific validations
    if spec.id == "dc6":
        carrier = merged.get("carrier_type", "ip6gre")
        if carrier not in {"ip6gre", "ip6ip6", "sit"}:
            return False, "نوع حامل IPv6 نامعتبر است (باید ip6gre، ip6ip6 یا sit باشد)", {}

    elif spec.id == "nova":
        hop_min = int(merged.get("port_hopping_min", 20000))
        hop_max = int(merged.get("port_hopping_max", 50000))
        if hop_min < 1024 or hop_max > 65535 or hop_min >= hop_max:
            return False, "بازه پورت‌های Port Hopping نامعتبر است", {}
        merged["port_hopping_min"] = hop_min
        merged["port_hopping_max"] = hop_max

    return True, "", merged


# ==============================================================================
# kernel-based telemetry Engine
# Reads real socket struct tcp_info from Linux kernel and performs HMAC probes.
# ==============================================================================

def unpack_kernel_tcp_info(raw_bytes: bytes) -> dict:
    """Unpacks Linux struct tcp_info bytes directly into real network metrics.
    
    Fields extracted:
      - rtt_us: real microsecond round-trip time from kernel ACK sampling
      - rttvar_us: microsecond latency variance (true layer-4 jitter)
      - total_retrans: hardware/kernel retransmit counter
      - snd_cwnd: instantaneous congestion window packets
    """
    if not raw_bytes or len(raw_bytes) < 104:
        return {"valid": False, "error": "Insufficient tcp_info payload"}

    try:
        # 8 uint8s + 24 uint32s from linux/tcp.h struct tcp_info
        fields = struct.unpack_from("8B24I", raw_bytes)
        # Offset 8 + 15 = tcpi_rtt (us)
        # Offset 8 + 16 = tcpi_rttvar (us)
        # Offset 8 + 18 = tcpi_snd_cwnd
        # Offset 8 + 23 = tcpi_total_retrans
        rtt_us = fields[23]
        rttvar_us = fields[24]
        snd_cwnd = fields[26]
        total_retrans = fields[31]

        return {
            "valid": True,
            "rtt_ms": round(rtt_us / 1000.0, 2),
            "rttvar_ms": round(rttvar_us / 1000.0, 2),
            "cwnd_pkts": snd_cwnd,
            "retransmits": total_retrans,
            "raw_state": fields[0],
        }
    except Exception as exc:
        return {"valid": False, "error": str(exc)}

def extract_socket_telemetry(sock: socket.socket) -> dict:
    """Queries an active connected socket for real kernel diagnostics."""
    if not hasattr(socket, "TCP_INFO") or not hasattr(socket, "IPPROTO_TCP"):
        return {"supported": False, "reason": "Platform does not expose TCP_INFO"}

    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 256)
        parsed = unpack_kernel_tcp_info(raw)
        parsed["supported"] = True
        return parsed
    except Exception as exc:
        return {"supported": False, "error": str(exc)}

def compute_ewma_score(
    previous_score: float,
    current_rtt_ms: float,
    loss_ratio: float,
    alpha: float = 0.25,
) -> float:
    """Calculates Exponentially Weighted Moving Average (EWMA) health score (0.0 to 100.0).
    
    A higher score indicates better link quality.
    Heavy loss or latency spike degrades score smoothly without erratic flipping.
    """
    # Base score: 100 minus latency penalty and heavy loss penalty
    latency_penalty = min(50.0, (current_rtt_ms / 150.0) * 25.0)
    loss_penalty = min(50.0, loss_ratio * 100.0 * 2.5)
    instant_score = max(0.0, 100.0 - latency_penalty - loss_penalty)

    if previous_score is None or previous_score < 0:
        return round(instant_score, 1)

    new_score = (alpha * instant_score) + ((1.0 - alpha) * previous_score)
    return round(new_score, 1)

def generate_canary_challenge(token: str) -> Tuple[str, str]:
    """Generates a cryptographically random HMAC canary challenge nonce."""
    nonce = secrets.token_hex(16)
    expected_response = hmac.new(
        token.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return nonce, expected_response

def verify_canary_response(token: str, nonce: str, response: str) -> bool:
    """Verifies that an active endpoint correctly proved possession of the pool token."""
    expected = hmac.new(
        token.encode("utf-8"), nonce.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, str(response).strip())
