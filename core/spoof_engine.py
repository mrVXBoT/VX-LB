"""Packet codecs and standalone experiments for unfinished raw/DNS carriers.

These helpers are not managed deployment, data-path acceptance or evidence of
DPI circumvention. They make no verified throughput or resilience guarantee.
"""
from __future__ import annotations

import array
import asyncio
import base64
import ctypes
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import random
import secrets
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("vxlb.spoof_engine")

# ---------------------------------------------------------------------------
# Base32 & DNS Encoding Utilities (QS-Tunnel Compatible)
# ---------------------------------------------------------------------------

BASE32_ALPHABET = b"abcdefghijklmnopqrstuvwxyz234567"
BASE32_LOOKUP = {c: i for i, c in enumerate(BASE32_ALPHABET)}

def b32encode_nopad_lower(data: bytes) -> bytes:
    """Encode binary data to lowercase unpadded Base32."""
    encoded = base64.b32encode(data).lower().rstrip(b"=")
    return encoded

def b32decode_nopad(data: bytes) -> bytes:
    """Decode unpadded or padded lowercase Base32."""
    pad_len = (8 - (len(data) % 8)) % 8
    padded = data.upper() + (b"=" * pad_len)
    return base64.b32decode(padded)

def number_to_base32_lower(num: int, width: int) -> bytes:
    """Converts an integer to a fixed-width base32 byte string."""
    res = bytearray(width)
    for i in range(width - 1, -1, -1):
        res[i] = BASE32_ALPHABET[num & 31]
        num >>= 5
    return bytes(res)

def base32_to_number(data: bytes) -> int:
    """Converts a base32 byte string to an integer."""
    res = 0
    for b in data:
        res = (res << 5) | BASE32_LOOKUP.get(b, 0)
    return res

def insert_dots(data: bytes, max_sub_len: int = 63) -> bytes:
    """Splits data into DNS labels separated by dots (max 63 chars per label)."""
    parts = []
    for i in range(0, len(data), max_sub_len):
        parts.append(data[i:i + max_sub_len])
    return b".".join(parts)

def encode_qname(domain: bytes) -> bytes:
    """Encodes a domain name into DNS wire format (e.g. 3www7example3com0)."""
    parts = domain.strip(b".").split(b".")
    out = bytearray()
    for p in parts:
        out.append(len(p))
        out.extend(p)
    out.append(0)
    return bytes(out)

def build_dns_query(qname_wire: bytes, qtype: int = 1, txid: Optional[int] = None) -> bytes:
    """Builds a standard DNS wire-format query (UDP port 53)."""
    if txid is None:
        txid = random.randint(0, 0xFFFF)
    flags = 0x0100  # Standard query with recursion desired (RD=1)
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack(">HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    qclass = 1  # IN (Internet)
    trailer = struct.pack(">HH", qtype, qclass)
    return header + qname_wire + trailer

# ---------------------------------------------------------------------------
# Out-of-Order Data Assembly Handler (QS-Tunnel Compatible)
# ---------------------------------------------------------------------------

class DataAssemblyHandler:
    """Reassembles chunked, out-of-order packets with timeout-based eviction."""

    def __init__(self, offsets_size: int = 1024, assemble_timeout: float = 12.0):
        self.offsets_size = offsets_size
        self.assemble_timeout = assemble_timeout
        self.lock = asyncio.Lock()
        self.mpp_list: List[Any] = [None] * offsets_size
        self.active_keys: Dict[int, float] = {}

    async def add_fragment(
        self, key: int, fragment_part: int, last_fragment: bool, data: bytes
    ) -> Optional[bytes]:
        """Adds a packet fragment. Returns complete assembled bytes when finished."""
        now = time.monotonic()
        async with self.lock:
            # Clean expired keys
            expired = [k for k, t in self.active_keys.items() if (now - t) > self.assemble_timeout]
            for exp_k in expired:
                self.mpp_list[exp_k] = None
                self.active_keys.pop(exp_k, None)

            key %= self.offsets_size
            mpp = self.mpp_list[key]

            # Fast path: single-fragment packet
            if mpp is None and last_fragment and fragment_part == 0:
                self.mpp_list[key] = True
                self.active_keys[key] = now
                return data

            if mpp is None:
                # Initialize new assembly container
                # [chunks... (up to 64), received_count, highest_index_plus_1, seen_last]
                chunks: List[Optional[bytes]] = [None] * 64
                chunks[fragment_part] = data
                mpp = {
                    "chunks": chunks,
                    "rec_count": 1,
                    "max_index": fragment_part + 1,
                    "seen_last": last_fragment,
                }
                self.mpp_list[key] = mpp
                self.active_keys[key] = now
                return None

            if isinstance(mpp, bool):
                return None

            # Add to existing container
            if mpp["chunks"][fragment_part] is not None:
                return None  # duplicate

            mpp["chunks"][fragment_part] = data
            mpp["rec_count"] += 1
            if (fragment_part + 1) > mpp["max_index"]:
                mpp["max_index"] = fragment_part + 1
            if last_fragment:
                mpp["seen_last"] = True

            # Check if all fragments have arrived
            if mpp["seen_last"] and mpp["rec_count"] == mpp["max_index"]:
                complete_data = b"".join(mpp["chunks"][:mpp["rec_count"]])
                self.mpp_list[key] = True
                return complete_data

            return None

# ---------------------------------------------------------------------------
# L3/L4 Checksum & Raw Packet Builders (ParsaKSH & Kernel Native)
# ---------------------------------------------------------------------------

def calculate_checksum(data: bytes) -> int:
    """Calculates RFC 1071 Internet Checksum using fast array memoryview summing."""
    if len(data) % 2 == 1:
        data = data + b"\x00"
    arr = array.array("H", data)
    s = sum(arr)
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    if sys.byteorder == "little":
        return socket.htons((~s) & 0xFFFF)
    return (~s) & 0xFFFF

def build_ipv4_header(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload_len: int,
    identification: int = 54321,
    ttl: int = 64,
    df: bool = True,
) -> bytes:
    """Constructs a 20-byte standard IPv4 header."""
    version_ihl = (4 << 4) | 5
    dscp_ecn = 0
    total_length = 20 + payload_len
    flags_fragment = 0x4000 if df else 0
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    header_pre = struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_bytes,
        dst_bytes,
    )
    checksum = calculate_checksum(header_pre)
    return struct.pack(
        ">BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        src_bytes,
        dst_bytes,
    )

def build_raw_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    ttl: int = 64,
    bad_checksum: bool = False,
) -> bytes:
    """Constructs a raw IPv4 + UDP packet with manual checksum calculation."""
    udp_len = 8 + len(payload)
    pseudo_hdr = struct.pack(
        ">4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_UDP,
        udp_len,
    )
    udp_pre = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    csum = calculate_checksum(pseudo_hdr + udp_pre)
    if bad_checksum:
        csum ^= 0xFFFF
    if csum == 0:
        csum = 0xFFFF
    udp_header = struct.pack(">HHHH", src_port, dst_port, udp_len, csum)
    ip_header = build_ipv4_header(src_ip, dst_ip, socket.IPPROTO_UDP, len(udp_header) + len(payload), ttl=ttl)
    return ip_header + udp_header + payload

def build_raw_tcp_syn_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int = 1,
    payload: bytes = b"",
    ttl: int = 64,
    bad_checksum: bool = False,
) -> bytes:
    """Constructs a raw IPv4 + TCP SYN packet (ParsaKSH 1-to-1 matching)."""
    tcp_len = 20 + len(payload)
    pseudo_hdr = struct.pack(
        ">4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_len,
    )
    # TCP Header: Source Port, Dest Port, Seq, Ack (0), Data Offset (5 << 4 = 0x50), Flags (SYN = 0x02), Window (64240), Checksum (0), Urgent (0)
    data_offset_flags = (5 << 12) | 0x0002  # SYN flag
    tcp_pre = struct.pack(
        ">HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        data_offset_flags,
        64240,
        0,
        0,
    ) + payload

    csum = calculate_checksum(pseudo_hdr + tcp_pre)
    if bad_checksum:
        csum ^= 0xFFFF
    if csum == 0:
        csum = 0xFFFF

    tcp_header = struct.pack(
        ">HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        data_offset_flags,
        64240,
        csum,
        0,
    )
    ip_header = build_ipv4_header(src_ip, dst_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload), ttl=ttl)
    return ip_header + tcp_header + payload

def build_raw_icmp_echo_packet(
    src_ip: str,
    dst_ip: str,
    payload: bytes,
    ident: int = 1234,
    seq: int = 1,
    is_reply: bool = False,
    ttl: int = 64,
) -> bytes:
    """Constructs an ICMP Echo Request/Reply packet with payload (ParsaKSH 1-to-1)."""
    icmp_type = 0 if is_reply else 8  # 8 = Echo Request, 0 = Echo Reply
    icmp_code = 0
    icmp_pre = struct.pack(">BBHHH", icmp_type, icmp_code, 0, ident, seq) + payload
    csum = calculate_checksum(icmp_pre)
    icmp_header = struct.pack(">BBHHH", icmp_type, icmp_code, csum, ident, seq)
    ip_header = build_ipv4_header(src_ip, dst_ip, socket.IPPROTO_ICMP, len(icmp_header) + len(payload), ttl=ttl)
    return ip_header + icmp_header + payload

# ---------------------------------------------------------------------------
# Round-Robin Rotating IP Pool (ParsaKSH Matching)
# ---------------------------------------------------------------------------

class RotatingIPPool:
    """Thread-safe round-robin source IP rotator."""

    def __init__(self, ips: List[str]):
        clean_ips = [ip.strip() for ip in ips if ip.strip()]
        if not clean_ips:
            clean_ips = ["127.0.0.1"]
        self._ips = clean_ips
        self._index = 0
        self._lock = threading.Lock()

    def next_ip(self) -> str:
        with self._lock:
            ip = self._ips[self._index % len(self._ips)]
            self._index += 1
            return ip

    @property
    def count(self) -> int:
        return len(self._ips)

# ---------------------------------------------------------------------------
# HYPERION-X Proprietary Masterpiece Innovations
# ---------------------------------------------------------------------------

KNOCK_FLAG_REGISTRATION = 0x01
KNOCK_FLAG_FASTPATH = 0x02

class KnockResult(tuple):
    """Tuple subclass returning (valid, payload) while providing .session_id."""
    def __new__(cls, valid: bool, payload: bytes, session_id: Optional[int] = None):
        obj = super().__new__(cls, (valid, payload))
        obj.session_id = session_id
        return obj

class HyperionKnockVerifier:
    """Dark Host Verification: Validates HMAC-SHA256 authenticated packet knock with O(1) session fast-path."""

    def __init__(self, secret_key: bytes, session_ttl: float = 60.0):
        self.secret_key = secret_key
        self.session_ttl = session_ttl
        self._active_sessions: Dict[int, float] = {}  # session_id -> expires_at
        self._lock = threading.Lock()

    def stamp_knock(
        self, payload: bytes, session_id: Optional[int] = None, force_registration: bool = False
    ) -> bytes:
        """Pushes knock header into packet. Uses 17-byte HMAC registration on first packet or 5-byte session fast-path."""
        if force_registration or session_id is None:
            # Registration packet: [FLAG 0x01] + [NONCE 8B] + [HMAC 8B] + [PAYLOAD]
            timestamp = int(time.time()) // 30
            sess = session_id if session_id is not None else (secrets.randbelow(0x7FFFFFFF) + 1)
            nonce = struct.pack(">II", timestamp, sess)
            mac = hmac.new(self.secret_key, nonce + payload[:32], hashlib.sha256).digest()[:8]
            return bytes([KNOCK_FLAG_REGISTRATION]) + nonce + mac + payload
        else:
            # Fast-path packet: [FLAG 0x02] + [SESSION_ID 4B] + [PAYLOAD]
            # Zero HMAC hashing overhead under GIL!
            return bytes([KNOCK_FLAG_FASTPATH]) + struct.pack(">I", session_id) + payload

    def verify_knock(self, stamped_payload: bytes) -> KnockResult:
        """Verifies the knock stamp. Supports full HMAC registration and sub-microsecond O(1) fast-path."""
        if not stamped_payload:
            return KnockResult(False, b"", None)

        flag = stamped_payload[0]
        now = time.monotonic()

        if flag == KNOCK_FLAG_REGISTRATION:
            if len(stamped_payload) < 17:
                return KnockResult(False, b"", None)
            nonce = stamped_payload[1:9]
            mac = stamped_payload[9:17]
            real_payload = stamped_payload[17:]

            timestamp, session_id = struct.unpack(">II", nonce)
            current_ts = int(time.time()) // 30
            if abs(current_ts - timestamp) > 1:
                return KnockResult(False, b"", None)

            expected_mac = hmac.new(self.secret_key, nonce + real_payload[:32], hashlib.sha256).digest()[:8]
            if hmac.compare_digest(mac, expected_mac):
                with self._lock:
                    self._active_sessions[session_id] = now + self.session_ttl
                return KnockResult(True, real_payload, session_id)
            return KnockResult(False, b"", None)

        elif flag == KNOCK_FLAG_FASTPATH:
            if len(stamped_payload) < 5:
                return KnockResult(False, b"", None)
            session_id = struct.unpack(">I", stamped_payload[1:5])[0]
            real_payload = stamped_payload[5:]

            with self._lock:
                expiry = self._active_sessions.get(session_id)
                if expiry is not None and now <= expiry:
                    # Extend session TTL on active transmission
                    self._active_sessions[session_id] = now + self.session_ttl
                    return KnockResult(True, real_payload, session_id)
                else:
                    self._active_sessions.pop(session_id, None)
                    return KnockResult(False, b"", None)

        # Legacy 16-byte unflagged packet compatibility
        elif len(stamped_payload) >= 16:
            nonce = stamped_payload[:8]
            mac = stamped_payload[8:16]
            real_payload = stamped_payload[16:]
            timestamp = struct.unpack(">I", nonce[:4])[0]
            current_ts = int(time.time()) // 30
            if abs(current_ts - timestamp) <= 1:
                expected_mac = hmac.new(self.secret_key, nonce + real_payload[:32], hashlib.sha256).digest()[:8]
                if hmac.compare_digest(mac, expected_mac):
                    return KnockResult(True, real_payload, None)

        return KnockResult(False, b"", None)

def apply_polymorphic_jitter(
    data: bytes, min_pad: int = 8, max_pad: int = 48, max_mtu: int = 1360
) -> bytes:
    """Clamped Gaussian padding: ONLY applied to small/handshake packets (< 600 bytes).
    Large/bulk data packets pass through unpadded to completely avoid IP fragmentation.
    """
    if len(data) < 600:
        safe_max_pad = min(max_pad, max_mtu - len(data) - 2)
        if safe_max_pad > 0:
            pad_len = min(max(0, int(random.gauss(32, 16))), safe_max_pad)
            if pad_len < min_pad and safe_max_pad >= min_pad:
                pad_len = random.randint(min_pad, safe_max_pad)
            if pad_len > 0:
                pad_bytes = secrets.token_bytes(pad_len)
                return bytes([0xFD, pad_len]) + pad_bytes + data
    return data

def strip_polymorphic_jitter(data: bytes) -> bytes:
    """Strips the polymorphic jitter padding if present."""
    if len(data) >= 2 and data[0] == 0xFD:
        pad_len = data[1]
        if len(data) >= 2 + pad_len:
            return data[2 + pad_len:]
    return data

# ---------------------------------------------------------------------------
# High-Level Spoof & Evasion Controller
# ---------------------------------------------------------------------------

@dataclass
class SpoofRuntimeConfig:
    pool_name: str
    transport: str
    role: str  # "iran" or "kharej"
    listen_addr: str
    remote_ip: str
    remote_port: int
    spoof_ips: List[str] = field(default_factory=lambda: ["127.0.0.1"])
    spoof_port: int = 443
    peer_spoof_ip: str = "127.0.0.1"
    recv_port: int = 5001
    fake_sni: str = "www.shaparak.ir"
    auto_ttl_delta: int = 3
    dns_resolvers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1", "10.202.10.202"])
    send_domains: List[str] = field(default_factory=lambda: ["cloud.cloudflare.com", "cdn.samt.ir"])
    mode: str = "1-1"  # "1-1" or "n-1"
    knock_key: str = "hyperion-x-master-canary-key"
    direct_authoritative: bool = True

class SpoofController:
    """Unified runtime controller managing all spoof transport mechanics."""

    def __init__(self, config: SpoofRuntimeConfig):
        self.config = config
        self.ip_pool = RotatingIPPool(config.spoof_ips)
        self.dns_pool = RotatingIPPool(config.dns_resolvers)
        self.knock_verifier = HyperionKnockVerifier(config.knock_key.encode())
        self.data_handler = DataAssemblyHandler()
        self._running = False
        self._seq = 1
        self._session_id: Optional[int] = None

    def create_raw_sender_socket(self) -> socket.socket:
        """Creates a Linux Raw IP socket with IP_HDRINCL."""
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s

    def dispatch_packet(
        self, payload: bytes, dst_ip: Optional[str] = None, dst_port: Optional[int] = None
    ) -> bytes:
        """Formats and wraps payload according to the active transport mode."""
        target_ip = dst_ip or self.config.remote_ip
        target_port = dst_port or self.config.remote_port
        src_ip = self.ip_pool.next_ip()
        src_port = self.config.spoof_port

        transport = self.config.transport

        if transport in ("spoof-tcp-syn", "tcp-state-desync"):
            pkt = build_raw_tcp_syn_packet(
                src_ip, target_ip, src_port, target_port, seq=self._seq, payload=payload
            )
            self._seq = (self._seq + 1) & 0xFFFFFFFF
            return pkt

        elif transport in ("spoof-udp-raw", "udp-raw-spoof"):
            return build_raw_udp_packet(src_ip, target_ip, src_port, target_port, payload)

        elif transport == "spoof-icmp":
            return build_raw_icmp_echo_packet(src_ip, target_ip, payload, seq=self._seq)

        elif transport == "hyperion-x":
            # 1. Apply Dark Host HMAC Knock stamp (auto session fastpath after registration)
            knocked = self.knock_verifier.stamp_knock(payload, session_id=self._session_id)
            if self._session_id is None:
                res = self.knock_verifier.verify_knock(knocked)
                self._session_id = res.session_id
            # 2. Apply MTU-Safe Polymorphic Gaussian Jitter (clamped for packets < 600 bytes)
            jittered = apply_polymorphic_jitter(knocked, max_mtu=1360)
            # 3. Encapsulate into Raw UDP packet with Rotating Whitelist IP
            return build_raw_udp_packet(src_ip, target_ip, src_port, target_port, jittered)

        else:
            # Default to Raw UDP
            return build_raw_udp_packet(src_ip, target_ip, src_port, target_port, payload)

    def get_qs_target_resolver(self, direct_authoritative: Optional[bool] = None) -> Tuple[str, int]:
        """Returns the DNS query target resolver.
        By default (direct_authoritative=True), sends UDP:53 directly to foreign server,
        bypassing public recursive DNS (8.8.8.8) QPS rate limits.
        When direct_authoritative=False (e.g. national intranet isolation), falls back to
        round-robin rotation across recursive dns_resolvers.
        """
        use_direct = self.config.direct_authoritative if direct_authoritative is None else direct_authoritative
        if use_direct:
            return (self.config.remote_ip, 53)
        return (self.dns_pool.next_ip(), 53)

    def encode_qs_dns_queries(
        self, data: bytes, client_id: bytes = b"", send_domain: str = "cdn.shaparak.ir"
    ) -> List[bytes]:
        """Encodes payload into DNS Query wires using Base32 chunking (QS-Tunnel 1-to-1)."""
        b32_data = b32encode_nopad_lower(data)
        max_chunk = 45  # fits within 63-char DNS label
        chunks = [b32_data[i:i + max_chunk] for i in range(0, len(b32_data), max_chunk)]
        queries = []

        total = len(chunks)
        data_offset = number_to_base32_lower(self._seq & 0x7FFF, 3)
        self._seq = (self._seq + 1) & 0x7FFF

        for idx, chunk in enumerate(chunks):
            is_last = (idx == total - 1)
            flag = b"1" if is_last else b"0"
            frag_idx = number_to_base32_lower(idx, 1)
            subdomain = f"{client_id.decode('ascii', 'ignore')}{data_offset.decode()}{frag_idx.decode()}{flag.decode()}{chunk.decode()}.{send_domain}"
            wire_qname = encode_qname(subdomain.encode())
            query_pkt = build_dns_query(wire_qname, qtype=1)
            queries.append(query_pkt)

        return queries
