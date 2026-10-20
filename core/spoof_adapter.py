"""Managed packet-profile adapter and schemas for unfinished raw carriers.

Implemented packet profiles use pinned NFQWS2 with mTLS, owned queue rules,
actual data challenges and observed packet changes. Raw/DNS hybrid builders
are not a deployed tunnel runtime and cannot establish evasion success.
"""
from __future__ import annotations

import asyncio
import copy
import ctypes
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import socket
import struct
import threading
import time
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Final, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.capabilities import get_capability
from core.ssh_client import SSHManager
from core.storage import atomic_update, delete_pool, get_pools, load_data, save_pool
from core.transport_change import connect
from core.validation import (
    shquote,
    validate_pool_name,
    validate_port,
    validate_ports,
)

logger = logging.getLogger("vxlb.spoof_adapter")

ENGINE_ID = "spoof"

SPOOF_TRANSPORTS = {
    "fake-sni",
    "split-tls",
    "hop-ttl-injection",
    "tcp-state-desync",
    "l3-ip-spoof",
    "l7-header-mutation",
    "udp-raw-spoof",
    "dns-spoof",
    "spoof",
    "spoof-tcp-syn",
    "spoof-udp-raw",
    "spoof-icmp",
    "qs-dns-hybrid",
    "hyperion-x",
}

# ---------------------------------------------------------------------------
# 1. Composable Pydantic Schemas
# ---------------------------------------------------------------------------

class DesyncEngineType(str, Enum):
    NFQWS_DESYNC = "nfqws_desync"
    CIADPI_SOCKS = "ciadpi_socks"
    L3_RAW_SPOOF = "l3_raw_spoof"
    PARSAKSH_SPOOF = "parsaksh_spoof"
    QS_DNS_HYBRID = "qs_dns_hybrid"
    HYPERION_X = "hyperion_x"

class FoolingMode(str, Enum):
    MD5SIG = "md5sig"
    BADSUM = "badsum"
    BADSEQ = "badseq"
    TTL = "ttl"
    AUTOTTL = "autottl"

class TTLStrategyConfig(BaseModel):
    mode: Literal["static", "autottl"] = "autottl"
    static_ttl: int = Field(default=6, ge=1, le=64)
    auto_ttl_delta: int = Field(default=3, ge=1, le=15)
    min_ttl: int = Field(default=3, ge=1, le=32)
    max_ttl: int = Field(default=14, ge=3, le=64)

class FragmentationConfig(BaseModel):
    split_modes: List[str] = Field(default_factory=lambda: ["fake", "multisplit"])
    split_offsets: List[str] = Field(default_factory=lambda: ["2", "sniext+1", "midsld"])
    tlsrec_split: bool = True
    tlsrec_pos: str = "sniext+4"

class L3RawSpoofConfig(BaseModel):
    enabled: bool = False
    spoof_src_ip: str = "2.188.21.10"
    spoof_ips: List[str] = Field(default_factory=lambda: ["2.188.21.10"])
    peer_spoof_ip: str = "104.16.132.229"
    local_listen: str = "127.0.0.1:5330"
    remote_port: int = 8090
    recv_port: int = 5001

class QSTunnelConfig(BaseModel):
    enabled: bool = False
    mode: Literal["1-1", "n-1"] = "1-1"
    dns_resolvers: List[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1", "10.202.10.202"])
    send_domains: List[str] = Field(default_factory=lambda: ["cdn.shaparak.ir", "cloud.cloudflare.com"])
    fake_send_ip: str = "4.2.2.4"
    fake_send_port: int = 443
    info_encryption_pass: str = "vxlb-qs-secret"
    max_domain_len: int = 253
    max_sub_len: int = 63

class HyperionConfig(BaseModel):
    enabled: bool = False
    tri_vector_enabled: bool = True
    dark_knock_key: str = "hyperion-x-master-canary-key"
    gaussian_jitter: bool = True
    whitelist_ips: List[str] = Field(default_factory=lambda: ["2.188.21.10", "185.143.232.10", "194.225.0.10"])

class SpoofProfile(BaseModel):
    profile_id: str
    transport_mode: str = "fake-sni"
    engine: DesyncEngineType = DesyncEngineType.NFQWS_DESYNC
    fwmark: int = 0x100
    queue_start: int = 100
    worker_count: int = Field(default=4, ge=1, le=32)
    first_n_packets: int = Field(default=6, ge=2, le=20)
    fake_sni: str = "www.shaparak.ir"
    fake_repeats: int = Field(default=2, ge=1, le=10)
    ttl: TTLStrategyConfig = Field(default_factory=TTLStrategyConfig)
    fooling: List[FoolingMode] = Field(
        default_factory=lambda: [FoolingMode.MD5SIG, FoolingMode.BADSUM]
    )
    fragmentation: FragmentationConfig = Field(default_factory=FragmentationConfig)
    l3_spoof: L3RawSpoofConfig = Field(default_factory=L3RawSpoofConfig)
    qs_tunnel: QSTunnelConfig = Field(default_factory=QSTunnelConfig)
    hyperion: HyperionConfig = Field(default_factory=HyperionConfig)

class TelemetryVerdict(str, Enum):
    DATA_VERIFIED = "DATA_VERIFIED"
    HEALTHY_EVADED = "HEALTHY_EVADED"
    UNVERIFIED = "UNVERIFIED"
    DPI_ACTIVE_RST_INJECTED = "DPI_ACTIVE_RST_INJECTED"
    DPI_SILENT_BLACKHOLE = "DPI_SILENT_BLACKHOLE"
    L3_ROUTING_UNREACHABLE = "L3_ROUTING_UNREACHABLE"
    PAYLOAD_CORRUPTED = "PAYLOAD_CORRUPTED"

class TelemetryReport(BaseModel):
    verdict: TelemetryVerdict
    handshake_rtt_ms: float
    synack_ttl: Optional[int]
    estimated_hops: Optional[int]
    tcpi_retransmits: int
    tcpi_bytes_acked: int
    rst_anomaly_detected: bool
    detail: str

# ---------------------------------------------------------------------------
# 2. Kernel struct tcp_info bindings for telemetry
# ---------------------------------------------------------------------------

SOL_TCP: Final[int] = 6
TCP_INFO: Final[int] = 11
SO_MARK: Final[int] = 36

class LinuxTcpInfo(ctypes.Structure):
    _fields_ = [
        ("tcpi_state", ctypes.c_uint8),
        ("tcpi_ca_state", ctypes.c_uint8),
        ("tcpi_retransmits", ctypes.c_uint8),
        ("tcpi_probes", ctypes.c_uint8),
        ("tcpi_backoff", ctypes.c_uint8),
        ("tcpi_options", ctypes.c_uint8),
        ("tcpi_snd_wscale_rcv_wscale", ctypes.c_uint8),
        ("tcpi_delivery_rate_app_limited", ctypes.c_uint8),
        ("tcpi_rto", ctypes.c_uint32),
        ("tcpi_ato", ctypes.c_uint32),
        ("tcpi_snd_mss", ctypes.c_uint32),
        ("tcpi_rcv_mss", ctypes.c_uint32),
        ("tcpi_unacked", ctypes.c_uint32),
        ("tcpi_sacked", ctypes.c_uint32),
        ("tcpi_lost", ctypes.c_uint32),
        ("tcpi_retrans", ctypes.c_uint32),
        ("tcpi_fackets", ctypes.c_uint32),
        ("tcpi_last_data_sent", ctypes.c_uint32),
        ("tcpi_last_ack_sent", ctypes.c_uint32),
        ("tcpi_last_data_recv", ctypes.c_uint32),
        ("tcpi_last_ack_recv", ctypes.c_uint32),
        ("tcpi_pmtu", ctypes.c_uint32),
        ("tcpi_rcv_ssthresh", ctypes.c_uint32),
        ("tcpi_rtt", ctypes.c_uint32),
        ("tcpi_rttvar", ctypes.c_uint32),
        ("tcpi_snd_ssthresh", ctypes.c_uint32),
        ("tcpi_snd_cwnd", ctypes.c_uint32),
        ("tcpi_advmss", ctypes.c_uint32),
        ("tcpi_reordering", ctypes.c_uint32),
        ("tcpi_rcv_rtt", ctypes.c_uint32),
        ("tcpi_rcv_space", ctypes.c_uint32),
        ("tcpi_total_retrans", ctypes.c_uint32),
        ("tcpi_pacing_rate", ctypes.c_uint64),
        ("tcpi_max_pacing_rate", ctypes.c_uint64),
        ("tcpi_bytes_acked", ctypes.c_uint64),
        ("tcpi_bytes_received", ctypes.c_uint64),
        ("tcpi_segs_out", ctypes.c_uint32),
        ("tcpi_segs_in", ctypes.c_uint32),
        ("tcpi_notsent_bytes", ctypes.c_uint32),
        ("tcpi_min_rtt", ctypes.c_uint32),
        ("tcpi_data_segs_in", ctypes.c_uint32),
        ("tcpi_data_segs_out", ctypes.c_uint32),
        ("tcpi_delivery_rate", ctypes.c_uint64),
        ("tcpi_busy_time", ctypes.c_uint64),
        ("tcpi_rwnd_limited", ctypes.c_uint64),
        ("tcpi_sndbuf_limited", ctypes.c_uint64),
        ("tcpi_delivered", ctypes.c_uint32),
        ("tcpi_delivered_ce", ctypes.c_uint32),
        ("tcpi_bytes_sent", ctypes.c_uint64),
    ]

def get_socket_tcp_info(sock: socket.socket) -> Optional[LinuxTcpInfo]:
    try:
        raw = sock.getsockopt(SOL_TCP, TCP_INFO, ctypes.sizeof(LinuxTcpInfo))
        return LinuxTcpInfo.from_buffer_copy(raw)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# 3. Dedicated Adapter Implementation
# ---------------------------------------------------------------------------

class SpoofDedicatedAdapter(BaseTunnelAdapter):
    """Owned packet runtime; service state alone never proves data or evasion."""
    def __init__(self):super().__init__(ENGINE_ID)

    def install(self,ssh,role,config):
        from core import spoof_transport as runtime
        if config.get('transport') not in runtime.MODES:return False,'Managed packet profile required'
        try:runtime.install(ssh);return True,'Pinned packet runtime prerequisites verified'
        except Exception as error:return False,str(error)

    def configure(self,iran_node,kharej_server,pool_config):
        from core import spoof_transport as runtime
        return runtime.plan(iran_node,{**pool_config,'kharej_server':kharej_server})

    def start(self,ssh,identifier,**kwargs):
        from core import spoof_transport as runtime
        node,pool,role=kwargs.get('node'),kwargs.get('pool'),kwargs.get('role')
        if not node or not pool or role not in ['client','server'] or identifier!=node.get('node_name'):
            return False,'Owned node, pool and endpoint role are required'
        try:
            configuration=runtime.plan(node,pool);runtime.install(ssh)
            runtime.deploy(ssh,configuration[role+'_files'],configuration[role+'_services'])
            return True,'Owned endpoint services started; data verification is separate'
        except Exception as error:return False,str(error)

    def stop(self,ssh,identifier,**kwargs):
        from core import spoof_transport as runtime
        node,pool,role=kwargs.get('node'),kwargs.get('pool'),kwargs.get('role')
        if not node or not pool or role not in ['client','server'] or identifier!=node.get('node_name'):
            return False,'Owned node, pool and endpoint role are required'
        try:
            configuration=runtime.plan(node,pool)
            for service in reversed(configuration[role+'_services']):
                runtime.execute(ssh,'systemctl stop '+shlex.quote(service))
                runtime.execute(ssh,'if systemctl is-active --quiet '+shlex.quote(service)+'; then exit 1; fi')
            if role=='client':
                directory=configuration['queue_directory']
                runtime.execute(ssh,'python3 '+shlex.quote(directory+'/queue-agent.py')+' remove '+shlex.quote(directory+'/queue.json'))
            return True,'Owned endpoint stopped; saved configuration retained'
        except Exception as error:return False,str(error)

    def status(self,ssh,identifier):
        if not re.fullmatch(r'vxlb-(?:http|spoof)-[0-9a-f]{32}-(?:client|server|nfq|queue|records)(?:-carrier|-firewall)?\.service',str(identifier)):
            return {'status':'DOWN','details':{'path_verified':False,'error':'Owned managed service identifier required'}}
        code,out,error=ssh.execute('systemctl is-active '+shlex.quote(identifier))
        return {'status':'UP' if code==0 and out.strip()=='active' else 'DOWN','details':{'path_verified':False,'error':error}}

    def probe(self,endpoint_ir,endpoint_kh,ports=None,**kwargs):
        from core import spoof_transport as runtime
        try:
            node=kwargs.get('node')
            if not node:raise ValueError('Owned managed packet node is required')
            result=runtime.verify(endpoint_ir['ssh'],endpoint_kh['ssh'],node)
            return dict(result,verdict='DATA_VERIFIED',evasion_verified=False)
        except Exception as error:
            return dict(passed=False,latency_ms=None,error=str(error),verdict=TelemetryVerdict.UNVERIFIED.value)

    def modify(self,pool_name,updates):
        from core import spoof_transport as runtime
        if 'client_ports' in updates and set(updates)=={'client_ports'}:
            return runtime.change_ports(pool_name,updates['client_ports'])
        return False,'Only checked application-port updates are supported'

    def rollback(self,pool_name,previous_state):
        from core import spoof_transport as runtime
        if set(previous_state)=={'client_ports'}:
            return runtime.change_ports(pool_name,previous_state['client_ports'])
        return False,'Packet rollback requires the complete checked transaction'

    def clean(self,ssh,identifier,**kwargs):
        from core import spoof_transport as runtime
        node,pool,role=kwargs.get('node'),kwargs.get('pool'),kwargs.get('role')
        if not node or not pool or role not in ['client','server'] or identifier!=node.get('node_name'):
            return False,'Owned node, pool and endpoint role are required'
        try:
            configuration=runtime.plan(node,pool)
            runtime.cleanup(ssh,configuration[role+'_files'],configuration[role+'_services'])
            return True,'Owned endpoint cleanup verified'
        except Exception as error:return False,str(error)


def create(pool_name,kharej_server,iran_servers,client_ports,transport='fake-sni',fake_sni='www.shaparak.ir',callback=None,**kwargs):
    from core import spoof_transport as runtime
    try:validate_pool_name(pool_name);validate_ports(client_ports)
    except ValueError as error:return False,str(error),{}
    if transport not in runtime.MODES:
        return False,'این پروفایل هنوز runtime انتقال دوطرفه و آزمون داده ندارد',{}
    return runtime.create(pool_name,kharej_server,iran_servers,client_ports,transport=transport,fake_sni=fake_sni,callback=callback,**kwargs)


def clean(ssh,pool,node,is_iran=True):
    return SpoofDedicatedAdapter().clean(ssh,node.get('node_name'),node=node,pool=pool,role='client' if is_iran else 'server')


register_adapter(SpoofDedicatedAdapter())
