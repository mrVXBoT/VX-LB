import http.server
import socketserver
import json
import gzip
import os
import sys
import time
import secrets
import hashlib
import hmac
import urllib.parse
from typing import Optional, Dict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.storage import (
    load_data, atomic_update, DATA_DIR, LOG_FILE, get_pools, get_servers,
    add_server, delete_server, update_server_telemetry,
    get_cf_profiles, get_cf_profile, cf_profile_public, save_cf_profile,
    update_cf_profile, delete_cf_profile, set_cf_profile_zones,
    cf_profile_pools, cf_audit, migrate_legacy_cf_profiles
)
from core.tunnel import SUPPORTED_TRANSPORTS
from core.watchdog import TelemetryWatchdog
from core.cloudflare import CloudflareManager
from core.dns_routing import routing_lock, route_key, effective_config, snapshot_matches
from core.dns_scheduler import pool_rotation_status, save_global_schedule, save_pool_schedule, rotate_pool
from core.transport_change import ACTIVE as TRANSPORT_ACTIVE, mutation_lock, busy as transport_busy, start_change, run_change, recover_changes, force_clear_change
from core.load_balancer import LoadBalancerManager
from core.ssh_client import SSHManager
from core.node_addition import start as start_node_addition, recover as recover_node_additions
from core.node_removal import start as start_node_removal, recover as recover_node_removals
from core.validation import validate_pool_name, validate_port, validate_ports, validate_transport, shquote, shquote
from core.domain_manager import get_dashboard_domain_config, apply_nginx_config, issue_letsencrypt_cert

WEB_DIR = os.path.join(BASE_DIR, "web")
AUTH_TOKENS: Dict[str, float] = {}  # token -> expiry_timestamp

# --- Security headers applied to every response (JSON + static + preflight) ---
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self'"
    ),
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
}

# --- Security hardening: password hashing, login rate limiting ---

_PBKDF2_ITERATIONS = 200_000
_LOGIN_WINDOW_S = 300
_LOGIN_MAX_ATTEMPTS = 10


def _hash_password(password: str) -> str:
    """Hash a dashboard password with PBKDF2-HMAC-SHA256 (stdlib, no new deps)."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Constant-time password check. Transparently migrates legacy plaintext."""
    if not stored or not password:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iters, salt, hexdk = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), int(iters))
            return hmac.compare_digest(dk.hex(), hexdk)
        except Exception:
            return False
    # Legacy plaintext password: compare, then upgrade to a hash on success.
    if hmac.compare_digest(password, stored):
        try:
            new_hash = _hash_password(password)

            def _migrate(d: dict):
                if d.get("web_password") == stored:
                    d["web_password"] = new_hash

            atomic_update(_migrate)
        except Exception:
            pass
        return True
    return False


def _login_attempts(client_ip: str) -> list:
    """Return timestamps of recent failed logins for an IP (persisted)."""
    try:
        return load_data().get("login_failures", {}).get(client_ip, []) or []
    except Exception:
        return []


def _login_allowed(client_ip: str) -> bool:
    now = time.time()
    records = _login_attempts(client_ip)
    fresh = [t for t in records if now - t < _LOGIN_WINDOW_S]
    if len(fresh) != len(records):
        def _up(d: dict):
            d.setdefault("login_failures", {})[client_ip] = fresh
        try:
            atomic_update(_up)
        except Exception:
            pass
    return len(fresh) < _LOGIN_MAX_ATTEMPTS


def _record_failed_login(client_ip: str) -> None:
    def _up(d: dict):
        lf = d.setdefault("login_failures", {})
        lst = lf.get(client_ip, []) or []
        lst.append(time.time())
        lf[client_ip] = lst[-200:]  # bound per-IP memory
    try:
        atomic_update(_up)
    except Exception:
        pass

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

def public_node_security(node):
    engine=node.get('engine')
    if engine=='spoof' and node.get('spoof') and node.get('http_connect'):return 'tls'
    for engines,key in [(('gre','gre_ipv4'),'gre'),(('geneve','geneve_ipsec'),'geneve'),(('vxlan_ipsec',),'vxsec')]:
        if engine in engines:
            config=(node.get(key,{}).get('configs') or [{}])[0]
            return 'ipsec' if config.get('security',{}).get('mode')=='ipsec' else 'unencrypted'
    return {'wireguard':'wireguard','tun':'noise','http':'tls','https':'tls',
            'vxlan':'unencrypted','gre6':'unencrypted','ip6ip6':'unencrypted','dc6':'unencrypted'}.get(engine)


class LDWebRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Quiet standard logging to avoid spamming terminal
        pass

    def _cors_headers(self):
        """Echo the request Origin only when it matches this server's own Host.

        Auth is cookie-based (SameSite=Lax), so cross-origin browsers never
        attach credentials; we never issue a wildcard origin.
        """
        origin = (self.headers.get("Origin") or "").strip()
        host = (self.headers.get("Host") or "").strip()
        if origin and host and origin in (f"http://{host}", f"https://{host}"):
            return {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        return {}

    def _send_json(self, data: dict, status: int = 200, headers: Optional[dict] = None):
        content = json.dumps(data, ensure_ascii=False).encode("utf-8")
        accept_encoding = self.headers.get("Accept-Encoding", "")
        use_gzip = "gzip" in accept_encoding and len(content) > 500
        if use_gzip:
            content = gzip.compress(content, compresslevel=6)

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in self._cors_headers().items():
            self.send_header(k, v)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def _send_file(self, file_path: str, content_type: str):
        if not os.path.exists(file_path):
            self.send_error(404, "File Not Found")
            return

        stat = os.stat(file_path)
        etag = f'"{int(stat.st_mtime)}-{stat.st_size}"'
        if_none_match = self.headers.get("If-None-Match")

        # Static assets: font, logo, css, js can be safely cached
        is_immutable = any(file_path.endswith(ext) for ext in [".css", ".js", ".png", ".woff2", ".ico"])
        cache_control = "public, max-age=86400" if is_immutable else "no-cache"

        if if_none_match and if_none_match.strip() == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", cache_control)
            for k, v in _SECURITY_HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            return

        with open(file_path, "rb") as f:
            content = f.read()

        accept_encoding = self.headers.get("Accept-Encoding", "")
        compressible = any(t in content_type for t in ["text/", "javascript", "json", "xml", "svg"])
        use_gzip = compressible and "gzip" in accept_encoding and len(content) > 500

        if use_gzip:
            content = gzip.compress(content, compresslevel=6)

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("ETag", etag)
        self.send_header("Cache-Control", cache_control)
        if use_gzip:
            self.send_header("Content-Encoding", "gzip")
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content)

    def _get_auth_token(self) -> Optional[str]:
        # Check Authorization Header
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        # Check Cookie
        cookie_header = self.headers.get("Cookie", "")
        for item in cookie_header.split(";"):
            item = item.strip()
            if item.startswith("ld_token="):
                return item[9:].strip()
        return None

    def _is_authenticated(self) -> bool:
        token = self._get_auth_token()
        if not token:
            return False
        expiry = AUTH_TOKENS.get(token)
        if expiry and time.time() < expiry:
            return True
        return False

    def _client_ip(self) -> str:
        """Return the client IP, honoring X-Forwarded-For only when enabled."""
        if os.environ.get("VX_LB_TRUST_PROXY") == "1":
            xff = self.headers.get("X-Forwarded-For", "").strip()
            if xff:
                return xff.split(",")[0].strip() or "unknown"
        return self.client_address[0] if self.client_address else "unknown"

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in self._cors_headers().items():
            self.send_header(k, v)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        for k, v in _SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Static assets
        if path == "/" or path == "/index.html":
            return self._send_file(os.path.join(WEB_DIR, "index.html"), "text/html; charset=utf-8")
        elif path == "/style.css":
            return self._send_file(os.path.join(WEB_DIR, "style.css"), "text/css; charset=utf-8")
        elif path == "/font.css":
            return self._send_file(os.path.join(WEB_DIR, "font.css"), "text/css; charset=utf-8")
        elif path == "/copy.fa.js":
            return self._send_file(os.path.join(WEB_DIR, "copy.fa.js"), "application/javascript; charset=utf-8")
        elif path == "/hairline.js":
            return self._send_file(os.path.join(WEB_DIR, "hairline.js"), "application/javascript; charset=utf-8")
        elif path == "/app.js":
            return self._send_file(os.path.join(WEB_DIR, "app.js"), "application/javascript; charset=utf-8")
        elif path == "/topology.html":
            return self._send_file(os.path.join(WEB_DIR, "topology.html"), "text/html; charset=utf-8")
        elif path in ("/logo.png", "/favicon.ico", "/logo-256.png", "/mark.png", "/wordmark.png", "/preview.png"):
            filename = "logo.png" if path == "/favicon.ico" else path.lstrip("/")
            return self._send_file(os.path.join(WEB_DIR, filename), "image/png")
        elif path in ("/logo.svg", "/logo-light.svg", "/mark.svg", "/mark-dark.svg", "/wordmark.svg"):
            return self._send_file(os.path.join(WEB_DIR, path.lstrip("/")), "image/svg+xml")

        # API Endpoints
        if path == "/api/status":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            
            data = load_data()
            watchdog = TelemetryWatchdog()
            from core.pool_creation import project
            pools_data = project(data)
            
            # Enrich pools with live node telemetry
            pools_resp = []
            for p_name, p_val in pools_data.items():
                cf_info = p_val.get("cloudflare") or data.get("cloudflare") or {}
                nodes_list = []
                for n in p_val.get("nodes", []):
                    ip = n["ip"]
                    telem = TelemetryWatchdog.get_node_telemetry(p_name, ip)
                    nodes_list.append({
                        "name": n.get("server_name", ip),
                        "ip": ip,
                        "tunnel_port": n.get("tunnel_port"),
                        "engine": n.get("engine", "backpack"),
                        "security": public_node_security(n),
                        "gre": {key:n.get("gre",{}).get(key) for key in ("mtu","local_private","remote_private")} if n.get("engine") in ("gre", "gre_ipv4") else None,
                        "gre6": {key:n.get("gre6",{}).get(key) for key in ("mtu","interface","local_ipv6","remote_ipv6","local_private","remote_private")} if n.get("engine") == "gre6" else None,
                        "ip6ip6": {key:n.get("ip6ip6",{}).get(key) for key in ("mtu","interface","local_ipv6","remote_ipv6","local_private","remote_private")} if n.get("engine") == "ip6ip6" else None,
                        "geneve": {key:n.get("geneve",{}).get(key) for key in ("vni","mtu","local_private","remote_private")} if n.get("engine") in ("geneve", "geneve_ipsec") else None,
                        "vxsec": {key:n.get("vxsec",{}).get(key) for key in ("vni","dst_port","mtu","local_private","remote_private")} if n.get("engine") == "vxlan_ipsec" else None,
                        "vxlan": {key:n.get("vxlan",{}).get(key) for key in ("vni","dst_port","mtu","method","method_title","iface","bridge","local_private","remote_private")} if n.get("engine") == "vxlan" else None,
                        "wireguard": {key: n.get("wireguard", {}).get(key) for key in ("interface", "tunnel_port", "mtu", "local_private", "remote_private", "iran_public_key", "kharej_public_key", "ipv4_subnet")} if n.get("engine") == "wireguard" else None,
                        "tun": {key:n.get("tun",{}).get(key) for key in ("interface","mtu","local_private","remote_private")} if n.get("engine") == "tun" else None,
                        "dc6": {key:n.get("dc6",{}).get(key) for key in ("interface","mtu","mss_clamp","carrier_type","local_private","remote_private")} if n.get("engine") == "dc6" else None,
                        "spoof": {"profile": n.get("transport") or p_val.get("transport"), "wire_verified": n.get("spoof",{}).get("wire_evidence",{}).get("passed") is True, "fake_sni": n.get("fake_sni") or (n.get("spoof") or {}).get("fake_sni") or p_val.get("fake_sni") or (p_val.get("camouflage") or {}).get("server_name"), "ttl_delta": n.get("ttl_delta") or (n.get("spoof") or {}).get("ttl_delta") or p_val.get("auto_ttl_delta")} if (n.get("engine") == "spoof" or p_val.get("engine") == "spoof") else None,
                        "slipstream": {"domain": p_val.get("domain") or (p_val.get("slipstream") or {}).get("domain"), "rate_limit": p_val.get("rate_limit") or (p_val.get("slipstream") or {}).get("rate_limit", 1000), "dns_port": p_val.get("dns_port") or (p_val.get("slipstream") or {}).get("dns_port", 53)} if (n.get("engine") == "slipstream" or p_val.get("engine") == "slipstream") else None,
                        "http_connect": {"public_port":n.get("http_connect",{}).get("public_port"),"mode":n.get("transport"),"mutual_tls":True} if n.get("engine") in ("http","https") else None,
                        "status_note": n.get("status_note") or p_val.get("status_note") if n.get("engine") == "wireguard" else None,
                        "waterwall": {"uuid_tcp": n.get("waterwall", {}).get("uuid_tcp"), "outer_port": n.get("waterwall", {}).get("outer_port"), "server_name": n.get("waterwall", {}).get("profile", {}).get("server_name") or n.get("waterwall", {}).get("server_name"), "profile": n.get("waterwall", {}).get("profile")} if n.get("engine") == "waterwall" else None,
                        "rathole": {"transport": n.get("rathole", {}).get("transport") or p_val.get("rathole_transport") or (p_val.get("camouflage") or {}).get("transport", "tcp"), "proto": n.get("rathole", {}).get("proto") or (p_val.get("camouflage") or {}).get("proto", "tcp"), "port": n.get("rathole", {}).get("port") or n.get("tunnel_port") or (p_val.get("camouflage") or {}).get("port", 2333)} if (n.get("engine") == "rathole" or p_val.get("engine") == "rathole" or p_val.get("transport") == "rathole") else None,
                        "transport": n.get("transport", p_val.get("transport", "tcp")),
                        "status": "PROVISIONING" if n.get("creation_pending") else "DOWN" if n.get("provisioning") else telem.get("status", "IDLE"),
                        "reason": p_val.get("creation_job", {}).get("message", "در انتظار راه‌اندازی") if n.get("creation_pending") else "راه‌اندازی نود کامل نشده؛ منابع آن را بررسی یا پاک‌سازی کنید" if n.get("provisioning") else telem.get("reason", "Awaiting checks"),
                        "status_since": telem.get("status_since", ""),
                        "latency_ms": n.get("latency_ms") or telem.get("latency_ms") or next((v.get("latency_ms") for v in telem.get("port_details", {}).values() if v.get("latency_ms")), None),
                        "port_details": {port: {k: v for k, v in detail.items() if k != "socket_samples"} for port, detail in telem.get("port_details", {}).items()},
                        "updated_at": telem.get("updated_at", "")
                    })

                
                pools_resp.append({
                    "name": p_name,
                    "transport": p_val.get("transport", "tcp"),
                    "engine": p_val.get("engine", "backpack"),
                    "composition": p_val.get("composition"),
                    "slipstream": {key: p_val.get(key) for key in ("domain", "resolvers", "dns_port", "rate_limit", "slipstream_runtime_version")} if p_val.get("engine") == "slipstream" else None,
                    "tun_mtu": p_val.get("tun_mtu"),
                    "dc6_mtu": p_val.get("dc6_mtu"),
                    "carrier_type": p_val.get("carrier_type"),
                    "gre_mtu": p_val.get("gre_mtu"),
                    "gre6_mtu": p_val.get("gre6_mtu"),
                    "ip6ip6_mtu": p_val.get("ip6ip6_mtu"),
                    "geneve_mtu": p_val.get("geneve_mtu"),
                    "vxlan_mtu": p_val.get("vxlan_mtu"),
                    "vxsec_mtu": p_val.get("vxsec_mtu"),
                    "vxsec_dst_port": p_val.get("vxsec_dst_port"),
                    "vxlan_method": p_val.get("vxlan_method"),
                    "dst_port": p_val.get("dst_port"),
                    "wireguard_mtu": p_val.get("wireguard_mtu") or p_val.get("mtu"),
                    "wireguard_port": p_val.get("wireguard_port") or p_val.get("tunnel_port"),
                    "status_note": p_val.get("status_note"),
                    "vni": p_val.get("vni"),
                    "camouflage": {key:p_val.get("camouflage",{}).get(key) for key in ("mode","server_name","profile","persona","transport","proto","port")} if (p_val.get("engine") in ("waterwall", "gost", "frp", "hedioum", "rathole", "paqet") or p_val.get("transport") in ("waterwall", "gost", "frp", "hedioum", "rathole", "paqet")) else None,
                    "rathole_transport": p_val.get("rathole_transport") or (p_val.get("camouflage") or {}).get("transport"),
                    "rathole_proto": (p_val.get("camouflage") or {}).get("proto", "tcp"),
                    "operation_task": p_val.get("operation_task"),
                    "creation_job": p_val.get("creation_job"),
                    "creation_placeholder": p_val.get("creation_placeholder", False),
                    "gre_update": p_val.get("gre_update"),
                    "transport_change": p_val.get("transport_change"),
                    "node_removals": p_val.get("node_removals", {}),
                    "node_additions": p_val.get("node_additions", {}),
                    "client_ports": p_val.get("client_ports", []),
                    "kharej_ip": p_val.get("kharej_server", {}).get("ip", ""),
                    "subdomain": cf_info.get("subdomain", "Not set"),
                    "cf_enabled": cf_info.get("enabled", False),
                    "dns_scope": cf_info.get("scope", "single"),
                    "dns_mode": "manual" if data.get("dns_overrides", {}).get(route_key(cf_info)) else "auto",
                    "dns_override": data.get("dns_overrides", {}).get(route_key(cf_info)),
                    "dns_report": data.get("watchdog_status", {}).get("pool_reports", {}).get(p_name, {}),
                    "rotation": pool_rotation_status(data, p_name),
                    "nodes": nodes_list
                })

            cf_raw = data.get("cloudflare", {})
            global_cf_masked = dict(cf_raw)
            if "api_token" in global_cf_masked and global_cf_masked["api_token"]:
                tok = str(global_cf_masked["api_token"])
                global_cf_masked["api_token"] = ("…" + tok[-4:]) if tok else ""

            resp = {
                "daemon_running": watchdog.is_daemon_running(),
                "daemon_pid": watchdog.get_daemon_pid(),
                "last_check": data.get("watchdog_status", {}).get("last_check", ""),
                "healthy_ips": data.get("watchdog_status", {}).get("healthy_ips", []),
                "filtered_ips": data.get("watchdog_status", {}).get("filtered_ips", []),
                "iran_count": len(get_servers("iran")),
                "kharej_count": len(get_servers("kharej")),
                "global_cloudflare": global_cf_masked,
                "rotation_global": data.get("dns_scheduler", {}),
                "dashboard_domain": get_dashboard_domain_config(),
                "pools": pools_resp,
                "private_links": data.get("custom_links", {}),
                "link_tasks": data.get("link_tasks", {})
            }
            return self._send_json(resp)

        elif path == "/api/servers":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            iran_srvs = get_servers("iran")
            kharej_srvs = get_servers("kharej")
            pools = get_pools()
            
            # Map which servers are in active use in pools
            used_iran_ips = set()
            used_kharej_ips = set()
            for p in pools.values():
                if p.get("kharej_server", {}).get("ip"):
                    used_kharej_ips.add(p["kharej_server"]["ip"])
                for n in p.get("nodes", []):
                    used_iran_ips.add(n["ip"])

            def sanitize(srv, is_iran):
                return {
                    "name": srv.get("name", srv["ip"]),
                    "ip": srv["ip"],
                    "port": srv.get("port", 22),
                    "username": srv.get("username", "root"),
                    "arch": srv.get("arch", "unknown"),
                    "ipv6": srv.get("ipv6", ""),
                    "health": srv.get("health", "unknown"),
                    "last_seen": srv.get("last_seen"),
                    "last_latency_ms": srv.get("last_latency_ms"),
                    "in_use": srv["ip"] in (used_iran_ips if is_iran else used_kharej_ips)
                }

            return self._send_json({
                "iran": [sanitize(s, True) for s in iran_srvs],
                "kharej": [sanitize(s, False) for s in kharej_srvs]
            })

        elif path == "/api/transports":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            from core.transports_13 import get_transport_spec, CATEGORY_TITLES
            transports_list = []
            for k, (proto, desc) in SUPPORTED_TRANSPORTS.items():
                item = {
                    "id": proto,
                    "key": k,
                    "name": desc
                }
                spec = get_transport_spec(proto)
                if spec:
                    item.update({
                        "category": spec.category,
                        "category_title_fa": spec.category_title_fa,
                        "layer": spec.layer,
                        "overhead": spec.header_overhead_bytes,
                        "dpi": spec.dpi_resistance,
                        "default_mtu": spec.default_mtu,
                        "min_mtu": spec.min_mtu,
                        "max_mtu": spec.max_mtu,
                        "supports_fec": spec.supports_fec,
                        "supports_xmux": spec.supports_xmux,
                        "supports_padding": spec.supports_padding,
                        "supports_port_hopping": spec.supports_port_hopping,
                        "default_params": spec.default_parameters,
                    })
                transports_list.append(item)
            return self._send_json({"transports": transports_list, "categories": CATEGORY_TITLES})

        elif path == "/api/pools/cloudflare":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            name = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("pool", [""])[0]
            data = load_data()
            if name not in data.get("pools", {}):
                return self._send_json({"error": "استخر یافت نشد"}, 404)
            config = effective_config(data, name)
            masked = dict(config)
            tok = config.get("api_token", "")
            masked["api_token"] = ("…" + tok[-4:]) if tok else ""
            return self._send_json({key: masked.get(key, "single" if key == "scope" else "") for key in ("api_token", "zone_id", "subdomain", "enabled", "scope")}, headers={"Cache-Control": "no-store"})

        elif path == "/api/pools/composition":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            name = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("pool", [""])[0]
            data = load_data()
            pool = data.get("pools", {}).get(name)
            if not pool:
                return self._send_json({"error": "استخر یافت نشد"}, 404)
            from core.composition_schema import deconstruct_legacy_pool
            comp = pool.get("composition") or deconstruct_legacy_pool(pool).to_dict()
            return self._send_json({"pool": name, "composition": comp})

        elif path == "/api/cloudflare/profiles":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            migrate_legacy_cf_profiles()
            profiles = get_cf_profiles()
            return self._send_json(
                {"profiles": [cf_profile_public(pid, p) for pid, p in profiles.items()]},
                headers={"Cache-Control": "no-store"})

        elif path.startswith("/api/cloudflare/profiles/") and path.endswith("/zones"):
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            pid = path[len("/api/cloudflare/profiles/"):-len("/zones")].strip("/")
            profile = get_cf_profile(pid)
            if not profile:
                return self._send_json({"error": "پروفایل یافت نشد"}, 404)
            refresh = query.get("refresh", [""])[0] in ("1", "true", "yes")
            if refresh or not profile.get("zone_cache"):
                mgr = CloudflareManager(profile.get("token", ""))
                res = mgr.list_zones()
                if not res.get("success"):
                    cf_audit("zones.discover", pid, ok=False, detail=res.get("error", ""))
                    return self._send_json({"error": res.get("error", "کشف Zoneها ناموفق بود")}, 502)
                zones = [{"id": z.get("id"), "name": z.get("name"),
                          "status": z.get("status"), "paused": z.get("paused", False),
                          "name_servers": z.get("name_servers", [])}
                         for z in res.get("zones", [])]
                set_cf_profile_zones(pid, zones)
                cf_audit("zones.discover", pid, detail=f"{len(zones)} zones")
                profile = get_cf_profile(pid)
            return self._send_json(
                {"zones": profile.get("zone_cache", []),
                 "fetched_at": profile.get("zone_cache_fetched_at", "")},
                headers={"Cache-Control": "no-store"})

        elif path == "/api/cloudflare/zones/records":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            pid = query.get("profile", [""])[0]
            zid = query.get("zone", [""])[0].strip()
            profile = get_cf_profile(pid)
            if not profile or not profile.get("enabled", True):
                return self._send_json({"error": "پروفایل یافت نشد یا غیرفعال است"}, 404)
            if not any(z.get("id") == zid for z in profile.get("zone_cache", [])):
                return self._send_json({"error": "Zone برای این پروفایل مجاز نیست"}, 403)
            mgr = CloudflareManager(profile.get("token", ""))
            res = mgr.list_records_typed(
                zid, rtype=query.get("type", [""])[0],
                name=query.get("name", [""])[0])
            if not res.get("success"):
                return self._send_json({"error": res.get("error", "خواندن رکوردها ناموفق بود")}, 502)
            return self._send_json(
                {"records": res["records"], "count": res["count"]},
                headers={"Cache-Control": "no-store"})

        elif path == "/api/cloudflare/audit":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            return self._send_json(
                {"audit": load_data().get("cloudflare_audit", [])[-100:]},
                headers={"Cache-Control": "no-store"})

        elif path == "/api/cloudflare":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            data = load_data()
            cf = data.get("cloudflare", {})
            return self._send_json({
                "api_token": ("…" + cf["api_token"][-4:]) if cf.get("api_token") else "",
                "zone_id": cf.get("zone_id", ""),
                "subdomain": cf.get("subdomain", ""),
                "enabled": cf.get("enabled", False),
                "profile_id": cf.get("profile_id", "")
            })

        elif path == "/api/logs":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            
            ip = query.get("ip", [""])[0]
            if not ip:
                return self._send_json({"error": "Missing IP parameter"}, 400)

            # Find server credentials in inventory
            data = load_data()
            target_node = None
            requested_pool=query.get("pool",[""])[0]
            for pool_name,p in data.get("pools", {}).items():
                if requested_pool and pool_name != requested_pool:continue
                for n in p.get("nodes", []):
                    if n.get("ip") == ip:
                        target_node = n
                        break
                if target_node:
                    break

            if not target_node:
                for s in data.get("iran_servers", []):
                    if s.get("ip") == ip:
                        target_node = s
                        break

            if not target_node:
                return self._send_json({"error": "Server not found in inventory"}, 404)

            ssh = SSHManager(
                target_node["ip"],
                target_node.get("port", 22),
                target_node.get("username", "root"),
                target_node.get("password"),
                timeout=6
            )
            ok, msg = ssh.connect()
            if not ok:
                return self._send_json({"error": f"SSH connection failed: {msg}"}, 502)

            eng = target_node.get('engine', 'backpack')
            node_name = target_node.get("node_name", "")
            nnq = shquote(node_name) if node_name else ""
            if eng == 'waterwall':
                svc = f"{nnq}.service" if node_name else "ldw*.service"
                alt_svc = f"vxlb-waterwall-{nnq}.service" if node_name else "vxlb-waterwall*.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {alt_svc} 2>/dev/null || journalctl --no-pager -n 80 | grep -i waterwall")
            elif eng in ('gre', 'gre_ipv4'):
                svc = f"vxlb-gre-{nnq}.service" if node_name else "vxlb-gre*.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc}")
            elif eng in ('geneve', 'geneve_ipsec'):
                svc = f"vxlb-geneve-{nnq}.service" if node_name else "vxlb-geneve*.service"
                relay_svc = f"vxlb-geneve-{nnq}-relay.service" if node_name else "vxlb-geneve*-relay.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {relay_svc} 2>/dev/null")
            elif eng == 'gre6':
                svc = f"vxlb-gre6-{nnq}.service" if node_name else "vxlb-gre6*.service"
                relay_svc = f"vxlb-gre6-{nnq}-relay.service" if node_name else "vxlb-gre6*-relay.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {relay_svc} 2>/dev/null")
            elif eng == 'ip6ip6':
                svc = f"vxlb-ip6ip6-{nnq}.service" if node_name else "vxlb-ip6ip6*.service"
                relay_svc = f"vxlb-ip6ip6-{nnq}-relay.service" if node_name else "vxlb-ip6ip6*-relay.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {relay_svc} 2>/dev/null")
            elif eng == 'wireguard':
                iface_raw = target_node.get("wireguard", {}).get("interface") or (f"wg-{node_name}" if node_name else "")
                iface = shquote(iface_raw) if iface_raw else ""
                svc = f"wg-quick@{iface}.service"
                relay_svc = f"vxlb-wg-{iface}-relay.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {relay_svc} 2>/dev/null")
            elif eng == 'vxlan':
                iface_raw = target_node.get("vxlan", {}).get("iface") or (f"vx-{node_name}" if node_name else "")
                iface = shquote(iface_raw) if iface_raw else ""
                svc = f"vxlb-vxlan-{iface}.service"
                relay_svc = f"vxlb-{iface}-relay.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {relay_svc} 2>/dev/null")
            elif eng == 'vxlan_ipsec':
                iface_raw = (target_node.get("vxsec", {}).get("configs") or [{}])[0].get("interface") or node_name
                iface = shquote(iface_raw) if iface_raw else ""
                svc = f"vxlb-vxsec-{iface}.service"
                relay_svc = f"vxlb-vxsec-{iface}-relay.service"
                _, log_text, _ = ssh.execute(f"journalctl --no-pager -n 80 -u {svc} -u {relay_svc} 2>/dev/null")
            else:
                _, log_text, _ = ssh.execute("tail -n 60 /var/log/vxlb-user-connections.log 2>/dev/null || echo 'No connection logs yet.'")
            ssh.close()
            lines = [l.strip() for l in log_text.strip().split("\n") if l.strip()]
            return self._send_json({"ip": ip, "logs": lines})

        elif path == "/api/capabilities":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            from core.capabilities import list_all_capabilities
            return self._send_json(list_all_capabilities())

        elif path == "/api/compositions":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            from core.composition import get_available_compositions
            return self._send_json({
                "compositions": get_available_compositions(),
                "schema_models": {
                    "TransportLayer": {
                        "fields": ["type", "layer", "mtu", "vni", "interface"],
                        "required": ["type", "layer", "mtu"]
                    },
                    "EncryptionLayer": {
                        "fields": ["type", "cipher", "auth_mode", "enabled"],
                        "required": ["type"]
                    },
                    "CamouflageLayer": {
                        "fields": ["type", "mode", "domain", "rate_limit", "resolvers"],
                        "required": ["type"]
                    },
                    "PoolComposition": {
                        "fields": ["transport", "encryption", "camouflage"],
                        "required": ["transport", "encryption", "camouflage"]
                    }
                }
            })

        elif path == "/api/link-tasks":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            return self._send_json(load_data().get('link_tasks', {}))

        elif path == "/api/links":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            data = load_data()
            return self._send_json(data.get("custom_links", {}))

        elif path == "/api/links/preview-delete":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            link_name = query.get("link", [""])[0].strip()
            from core.firewall_lifecycle_manager import DependencyLifecycleManager
            preview = DependencyLifecycleManager.preview_dependent_resources(link_name)
            return self._send_json(preview)

        elif path == "/api/telemetry/server-counts":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            from core.telemetry_supervisor import TelemetrySupervisor
            counts = TelemetrySupervisor.count_server_online_links(load_data())
            return self._send_json(counts)


        elif path == "/api/daemon_logs":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            
            lines = []
            if os.path.exists(LOG_FILE):
                try:
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        lines = [l.strip() for l in f.readlines()[-40:] if l.strip()]
                except Exception:
                    pass
            return self._send_json({"logs": lines})

        elif path == "/api/reconfig/status":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            from core.reconfig_bot import ReconfigBot
            return self._send_json(ReconfigBot.get_status())

        elif path == "/api/reconfig/logs":
            if not self._is_authenticated():
                return self._send_json({"error": "Unauthorized"}, 401)
            from core.reconfig_bot import ReconfigBot
            query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                limit = int(query.get("limit", [50])[0])
            except (ValueError, TypeError, IndexError):
                limit = 50
            limit = max(0, min(limit, 500))
            return self._send_json({"logs": ReconfigBot.get_audit_logs(limit)})

        self.send_error(404, "Not Found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if (path.startswith("/api/pools/") or path == "/api/ports") and self._is_authenticated():
            if transport_busy() and path not in ("/api/pools/transport-rollback", "/api/pools/transport-force-clear", "/api/pools/gre-recover"):
                return self._send_json({"error": "تغییر تونل یا بازگردانی در جریان است؛ عملیات استخر موقتاً قفل است"}, 409)
            with mutation_lock():
                if transport_busy() and path not in ("/api/pools/transport-rollback", "/api/pools/transport-force-clear", "/api/pools/gre-recover"):
                    return self._send_json({"error": "تغییر تونل یا بازگردانی در جریان است؛ عملیات استخر موقتاً قفل است"}, 409)
                return self._do_POST()
        return self._do_POST()

    def _do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        # Read body with size limits to prevent Content-Length DoS
        MAX_BODY_SIZE = int(os.environ.get("VX_LB_MAX_BODY_SIZE", 2 * 1024 * 1024))
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            return self._send_json({"error": "Invalid Content-Length"}, 400)

        if content_length < 0:
            return self._send_json({"error": "Invalid Content-Length"}, 400)
        if content_length > MAX_BODY_SIZE:
            return self._send_json({"error": f"Payload too large. Maximum allowed size is {MAX_BODY_SIZE} bytes"}, 413)

        body = {}
        if content_length > 0:
            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                body = json.loads(raw_body)
            except Exception:
                return self._send_json({"error": "Invalid JSON"}, 400)

        # 1. Login endpoint (open to unauthenticated)
        if path == "/api/login":
            password_input = body.get("password", "")
            client_ip = self._client_ip()
            if not _login_allowed(client_ip):
                return self._send_json({"error": "تلاش‌های ناموفق زیاد؛ ۵ دقیقه صبر کنید"}, 429)
            data = load_data()
            stored_pass = data.get("web_password")

            # Security: NEVER let the first visitor claim the dashboard.
            # Bootstrap the password via the VX_LB_WEB_PASSWORD env var on
            # first run (min 8 chars); otherwise fail closed with guidance.
            if not stored_pass:
                bootstrap = os.environ.get("VX_LB_WEB_PASSWORD", "")
                if bootstrap and len(bootstrap) >= 8 and hmac.compare_digest(password_input, bootstrap):
                    def _set_p(d: dict):
                        d["web_password"] = _hash_password(bootstrap)
                    atomic_update(_set_p)
                    stored_pass = load_data().get("web_password")
                else:
                    _record_failed_login(client_ip)
                    return self._send_json(
                        {"error": "رمز داشبورد تنظیم نشده. ابتدا VX_LB_WEB_PASSWORD را ست کنید و دوباره تلاش کنید"},
                        503,
                    )

            if _verify_password(password_input, stored_pass):
                token = secrets.token_hex(24)
                AUTH_TOKENS[token] = time.time() + 86400  # 24 hours
                secure = " Secure" if os.environ.get("VX_LB_WEB_SECURE_COOKIE") == "1" else ""
                set_cookie = (
                    f"ld_token={token}; HttpOnly; SameSite=Lax; Path=/; "
                    f"Max-Age=86400{secure}"
                )
                # The session token lives in an HttpOnly cookie (not readable by
                # JS), which keeps it out of localStorage and out of XSS reach.
                return self._send_json({"success": True}, 200, {"Set-Cookie": set_cookie})
            else:
                _record_failed_login(client_ip)
                # Small constant delay to slow credential stuffing.
                time.sleep(0.5)
                return self._send_json({"error": "رمز عبور نادرست است"}, 401)

        # Logout: invalidate the caller's token and clear the session cookie
        if path == "/api/logout":
            token = self._get_auth_token()
            if token and token in AUTH_TOKENS:
                del AUTH_TOKENS[token]
            clear_cookie = "ld_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
            return self._send_json({"success": True}, 200, {"Set-Cookie": clear_cookie})

        # Protected endpoints below
        if not self._is_authenticated():
            return self._send_json({"error": "Unauthorized"}, 401)

        if path == "/api/rotation/settings":
            try:
                if body.get("pool"):
                    name = str(body.get("pool")).strip()
                    data = load_data()
                    if name not in data.get("pools", {}):
                        return self._send_json({"error": "استخر یافت نشد"}, 404)
                    result = save_pool_schedule(name, body)
                else:
                    result = save_global_schedule(body)
                return self._send_json({"success": True, "settings": result})
            except (ValueError, KeyError) as exc:
                return self._send_json({"error": str(exc)}, 400)

        if path == "/api/rotation/rotate":
            name = str(body.get("pool", "")).strip()
            if not name:
                return self._send_json({"error": "نام استخر مشخص نشده است"}, 400)
            result = rotate_pool(name, "manual")
            return self._send_json(result, 200 if result.get("success") else 409)

        if path == "/api/check":
            watchdog = TelemetryWatchdog()
            reports = watchdog.run_check_cycle()
            def save_check(data):
                data["watchdog_status"] = {
                    "last_check": reports.get("timestamp"),
                    "healthy_ips": reports.get("healthy_ips", []),
                    "filtered_ips": reports.get("filtered_ips", []),
                    "pool_reports": reports.get("pool_reports", {})
                }
            atomic_update(save_check)
            return self._send_json({"success": True, "report": reports})

        elif path == "/api/daemon":
            action = body.get("action")
            watchdog = TelemetryWatchdog()
            if action == "start":
                watchdog.start_background_daemon()
                time.sleep(1)
                return self._send_json({
                    "success": True,
                    "running": watchdog.is_daemon_running(),
                    "pid": watchdog.get_daemon_pid()
                })
            elif action == "stop":
                watchdog.stop_background_daemon()
                time.sleep(1)
                return self._send_json({
                    "success": True,
                    "running": watchdog.is_daemon_running()
                })
            return self._send_json({"error": "Invalid action"}, 400)

        elif path == "/api/servers/add":
            stype = body.get("type", "iran").lower()
            name = body.get("name", "").strip()
            ip = body.get("ip", "").strip()
            try:
                port = int(validate_port(body.get("port", 22)))
            except ValueError as e:
                return self._send_json({"error": str(e)}, 400)
            username = body.get("username", "root").strip()
            password = body.get("password", "")
            ipv6 = str(body.get("ipv6") or "").strip()
            if ipv6:
                from core.ipv6_tunnel_tools import validate_ipv6_address
                try:
                    ipv6 = validate_ipv6_address(ipv6)
                except ValueError as e:
                    return self._send_json({"error": str(e)}, 400)

            if not ip or not password:
                return self._send_json({"error": "آدرس IP و رمز عبور الزامی است"}, 400)
            if not name:
                name = ip

            # Test SSH connection
            ssh = SSHManager(ip=ip, port=port, username=username, password=password, timeout=8)
            ok, msg = ssh.connect()
            if not ok:
                return self._send_json({"error": f"خطای اتصال SSH: {msg}"}, 400)

            _, out, _ = ssh.execute("uname -m")
            arch = out.strip() or "unknown"
            ssh.close()

            server_info = {
                "name": name,
                "ip": ip,
                "ipv6": ipv6,
                "port": port,
                "username": username,
                "password": password,
                "arch": arch
            }
            add_server(stype, server_info)
            return self._send_json({"success": True, "message": f"سرور {ip} با موفقیت ذخیره شد", "arch": arch})

        elif path == "/api/servers/delete":
            stype = body.get("type", "iran").lower()
            ip = body.get("ip", "").strip()
            if not ip:
                return self._send_json({"error": "آدرس IP ارسال نشده است"}, 400)

            # Check if server is currently in an active load balancer pool
            pools = get_pools()
            for p_name, p_data in pools.items():
                if stype == "kharej" and p_data.get("kharej_server", {}).get("ip") == ip:
                    return self._send_json({
                        "error": f"امکان حذف نیست: این سرور خارج، مقصد استخر فعال '{p_name}' است. ابتدا استخر را حذف کنید."
                    }, 400)
                if stype == "iran":
                    for n in p_data.get("nodes", []):
                        if n.get("ip") == ip:
                            return self._send_json({
                                "error": f"امکان حذف نیست: این سرور نود فعال در استخر '{p_name}' است. ابتدا آن را از استخر خارج کنید."
                            }, 400)

            if delete_server(stype, ip):
                return self._send_json({"success": True, "message": f"سرور {ip} با موفقیت حذف شد"})
            else:
                return self._send_json({"error": "سرور در مخزن یافت نشد"}, 404)

        elif path == "/api/servers/test":
            stype = body.get("type", "iran").lower()
            ip = body.get("ip", "").strip()
            if not ip:
                return self._send_json({"error": "آدرس IP ارسال نشده است"}, 400)
            target = None
            for s in get_servers(stype):
                if s.get("ip") == ip:
                    target = s
                    break
            if not target:
                return self._send_json({"error": "سرور در مخزن یافت نشد"}, 404)

            try:
                ssh = SSHManager.from_server(target, timeout=10)
                diag = ssh.diagnose()
            except Exception as e:
                diag = {"reachable": False, "latency_ms": 0, "error": str(e)}

            health = "ok" if diag.get("reachable") else "err"
            update_server_telemetry(stype, ip, {
                "health": health,
                "last_seen": int(time.time()),
                "last_latency_ms": diag.get("latency_ms", 0),
            })
            diag["health"] = health
            diag["ip"] = ip
            return self._send_json(diag)

        elif path == "/api/servers/cc":
            stype = body.get("type", "iran").lower()
            ip = body.get("ip", "").strip()
            action = (body.get("action", "status") or "status").lower()
            if not ip:
                return self._send_json({"error": "آدرس IP ارسال نشده است"}, 400)
            target = None
            for s in get_servers(stype):
                if s.get("ip") == ip:
                    target = s
                    break
            if not target:
                return self._send_json({"error": "سرور در مخزن یافت نشد"}, 404)
            try:
                ssh = SSHManager.from_server(target, timeout=10)
                if action == "enable":
                    orig = ssh.tcp_cc_status()
                    status = ssh.set_tcp_cc("bbr", "fq")
                    update_server_telemetry(stype, ip, {
                        "cc_before": orig.get("cc"), "qdisc_before": orig.get("default_qdisc"),
                        "cc_enabled": True,
                    })
                elif action == "disable":
                    prev_cc = target.get("cc_before") or "cubic"
                    prev_qd = target.get("qdisc_before") or "pfifo_fast"
                    ssh.execute("rm -f /etc/sysctl.d/99-vxlb-bbr.conf", timeout=20)
                    ssh.execute(f"sysctl -w net.ipv4.tcp_congestion_control={shquote(prev_cc)}", timeout=20)
                    ssh.execute(f"sysctl -w net.core.default_qdisc={shquote(prev_qd)}", timeout=20)
                    ssh.execute("sysctl --system 2>/dev/null || true", timeout=20)
                    status = ssh.tcp_cc_status()
                    update_server_telemetry(stype, ip, {
                        "cc_before": None, "qdisc_before": None, "cc_enabled": False,
                    })
                else:
                    status = ssh.tcp_cc_status()
                ssh.close()
            except Exception as e:
                return self._send_json({"error": f"خطا در مدیریت CC: {e}"}, 502)

            enabled = bool(target.get("cc_enabled"))
            if action == "enable":
                enabled = True
            elif action == "disable":
                enabled = False
            return self._send_json({"ip": ip, "enabled": enabled, "status": status})

        elif path == "/api/pools/create":
            pool_name = body.get("name", "").strip()
            kharej_ip = body.get("kharej_ip", "").strip()
            iran_ips = body.get("iran_ips", [])
            transport = body.get("transport", "pck").strip()
            raw_ports = [str(p).strip() for p in body.get("client_ports", ["443"]) if str(p).strip()]

            if not pool_name or not kharej_ip or not iran_ips:
                return self._send_json({"error": "نام استخر، سرور خارج و حداقل یک سرور ایران الزامی است"}, 400)

            # Security: reject injection payloads before they reach provisioning.
            try:
                pool_name = validate_pool_name(pool_name)
                transport = validate_transport(transport, SUPPORTED_TRANSPORTS)
                client_ports = validate_ports(raw_ports)
            except ValueError as e:
                return self._send_json({"error": str(e)}, 400)

            # Find server configs
            kh_srvs = [s for s in get_servers("kharej") if s["ip"] == kharej_ip]
            if not kh_srvs:
                return self._send_json({"error": f"سرور خارج {kharej_ip} در مخزن سرورها یافت نشد"}, 404)
            selected_kharej = kh_srvs[0]

            ir_srvs = [s for s in get_servers("iran") if s["ip"] in iran_ips]
            if not ir_srvs or {s["ip"] for s in ir_srvs} != set(iran_ips):
                return self._send_json({"error": "هیچ‌کدام از سرورهای ایران انتخاب‌شده در مخزن یافت نشد"}, 400)

            extra_args = {}
            if transport == "gre":
                extra_args["gre_mtu"] = body.get("gre_mtu", 1280)
            elif transport == "gre6":
                extra_args["gre6_mtu"] = body.get("gre6_mtu", 1280)
            elif transport == "ip6ip6":
                extra_args["ip6ip6_mtu"] = body.get("ip6ip6_mtu", 1280)
            elif transport in ("geneve", "geneve_ipsec"):
                extra_args["geneve_mtu"] = body.get("geneve_mtu", 1280)
                extra_args["vni"] = body.get("vni")
            elif transport == "vxlan_ipsec":
                extra_args.update({
                    "vni": body.get("vni"),
                    "dst_port": body.get("dst_port", 4789),
                    "vxsec_mtu": body.get("vxsec_mtu") or body.get("mtu") or 1280,
                })
            elif transport == "vxlan":
                extra_args.update({
                    "vni": body.get("vni"),
                    "vxlan_method": body.get("vxlan_method", "p2p"),
                    "dst_port": body.get("dst_port", 4789),
                    "vxlan_mtu": body.get("vxlan_mtu", 1280),
                    "bridge_name": body.get("bridge_name"),
                    "underlay_dev": body.get("underlay_dev")
                })
            elif transport == "wireguard":
                extra_args.update({
                    "tunnel_port": body.get("tunnel_port") or body.get("wireguard_port", 51820),
                    "mtu": body.get("mtu") or body.get("wireguard_mtu", 1280),
                    "enable_psk": body.get("enable_psk", False)
                })
            elif transport == "slipstream":
                extra_args.update({
                    "domain": body.get("domain"),
                    "resolvers": body.get("resolvers"),
                    "dns_port": body.get("dns_port", 53),
                    "rate_limit": body.get("rate_limit", 1000)
                })
            elif transport in ("xhttp", "xhttps", "gre_xhttp", "reality", "nova", "waterwall", "gost", "frp", "hedioum", "rathole", "paqet"):
                extra_args["camouflage"] = body.get("camouflage", {})
            elif transport == "tun":
                extra_args["mtu"] = body.get("tun_mtu") or body.get("mtu", 1280)
            elif transport == "dc6":
                extra_args["mtu"] = body.get("dc6_mtu") or body.get("mtu", 1280)
                extra_args["carrier"] = body.get("carrier") or body.get("carrier_type", "ip6gre")
            from core.spoof_adapter import SPOOF_TRANSPORTS as _SPOOF_TRANSPORTS
            if transport in _SPOOF_TRANSPORTS or body.get("engine") == "spoof":
                extra_args["engine"] = "spoof"
                extra_args["fake_sni"] = body.get("fake_sni") or (body.get("camouflage") or {}).get("server_name") or "www.shaparak.ir"
                extra_args["auto_ttl_delta"] = body.get("auto_ttl_delta", 3)
                extra_args["camouflage"] = body.get("camouflage", {})
                for k in ("spoof_ips", "peer_spoof_ip", "dns_resolvers", "send_domains", "fake_send_ip", "fake_send_port", "info_encryption_pass", "knock_key", "mode"):
                    if body.get(k):
                        extra_args[k] = body.get(k)

            if "is_production" in body:
                extra_args["is_production"] = bool(body["is_production"])
            if "allow_experimental" in body:
                extra_args["allow_experimental"] = bool(body["allow_experimental"])

            from core.pool_creation import start as start_creation
            ok, result = start_creation(dict(
                pool_name=pool_name,
                kharej_server=selected_kharej,
                iran_servers=ir_srvs,
                transport=transport,
                client_ports=client_ports,
                **extra_args
            ))
            if ok:
                return self._send_json({"success": True, "accepted": True, "message": "ساخت استخر شروع شد؛ وضعیت را در کارت استخر دنبال کنید", "job": result}, 202)
            return self._send_json({"error": result}, 409)

        elif path == "/api/pools/delete":
            pool_name = body.get("pool", "").strip()
            if not pool_name:
                return self._send_json({"error": "نام استخر مشخص نشده است"}, 400)
            forget = body.get("forget", False)
            if not isinstance(forget, bool):
                return self._send_json({"error": "گزینهٔ حذف از پنل باید boolean باشد"}, 400)
            if forget:
                ok, msg = LoadBalancerManager.forget_pool(pool_name)
                return self._send_json({"success": ok, **({"message": msg} if ok else {"error": msg})}, 200 if ok else 409)
            from core.pool_tasks import start as start_task
            ok, result = start_task(pool_name, 'delete')
            return self._send_json({"success": True, "accepted": True, "job": result} if ok else {"error": result}, 202 if ok else 409)

        elif path == "/api/pools/add_node":
            pool_name = body.get("pool", "").strip()
            iran_ip = body.get("iran_ip", "").strip()
            if not pool_name or not iran_ip:
                return self._send_json({"error": "نام استخر و آی‌پی سرور ایران الزامی است"}, 400)

            ir_srvs = [s for s in get_servers("iran") if s["ip"] == iran_ip]
            if not ir_srvs:
                return self._send_json({"error": f"سرور {iran_ip} در مخزن سرورهای ایران یافت نشد"}, 404)

            ok, msg = start_node_addition(pool_name, ir_srvs[0])
            if ok:
                return self._send_json({"success": True, "job": msg}, 202)
            else:
                return self._send_json({"error": msg}, 409)

        elif path == "/api/pools/remove_node":
            pool_name = body.get("pool", "").strip()
            iran_ip = body.get("iran_ip", "").strip()
            force = bool(body.get("force", False))
            if not pool_name or not iran_ip:
                return self._send_json({"error": "نام استخر و آی‌پی سرور ایران الزامی است"}, 400)

            forget = body.get("forget", False)
            if not isinstance(forget, bool):
                return self._send_json({"error": "گزینهٔ حذف از پنل باید boolean باشد"}, 400)
            if forget:
                ok, msg = start_node_removal(pool_name, iran_ip, forget=True)
            else:
                ok, msg = start_node_removal(pool_name, iran_ip, force=force)
            if ok:
                return self._send_json({"success": True, "job": msg}, 202)
            else:
                return self._send_json({"error": msg}, 409)

        elif path in ("/api/pools/gre-settings", "/api/pools/gre-recover"):
            from core.gre import change_mtu, recover_update
            name = str(body.get("pool", "")).strip()
            ok, message = recover_update(name) if path.endswith("gre-recover") else change_mtu(name, body.get("mtu"))
            return self._send_json({"success":ok,"message":message, **({"error":message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/links/matrix":
            from core.link_tasks import start_matrix
            ok, result = start_matrix(body.get('pairs'), body.get('port', 51820), body.get('mtu', 1400))
            return self._send_json({"success":ok,"accepted":ok, **({"job":result} if ok else {"error":result})}, 202 if ok else 409)

        elif path == "/api/links/delete":
            from core.link_tasks import start_delete
            ok, result = start_delete(str(body.get('link', '')))
            return self._send_json({"success":ok,"accepted":ok, **({"job":result} if ok else {"error":result})}, 202 if ok else 409)

        elif path == "/api/links/forwarding/apply":
            from core.private_link_forwarding import apply_forwarding_rules
            link_name = str(body.get('link', '')).strip()
            rules = body.get('rules', [])
            ok, msg = apply_forwarding_rules(link_name, rules)
            return self._send_json({"success": ok, "message": msg, **({"error": msg} if not ok else {})}, 200 if ok else 400)

        elif path == "/api/links/forwarding/remove":
            from core.private_link_forwarding import remove_forwarding_rules
            link_name = str(body.get('link', '')).strip()
            ok, msg = remove_forwarding_rules(link_name)
            return self._send_json({"success": ok, "message": msg, **({"error": msg} if not ok else {})}, 200 if ok else 400)

        elif path == "/api/pools/migration-preview":
            from core.telemetry_supervisor import PhasedMigrationManager
            pool_name = str(body.get("pool", "")).strip()
            cur_tr = str(body.get("current_transport", "")).strip()
            tgt_tr = str(body.get("target_transport", "")).strip()
            ports = body.get("ports", [443])
            preview = PhasedMigrationManager.execute_migration_dry_run(pool_name, cur_tr, tgt_tr, ports)
            return self._send_json(preview)

        elif path == "/api/links/mutation-impact":
            from core.private_link_manager import PrivateLinkManager
            target_type = str(body.get("target_type", "link")).strip()
            target_name = str(body.get("target_name", "")).strip()
            updates = body.get("updates", {})
            try:
                impact = PrivateLinkManager.estimate_mutation_impact(target_type, target_name, updates)
                return self._send_json(impact)
            except Exception as e:
                return self._send_json({"error": str(e)}, 400)

        elif path == "/api/reconfig/trigger":
            from core.reconfig_bot import ReconfigBot
            target_name = str(body.get("target_name", "")).strip()
            target_type = str(body.get("target_type", "link")).strip()
            new_config = body.get("new_config", {})
            try:
                res = ReconfigBot.trigger_reconfig(target_name, target_type, new_config)
                return self._send_json({"success": True, **res}, 202)
            except Exception as e:
                return self._send_json({"error": str(e)}, 409)

        elif path == "/api/reconfig/pause":
            from core.reconfig_bot import ReconfigBot
            res = ReconfigBot.pause()
            return self._send_json(res)

        elif path == "/api/reconfig/resume":
            from core.reconfig_bot import ReconfigBot
            res = ReconfigBot.resume()
            return self._send_json(res)

        elif path == "/api/reconfig/rollback":
            from core.reconfig_bot import ReconfigBot
            try:
                res = ReconfigBot.rollback()
                return self._send_json(res)
            except Exception as e:
                return self._send_json({"error": str(e)}, 409)

        elif path == "/api/reconfig/settings":
            from core.reconfig_bot import ReconfigBot
            enabled = bool(body.get("enabled", False))
            webhook_url = body.get("webhook_url")
            bot_token = body.get("bot_token")
            chat_id = body.get("chat_id")
            res = ReconfigBot.configure_notifications(enabled, webhook_url, bot_token, chat_id)
            return self._send_json({"success": True, **res})


        elif path == "/api/pools/slipstream-settings":
            from core.pool_tasks import start as start_task
            name = str(body.get("pool", "")).strip()
            ok, result = start_task(name, 'slipstream_settings', body.get('settings'))
            return self._send_json({"success": ok, "accepted": ok, **({"job": result} if ok else {"error": result})}, 202 if ok else 409)

        elif path == "/api/pools/gre6-settings":
            from core.gre6 import change_mtu
            name = str(body.get("pool", "")).strip()
            ok, message = change_mtu(name, int(body.get("mtu", 1400)))
            return self._send_json({"success": ok, "message": message, **({"error": message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/pools/ip6ip6-settings":
            from core.ip6ip6 import change_mtu
            name = str(body.get("pool", "")).strip()
            ok, message = change_mtu(name, int(body.get("mtu", 1420)))
            return self._send_json({"success": ok, "message": message, **({"error": message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/pools/gre6-status":
            from core.gre6 import pool_status
            name = str(body.get("pool", "")).strip()
            ok, message, data = pool_status(name)
            return self._send_json({"success": ok, "message": message, "status": data}, 200 if ok else 409)

        elif path == "/api/pools/ip6ip6-status":
            from core.ip6ip6 import pool_status
            name = str(body.get("pool", "")).strip()
            ok, message, data = pool_status(name)
            return self._send_json({"success": ok, "message": message, "status": data}, 200 if ok else 409)

        elif path == "/api/pools/geneve-settings":
            from core.geneve import change_mtu
            name = str(body.get("pool", "")).strip()
            ok, message = change_mtu(name, int(body.get("mtu", 1400)))
            return self._send_json({"success":ok,"message":message, **({"error":message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/pools/vxlan-settings":
            from core.vxlan_adapter import change_mtu
            name = str(body.get("pool", "")).strip()
            ok, message = change_mtu(name, int(body.get("mtu", 1400)))
            return self._send_json({"success": ok, "message": message, **({"error": message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/pools/vxlan-ipsec-settings":
            from core.vxlan_ipsec import change_mtu
            name = str(body.get("pool", "")).strip()
            ok, message = change_mtu(name, int(body.get("mtu", 1280)))
            return self._send_json({"success": ok, "message": message, **({"error": message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/pools/vxlan-status":
            from core.vxlan_adapter import pool_status
            name = str(body.get("pool", "")).strip()
            ok, message, data = pool_status(name)
            return self._send_json({"success": ok, "message": message, "status": data}, 200 if ok else 409)

        elif path == "/api/pools/wireguard-settings":
            from core.wireguard_adapter import change_mtu
            name = str(body.get("pool", "")).strip()
            ok, message = change_mtu(name, int(body.get("mtu", 1420)))
            return self._send_json({"success": ok, "message": message, **({"error": message} if not ok else {})}, 200 if ok else 409)

        elif path == "/api/pools/wireguard-status":
            from core.wireguard_adapter import pool_status
            name = str(body.get("pool", "")).strip()
            ok, message, data = pool_status(name)
            return self._send_json({"success": ok, "message": message, "status": data}, 200 if ok else 409)

        elif path == "/api/pools/wireguard-probe":
            from core.wireguard_adapter import probe_pool
            name = str(body.get("pool", "")).strip()
            iran_ip = str(body.get("ip", "")).strip() or None
            res = probe_pool(name, iran_ip=iran_ip)
            return self._send_json(res, 200 if res.get("passed") else 200)

        elif path == "/api/pools/transport":
            pool_name = str(body.get("pool", "")).strip()
            transport = str(body.get("transport", "")).strip()
            current = get_pools().get(pool_name, {})
            from core.nfqws2_profiles import MODES as packet_modes
            if current.get('engine')=='spoof' or transport in packet_modes:
                return self._send_json({'success':False,'error':'برای پروفایل پردازش بسته استخر جداگانه بسازید؛ تغییر موتور درجا پشتیبانی نمی‌شود'},409)
            if transport in ('http','https') or current.get('transport') in ('http','https'):
                if current.get('transport') not in ('http','https') or transport not in ('http','https'):
                    return self._send_json({"success":False,"error":"مهاجرت بین CONNECT و موتورهای دیگر پشتیبانی نمی‌شود؛ استخر جداگانه بسازید"},409)
                from core.pool_tasks import start as start_task
                ok,result=start_task(pool_name,'http_transport',transport)
                return self._send_json({"success":ok,"accepted":ok,**({"job":result} if ok else {"error":result})},202 if ok else 409)
            extra_args = {}
            if "engine" in body and body["engine"]:
                extra_args["engine"] = str(body.get("engine", "")).strip()
            if "camouflage" in body and isinstance(body.get("camouflage"), dict):
                extra_args["camouflage"] = dict(body["camouflage"])
            if "server_name" in body and body["server_name"]:
                extra_args.setdefault("camouflage", {})["server_name"] = str(body["server_name"]).strip()
            if "port" in body and body["port"] is not None:
                extra_args.setdefault("camouflage", {})["port"] = body["port"]
            if "mtu" in body and body["mtu"]:
                try: extra_args["mtu"] = int(body["mtu"])
                except (ValueError, TypeError): pass
            if "tunnel_port" in body and body["tunnel_port"]:
                try: extra_args["tunnel_port"] = int(body["tunnel_port"])
                except (ValueError, TypeError): pass
            if "fec_datashard" in body and body["fec_datashard"]:
                try: extra_args["fec_datashard"] = int(body["fec_datashard"])
                except (ValueError, TypeError): pass
            if "fec_parityshard" in body and body["fec_parityshard"]:
                try: extra_args["fec_parityshard"] = int(body["fec_parityshard"])
                except (ValueError, TypeError): pass
            if "domain" in body and body["domain"]:
                extra_args["domain"] = str(body["domain"]).strip()
            if "resolvers" in body and body["resolvers"]:
                extra_args["resolvers"] = str(body["resolvers"]).strip()
            if "fake_sni" in body and body["fake_sni"]:
                extra_args["fake_sni"] = str(body["fake_sni"]).strip()
            if "auto_ttl_delta" in body and body["auto_ttl_delta"]:
                try: extra_args["auto_ttl_delta"] = int(body["auto_ttl_delta"])
                except (ValueError, TypeError): pass
            for k in ("spoof_ips", "peer_spoof_ip", "dns_resolvers", "send_domains", "fake_send_ip", "fake_send_port", "info_encryption_pass", "knock_key", "mode", "carrier", "carrier_type", "dc6_mtu"):
                if body.get(k):
                    extra_args[k] = body.get(k)

            if "is_production" in body:
                extra_args["is_production"] = bool(body["is_production"])
            if "allow_experimental" in body:
                extra_args["allow_experimental"] = bool(body["allow_experimental"])

            ok, message = start_change(pool_name, transport, **extra_args)
            return self._send_json({"success": ok, "message": message}, 202 if ok else 409)

        elif path == "/api/pools/transport-rollback":
            name = str(body.get("pool", ""))
            pool = load_data().get("pools", {}).get(name, {})
            if pool.get("transport_change", {}).get("status") != "rollback_failed":
                return self._send_json({"error": "عملیات ناموفق قابل بازگردانی یافت نشد"}, 409)
            from core.transport_change import update_job
            import threading
            update_job(name, status="rolling_back", message="تلاش دوباره برای بازگردانی")
            threading.Thread(target=run_change, args=(name, True), daemon=True).start()
            return self._send_json({"success": True, "message": "بازگردانی دوباره شروع شد"}, 202)

        elif path == "/api/pools/transport-force-clear":
            # Manual recovery: abandon a wedged rollback_failed job (e.g.
            # decommissioned node). Requires explicit confirmation flag.
            name = str(body.get("pool", ""))
            confirm = body.get("confirm", "")
            if confirm != f"abandon-{name}":
                return self._send_json(
                    {"error": "نیاز به تأیید صریح است: confirm را برابر abandon-<pool> بفرستید"}, 400
                )
            ok, msg = force_clear_change(name)
            return self._send_json({"success": ok, "message": msg}, 200 if ok else 409)

        elif path == "/api/pools/clear-operation":
            name = str(body.get("pool", "")).strip()
            kind = str(body.get("kind", "")).strip()  # "transport", "removal", "addition", or "all"
            target_id = str(body.get("id", "")).strip()  # specific ip or job id (optional)

            def _clear_op(data):
                if kind in ('task','all'):
                    task = data.get('pool_tasks', {}).get(name)
                    if task and task.get('status') in ('succeeded','failed'):
                        data['pool_tasks'].pop(name, None)
                if kind in ('creation','all'):
                    creation = data.get('pool_creations', {}).get(name)
                    if creation and creation.get('status') in ('succeeded','failed'):
                        data['pool_creations'].pop(name, None)
                p = data.get("pools", {}).get(name)
                if not p:
                    return
                # Dismiss terminal messages, including failed preflight/connection attempts.
                # rollback_failed retains its separate recovery/abandon workflow.
                if kind in ("transport", "all"):
                    tc = p.get("transport_change")
                    if tc and tc.get("status") in ("succeeded", "failed", "rolled_back", "abandoned"):
                        p.pop("transport_change", None)
                # Clear node_removals
                if kind in ("removal", "all"):
                    removals = p.get("node_removals")
                    if removals and isinstance(removals, dict):
                        if target_id and target_id in removals:
                            if removals[target_id].get("status") in ("succeeded", "failed"):
                                removals.pop(target_id, None)
                        elif not target_id or kind == "all":
                            p["node_removals"] = {k: v for k, v in removals.items() if v.get("status") in ("queued", "running")}
                if kind in ('gre','all') and p.get('gre_update',{}).get('status') in ('succeeded','failed'):
                    p.pop('gre_update',None)
                # Clear node_additions
                if kind in ("addition", "all"):
                    additions = p.get("node_additions")
                    if additions and isinstance(additions, dict):
                        if target_id and target_id in additions:
                            if additions[target_id].get("status") in ("succeeded", "failed"):
                                additions.pop(target_id, None)
                        elif not target_id or kind == "all":
                            p["node_additions"] = {k: v for k, v in additions.items() if v.get("status") in ("queued", "running")}

            atomic_update(_clear_op)
            return self._send_json({"success": True, "message": "پیام عملیات با موفقیت پاک شد"})

        elif path == "/api/pools/dns-route":
            name = str(body.get("pool", "")).strip()
            mode = body.get("mode")
            ip = str(body.get("ip", "")).strip()
            with routing_lock():
                data = load_data()
                pool = data.get("pools", {}).get(name)
                if not pool or mode not in ("auto", "manual"):
                    return self._send_json({"error": "استخر یا حالت DNS نامعتبر است"}, 400)
                config = effective_config(data, name)
                key = route_key(config)
                if mode == "auto":
                    def restore_auto(data):
                        data.setdefault("dns_overrides", {}).pop(key, None)
                    atomic_update(restore_auto)
                    return self._send_json({"success": True, "message": "حالت خودکار فعال شد؛ مسیر در پایش بعدی هماهنگ می‌شود"})
                if ip not in [node.get("ip") for node in pool.get("nodes", [])]:
                    return self._send_json({"error": "این آی‌پی عضو استخر نیست"}, 400)
                if not all(config.get(field) for field in ("api_token", "zone_id", "subdomain")) or not config.get("enabled"):
                    return self._send_json({"error": "ابتدا تنظیمات کلودفلر استخر را فعال کنید"}, 400)
                manager = CloudflareManager(config["api_token"], config["zone_id"])
                manager.scope = config.get('scope','single')
                before = manager.record_snapshot(config["subdomain"])
                if not before.get("success"):
                    return self._send_json({"error": "خواندن رکورد DNS ناموفق بود؛ تغییری اعمال نشد"}, 502)
                sync = manager.sync_subdomain(config["subdomain"], [ip], proxied=False, ttl=60)
                snapshot = manager.record_snapshot(config["subdomain"])
                if not snapshot_matches(snapshot, [ip]):
                    return self._send_json({"error": "انتقال کامل DNS تأیید نشد؛ وضعیت رکوردها را دوباره بررسی کنید"}, 502)
                override = {"ip": ip, "changed_at": time.strftime("%Y-%m-%d %H:%M:%S"), "version": secrets.token_hex(12)}
                def save_manual(data):
                    data.setdefault("dns_overrides", {})[key] = override
                    reports = data.setdefault("watchdog_status", {}).setdefault("pool_reports", {})
                    for pool_name in data.get("pools", {}):
                        if route_key(effective_config(data, pool_name)) == key:
                            reports[pool_name] = {"scope": config.get("scope","single"), "subdomain": config["subdomain"], "checked_at": override["changed_at"], "dns_snapshot": snapshot, "source": "manual", "override_version": override["version"], "cloudflare_sync": sync}
                atomic_update(save_manual)
                return self._send_json({"success": True, "message": "DNS به آی‌پی انتخاب‌شده منتقل شد؛ حالت دستی فعال است"})

        elif path == "/api/pools/cloudflare-preview":
            token, zone, domain = (body.get(k, '').strip() for k in ('api_token','zone_id','subdomain'))
            if not token or not zone or not domain:
                return self._send_json({'error':'توکن، Zone ID و دامنه را وارد کنید'},400)
            result = CloudflareManager(token,zone).subdomain_records(domain)
            if not result.get('success'): return self._send_json({'error':result.get('error','خواندن رکوردها ناموفق بود')},502)
            if not result.get('names'): return self._send_json({'error':'هیچ ساب‌دامینی با رکورد A پیدا نشد'},400)
            return self._send_json({'success':True,'names':result['names'], 'records':[{k:r.get(k) for k in ('name','content','proxied')} for r in result['records']]})

        elif path == "/api/pools/cloudflare":
            pool_name = body.get("pool", "").strip()
            token = body.get("api_token", "").strip()
            zone_id = body.get("zone_id", "").strip()
            subdomain = body.get("subdomain", "").strip()
            enabled = bool(body.get("enabled", True))

            if token.startswith("…"):
                stored = effective_config(load_data(), pool_name).get("api_token", "") if pool_name else ""
                if stored and token == "…" + stored[-4:]:
                    token = stored
                else:
                    return self._send_json({"error": "توکن ذخیره‌شده با فرم مطابقت ندارد؛ توکن کامل را وارد کنید"}, 400)

            if not pool_name or not token or not zone_id or not subdomain:
                return self._send_json({"error": "نام استخر، API Token، Zone ID و ساب‌دومین الزامی است"}, 400)

            scope = body.get('scope','single')
            if scope not in ('single','all_subdomains'): return self._send_json({'error':'محدوده DNS نامعتبر است'},400)
            if scope == 'all_subdomains': subdomain = subdomain.lower().removeprefix('*.').rstrip('.')
            with routing_lock():
                if scope == 'all_subdomains':
                    preview = CloudflareManager(token,zone_id).subdomain_records(subdomain)
                    if not preview.get('success') or not preview.get('names'):
                        return self._send_json({'error':'خواندن کامل رکوردها تأیید نشد؛ تنظیمات ذخیره نشد'},502)
                    if sorted(body.get('confirmed_names',[])) != preview['names']:
                        return self._send_json({'error':'فهرست رکوردها تغییر کرده؛ پیش‌نمایش را دوباره دریافت کنید'},409)
                ok, msg = LoadBalancerManager.set_pool_cloudflare(pool_name, token, zone_id, subdomain, enabled, scope=scope)
            if ok:
                return self._send_json({"success": True, "message": msg})
            else:
                return self._send_json({"error": msg}, 400)

        elif path == "/api/pools/composition/validate":
            from core.composition_schema import validate_composition, UnifiedComposition, NetworkLayerSpec, EncryptionLayerSpec, CamouflageLayerSpec
            comp_dict = body.get("composition", {})
            try:
                comp = UnifiedComposition(
                    engine=comp_dict.get("engine", "custom"),
                    network=NetworkLayerSpec(**comp_dict.get("network", {})),
                    encryption=EncryptionLayerSpec(**comp_dict.get("encryption", {})),
                    camouflage=CamouflageLayerSpec(**comp_dict.get("camouflage", {})),
                )
                valid, msg = validate_composition(comp)
                return self._send_json({"valid": valid, "message": msg, "composition": comp.to_dict()})
            except Exception as e:
                return self._send_json({"valid": False, "message": str(e)}, 400)

        # ---- Cloudflare profile + DNS management (token-only, multi-profile) ----
        elif path == "/api/cloudflare/profiles":
            action = str(body.get("action", "create")).strip().lower()
            if action == "create":
                label = str(body.get("label", "")).strip()[:60] or "Cloudflare"
                token = str(body.get("token", "")).strip()
                if not token:
                    return self._send_json({"error": "API Token الزامی است"}, 400)
                mgr = CloudflareManager(token)
                ok, err = mgr.verify_token()
                if not ok:
                    return self._send_json({"error": f"توکن نامعتبر است: {err}"}, 400)
                res = mgr.list_zones()
                if not res.get("success"):
                    return self._send_json({"error": res.get("error", "کشف Zoneها ناموفق بود")}, 502)
                import datetime
                pid = "cf-" + secrets.token_hex(8)
                zones = [{"id": z.get("id"), "name": z.get("name"),
                          "status": z.get("status"), "paused": z.get("paused", False),
                          "name_servers": z.get("name_servers", [])}
                         for z in res.get("zones", [])]
                now = datetime.datetime.utcnow().isoformat() + "Z"
                save_cf_profile(pid, {
                    "label": label, "token": token, "enabled": True,
                    "created_at": now, "updated_at": now,
                    "last_validated_at": now,
                    "zone_cache": zones, "zone_cache_fetched_at": now,
                })
                cf_audit("profile.create", pid, detail=f"{len(zones)} zones")
                return self._send_json({
                    "success": True,
                    "profile": cf_profile_public(pid, get_cf_profile(pid)),
                    "zones": zones
                }, 201)
            return self._send_json({"error": "Invalid action"}, 400)

        elif path.startswith("/api/cloudflare/profiles/"):
            # /api/cloudflare/profiles/{pid}   or   .../{pid}/rotate-token
            rest = path[len("/api/cloudflare/profiles/"):].strip("/")
            parts = rest.split("/")
            pid = parts[0]
            profile = get_cf_profile(pid)
            if not profile:
                return self._send_json({"error": "پروفایل یافت نشد"}, 404)
            if len(parts) == 1:
                action = str(body.get("action", "")).strip().lower()
                if action == "update":
                    fields = {}
                    if "label" in body:
                        fields["label"] = str(body["label"]).strip()[:60]
                    if "enabled" in body:
                        fields["enabled"] = bool(body["enabled"])
                    import datetime
                    fields["updated_at"] = datetime.datetime.utcnow().isoformat() + "Z"
                    update_cf_profile(pid, fields)
                    cf_audit("profile.update", pid, detail=str(list(fields)))
                    return self._send_json({"success": True,
                        "profile": cf_profile_public(pid, get_cf_profile(pid))})
                elif action == "delete":
                    deleted, using = delete_cf_profile(pid)
                    if using:
                        return self._send_json({
                            "error": "این پروفایل در حال استفاده است",
                            "pools": using
                        }, 409)
                    if not deleted:
                        return self._send_json({"error": "پروفایل یافت نشد"}, 404)
                    cf_audit("profile.delete", pid)
                    return self._send_json({"success": True})
                return self._send_json({"error": "Invalid action"}, 400)
            elif parts[1] == "rotate-token":
                token = str(body.get("token", "")).strip()
                if not token:
                    return self._send_json({"error": "API Token جدید الزامی است"}, 400)
                mgr = CloudflareManager(token)
                ok, err = mgr.verify_token()
                if not ok:
                    return self._send_json({"error": f"توکن نامعتبر است: {err}"}, 400)
                import datetime
                update_cf_profile(pid, {
                    "token": token,
                    "last_validated_at": datetime.datetime.utcnow().isoformat() + "Z",
                    "zone_cache": [],  # force rediscovery with new token
                })
                cf_audit("profile.rotate-token", pid)
                return self._send_json({"success": True})
            return self._send_json({"error": "Not Found"}, 404)

        elif path == "/api/cloudflare/records":
            # create / update / delete a DNS record — profile+zone verified server-side
            action = str(body.get("action", "")).strip().lower()
            pid = str(body.get("profile_id", "")).strip()
            zid = str(body.get("zone_id", "")).strip()
            record_id = str(body.get("record_id", "")).strip()
            profile = get_cf_profile(pid)
            if not profile or not profile.get("enabled", True):
                return self._send_json({"error": "پروفایل یافت نشد یا غیرفعال است"}, 404)
            if not any(z.get("id") == zid for z in profile.get("zone_cache", [])):
                return self._send_json({"error": "Zone برای این پروفایل مجاز نیست"}, 403)
            mgr = CloudflareManager(profile.get("token", ""))
            if action == "create":
                record = body.get("record") or {}
                ok, rid_or_err = mgr.create_record(zid, record)
                cf_audit("record.create", pid, zid,
                         f"{record.get('type','')} {record.get('name','')}", ok)
                return self._send_json(
                    {"success": True, "record_id": rid_or_err} if ok
                    else {"error": rid_or_err}, 201 if ok else 400)
            elif action == "update":
                record = body.get("record") or {}
                if not record_id:
                    return self._send_json({"error": "record_id الزامی است"}, 400)
                ok, res = mgr.update_record(zid, record_id, record)
                cf_audit("record.update", pid, zid, record_id, ok)
                return self._send_json({"success": True} if ok else {"error": res},
                                       200 if ok else 400)
            elif action == "patch":
                fields = body.get("fields") or {}
                if not record_id:
                    return self._send_json({"error": "record_id الزامی است"}, 400)
                ok, res = mgr.patch_record(zid, record_id, fields)
                cf_audit("record.patch", pid, zid, record_id, ok)
                return self._send_json({"success": True} if ok else {"error": res},
                                       200 if ok else 400)
            elif action == "delete":
                if not record_id:
                    return self._send_json({"error": "record_id الزامی است"}, 400)
                ok, res = mgr.delete_record_zoned(zid, record_id)
                cf_audit("record.delete", pid, zid, record_id, ok)
                return self._send_json({"success": True} if ok else {"error": res},
                                       200 if ok else 400)
            return self._send_json({"error": "Invalid action"}, 400)

        elif path == "/api/cloudflare":
            token = body.get("api_token", "").strip()
            zone_id = body.get("zone_id", "").strip()
            subdomain = body.get("subdomain", "").strip()
            enabled = bool(body.get("enabled", True))

            if token.startswith("…"):
                stored = load_data().get("cloudflare", {}).get("api_token", "")
                if stored and token == "…" + stored[-4:]:
                    token = stored
                else:
                    return self._send_json({"error": "توکن ذخیره‌شده با فرم مطابقت ندارد؛ توکن کامل را وارد کنید"}, 400)

            if not token or not zone_id or not subdomain:
                return self._send_json({"error": "API Token، Zone ID و ساب‌دومین الزامی است"}, 400)

            TelemetryWatchdog.set_cloudflare_config(token, zone_id, subdomain, enabled)
            return self._send_json({"success": True, "message": "تنظیمات عمومی کلودفلر ذخیره شد"})

        elif path == "/api/ports":
            pool_name = body.get("pool")
            action = body.get("action")
            if not pool_name:
                return self._send_json({"error": "Missing pool name"}, 400)
            
            from core.pool_tasks import start as start_task
            if action not in ('add','remove'):
                return self._send_json({"error": "Invalid action"}, 400)
            ok, result = start_task(pool_name, 'ports_' + action, body.get('ports',[]) if action=='add' else body.get('port',''))
            return self._send_json({"success": True, "accepted": True, "job": result} if ok else {"error": result}, 202 if ok else 409)

        elif path == "/api/system/restart":
            # Restart the panel in place: a detached helper briefly waits for
            # this response to flush, terminates the current process, then
            # starts a fresh copy on the same port.
            import signal
            port = get_web_port() or 8088
            script = os.path.abspath(__file__)
            helper = (
                "import os,sys,time,subprocess,signal;"
                "time.sleep(1);"
                f"target={os.getpid()!r};"
                "\n"
                "try:\n"
                "    os.kill(target, signal.SIGTERM)\n"
                "except OSError:\n"
                "    pass\n"
                "deadline=time.time()+30\n"
                "while time.time()<deadline:\n"
                "    try:\n"
                "        os.kill(target,0); time.sleep(0.3); continue\n"
                "    except OSError:\n"
                "        break\n"
                f"subprocess.Popen([sys.executable,{script!r},'--foreground',{port!r}],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
                "stdin=subprocess.DEVNULL,start_new_session=True)"
            )
            _spawn_detached([sys.executable, "-c", helper])
            return self._send_json({"success": True, "message": "پنل در حال راه‌اندازی مجدد است؛ چند ثانیه صبر کنید و صفحه را تازه کنید"})

        elif path == "/api/password":
            new_pass = body.get("new_password", "")
            if len(new_pass) < 8:
                return self._send_json({"error": "رمز عبور باید حداقل ۸ کاراکتر باشد"}, 400)
            def _change_p(d: dict):
                d["web_password"] = _hash_password(new_pass)
            atomic_update(_change_p)
            current_tok = self._get_auth_token()
            AUTH_TOKENS.clear()
            if current_tok:
                AUTH_TOKENS[current_tok] = time.time() + 86400
            return self._send_json({"success": True, "message": "رمز عبور داشبورد با موفقیت به‌روزرسانی شد"})

        elif path == "/api/dashboard-domain":
            domain = str(body.get("domain", "")).strip().lower()
            ssl_mode = str(body.get("ssl_mode", "cloudflare")).strip().lower()
            action = str(body.get("action", "save")).strip().lower()

            if action == "issue_ssl":
                if not domain:
                    return self._send_json({"error": "ابتدا نام دامنه را وارد کنید"}, 400)
                ok, msg = issue_letsencrypt_cert(domain)
                if not ok:
                    def _save_err(d: dict):
                        cfg = d.setdefault("dashboard_domain", {})
                        cfg["last_error"] = msg
                    atomic_update(_save_err)
                    return self._send_json({"error": msg}, 400)
                
                # Re-apply nginx with letsencrypt mode
                nginx_ok, nginx_msg = apply_nginx_config(domain, ssl_mode="letsencrypt")
                if not nginx_ok:
                    return self._send_json({"error": f"گواهینامه دریافت شد ولی اعمال وب‌سرور با خطا مواجه شد: {nginx_msg}"}, 500)
                
                def _save_le_success(d: dict):
                    cfg = d.setdefault("dashboard_domain", {})
                    cfg["domain"] = domain
                    cfg["ssl_mode"] = "letsencrypt"
                    cfg["configured"] = True
                    cfg["ssl_active"] = True
                    cfg["last_error"] = ""
                atomic_update(_save_le_success)
                return self._send_json({"success": True, "message": "گواهینامه Let's Encrypt با موفقیت صادر و فعال شد!"})

            # Save configuration (Cloudflare or standard proxy)
            nginx_ok, nginx_msg = apply_nginx_config(domain, ssl_mode=ssl_mode)
            if not nginx_ok:
                return self._send_json({"error": f"خطا در اعمال وب‌سرور: {nginx_msg}"}, 500)

            def _save_cfg(d: dict):
                cfg = d.setdefault("dashboard_domain", {})
                cfg["domain"] = domain
                cfg["ssl_mode"] = ssl_mode
                cfg["configured"] = bool(domain)
                cfg["ssl_active"] = True
                cfg["last_error"] = ""
            atomic_update(_save_cfg)
            return self._send_json({
                "success": True,
                "message": "تنظیمات دامنه و پروکسی با موفقیت ذخیره و فعال شد",
                "domain_config": get_dashboard_domain_config()
            })

        self.send_error(404, "Not Found")

PID_FILE = os.path.join(DATA_DIR, "web.pid")
PORT_FILE = os.path.join(DATA_DIR, "web.port")

def get_web_pid() -> int:
    if os.path.exists(PID_FILE):
        try:
            with open(PID_FILE, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            return pid
        except (ValueError, OSError):
            return 0
    return 0

def is_web_running() -> bool:
    return get_web_pid() > 0

def get_web_port() -> int:
    if os.path.exists(PORT_FILE):
        try:
            with open(PORT_FILE, "r") as f:
                return int(f.read().strip())
        except (ValueError, OSError):
            pass
    return 8088

def open_web_port(port: int) -> tuple[bool, str]:
    """Try to open the dashboard TCP port in common firewall frontends."""
    if port <= 0 or port > 65535:
        return False, "invalid port"
    import shutil
    import subprocess
    if shutil.which("ufw"):
        result = subprocess.run(["ufw", "allow", f"{port}/tcp"], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return True, "ufw rule added"
        return False, (result.stderr or result.stdout or "ufw failed").strip()
    if shutil.which("nft"):
        result = subprocess.run(["nft", "add", "rule", "inet", "filter", "input", "tcp", "dport", str(port), "accept"], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return True, "nftables rule added"
    if shutil.which("iptables"):
        check = subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True, text=True, timeout=15)
        if check.returncode == 0:
            return True, "iptables rule already present"
        result = subprocess.run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return True, "iptables rule added"
        return False, (result.stderr or result.stdout or "iptables failed").strip()
    return False, "no supported firewall tool found"

def _spawn_detached(cmd):
    import subprocess
    subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        start_new_session=True
    )


def start_background_web(port: int = 8088) -> bool:
    if is_web_running():
        return True
    cmd = [sys.executable, os.path.abspath(__file__), "--foreground", str(port)]
    _spawn_detached(cmd)
    # Give it a moment to bind and write pid
    for _ in range(15):
        time.sleep(0.2)
        if is_web_running():
            return True
    return False

def stop_background_web() -> bool:
    pid = get_web_pid()
    if pid > 0:
        import signal
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(15):
                time.sleep(0.2)
                try:
                    os.kill(pid, 0)
                except OSError:
                    break
            else:
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except OSError:
                pass
        return True
    return False

def run_web_server(host: str = None, port: int = 8088):
    import signal
    # Security: bind localhost by default. The dashboard holds SSH credentials
    # for the whole fleet -- it must not be on 0.0.0.0 unless the operator
    # explicitly opts in via VX_LB_WEB_HOST (prefer an SSH tunnel instead).
    if host is None:
        host = os.environ.get("VX_LB_WEB_HOST", "127.0.0.1")
    if host == "0.0.0.0":
        print("[!] WARNING: web dashboard bound to 0.0.0.0 -- ensure the dashboard password is set and the port is firewalled.")
    
    # Save PID and Port
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    with open(PORT_FILE, "w") as f:
        f.write(str(port))

    from core.link_tasks import recover as recover_link_tasks
    recover_link_tasks()
    from core.pool_creation import recover as recover_pool_creation
    recover_pool_creation()
    from core.pool_tasks import recover as recover_pool_tasks
    recover_pool_tasks()
    recover_node_removals()
    recover_node_additions()
    from core.gre import recover_interrupted
    recover_interrupted()
    recover_changes()
    server = ThreadedHTTPServer((host, port), LDWebRequestHandler)
    print(f"[*] VX-LB Mobile Web Dashboard running on http://{host}:{port} (PID: {os.getpid()})")
    
    def _cleanup_and_exit(sig=None, frame=None):
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
        except Exception:
            pass
        try:
            # The signal handler runs on the serve_forever thread; shutdown()
            # would wait for this same thread and deadlock. Closing is enough
            # because SystemExit below unwinds serve_forever.
            server.server_close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup_and_exit)
    signal.signal(signal.SIGINT, _cleanup_and_exit)

    try:
        server.serve_forever()
    except Exception:
        pass
    finally:
        _cleanup_and_exit()

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--start" in args:
        idx = args.index("--start")
        p = int(args[idx + 1]) if idx + 1 < len(args) and args[idx + 1].isdigit() else 8088
        if start_background_web(p):
            print(f"SUCCESS: Web Dashboard started on port {p} (PID: {get_web_pid()})")
            sys.exit(0)
        else:
            print("ERROR: Failed to start Web Dashboard")
            sys.exit(1)
    elif "--stop" in args:
        if stop_background_web():
            print("SUCCESS: Web Dashboard stopped")
        else:
            print("INFO: Web Dashboard was not running")
        sys.exit(0)
    elif "--status" in args:
        if is_web_running():
            print(f"RUNNING: PID={get_web_pid()} PORT={get_web_port()}")
            sys.exit(0)
        else:
            print("STOPPED")
            sys.exit(1)
    elif "--foreground" in args:
        idx = args.index("--foreground")
        p = int(args[idx + 1]) if idx + 1 < len(args) and args[idx + 1].isdigit() else 8088
        run_web_server(port=p)
    else:
        p = int(args[0]) if args and args[0].isdigit() else 8088
        run_web_server(port=p)
