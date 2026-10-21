"""Slipstream DNS-tunneling emergency fallback adapter for VX-LB.

Slipstream DNS tunnel with delegated subdomain configuration,
recursive resolver pool, client/server configuration generation, rate-limiting,
transactional rollback, and BaseTunnelAdapter lifecycle integration.
"""
import copy
import json
import logging
import os
import secrets
import shlex
import time
from typing import Dict, List, Tuple, Optional, Any

from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.dependency_manifest import get_dependency_manifest, validate_binary_prerequisites
from core.ssh_client import SSHManager
from core.validation import validate_pool_name, validate_tunnel_name, validate_port, validate_ports

logger = logging.getLogger("vxlb.slipstream_adapter")

DEFAULT_DNS_RESOLVERS = [
    "1.1.1.1:53",
    "8.8.8.8:53",
    "9.9.9.9:53",
]


def _service_name(identifier):
    stem = str(identifier).removesuffix(".service")
    if not stem.startswith("vxlb-slipstream-"):
        stem = "vxlb-slipstream-" + stem
    return validate_tunnel_name(stem) + ".service"


class SlipstreamAdapter(BaseTunnelAdapter):
    """Full lifecycle adapter for Slipstream DNS emergency tunneling."""

    def __init__(self):
        super().__init__("slipstream")
        self.binary_name = "slipstream"

    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        """Verify or install slipstream binary on remote host.

        Local-first policy: prefer the verified bundled depot over any network
        fetch. A remote download is attempted only when the operator explicitly
        opts in via ``config["allow_download"]`` and no local artifact exists.
        """
        if role not in ("iran", "kharej"):
            return False, "Slipstream role must be iran or kharej"
        manifest = get_dependency_manifest("slipstream-server" if role == "kharej" else "slipstream")
        code, arch, err = ssh.execute("uname -m")
        if code or arch.strip() not in manifest.architectures:
            return False, f"Architecture '{arch.strip()}' not supported in dependency manifest for slipstream"
        artifact = manifest.architectures[arch.strip()]
        expected = artifact.get("sha256")
        if not artifact.get("is_verified") or not expected:
            return False, "Slipstream release has no verified checksum"
        destination = "/usr/local/bin/" + manifest.executable_name
        arch_clean = arch.strip()

        # 1. If the destination already matches the pinned SHA-256, done.
        probe = (
            f"if [ -x {shlex.quote(destination)} ]; then "
            f"sha256sum {shlex.quote(destination)} | awk '{{print $1}}'; fi"
        )
        code, out, _ = ssh.execute(probe)
        if code == 0 and out.strip().lower() == expected.lower():
            ssh.execute(f"chmod 755 {shlex.quote(destination)}")
            return True, f"Slipstream {manifest.pinned_version} already installed with verified SHA-256"

        # 2. Local-first: try the bundled depot before any remote network use.
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidate = os.path.join(base_dir, "bin", arch_clean, manifest.executable_name)
        if os.path.isfile(candidate):
            import hashlib
            with open(candidate, "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() == expected:
                    if hasattr(ssh, "upload_binary") and ssh.upload_binary(candidate, destination, mode=0o755):
                        code, out, _ = ssh.execute(
                            f"sha256sum {shlex.quote(destination)} | awk '{{print $1}}'"
                        )
                        if code == 0 and out.strip().lower() == expected.lower():
                            return True, f"Slipstream installed from local bundled binary ({arch_clean})"
                        return False, "Slipstream local upload succeeded but post-install checksum failed"

        # 3. Remote download only when the operator explicitly allows it.
        if not config.get("allow_download"):
            return False, (
                "Slipstream verified local binary unavailable and remote download "
                "is disabled (strict offline). Bundle bin/%s/%s or set allow_download=True."
                % (arch_clean, manifest.executable_name)
            )

        # Download beside the destination; verify before replacing an existing
        # executable. A failure leaves the installed file untouched.
        program = """import hashlib,os,sys,tempfile,urllib.request
url,expected,destination=sys.argv[1:]
if os.path.isfile(destination):
 digest=hashlib.sha256()
 with open(destination,'rb') as src:
  for chunk in iter(lambda:src.read(65536),b''):digest.update(chunk)
 current=digest.hexdigest()
 if current==expected:
  os.chmod(destination,0o755);sys.exit(0)
os.makedirs(os.path.dirname(destination),exist_ok=True)
fd,path=tempfile.mkstemp(prefix='.vxlb-slipstream-',dir=os.path.dirname(destination))
try:
 with os.fdopen(fd,'wb') as target, urllib.request.urlopen(url,timeout=60) as response:
  digest=hashlib.sha256()
  while True:
   chunk=response.read(65536)
   if not chunk:break
   target.write(chunk);digest.update(chunk)
  target.flush();os.fsync(target.fileno())
 if digest.hexdigest()!=expected:raise RuntimeError('Slipstream SHA-256 mismatch')
 os.chmod(path,0o755);os.replace(path,destination)
finally:
 if os.path.exists(path):os.unlink(path)
"""
        command = "python3 -c " + shlex.quote(program) + " " + " ".join(
            shlex.quote(value) for value in (artifact["source_url"], expected, destination)
        )
        code, out, err = ssh.execute(command, timeout=120)
        if code:
            return False, f"Failed to install verified Slipstream binary: {err or out}"
        return True, f"Slipstream {manifest.pinned_version} {manifest.executable_name} successfully installed with SHA-256 verification"

    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        """Generate client/server configuration and systemd service units."""
        from core.slipstream_deploy import plan
        return plan(iran_node, kharej_server, pool_config)

    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Start slipstream systemd service."""
        svc = _service_name(identifier)
        cmd = f"systemctl daemon-reload && systemctl enable {svc} && systemctl restart {svc}"
        code, out, err = ssh.execute(cmd)
        if code != 0:
            return False, f"Failed to start {svc}: {err or out}"
        return True, f"Service {svc} started"

    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Stop and disable slipstream systemd service."""
        svc = _service_name(identifier)
        cmd = f"systemctl stop {svc} 2>/dev/null; systemctl disable {svc} 2>/dev/null"
        code, out, err = ssh.execute(cmd)
        if code != 0:
            return False, f"Failed to stop {svc}: {err or out}"
        return True, f"Service {svc} stopped"

    def status(self, ssh: SSHManager, identifier: str) -> dict:
        """Query host for service status and process state."""
        svc = _service_name(identifier)
        code, out, _ = ssh.execute(f"systemctl is-active {svc}")
        is_active = (code == 0 and out.strip() == "active")
        
        # Check listening port
        code, ss_out, _ = ssh.execute("ss -tuln | grep -E ':53[ \t]' || true")

        return {
            "engine": "slipstream",
            "service": svc,
            "status": "DEGRADED" if is_active else "DOWN",
            "data_path": "UNVERIFIED",
            "is_active": is_active,
            "dns_listener_detected": bool(ss_out.strip()),
        }

    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        """Active health probe verifying DNS tunnel data carrier."""
        from core.slipstream_deploy import probe
        node = kwargs.get("node") or {}
        path = kwargs.get("config_path") or node.get("slipstream_config_path")
        if path and hasattr(endpoint_ir, "execute"):
            import re
            if re.fullmatch(r"/etc/vxlb/slipstream/[0-9a-f]{16}/[0-9a-f]{16}-[0-9a-f]{10}\.json", str(path)):
                return probe(endpoint_ir, path)
        return {"passed": False, "status": "UNVERIFIED", "latency_ms": None,
                "protocols": [], "error": "Slipstream node has no verified runtime configuration"}

    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        """Modify configuration parameters (domain, resolvers, MTU) transactionally."""
        from core.slipstream_update import change
        return change(pool_name, updates)

    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        from core.slipstream_update import recover
        return recover(pool_name)

    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Stop services and purge configuration files."""
        from core.slipstream_deploy import plan, cleanup
        for pool in get_pools().values():
            if pool.get("engine") != "slipstream":
                continue
            for node in pool.get("nodes", []):
                if node.get("node_name") == identifier:
                    try:
                        cfg = plan(node, pool["kharej_server"], pool)
                        cleanup(ssh, cfg["client_files"], cfg["client_services"])
                        return True, "Slipstream resources removed"
                    except Exception as error:
                        return False, str(error)
        return False, "Slipstream resource ownership was not found; no files removed"


# Register adapter instance in registry
_slipstream_adapter_instance = SlipstreamAdapter()
register_adapter(_slipstream_adapter_instance)


def get_pools() -> dict:
    from core.storage import load_data
    return load_data().get("pools", {})


def save_pool(name: str, pool_data: dict):
    from core.storage import atomic_update
    def _update(data):
        if "pools" not in data:
            data["pools"] = {}
        data["pools"][name] = pool_data
        return data
    atomic_update(_update)


def create(name, kharej, servers, ports, domain=None, resolvers=None, dns_port=53, callback=None, **kwargs):
    from core.slipstream_deploy import create as deploy_create
    return deploy_create(name, kharej, servers, ports, domain, resolvers, dns_port, callback, **kwargs)


def add(name, server, callback=None):
    from core.slipstream_deploy import add as deploy_add
    return deploy_add(name, server, callback)


def remove(name, iran_ip, callback=None):
    from core.slipstream_deploy import remove as deploy_remove
    return deploy_remove(name, iran_ip, callback)


def delete_pool(name, callback=None):
    from core.slipstream_deploy import delete_pool as deploy_delete
    return deploy_delete(name, callback)


def health(pool_name, node, ports):
    from core.slipstream_deploy import connection
    from core.storage import load_data
    if node.get("provisioning") or not node.get("slipstream_config_path"):
        return "IDLE", "راه‌اندازی امن Slipstream کامل نشده است", {}
    server = next((item for item in load_data().get("iran_servers", []) if item.get("ip") == node["ip"]), None)
    if not server:
        return "IDLE", "اطلاعات اتصال نود یافت نشد", {}
    ssh = None
    try:
        ssh = connection(server)
        result = SlipstreamAdapter().probe(ssh, None, node=node)
        details = {str(port): {"transport_probe": result, "status": "UNVERIFIED"} for port in ports}
        if not result.get("passed"):
            return "FILTERED", "آزمون دادهٔ احرازهویت‌شدهٔ مسیر DNS ناموفق بود", details
        # مسیر DNS و TLS 1.3 و احراز هویت متقابل تأیید شد؛ این پروب سلامت مسیر
        # دیتاپلین را اثبات می‌کند و برای ورود نود به لیست DNS کافی است. سلامت
        # برنامهٔ نهایی در مقصد از طریق مکانیسم‌های دیگر پایش می‌شود.
        return "HEALTHY", "مسیر DNS و TLS با احراز هویت متقابل تأیید شد", details
    except Exception:
        return "IDLE", "ارزیابی مسیر Slipstream کامل نشد", {}
    finally:
        if ssh:
            ssh.close()
