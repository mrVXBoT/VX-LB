"""Port forwarding relay driver for independent private links.

Enables TCP/UDP port forwarding from an ingress endpoint across the verified
private /30 subnet to the destination peer. Supports atomic configuration,
systemd lifecycle, listener ownership verification, and clean removal.
"""
import hashlib
import ipaddress
import json
import logging
import re
import shlex
import time
from typing import Dict, List, Optional, Tuple, Any

from core.storage import load_data, atomic_update
from core.transport_change import mutation_lock, busy, connect
from core.validation import validate_port

logger = logging.getLogger("ldbp.private_link_forwarding")


def validate_rule(rule: dict) -> dict:
    if not isinstance(rule, dict):
        raise ValueError("Forwarding rule must be a dictionary")
    listen_port = int(validate_port(rule.get("listen_port") or rule.get("port")))
    target_port = int(validate_port(rule.get("target_port") or listen_port))
    protocol = str(rule.get("protocol", "both")).lower()
    if protocol not in ("tcp", "udp", "both"):
        raise ValueError("Protocol must be 'tcp', 'udp', or 'both'")
    return {
        "listen_port": listen_port,
        "target_port": target_port,
        "protocol": protocol,
    }


def validate_forwarding_rules(rules: List[dict], excluded_ports: Optional[List[int]] = None) -> List[dict]:
    if not isinstance(rules, list) or not rules:
        raise ValueError("At least one port forwarding rule is required")
    excluded = set(excluded_ports or [])
    validated = []
    seen_listen_ports = set()
    for item in rules:
        rule = validate_rule(item)
        lp = rule["listen_port"]
        if lp in seen_listen_ports:
            raise ValueError(f"Duplicate listen port {lp} in forwarding rules")
        if lp in excluded:
            raise ValueError(f"Port {lp} is reserved or conflicts with link tunnel port")
        seen_listen_ports.add(lp)
        validated.append(rule)
    return validated


def render_relay_script(peer_ip: str, rules: List[dict]) -> str:
    rules_json = json.dumps(rules)
    return f'''#!/usr/bin/env python3
"""LD-BP standalone private link port forwarding daemon."""
import asyncio, json, sys, time

PEER = {peer_ip!r}
RULES = {rules_json}

async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass

async def forward_tcp(reader, writer, target_port):
    try:
        r_remote, w_remote = await asyncio.wait_for(
            asyncio.open_connection(PEER, target_port), 8
        )
    except Exception:
        writer.close()
        return
    try:
        await asyncio.gather(pipe(reader, w_remote), pipe(r_remote, writer))
    finally:
        writer.close()
        w_remote.close()

class UdpReplies(asyncio.DatagramProtocol):
    def __init__(self, parent, addr):
        self.parent = parent
        self.addr = addr
    def datagram_received(self, data, addr):
        if self.addr in self.parent.sessions:
            self.parent.sessions[self.addr][1] = time.monotonic()
            self.parent.transport.sendto(data, self.addr)

class UdpRelay(asyncio.DatagramProtocol):
    def __init__(self, target_port):
        self.target_port = target_port
        self.sessions = {{}}
        self.transport = None
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        if addr in self.sessions:
            self.sessions[addr][1] = time.monotonic()
            self.sessions[addr][0].sendto(data)
            return
        if len(self.sessions) >= 2048:
            return
        asyncio.create_task(self.setup_peer(data, addr))
    async def setup_peer(self, data, addr):
        try:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: UdpReplies(self, addr), remote_addr=(PEER, self.target_port)
            )
            self.sessions[addr] = [transport, time.monotonic()]
            transport.sendto(data)
        except Exception:
            pass
    def sweep(self):
        now = time.monotonic()
        for addr, (tr, t_last) in list(self.sessions.items()):
            if now - t_last > 60:
                tr.close()
                del self.sessions[addr]

async def main():
    loop = asyncio.get_running_loop()
    servers = []
    udp_transports = []
    udp_protocols = []
    for r in RULES:
        lp = r["listen_port"]
        tp = r["target_port"]
        proto = r["protocol"]
        if proto in ("tcp", "both"):
            srv = await asyncio.start_server(
                lambda rdr, wtr, port=tp: forward_tcp(rdr, wtr, port), "0.0.0.0", lp
            )
            servers.append(srv)
        if proto in ("udp", "both"):
            tr, pr = await loop.create_datagram_endpoint(
                lambda port=tp: UdpRelay(port), local_addr=("0.0.0.0", lp)
            )
            udp_transports.append(tr)
            udp_protocols.append(pr)

    async def janitor():
        while True:
            await asyncio.sleep(15)
            for pr in udp_protocols:
                pr.sweep()

    sweep_task = asyncio.create_task(janitor())
    try:
        await asyncio.Event().wait()
    finally:
        sweep_task.cancel()
        for s in servers:
            s.close()
            await s.wait_closed()
        for tr in udp_transports:
            tr.close()

if __name__ == "__main__":
    asyncio.run(main())
'''


def render_relay_unit(service_name: str, script_path: str, interface: str) -> str:
    return f"""[Unit]
Description=LD-BP Private Link Port Forwarding Relay ({service_name})
After=network.target wg-quick@{interface}.service
Requires=wg-quick@{interface}.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""


def apply_forwarding_rules(link_name: str, rules: List[dict]) -> Tuple[bool, str]:
    """Installs and activates port forwarding relay on the Iran endpoint of an active link."""
    with mutation_lock():
        data = load_data()
        if busy(data):
            return False, "Another runtime mutation is active"
        link = data.get("custom_links", {}).get(link_name)
        if not link:
            return False, f"Private link '{link_name}' not found"
        if link.get("status") != "active":
            return False, f"Private link must be in 'active' status to enable port forwarding (current: {link.get('status')})"

        validated = validate_forwarding_rules(rules, excluded_ports=[link.get("tunnel_port", 0)])

        identity = link["link_id"]
        iface = link["interface"]
        peer_private_ip = link["kharej_server"]["private_ip"]
        service_name = f"ldbp-pl-{identity}-relay.service"
        script_path = f"/usr/local/bin/ldbp-pl-{identity}-relay.py"
        unit_path = f"/etc/systemd/system/{service_name}"

        script_code = render_relay_script(peer_private_ip, validated)
        unit_code = render_relay_unit(service_name, script_path, iface)

        script_digest = hashlib.sha256(script_code.encode("utf-8")).hexdigest()
        unit_digest = hashlib.sha256(unit_code.encode("utf-8")).hexdigest()

        # Connect to Iran server
        servers = data.get("iran_servers", [])
        if isinstance(servers, dict):
            servers = servers.values()
        server_cred = next((s for s in servers if s.get("ip") == link["iran_server"]["ip"]), None)
        if not server_cred:
            return False, "Iran server SSH credentials not found"

        ssh = None
        try:
            ssh = connect(server_cred)
            # Stage script
            staged_script = script_path + ".stage-" + identity
            if not ssh.write_file(staged_script, script_code):
                return False, "Failed to write relay script to remote host"
            code, _, _ = ssh.execute(f"chmod 0755 {shlex.quote(staged_script)} && mv -f {shlex.quote(staged_script)} {shlex.quote(script_path)}")
            if code != 0:
                return False, "Failed to install relay executable"

            # Stage unit
            staged_unit = unit_path + ".stage-" + identity
            if not ssh.write_file(staged_unit, unit_code):
                return False, "Failed to write relay systemd unit"
            code, _, _ = ssh.execute(f"chmod 0644 {shlex.quote(staged_unit)} && mv -f {shlex.quote(staged_unit)} {shlex.quote(unit_path)}")
            if code != 0:
                return False, "Failed to install relay systemd unit"

            # Start service
            code, _, err = ssh.execute(f"systemctl daemon-reload && systemctl enable {shlex.quote(service_name)} && systemctl restart {shlex.quote(service_name)}")
            if code != 0:
                return False, f"Failed to start relay service: {err}"

            # Verify listeners belong to this service
            ports_to_verify = [r["listen_port"] for r in validated]
            from core.kernel_relay_ports import verify_listeners
            try:
                verify_listeners(ssh, service_name, ports_to_verify)
            except Exception as e:
                # Rollback on listener verification failure
                ssh.execute(f"systemctl stop {shlex.quote(service_name)} && systemctl disable {shlex.quote(service_name)} && rm -f {shlex.quote(script_path)} {shlex.quote(unit_path)} && systemctl daemon-reload")
                return False, f"Relay listener verification failed: {e}"

            # Atomically update storage
            def update_data(store):
                target = store["custom_links"][link_name]
                target["port_forwarding_rules"] = validated
                target.setdefault("runtime", {})["relay"] = {
                    "service": service_name,
                    "script": script_path,
                    "unit": unit_path,
                    "script_sha256": script_digest,
                    "unit_sha256": unit_digest,
                    "ports": ports_to_verify,
                    "state": "active",
                }
            atomic_update(update_data)
            return True, f"Port forwarding activated for {len(validated)} rule(s)"
        except Exception as e:
            logger.exception("Failed to apply port forwarding")
            return False, str(e)
        finally:
            if ssh:
                ssh.close()


def remove_forwarding_rules(link_name: str) -> Tuple[bool, str]:
    """Stops and cleanly removes port forwarding relay from the Iran endpoint."""
    with mutation_lock():
        data = load_data()
        if busy(data):
            return False, "Another runtime mutation is active"
        link = data.get("custom_links", {}).get(link_name)
        if not link:
            return False, f"Private link '{link_name}' not found"

        relay_meta = link.get("runtime", {}).get("relay")
        identity = link["link_id"]
        service_name = relay_meta.get("service") if relay_meta else f"ldbp-pl-{identity}-relay.service"
        script_path = relay_meta.get("script") if relay_meta else f"/usr/local/bin/ldbp-pl-{identity}-relay.py"
        unit_path = relay_meta.get("unit") if relay_meta else f"/etc/systemd/system/{service_name}"

        servers = data.get("iran_servers", [])
        if isinstance(servers, dict):
            servers = servers.values()
        server_cred = next((s for s in servers if s.get("ip") == link["iran_server"]["ip"]), None)
        if not server_cred:
            return False, "Iran server SSH credentials not found"

        ssh = None
        try:
            ssh = connect(server_cred)
            # Verify ownership if sha256 is recorded
            if relay_meta and relay_meta.get("unit_sha256"):
                code, out, _ = ssh.execute(f"if test -f {shlex.quote(unit_path)}; then sha256sum -- {shlex.quote(unit_path)}; fi")
                if code == 0 and out.strip():
                    digest = out.split()[0]
                    if digest != relay_meta["unit_sha256"]:
                        return False, "Relay unit ownership verification failed; foreign unit preserved"

            cmd = (
                f"systemctl stop {shlex.quote(service_name)} 2>/dev/null; "
                f"systemctl disable {shlex.quote(service_name)} 2>/dev/null; "
                f"rm -f -- {shlex.quote(script_path)} {shlex.quote(unit_path)}; "
                f"systemctl daemon-reload"
            )
            ssh.execute(cmd)

            def clear_data(store):
                target = store["custom_links"][link_name]
                target["port_forwarding_rules"] = []
                if "runtime" in target and "relay" in target["runtime"]:
                    del target["runtime"]["relay"]
            atomic_update(clear_data)
            return True, "Port forwarding relay stopped and removed"
        except Exception as e:
            logger.exception("Failed to remove port forwarding")
            return False, str(e)
        finally:
            if ssh:
                ssh.close()
