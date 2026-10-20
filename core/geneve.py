"""Geneve + IPsec pool manager and orchestrator for VX-LB.

Manages two-server and multi-node Geneve + IPsec links:
- Allocates VNI, /30 private IP subnets, MTU, and authenticated IPsec credentials.
- Installs the isolated Geneve agent and VICI client via SSH.
- Configures systemd services for the link and client port relays.
- Performs end-to-end TCP/UDP nonced verification.
- Enforces fail-closed cleanup, atomic MTU modification, and rollback.
"""
import copy
import ipaddress
import json
import secrets
import shlex
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from core.geneve_agent import validate, secure_config
from core.storage import load_data, atomic_update, get_pools, save_pool, delete_pool
from core.validation import validate_pool_name, validate_ports
from core.transport_change import connect

AGENT = "/usr/local/libexec/vxlb-geneve-v1.py"
CONFIG_DIR = "/etc/vxlb/geneve"
DEFAULT_DST_PORT = 6081


def validate_mtu(value) -> int:
    if str(value).strip().isdigit() and 576 <= int(value) <= 1420:
        return int(value)
    raise ValueError("Geneve MTU must be an integer between 576 and 1420")


def validate_vni(value) -> int:
    if str(value).strip().isdigit() and 1 <= int(value) <= 16777215:
        return int(value)
    raise ValueError("Geneve VNI must be an integer between 1 and 16777215")


def execute(ssh, command, timeout=30) -> str:
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or "Geneve remote command failed")
    return out.strip()


def detect_ipsec_unit(ssh):
    """Return the strongSwan unit name that provides a VICI socket, or None."""
    for candidate in ("strongswan.service", "strongswan-starter.service",
                      "strongswan-swanctl.service", "ipsec.service"):
        code, _, _ = ssh.execute(
            "systemctl cat " + shlex.quote(candidate) + " >/dev/null 2>&1 && "
            "systemctl is-active --quiet " + shlex.quote(candidate),
            timeout=15,
        )
        if code == 0:
            code, _, _ = ssh.execute(
                "test -S /run/charon.vici -o -S /var/run/charon.vici",
                timeout=15,
            )
            if code == 0:
                return candidate
    return None


def install_agent(ssh, node=None):
    try:
        execute(
            ssh,
            'command -v python3 && command -v ip && command -v iptables && '
            'command -v systemctl && test "$(id -u)" = 0',
        )
    except RuntimeError as error:
        raise RuntimeError(
            "Geneve + IPsec requires root, iproute2, iptables and systemd; "
            "raw/plain mode is not allowed. " + str(error)
        ) from error

    unit_name = detect_ipsec_unit(ssh)
    if not unit_name:
        raise RuntimeError(
            "Geneve + IPsec needs an active strongSwan daemon exposing a VICI socket "
            "(/run/charon.vici); raw mode is not allowed. On Debian/Ubuntu install "
            "'charon-systemd' (provides strongswan.service), then enable and start it."
        )
    if node is not None:
        node.setdefault("geneve", {})["ipsec_unit"] = unit_name

    vici_dir = Path(__file__).resolve().parent / "vendor" / "vici"
    if vici_dir.exists():
        for file in vici_dir.glob("*.py"):
            write(ssh, "/usr/local/libexec/vxlb-geneve-vici/vici/" + file.name, file.read_text())
        lic = vici_dir / "LICENSE"
        if lic.exists():
            write(ssh, "/usr/local/libexec/vxlb-geneve-vici/LICENSE", lic.read_text())

    agent_code = (Path(__file__).resolve().parent / "geneve_agent.py").read_text()
    write(ssh, AGENT, agent_code)


def write(ssh, path_target, content, exclusive=False):
    staged = path_target + ".tmp-" + secrets.token_hex(4)
    if not ssh.write_file(staged, content):
        raise RuntimeError("Writing Geneve configuration failed")
    try:
        publish = (
            ("ln " + shlex.quote(staged) + " " + shlex.quote(path_target) + " && rm -f " + shlex.quote(staged))
            if exclusive
            else ("mv -f " + shlex.quote(staged) + " " + shlex.quote(path_target))
        )
        execute(ssh, "chmod 600 " + shlex.quote(staged) + " && " + publish)
    except Exception:
        ssh.execute("rm -f " + shlex.quote(staged))
        raise


def path(node) -> str:
    return CONFIG_DIR + "/" + validate(node["geneve"]["configs"][0])["interface"] + ".json"


def unit(node, relay=False) -> str:
    return "vxlb-geneve-" + validate(node["geneve"]["configs"][0])["interface"] + ("-relay" if relay else "") + ".service"


def run_agent(ssh, node, action, *args) -> str:
    return execute(
        ssh,
        "python3 "
        + shlex.quote(AGENT)
        + " "
        + shlex.quote(action)
        + " "
        + shlex.quote(path(node))
        + "".join(" " + shlex.quote(str(arg)) for arg in args),
        timeout=60 if action == "secure-start" else 30,
    )


def service(node, relay=False) -> str:
    config_path = path(node)
    helper = "python3 " + AGENT
    link_unit = unit(node)
    ipsec_unit = node.get("geneve", {}).get("ipsec_unit") or "strongswan.service"
    return f"""[Unit]
Description=VX-LB Geneve {'TCP/UDP relay' if relay else 'private link + IPsec'}
After=network-online.target {ipsec_unit} {link_unit if relay else ''}
Requires={ipsec_unit}
PartOf={ipsec_unit}
Wants=network-online.target
{'Requires=' + link_unit if relay else ''}
[Service]
Type={'simple' if relay else 'oneshot'}
{'RemainAfterExit=yes' if not relay else 'Restart=on-failure'}
ExecStart=/usr/bin/{helper} {'relay' if relay else 'up'} {config_path}
{'' if relay else 'ExecStop=/usr/bin/' + helper + ' down ' + config_path}
{'' if relay else 'ExecReload=/usr/bin/' + helper + ' up ' + config_path}
{'RestartSec=3' if relay else 'TimeoutStartSec=90'}
TimeoutStopSec=30
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
{'ProtectSystem=strict' if relay else ''}
[Install]
WantedBy=multi-user.target
"""


def allocate(server: dict, kharej: dict, ports: list, mtu: int = 1280, vni: Optional[int] = None) -> dict:
    local = str(ipaddress.IPv4Address(server["ip"]))
    remote = str(ipaddress.IPv4Address(kharej["ip"]))
    if local == remote:
        raise ValueError("Geneve endpoints must be different servers")

    # Allocate unused private /30 subnet in 10.205.0.0/16
    used = {
        c["private"]
        for pool in get_pools().values()
        for node in pool.get("nodes", [])
        for c in node.get("geneve", {}).get("configs", [])
    }
    block = ipaddress.IPv4Network("10.205.0.0/16")
    start = secrets.randbelow(16384)
    for index in range(16384):
        base = int(block.network_address) + ((start + index) % 16384) * 4
        private, peer = str(ipaddress.IPv4Address(base + 1)), str(ipaddress.IPv4Address(base + 2))
        if private not in used and peer not in used:
            break
    else:
        raise ValueError("Geneve private address pool exhausted")

    # Allocate or validate VNI
    used_vnis = {
        node.get("geneve", {}).get("vni")
        for pool in get_pools().values()
        for node in pool.get("nodes", [])
        if node.get("geneve", {}).get("vni")
    }
    if vni is not None:
        vni = validate_vni(vni)
        if vni in used_vnis:
            raise ValueError(f"VNI {vni} is already assigned to an existing tunnel")
    else:
        vni = 1000
        while vni in used_vnis:
            vni += 1
            if vni > 16777215:
                raise ValueError("VNI address space exhausted")

    # Check for duplicate endpoint link
    for pool in get_pools().values():
        for n in pool.get("nodes", []):
            for c in n.get("geneve", {}).get("configs", []):
                if {c["local"], c["remote"]} == {local, remote}:
                    raise ValueError("Only one managed IPsec Geneve link per endpoint pair is currently supported")

    interface = "gni" + secrets.token_hex(5)
    security = {
        "mode": "ipsec",
        "psk": secrets.token_hex(32),
        "reqid": secrets.randbelow(2147483647) + 1,
    }

    common = dict(
        security=security,
        owner="vxlb-geneve-v1",
        interface=interface,
        vni=vni,
        dst_port=DEFAULT_DST_PORT,
        mtu=validate_mtu(mtu),
        ports=validate_ports(ports),
    )

    configs = [
        validate(dict(common, role="iran", local=local, remote=remote, private=private, peer=peer)),
        validate(dict(common, role="kharej", local=remote, remote=local, private=peer, peer=private)),
    ]

    return dict(
        server,
        server_name=server.get("name", interface),
        node_name=interface,
        engine="geneve_ipsec",
        transport="geneve",
        status="pending",
        provisioning=True,
        geneve={
            "configs": configs,
            "mtu": mtu,
            "vni": vni,
            "local_private": private,
            "remote_private": peer,
        },
    )


def verify(iran, kharej, node) -> bool:
    for ssh in (iran, kharej):
        run_agent(ssh, node, "secure-check")

    for source, target in ((iran, kharej), (kharej, iran)):
        channel = None
        try:
            stdin, stdout, stderr = target.client.exec_command(
                "python3 " + shlex.quote(AGENT) + " echo " + shlex.quote(path(node)),
                timeout=10,
            )
            channel = stdout.channel
            line = stdout.readline().strip()
            if not line.isdigit():
                raise RuntimeError("Geneve echo endpoint failed to start")
            run_agent(source, node, "probe", int(line), secrets.token_hex(24))
        finally:
            if channel:
                channel.close()
    return True


def verify_geneve_tunnel(endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None) -> Tuple[bool, Optional[float]]:
    """Active end-to-end data probe across endpoints with nonce validation."""
    from core.private_link_health import probe_pair
    try:
        if not isinstance(endpoint_ir, dict) or not isinstance(endpoint_kh, dict):
            return False, None
        result = probe_pair(endpoint_ir['ssh'], endpoint_kh['ssh'], endpoint_ir['private_ip'], endpoint_kh['private_ip'], endpoint_ir['interface'])
        return result['passed'], result['latency_ms']
    except Exception:
        return False, None


def cleanup_endpoint(ssh, node, iran: bool):
    units = [unit(node, True), unit(node)] if iran else [unit(node)]
    for name in units:
        execute(
            ssh,
            "if test -f "
            + shlex.quote("/etc/systemd/system/" + name)
            + "; then systemctl disable --now "
            + shlex.quote(name)
            + "; fi",
            timeout=90,
        )
    run_agent(ssh, node, "down")
    execute(
        ssh,
        "rm -f "
        + " ".join(shlex.quote("/etc/systemd/system/" + name) for name in units)
        + " "
        + shlex.quote(path(node)),
    )
    execute(ssh, "systemctl daemon-reload")


def cleanup_geneve_node(ssh, identifier: str) -> Tuple[bool, str]:
    iface = identifier.replace("vxlb-geneve-", "").replace(".service", "").replace("-relay", "")
    svc = f"vxlb-geneve-{iface}.service"
    relay_svc = f"vxlb-geneve-{iface}-relay.service"
    cmd = (
        f"systemctl stop {relay_svc} {svc} 2>/dev/null; "
        f"systemctl disable {relay_svc} {svc} 2>/dev/null; "
        f"ip link del {iface} 2>/dev/null; "
        f"rm -f /etc/systemd/system/{svc} /etc/systemd/system/{relay_svc} /etc/vxlb/geneve/{iface}.json; "
        f"systemctl daemon-reload"
    )
    ok, out, err = ssh.execute(cmd)
    return (ok == 0), (out if ok == 0 else err)


def update_job(pool: str, target_ip: str, **fields):
    def write_job(data):
        data["pools"][pool].setdefault("node_additions", {}).setdefault(target_ip, {}).update(
            fields, updated_at=time.time()
        )
    atomic_update(write_job)


def add(pool_name: str, server: dict, callback=None) -> Tuple[bool, str]:
    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Geneve pool not found"
    if any(n["ip"] == server["ip"] for n in pool["nodes"]):
        return False, "Server already belongs to this pool"
    from core.load_balancer import LoadBalancerManager

    ok, message = LoadBalancerManager.check_port_conflicts(
        pool["client_ports"], [server["ip"]], exclude_pool_name=pool_name
    )
    if not ok:
        return False, message

    try:
        node = allocate(
            server,
            pool["kharej_server"],
            pool["client_ports"],
            pool.get("geneve_mtu", 1400),
            vni=pool.get("vni"),
        )
    except ValueError as error:
        return False, str(error)

    sessions = []
    installed = []
    configs_written = []
    committed = False

    def progress(msg):
        update_job(pool_name, server["ip"], status="running", ip=server["ip"], name=server.get("name", server["ip"]), message=msg)
        if callback:
            callback(msg)

    try:
        progress("بررسی پیش‌نیازهای Geneve + IPsec و دسترسی دو سرور")
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool["kharej_server"])
        sessions.append(kharej)

        for ssh, c in zip(sessions, node["geneve"]["configs"]):
            install_agent(ssh, node)
            execute(
                ssh,
                "test ! -e "
                + shlex.quote("/etc/systemd/system/" + unit(node))
                + " && test ! -e "
                + shlex.quote("/etc/systemd/system/" + unit(node, True)),
            )
            write(ssh, path(node), json.dumps(c), exclusive=True)
            configs_written.append(ssh)
            run_agent(ssh, node, "preflight")

        def reserve(data):
            data["pools"][pool_name]["nodes"].append(node)

        atomic_update(reserve)
        committed = True
        installed = list(sessions)

        progress("ساخت لینک Geneve و بارگذاری سیاست‌های IPsec با دیوار آتش محافظ")
        for ssh in sessions:
            write(ssh, "/etc/systemd/system/" + unit(node), service(node))
            execute(ssh, "systemctl daemon-reload")
            execute(ssh, "systemctl enable --now " + shlex.quote(unit(node)), timeout=90)

        run_agent(iran, node, "secure-start")

        progress("آزمون رمزنگاری و عبور ترافیک TCP و UDP")
        verify(iran, kharej, node)

        progress("راه‌اندازی فوروارد TCP و UDP پورت‌های استخر")
        write(iran, "/etc/systemd/system/" + unit(node, True), service(node, True))
        execute(iran, "systemctl daemon-reload")
        execute(iran, "systemctl enable --now " + shlex.quote(unit(node, True)), timeout=90)
        verify_relay(iran, node, pool["client_ports"])

        def finish(data):
            for member in data["pools"][pool_name]["nodes"]:
                if member["node_name"] == node["node_name"]:
                    member.update(provisioning=False, status="active")

        atomic_update(finish)
        update_job(pool_name, server["ip"], status="succeeded", message="لینک Geneve + IPsec آماده شد", error="")
        return True, "Geneve + IPsec link and TCP/UDP relay verified"

    except Exception as error:
        failures = []
        for index, ssh in enumerate(sessions):
            if ssh not in installed:
                if ssh in configs_written:
                    try:
                        execute(ssh, "rm -f " + shlex.quote(path(node)))
                    except Exception:
                        pass
                continue
            try:
                cleanup_endpoint(ssh, node, index == 0)
            except Exception as cleanup_error:
                failures.append(str(cleanup_error))

        if committed and not failures:
            def discard(data):
                data["pools"][pool_name]["nodes"] = [
                    n for n in data["pools"][pool_name]["nodes"] if n["node_name"] != node["node_name"]
                ]
            atomic_update(discard)

        message = str(error) + (("; پاک‌سازی کامل نشد: " + "; ".join(failures)) if failures else "")
        update_job(pool_name, server["ip"], status="failed", message="راه‌اندازی Geneve کامل نشد", error=message)
        return False, message
    finally:
        for ssh in sessions:
            ssh.close()


def verify_relay(ssh, node, ports):
    script = """import json,subprocess,sys
unit=sys.argv[1];ports=set(map(int,json.loads(sys.argv[2])))
pid=subprocess.check_output(['systemctl','show',unit,'--property=MainPID','--value'],text=True).strip()
if not pid.isdigit() or int(pid)==0:sys.exit(1)
for kind in ['-ltnp','-lunp']:
 text=subprocess.check_output(['ss',kind],text=True)
 found={int(line.split()[3].rsplit(':',1)[-1]) for line in text.splitlines()[1:] if 'pid='+pid+',' in line}
 if not ports.issubset(found):sys.exit(1)
"""
    command = "python3 -c " + shlex.quote(script) + " " + shlex.quote(unit(node, True)) + " " + shlex.quote(json.dumps(ports))
    for _ in range(10):
        if ssh.execute(command)[0] == 0:
            return
        time.sleep(0.3)
    raise RuntimeError("Geneve relay did not bind all TCP and UDP ports")


def create(name: str, kharej: dict, servers: list, ports: list, mtu: int = 1280, vni: Optional[int] = None, callback=None) -> Tuple[bool, str, dict]:
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mtu = validate_mtu(mtu)
        if vni == "":
            vni = None
        if vni is not None:
            vni = validate_vni(vni)
        ipaddress.IPv4Address(kharej["ip"])
        if not servers:
            raise ValueError("Select at least one Iran server")
        for server in servers:
            ipaddress.IPv4Address(server["ip"])
        if len({s["ip"] for s in servers}) != len(servers):
            raise ValueError("Duplicate Iran server")
        if name in get_pools():
            raise ValueError("Pool name already exists")
        from core.load_balancer import LoadBalancerManager

        ok, message = LoadBalancerManager.check_port_conflicts(ports, [s["ip"] for s in servers])
        if not ok:
            return False, message, {}
    except ValueError as error:
        return False, str(error), {}

    pool = dict(
        name=name,
        engine="geneve_ipsec",
        transport="geneve",
        geneve_mtu=mtu,
        vni=vni,
        client_ports=ports,
        kharej_server=kharej,
        nodes=[],
        created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    save_pool(name, pool)
    failures = []
    for server in servers:
        ok, message = add(name, server, callback)
        if not ok:
            failures.append(server["ip"] + ": " + message)

    pool = get_pools()[name]
    ready = [n for n in pool["nodes"] if not n.get("provisioning")]
    return (
        bool(ready),
        (
            "Geneve pool ready"
            + ("; failures: " + "; ".join(failures) if failures else "")
            if ready
            else "; ".join(failures)
        ),
        pool,
    )


def remove(pool_name: str, ip: str, callback=None) -> Tuple[bool, str]:
    pool = get_pools().get(pool_name, {})
    node = next((n for n in pool.get("nodes", []) if n["ip"] == ip), None)
    if not node:
        return False, "Geneve node not found"
    sessions = []
    try:
        sessions.append(connect(node))
        sessions.append(connect(pool["kharej_server"]))
        for index, ssh in enumerate(sessions):
            if callback:
                callback("در حال حذف منابع Geneve سمت " + ("ایران" if index == 0 else "خارج"))
            cleanup_endpoint(ssh, node, index == 0)
        def discard(data):
            data["pools"][pool_name]["nodes"] = [n for n in data["pools"][pool_name]["nodes"] if n["ip"] != ip]
        atomic_update(discard)
        return True, "Geneve node removed"
    except Exception as error:
        return False, str(error)
    finally:
        for ssh in sessions:
            ssh.close()


def change_mtu(pool_name: str, new_mtu: int) -> Tuple[bool, str]:
    new_mtu = validate_mtu(new_mtu)
    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Pool not found"
    old_mtu = pool.get("geneve_mtu", 1400)
    if old_mtu == new_mtu:
        return True, "MTU already up-to-date"

    kharej_ssh = None
    node_sessions = []
    try:
        kharej_ssh = connect(pool["kharej_server"])
        for node in pool.get("nodes", []):
            ir_ssh = connect(node)
            node_sessions.append((ir_ssh, node))
            # Update configs
            for c in node["geneve"]["configs"]:
                c["mtu"] = new_mtu
            write(ir_ssh, path(node), json.dumps(node["geneve"]["configs"][0]))
            run_agent(ir_ssh, node, "mtu")
            write(kharej_ssh, path(node), json.dumps(node["geneve"]["configs"][1]))
            run_agent(kharej_ssh, node, "mtu")
            verify(ir_ssh, kharej_ssh, node)

        def update_pool(data):
            data["pools"][pool_name]["geneve_mtu"] = new_mtu
            for node in data["pools"][pool_name]["nodes"]:
                node["geneve"]["mtu"] = new_mtu
                for c in node["geneve"]["configs"]:
                    c["mtu"] = new_mtu

        atomic_update(update_pool)
        return True, f"Geneve MTU updated to {new_mtu}"
    except Exception as error:
        # Rollback on failure
        rollback_mtu(pool_name, old_mtu)
        return False, f"MTU update failed, rolled back to {old_mtu}: {error}"
    finally:
        if kharej_ssh:
            kharej_ssh.close()
        for ssh, _ in node_sessions:
            ssh.close()


def rollback_mtu(pool_name: str, old_mtu: int) -> Tuple[bool, str]:
    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Pool not found"
    kharej_ssh = None
    try:
        kharej_ssh = connect(pool["kharej_server"])
        for node in pool.get("nodes", []):
            ir_ssh = connect(node)
            try:
                for c in node["geneve"]["configs"]:
                    c["mtu"] = old_mtu
                write(ir_ssh, path(node), json.dumps(node["geneve"]["configs"][0]))
                run_agent(ir_ssh, node, "mtu")
                write(kharej_ssh, path(node), json.dumps(node["geneve"]["configs"][1]))
                run_agent(kharej_ssh, node, "mtu")
            finally:
                ir_ssh.close()

        def revert_pool(data):
            data["pools"][pool_name]["geneve_mtu"] = old_mtu
            for node in data["pools"][pool_name]["nodes"]:
                node["geneve"]["mtu"] = old_mtu
                for c in node["geneve"]["configs"]:
                    c["mtu"] = old_mtu

        atomic_update(revert_pool)
        return True, f"Rollback to MTU {old_mtu} completed"
    except Exception as error:
        return False, f"Rollback failed: {error}"
    finally:
        if kharej_ssh:
            kharej_ssh.close()


def change_ports(pool_name: str, new_ports: list) -> Tuple[bool, str]:
    new_ports = validate_ports(new_ports)
    pool = get_pools().get(pool_name)
    if not pool:
        return False, "Pool not found"
    for node in pool.get("nodes", []):
        ir_ssh = connect(node)
        try:
            for c in node["geneve"]["configs"]:
                c["ports"] = new_ports
            write(ir_ssh, path(node), json.dumps(node["geneve"]["configs"][0]))
            write(ir_ssh, "/etc/systemd/system/" + unit(node, True), service(node, True))
            execute(ir_ssh, "systemctl daemon-reload && systemctl restart " + shlex.quote(unit(node, True)))
            verify_relay(ir_ssh, node, new_ports)
        finally:
            ir_ssh.close()

    def update_p(data):
        data["pools"][pool_name]["client_ports"] = new_ports
        for node in data["pools"][pool_name]["nodes"]:
            for c in node["geneve"]["configs"]:
                c["ports"] = new_ports

    atomic_update(update_p)
    return True, "Geneve client ports updated"


def remove_pool(name: str, callback=None) -> Tuple[bool, str]:
    pool = get_pools().get(name)
    if not pool:
        return False, "Geneve pool not found"
    for node in pool.get("nodes", []):
        ok, message = remove(name, node["ip"], callback)
        if not ok:
            return False, message
    delete_pool(name)
    return True, "Geneve pool removed"


def health(pool_name: str, node: dict, ports: list):
    if node.get("provisioning"):
        return "DOWN", "Geneve provisioning interrupted or cleanup required", {}
    pool = get_pools().get(pool_name, {})
    sessions = []
    try:
        iran = connect(node)
        sessions.append(iran)
        kharej = connect(pool["kharej_server"])
        sessions.append(kharej)
        verify(iran, kharej, node)
        verify_relay(iran, node, ports)
        script = """import socket,json,sys
result={}
for port in json.loads(sys.argv[2]):
 try:
  with socket.create_connection((sys.argv[1],int(port)),timeout=2):pass
  result[str(port)]=True
 except OSError:result[str(port)]=False
print(json.dumps(result))
"""
        out = execute(
            iran,
            "python3 -c "
            + shlex.quote(script)
            + " "
            + shlex.quote(node["geneve"]["remote_private"])
            + " "
            + shlex.quote(json.dumps(ports)),
        )
        availability = json.loads(out)
        details = {
            p: {
                "status": "HEALTHY" if live else "DOWN",
                "reason": (
                    "Geneve TCP/UDP path verified; TCP destination reachable"
                    if live
                    else "TCP destination is not listening/reachable; Geneve path passed"
                ),
                "last_success_epoch": time.time() if live else None,
            }
            for p, live in availability.items()
        }
        live = sum(availability.values())
        return (
            ("HEALTHY" if live == len(ports) and live else "DEGRADED" if live else "DOWN"),
            f"Geneve + IPsec data path verified; {live}/{len(ports)} TCP destinations reachable; UDP application health is not inferred",
            details,
        )
    except Exception as error:
        return "DOWN", "Geneve verification failed: " + str(error), {}
    finally:
        for ssh in sessions:
            ssh.close()
