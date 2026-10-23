"""VXLAN + IPsec pool manager and orchestrator for VX-LB.

Manages two-server and multi-node VXLAN + IPsec links:
- Allocates VNI, /30 private IP subnets, MTU, and authenticated IPsec credentials.
- Installs the isolated VXLAN agent and VICI client via SSH.
- Configures systemd services for the link and client port relays.
- Performs end-to-end TCP/UDP nonced verification.
- Enforces fail-closed cleanup, atomic MTU modification, and rollback.
"""
import copy
import ipaddress
import json
import re
import secrets
import shlex
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from core.vxlan_ipsec_agent import validate, secure_config
from core.storage import load_data, atomic_update, get_pools, save_pool, delete_pool
from core.validation import validate_pool_name, validate_ports
from core.transport_change import connect

AGENT = "/usr/local/libexec/vxlb-vxsec-v1.py"
VICI_DIR = "/usr/local/libexec/vxlb-vxsec-vici"
CONFIG_DIR = "/etc/vxlb/vxsec"
DEFAULT_DST_PORT = 4789
SUBNET_BASE = "10.206.0.0/16"


def validate_mtu(value) -> int:
    if str(value).strip().isdigit() and 576 <= int(value) <= 1400:
        return int(value)
    raise ValueError("VXLAN+IPsec MTU must be an integer between 576 and 1400")


def validate_vni(value) -> int:
    if str(value).strip().isdigit() and 1 <= int(value) <= 16777215:
        return int(value)
    raise ValueError("VXLAN VNI must be an integer between 1 and 16777215")


def execute(ssh, command, timeout=30) -> str:
    code, out, error = ssh.execute(command, timeout=timeout)
    if code:
        raise RuntimeError(error.strip() or out.strip() or "VXLAN+IPsec remote command failed")
    return out.strip()


def detect_ipsec_unit(ssh):
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


def install_strongswan(ssh) -> Optional[str]:
    code, out, _ = ssh.execute(
        "command -v apt-get || command -v dnf || command -v yum || command -v zypper",
        timeout=15,
    )
    if code != 0 or not out.strip():
        return None
    manager = out.strip().splitlines()[0]
    if "apt-get" in manager:
        execute(
            ssh,
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -y >/dev/null 2>&1 || true; "
            "apt-get install -y --no-install-recommends "
            "charon-systemd libstrongswan libstrongswan-standard-plugins >/dev/null",
            timeout=180,
        )
    elif "dnf" in manager or "yum" in manager:
        execute(
            ssh,
            "command -v dnf >/dev/null && dnf install -y strongswan >/dev/null "
            "|| yum install -y strongswan >/dev/null",
            timeout=180,
        )
    elif "zypper" in manager:
        execute(ssh, "zypper --non-interactive install strongswan >/dev/null", timeout=180)
    for _ in range(6):
        execute(
            ssh,
            "systemctl daemon-reload; "
            "systemctl enable --now strongswan.service 2>/dev/null "
            "|| systemctl enable --now strongswan-starter.service 2>/dev/null "
            "|| systemctl enable --now strongswan-swanctl.service 2>/dev/null "
            "|| systemctl enable --now ipsec.service 2>/dev/null || true",
            timeout=30,
        )
        unit_name = detect_ipsec_unit(ssh)
        if unit_name:
            return unit_name
        time.sleep(1)
    return None


def install_agent(ssh, node=None, config_index=0):
    try:
        execute(
            ssh,
            'command -v python3 && command -v ip && command -v iptables && '
            'command -v systemctl && test "$(id -u)" = 0 && modprobe vxlan',
        )
    except RuntimeError as error:
        raise RuntimeError(
            "VXLAN + IPsec requires root, iproute2, iptables, systemd and the vxlan "
            "kernel module; raw/plain mode is not allowed. " + str(error)
        ) from error

    unit_name = detect_ipsec_unit(ssh) or install_strongswan(ssh)
    if not unit_name:
        raise RuntimeError(
            "VXLAN + IPsec needs an active strongSwan daemon exposing a VICI socket "
            "(/run/charon.vici); automatic installation failed. On Debian/Ubuntu install "
            "'charon-systemd' (provides strongswan.service), then enable and start it."
        )
    if node is not None and 0 <= config_index < len(node.get("vxsec", {}).get("configs", [])):
        node["vxsec"]["configs"][config_index]["ipsec_unit"] = unit_name

    vici_dir = Path(__file__).resolve().parent / "vendor" / "vici"
    if vici_dir.exists():
        for file in vici_dir.glob("*.py"):
            write(ssh, VICI_DIR + "/vici/" + file.name, file.read_text())
        lic = vici_dir / "LICENSE"
        if lic.exists():
            write(ssh, VICI_DIR + "/LICENSE", lic.read_text())

    agent_code = (Path(__file__).resolve().parent / "vxlan_ipsec_agent.py").read_text()
    write(ssh, AGENT, agent_code)


def write(ssh, path_target, content, exclusive=False):
    staged = path_target + ".tmp-" + secrets.token_hex(4)
    if not ssh.write_file(staged, content):
        raise RuntimeError("Writing VXLAN configuration failed")
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
    return CONFIG_DIR + "/" + validate(node["vxsec"]["configs"][0])["interface"] + ".json"


def unit(node, relay=False) -> str:
    return "vxlb-vxsec-" + validate(node["vxsec"]["configs"][0])["interface"] + ("-relay" if relay else "") + ".service"


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


def service(node, relay=False, config_index=0) -> str:
    config_path = path(node)
    helper = "python3 " + AGENT
    link_unit = unit(node)
    config = node["vxsec"]["configs"][config_index] if node.get("vxsec", {}).get("configs") else {}
    ipsec_unit = config.get("ipsec_unit") or node.get("vxsec", {}).get("ipsec_unit") or "strongswan.service"
    return f"""[Unit]
Description=VX-LB VXLAN+IPsec {'TCP/UDP relay' if relay else 'private link'}
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


def allocate(server: dict, kharej: dict, ports: list, mtu: int = 1280, vni: Optional[int] = None, dst_port: int = DEFAULT_DST_PORT, node_name: Optional[str] = None) -> dict:
    local = str(ipaddress.IPv4Address(server["ip"]))
    remote = str(ipaddress.IPv4Address(kharej["ip"]))
    if local == remote:
        raise ValueError("VXLAN+IPsec endpoints must be different servers")

    used = {
        c["private"]
        for pool in get_pools().values()
        for node in pool.get("nodes", [])
        for c in node.get("vxsec", {}).get("configs", [])
    }
    block = ipaddress.IPv4Network(SUBNET_BASE)
    start = secrets.randbelow(16384)
    for index in range(16384):
        base = int(block.network_address) + ((start + index) % 16384) * 4
        private, peer = str(ipaddress.IPv4Address(base + 1)), str(ipaddress.IPv4Address(base + 2))
        if private not in used and peer not in used:
            break
    else:
        raise ValueError("VXLAN+IPsec private address pool exhausted")

    used_vnis = {
        node.get("vxsec", {}).get("vni")
        for pool in get_pools().values()
        for node in pool.get("nodes", [])
        if node.get("vxsec", {}).get("vni")
    }
    if vni is not None:
        vni = validate_vni(vni)
        if vni in used_vnis:
            raise ValueError(f"VNI {vni} is already assigned to an existing tunnel")
    else:
        vni = 4000
        while vni in used_vnis:
            vni += 1
            if vni > 16777215:
                raise ValueError("VNI address space exhausted")

    for pool in get_pools().values():
        for n in pool.get("nodes", []):
            for c in n.get("vxsec", {}).get("configs", []):
                if {c["local"], c["remote"]} == {local, remote}:
                    raise ValueError("Only one managed IPsec VXLAN link per endpoint pair is currently supported")

    interface = node_name or ("vx" + secrets.token_hex(5))
    if not re.fullmatch(r"vx[0-9a-f]{4,10}", interface):
        raise ValueError("Invalid VXLAN+IPsec interface name")
    security = {
        "mode": "ipsec",
        "psk": secrets.token_hex(32),
        "reqid": secrets.randbelow(2147483647) + 1,
    }

    if not (1 <= int(dst_port) <= 65535):
        raise ValueError("Invalid VXLAN destination port")

    common = dict(
        security=security,
        owner="vxlb-vxsec-v1",
        interface=interface,
        vni=vni,
        dst_port=int(dst_port),
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
        engine="vxlan_ipsec",
        transport="vxlan_ipsec",
        status="pending",
        provisioning=True,
        vxsec={
            "configs": configs,
            "mtu": mtu,
            "vni": vni,
            "dst_port": int(dst_port),
            "local_private": private,
            "remote_private": peer,
        },
    )


def verify(iran, kharej, node) -> bool:
    for ssh in (iran, kharej):
        run_agent(ssh, node, "secure-check")

    for source, target in ((iran, kharej), (kharej, iran)):
        port_file = "/tmp/vxsec-echo-" + secrets.token_hex(6) + ".port"
        pid = None
        try:
            # Launch the echo responder detached from the SSH channel so it
            # survives long enough for the probe to connect.
            code, out, _ = target.execute(
                "nohup python3 " + shlex.quote(AGENT) + " echo "
                + shlex.quote(path(node)) + " " + shlex.quote(port_file)
                + " >/tmp/vxsec-echo.log 2>&1 & "
                + "echo $!",
                timeout=10,
            )
            pid = out.strip().splitlines()[-1].strip() if out else ""
            if not pid.isdigit():
                raise RuntimeError("VXLAN echo endpoint failed to start")
            port = wait_for_echo_port(target, port_file, pid)
            run_agent(source, node, "probe", port, secrets.token_hex(24))
        finally:
            if pid and pid.isdigit():
                target.execute("kill -TERM " + shlex.quote(pid) + " 2>/dev/null", timeout=5)
            target.execute("rm -f " + shlex.quote(port_file), timeout=5)
    return True


def wait_for_echo_port(target, port_file, pid, attempts=40):
    """Wait until the echo responder writes its bound port to disk."""
    for _ in range(attempts):
        code, alive, _ = target.execute("kill -0 " + shlex.quote(pid) + " 2>/dev/null", timeout=10)
        if code != 0:
            code, log, _ = target.execute("tail -20 /tmp/vxsec-echo.log 2>/dev/null", timeout=10)
            raise RuntimeError("VXLAN echo endpoint exited: " + (log or "no log"))
        code, port, _ = target.execute("cat " + shlex.quote(port_file) + " 2>/dev/null", timeout=10)
        port = port.strip() if port else ""
        if port.isdigit() and int(port) > 0:
            return int(port)
        time.sleep(0.5)
    raise RuntimeError("VXLAN echo endpoint did not write a port file in time")


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


def update_job(pool: str, target_ip: str, **fields):
    def write_job(data):
        data["pools"][pool].setdefault("node_additions", {}).setdefault(target_ip, {}).update(
            fields, updated_at=time.time()
        )
    atomic_update(write_job)


def secure_start_with_retry(iran, node, attempts=12, delay=1.5):
    last = None
    for _ in range(attempts):
        try:
            return run_agent(iran, node, "secure-start")
        except RuntimeError as error:
            last = error
            time.sleep(delay)
    raise last


def add(pool_name: str, server: dict, callback=None) -> Tuple[bool, str]:
    pool = get_pools().get(pool_name)
    if not pool:
        return False, "VXLAN+IPsec pool not found"
    if any(n["ip"] == server["ip"] for n in pool["nodes"]):
        return False, "Server already belongs to this pool"

    update_job(
        pool_name, server["ip"], status="queued",
        ip=server["ip"], name=server.get("name", server["ip"]),
        message="در صف افزودن نود VXLAN+IPsec",
    )

    from core.load_balancer import LoadBalancerManager

    ok, message = LoadBalancerManager.check_port_conflicts(
        pool["client_ports"], [server["ip"]], exclude_pool_name=pool_name
    )
    if not ok:
        update_job(pool_name, server["ip"], status="failed", message="راه‌اندازی VXLAN+IPsec کامل نشد", error=message)
        return False, message

    try:
        node = allocate(
            server,
            pool["kharej_server"],
            pool["client_ports"],
            pool.get("vxsec_mtu", 1280),
            vni=pool.get("vni"),
            dst_port=pool.get("vxsec_dst_port", DEFAULT_DST_PORT),
            node_name=server.get("node_name"),
        )
    except ValueError as error:
        update_job(pool_name, server["ip"], status="failed", message="راه‌اندازی VXLAN+IPsec کامل نشد", error=str(error))
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
        progress("بررسی پیش‌نیازهای VXLAN + IPsec و دسترسی دو سرور")
        iran = connect(server)
        sessions.append(iran)
        kharej = connect(pool["kharej_server"])
        sessions.append(kharej)

        for index, (ssh, c) in enumerate(zip(sessions, node["vxsec"]["configs"])):
            install_agent(ssh, node, config_index=index)
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

        progress("ساخت لینک VXLAN و بارگذاری سیاست‌های IPsec با دیوار آتش محافظ")
        for index, ssh in enumerate(sessions):
            write(ssh, "/etc/systemd/system/" + unit(node), service(node, config_index=index))
            execute(ssh, "systemctl daemon-reload")
            execute(ssh, "systemctl enable --now " + shlex.quote(unit(node)), timeout=90)

        secure_start_with_retry(iran, node)

        progress("آزمون رمزنگاری و عبور ترافیک TCP و UDP")
        verify(iran, kharej, node)

        progress("راه‌اندازی فوروارد TCP و UDP پورت‌های استخر")
        from core.kernel_relay_ports import check_ports_free
        check_ports_free(iran, pool["client_ports"])
        write(iran, "/etc/systemd/system/" + unit(node, True), service(node, True))
        execute(iran, "systemctl daemon-reload")
        execute(iran, "systemctl enable --now " + shlex.quote(unit(node, True)), timeout=90)
        verify_relay(iran, node, pool["client_ports"])

        def finish(data):
            for member in data["pools"][pool_name]["nodes"]:
                if member["node_name"] == node["node_name"]:
                    member.update(provisioning=False, status="active")

        atomic_update(finish)
        update_job(pool_name, server["ip"], status="succeeded", message="لینک VXLAN + IPsec آماده شد", error="")
        return True, "VXLAN + IPsec link and TCP/UDP relay verified"

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
        update_job(
            pool_name, server["ip"], status="failed",
            message="راه‌اندازی VXLAN+IPsec کامل نشد", error=message,
            ip=server["ip"], name=server.get("name", server["ip"]),
        )
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
    raise RuntimeError("VXLAN+IPsec relay did not bind all TCP and UDP ports")


def create(name: str, kharej: dict, servers: list, ports: list, mtu: int = 1280, vni: Optional[int] = None, dst_port: int = DEFAULT_DST_PORT, callback=None) -> Tuple[bool, str, dict]:
    try:
        name = validate_pool_name(name)
        ports = validate_ports(ports)
        mtu = validate_mtu(mtu)
        if vni == "":
            vni = None
        if vni is not None:
            vni = validate_vni(vni)
        dst_port = int(dst_port or DEFAULT_DST_PORT)
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
        engine="vxlan_ipsec",
        transport="vxlan_ipsec",
        vxsec_mtu=mtu,
        vxsec_dst_port=dst_port,
        vni=vni,
        client_ports=ports,
        kharej_server=kharej,
        nodes=[],
        created_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        security="ipsec",
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
            "VXLAN+IPsec pool ready"
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
        return False, "VXLAN+IPsec node not found"
    sessions = []
    try:
        sessions.append(connect(node))
        sessions.append(connect(pool["kharej_server"]))
        for index, ssh in enumerate(sessions):
            if callback:
                callback("در حال حذف منابع VXLAN+IPsec سمت " + ("ایران" if index == 0 else "خارج"))
            cleanup_endpoint(ssh, node, index == 0)
        def discard(data):
            data["pools"][pool_name]["nodes"] = [n for n in data["pools"][pool_name]["nodes"] if n["ip"] != ip]
        atomic_update(discard)
        return True, "VXLAN+IPsec node removed"
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
    old_mtu = pool.get("vxsec_mtu", 1280)
    if old_mtu == new_mtu:
        return True, "MTU already up-to-date"

    kharej_ssh = None
    node_sessions = []
    try:
        kharej_ssh = connect(pool["kharej_server"])
        for node in pool.get("nodes", []):
            ir_ssh = connect(node)
            node_sessions.append((ir_ssh, node))
            for c in node["vxsec"]["configs"]:
                c["mtu"] = new_mtu
            write(ir_ssh, path(node), json.dumps(node["vxsec"]["configs"][0]))
            run_agent(ir_ssh, node, "mtu")
            write(kharej_ssh, path(node), json.dumps(node["vxsec"]["configs"][1]))
            run_agent(kharej_ssh, node, "mtu")
            verify(ir_ssh, kharej_ssh, node)

        def update_pool(data):
            data["pools"][pool_name]["vxsec_mtu"] = new_mtu
            for node in data["pools"][pool_name]["nodes"]:
                node["vxsec"]["mtu"] = new_mtu
                for c in node["vxsec"]["configs"]:
                    c["mtu"] = new_mtu

        atomic_update(update_pool)
        return True, f"VXLAN+IPsec MTU updated to {new_mtu}"
    except Exception as error:
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
                for c in node["vxsec"]["configs"]:
                    c["mtu"] = old_mtu
                write(ir_ssh, path(node), json.dumps(node["vxsec"]["configs"][0]))
                run_agent(ir_ssh, node, "mtu")
                write(kharej_ssh, path(node), json.dumps(node["vxsec"]["configs"][1]))
                run_agent(kharej_ssh, node, "mtu")
            finally:
                ir_ssh.close()

        def revert_pool(data):
            data["pools"][pool_name]["vxsec_mtu"] = old_mtu
            for node in data["pools"][pool_name]["nodes"]:
                node["vxsec"]["mtu"] = old_mtu
                for c in node["vxsec"]["configs"]:
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
    from core.kernel_relay_ports import check_ports_free
    for node in pool.get("nodes", []):
        ir_ssh = connect(node)
        try:
            check_ports_free(ir_ssh, new_ports)
            for c in node["vxsec"]["configs"]:
                c["ports"] = new_ports
            write(ir_ssh, path(node), json.dumps(node["vxsec"]["configs"][0]))
            write(ir_ssh, "/etc/systemd/system/" + unit(node, True), service(node, True))
            execute(ir_ssh, "systemctl daemon-reload && systemctl restart " + shlex.quote(unit(node, True)))
            verify_relay(ir_ssh, node, new_ports)
        finally:
            ir_ssh.close()

    def update_p(data):
        data["pools"][pool_name]["client_ports"] = new_ports
        for node in data["pools"][pool_name]["nodes"]:
            for c in node["vxsec"]["configs"]:
                c["ports"] = new_ports

    atomic_update(update_p)
    return True, "VXLAN+IPsec client ports updated"


def remove_pool(name: str, callback=None) -> Tuple[bool, str]:
    pool = get_pools().get(name)
    if not pool:
        return False, "VXLAN+IPsec pool not found"
    for node in pool.get("nodes", []):
        ok, message = remove(name, node["ip"], callback)
        if not ok:
            return False, message
    delete_pool(name)
    return True, "VXLAN+IPsec pool removed"


def health(pool_name: str, node: dict, ports: list):
    if node.get("provisioning"):
        return "DOWN", "VXLAN+IPsec provisioning interrupted or cleanup required", {}
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
            + shlex.quote(node["vxsec"]["remote_private"])
            + " "
            + shlex.quote(json.dumps(ports)),
        )
        availability = json.loads(out)
        details = {
            p: {
                "status": "HEALTHY" if live else "DOWN",
                "reason": (
                    "VXLAN+IPsec TCP/UDP path verified; TCP destination reachable"
                    if live
                    else "TCP destination is not listening/reachable; VXLAN path passed"
                ),
                "last_success_epoch": time.time() if live else None,
            }
            for p, live in availability.items()
        }
        live = sum(availability.values())
        return (
            ("HEALTHY" if live == len(ports) and live else "DEGRADED" if live else "DOWN"),
            f"VXLAN + IPsec data path verified; {live}/{len(ports)} TCP destinations reachable; UDP application health is not inferred",
            details,
        )
    except Exception as error:
        return "DOWN", "VXLAN+IPsec verification failed: " + str(error), {}
    finally:
        for ssh in sessions:
            ssh.close()
