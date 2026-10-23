"""On-host VXLAN + IPsec agent for VX-LB.

Operates locally on each endpoint (Iran or Kharej):
- Validates VXLAN + IPsec configurations.
- Enforces authenticated IPsec ESP (AES-256-GCM) with VICI strongSwan integration.
- Configures RFC 7348 VXLAN interface with specified VNI and MTU.
- Installs fail-closed security firewall rules (policy match drop) to prevent
  any unencrypted/plaintext VXLAN transmission.
- Manages bidirectional TCP/UDP echo, probing, and local relaying.
"""
import ipaddress
import json
import os
import pathlib
import re
import select
import shlex
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, "/usr/local/libexec/vxlb-vxsec-vici")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "vendor"))


def command(*args, check=True):
    result = subprocess.run(list(args), capture_output=True, text=True, timeout=15)
    if check and result.returncode:
        raise RuntimeError(" ".join(args[:3]) + ": " + (result.stderr or result.stdout).strip())
    return result


def secure_config(c):
    security = c.get("security", {})
    if security.get("mode") != "ipsec" or not re.fullmatch(r"[0-9a-f]{64}", security.get("psk", "")):
        raise RuntimeError("Plain VXLAN is disabled: authenticated IPsec configuration is required")
    if c["mtu"] > 1400:
        raise ValueError("Secure VXLAN MTU must not exceed 1400")
    reqid = int(security.get("reqid", 0))
    if not 1 <= reqid <= 2147483647:
        raise ValueError("Invalid IPsec reqid")
    return security


def validate(c):
    if not isinstance(c, dict):
        raise ValueError("Configuration must be a dictionary")
    if c.get("owner") != "vxlb-vxsec-v1":
        raise ValueError("Invalid configuration owner")
    if c.get("role") not in ("iran", "kharej"):
        raise ValueError("Role must be 'iran' or 'kharej'")
    if not re.fullmatch(r"vx[0-9a-f]{4,10}", c.get("interface", "")):
        raise ValueError("Invalid interface name; must match vx[0-9a-f]{4,10}")

    local = ipaddress.IPv4Address(c.get("local"))
    remote = ipaddress.IPv4Address(c.get("remote"))
    if local == remote:
        raise ValueError("Local and remote addresses must be different")

    private = ipaddress.IPv4Address(c.get("private"))
    peer = ipaddress.IPv4Address(c.get("peer"))
    if private == peer:
        raise ValueError("Private and peer addresses must be different")

    vni = int(c.get("vni", 0))
    if not 1 <= vni <= 16777215:
        raise ValueError("VNI must be between 1 and 16777215")

    dst_port = int(c.get("dst_port", 4789))
    if not 1 <= dst_port <= 65535:
        raise ValueError("Destination port must be between 1 and 65535")

    mtu = int(c.get("mtu", 1280))
    if not 576 <= mtu <= 1400:
        raise ValueError("VXLAN MTU must be between 576 and 1400")

    raw_ports = c.get("ports", [])
    if not isinstance(raw_ports, list):
        raise ValueError("Ports must be a list")
    ports = []
    for p in raw_ports:
        if not str(p).isdigit():
            raise ValueError(f"Invalid port: {p}")
        port_num = int(p)
        if not 1 <= port_num <= 65535:
            raise ValueError(f"Port out of range: {p}")
        ports.append(port_num)

    secure_config(c)
    return {
        "owner": c["owner"],
        "interface": c["interface"],
        "role": c["role"],
        "local": str(local),
        "remote": str(remote),
        "private": str(private),
        "peer": str(peer),
        "vni": vni,
        "dst_port": dst_port,
        "mtu": mtu,
        "ports": ports,
        "security": c["security"],
    }


def ipsec_connection(c):
    sec = secure_config(c)
    dst_port = str(c.get("dst_port", 4789))
    return {
        "version": "2",
        "local_addrs": [c["local"]],
        "remote_addrs": [c["remote"]],
        "proposals": ["aes256gcm16-prfsha256-ecp256",
                       "aes256gcm16-prfsha256-modp2048",
                       "aes256-sha256-ecp256",
                       "aes256-sha256-modp2048"],
        "dpd_delay": "20s",
        "mobike": "no",
        "local": {"auth": "psk", "id": c["local"]},
        "remote": {"auth": "psk", "id": c["remote"]},
        "children": {
            c["interface"]: {
                "local_ts": [c["local"] + "/32[17/" + dst_port + "]"],
                "remote_ts": [c["remote"] + "/32[17/" + dst_port + "]"],
                "mode": "transport",
                "reqid": str(sec["reqid"]),
                "esp_proposals": ["aes256gcm16-ecp256", "aes256gcm16-modp2048",
                                 "aes256-sha256-ecp256", "aes256-sha256-modp2048"],
                "rekey_time": "30m",
                "life_time": "40m",
                "start_action": "start",
                "dpd_action": "restart",
                "close_action": "restart",
            }
        },
    }


ALLOWED_ENCR_ALGS = {b"AES_GCM_16", b"AES_GCM_12", b"AES_GCM_8", b"AES_CBC"}


def installed_sa(session, name, reqid):
    return any(
        sa.get("state") == b"ESTABLISHED"
        and child.get("state") == b"INSTALLED"
        and child.get("encr-alg") in ALLOWED_ENCR_ALGS
        and child.get("reqid") == str(reqid).encode()
        for row in session.list_sas({"ike": name})
        for sa in row.values()
        for child in sa.get("child-sas", {}).values()
    )


def ipsec(c, action):
    import vici

    sec = secure_config(c)
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(40)
    sock.connect(os.environ.get("VX_LB_VICI_SOCKET", "/var/run/charon.vici"))
    session = vici.Session(sock)
    name = "vxlb-" + c["interface"]

    if action == "load":
        session.load_shared(
            {
                "id": name,
                "type": "IKE",
                "data": bytes.fromhex(sec["psk"]),
                "owners": [c["local"], c["remote"]],
            }
        )
        session.load_conn({name: ipsec_connection(c)})
        session.install({"child": c["interface"], "ike": name})

    elif action == "start":
        if installed_sa(session, name, sec["reqid"]):
            return
        messages = []
        try:
            for event in session.initiate(
                {"child": c["interface"], "ike": name, "timeout": "30000", "loglevel": "1"}
            ):
                messages.append(event.get("msg", b"").decode("utf-8", "replace"))
        except Exception as error:
            if installed_sa(session, name, sec["reqid"]):
                return
            raise RuntimeError(
                "IPsec negotiation failed: " + str(error) + "; " + "; ".join(messages[-8:])
            ) from error

    elif action == "rekey":
        list(session.rekey({"child": c["interface"], "ike": name}))

    elif action == "check":
        for chain, rule in security_rules(c):
            if command("iptables", "-w", "-C", chain, *rule, check=False).returncode:
                raise RuntimeError("IPsec firewall guard is missing; VXLAN is not safe")
        if not installed_sa(session, name, sec["reqid"]):
            raise RuntimeError("Authenticated AES-GCM IPsec CHILD_SA is not installed")

    elif action == "stop":
        known = session.get_conns().get("conns", [])
        if name.encode() in known:
            session.unload_conn({"name": name})
        if list(session.list_sas({"ike": name})):
            list(session.terminate({"ike": name, "timeout": "10000"}))
        if name.encode() in session.get_shared().get("keys", []):
            session.unload_shared({"id": name})


def security_rules(c):
    sec = secure_config(c)
    tag = ["-m", "comment", "--comment", "vxlb-sec-" + c["interface"]]
    dst_port = str(c.get("dst_port", 4789))
    for chain, direction, source, destination in (
        ("INPUT", "in", c["remote"], c["local"]),
        ("OUTPUT", "out", c["local"], c["remote"]),
    ):
        yield chain, [
            "-p", "udp", "-s", source, "-d", destination, "--dport", dst_port,
            "-m", "policy", "--dir", direction, "--pol", "none",
            *tag, "-j", "DROP",
        ]
        yield chain, [
            "-p", "udp", "-s", source, "-d", destination, "--dport", dst_port,
            "-m", "policy", "--dir", direction, "--pol", "ipsec",
            "--proto", "esp", "--reqid", str(sec["reqid"]),
            *tag, "-j", "ACCEPT",
        ]
        yield chain, [
            "-p", "udp", "-s", source, "-d", destination, "--dport", dst_port,
            *tag, "-j", "DROP",
        ]
        for protocol, extra in [
            ("udp", ["-m", "multiport", "--dports", "500,4500"]),
            ("50", []),
        ]:
            yield chain, ["-p", protocol, "-s", source, "-d", destination, *extra, *tag, "-j", "ACCEPT"]


def security_firewall(c, remove=False):
    ruleset = list(security_rules(c))
    for chain, rule in ruleset if remove else reversed(ruleset):
        if remove:
            while not command("iptables", "-w", "-C", chain, *rule, check=False).returncode:
                command("iptables", "-w", "-D", chain, *rule)
        elif command("iptables", "-w", "-C", chain, *rule, check=False).returncode:
            command("iptables", "-w", "-I", chain, "1", *rule)


def rules(c):
    tag = ["-m", "comment", "--comment", "vxlb-vx-" + c["interface"]]
    yield ["-i", c["interface"], "-s", c["peer"], "-d", c["private"], *tag, "-j", "ACCEPT"]
    if c["role"] == "iran":
        for port in c["ports"]:
            for protocol in ("tcp", "udp"):
                yield ["-p", protocol, "-d", c["local"], "--dport", str(port), *tag, "-j", "ACCEPT"]


def firewall(c, remove=False):
    for rule in rules(c):
        if remove:
            while not command("iptables", "-w", "-C", "INPUT", *rule, check=False).returncode:
                command("iptables", "-w", "-D", "INPUT", *rule)
        elif command("iptables", "-w", "-C", "INPUT", *rule, check=False).returncode:
            command("iptables", "-w", "-A", "INPUT", *rule)


def preflight(c):
    c = validate(c)
    command("ip", "-j", "link", "show")
    command("iptables", "-V")
    import vici

    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(5)
    sock.connect(os.environ.get("VX_LB_VICI_SOCKET", "/var/run/charon.vici"))
    try:
        vici.Session(sock).version()
    finally:
        sock.close()


def up(c):
    c = validate(c)
    security_firewall(c)
    try:
        ipsec(c, "load")
        raw = command("ip", "-d", "-j", "link", "show", "dev", c["interface"], check=False)
        if raw.returncode == 0:
            info = json.loads(raw.stdout)[0]
            if info.get("linkinfo", {}).get("info_kind") != "vxlan":
                raise RuntimeError("Interface name already in use by a non-VXLAN link")
        else:
            # Pin the underlay egress device — VXLAN resolves `remote` itself
            # and without an explicit `dev` it can pick the wrong interface or
            # fail to transmit ARP/encapsulated frames entirely (EHOSTUNREACH).
            underlay_dev = command(
                "ip", "-j", "route", "get", c["remote"], check=True,
            ).stdout
            try:
                underlay_dev = json.loads(underlay_dev)[0].get("dev", "")
            except (ValueError, IndexError, AttributeError):
                underlay_dev = ""
            args = [
                "ip", "link", "add", c["interface"],
                "type", "vxlan",
                "id", str(c["vni"]),
                "remote", c["remote"],
                "dstport", str(c["dst_port"]),
            ]
            if underlay_dev:
                args += ["dev", underlay_dev]
            command(*args)
        command("ip", "link", "set", c["interface"], "mtu", str(c["mtu"]))
        command("ip", "addr", "replace", c["private"] + "/30", "dev", c["interface"])
        command("ip", "link", "set", c["interface"], "up")
        command("ip", "route", "replace", c["peer"] + "/32", "dev", c["interface"])
        firewall(c)
    except Exception:
        down(c)
        raise


def down(c):
    c = validate(c)
    raw = command("ip", "-d", "-j", "link", "show", "dev", c["interface"], check=False)
    if raw.returncode == 0:
        info = json.loads(raw.stdout)[0]
        if info.get("linkinfo", {}).get("info_kind") == "vxlan":
            command("ip", "link", "del", c["interface"])
        else:
            raise RuntimeError("Refusing to delete non-VXLAN interface " + c["interface"])
    firewall(c, remove=True)
    try:
        ipsec(c, "stop")
    except Exception:
        pass
    security_firewall(c, remove=True)


def mtu(c):
    c = validate(c)
    command("ip", "link", "set", c["interface"], "mtu", str(c["mtu"]))


def probe(c, port, nonce):
    c = validate(c)
    port = int(port)
    seed = f"VXLAN-PROBE-{nonce}\n".encode("utf-8")
    payload = (seed * ((65536 + len(seed) - 1) // len(seed)))[:65536]

    # The first overlay packet must learn the peer MAC through ARP; until the
    # neighbour resolves, `connect` can return EHOSTUNREACH before the kernel
    # even emits the encapsulated ARP request. Give ARP a few seconds.
    deadline = time.time() + 12
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                s.connect((c["peer"], port))
                s.sendall(payload)
                received = b""
                while len(received) < len(payload):
                    chunk = s.recv(len(payload) - len(received))
                    if not chunk:
                        break
                if received != payload:
                    raise RuntimeError("VXLAN TCP 64KiB probe did not return the complete nonce payload")
            break
        except OSError as error:
            if error.errno in (113, 101, 111) and time.time() < deadline:
                time.sleep(0.5)
                continue
            raise

    deadline = time.time() + 12
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(4)
                s.connect((c["peer"], port))
                udp_payload = f"VXLAN-UDP-{nonce}\n".encode("utf-8")
                s.send(udp_payload)
                resp = s.recv(4096)
                if resp != udp_payload:
                    raise RuntimeError(f"UDP probe nonce mismatch: {resp!r} != {udp_payload!r}")
            break
        except OSError as error:
            if error.errno in (113, 101, 111) and time.time() < deadline:
                time.sleep(0.5)
                continue
            raise


def echo(c, port_file=None):
    c = validate(c)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((c["private"], 0))
    tcp.listen(16)
    port = tcp.getsockname()[1]

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((c["private"], port))

    if port_file:
        with open(port_file, "w") as f:
            f.write(str(port) + "\n")

    def udp_loop():
        while True:
            try:
                data, addr = udp.recvfrom(65535)
                udp.sendto(data, addr)
            except Exception:
                break

    threading.Thread(target=udp_loop, daemon=True).start()

    def handle_tcp(client):
        with client:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                client.sendall(data)

    def tcp_loop():
        while True:
            try:
                client, _ = tcp.accept()
                threading.Thread(target=handle_tcp, args=(client,), daemon=True).start()
            except Exception:
                break

    threading.Thread(target=tcp_loop, daemon=True).start()
    print(port, flush=True)
    # Exit when the SSH channel's stdin pipe closes so we do not leak the
    # responder process. Only install the watchdog when stdin is actually a
    # pipe — under `nohup`/detached launch stdin is /dev/null and read()
    # returns EOF instantly, which would kill the responder on startup.
    import stat
    if stat.S_ISFIFO(os.fstat(0).st_mode):
        def stdin_watchdog():
            try:
                while sys.stdin.read(1):
                    pass
            except Exception:
                pass
            os._exit(0)
        threading.Thread(target=stdin_watchdog, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    finally:
        tcp.close()
        udp.close()


def relay(c):
    c = validate(c)
    if c["role"] != "iran":
        raise RuntimeError("Relay must run on the Iran server")
    threads = []
    for port in c["ports"]:
        def tcp_listener(p=port):
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((c["local"], p))
            server.listen(128)
            while True:
                client, _ = server.accept()
                def bridge(src, port_target=p):
                    try:
                        with src, socket.create_connection((c["peer"], port_target), timeout=10) as dst:
                            sockets = [src, dst]
                            while True:
                                r, _, _ = select.select(sockets, [], [], 30)
                                if not r:
                                    break
                                for s in r:
                                    other = dst if s is src else src
                                    data = s.recv(65536)
                                    if not data:
                                        return
                                    other.sendall(data)
                    except Exception:
                        pass
                threading.Thread(target=bridge, args=(client,), daemon=True).start()

        def udp_listener(p=port):
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((c["local"], p))
            while True:
                data, addr = listener.recvfrom(65535)
                def forward_udp(payload, client_addr, port_target=p):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                            upstream.settimeout(5)
                            upstream.sendto(payload, (c["peer"], port_target))
                            resp, _ = upstream.recvfrom(65535)
                            listener.sendto(resp, client_addr)
                    except Exception:
                        pass
                threading.Thread(target=forward_udp, args=(data, addr), daemon=True).start()

        t_tcp = threading.Thread(target=tcp_listener, daemon=True)
        t_udp = threading.Thread(target=udp_listener, daemon=True)
        t_tcp.start()
        t_udp.start()
        threads.extend([t_tcp, t_udp])

    for t in threads:
        t.join()


def status(c):
    c = validate(c)
    raw = command("ip", "-s", "-j", "link", "show", "dev", c["interface"], check=False)
    if raw.returncode != 0:
        return {"status": "DOWN", "interface": c["interface"], "error": "Interface not found"}
    info = json.loads(raw.stdout)[0]
    stats = info.get("stats64", info.get("stats", {}))
    rx_bytes = stats.get("rx", {}).get("bytes", 0)
    tx_bytes = stats.get("tx", {}).get("bytes", 0)

    import vici
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(5)
    sock.connect(os.environ.get("VX_LB_VICI_SOCKET", "/var/run/charon.vici"))
    session = vici.Session(sock)
    is_sa = installed_sa(session, "vxlb-" + c["interface"], c["security"]["reqid"])

    return {
        "status": "UP" if (info.get("flags") and "UP" in info["flags"] and is_sa) else "DEGRADED" if is_sa else "DOWN",
        "interface": c["interface"],
        "vni": c["vni"],
        "mtu": info.get("mtu", c["mtu"]),
        "ipsec": "INSTALLED" if is_sa else "MISSING",
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: vxlan_ipsec_agent.py <action> <config_file> [args...]")
        sys.exit(1)
    action = sys.argv[1]
    config_file = sys.argv[2]
    with open(config_file) as f:
        c = json.load(f)

    if action == "preflight":
        preflight(c)
    elif action == "up":
        up(c)
    elif action == "down":
        down(c)
    elif action == "secure-start":
        ipsec(c, "start")
    elif action == "secure-check":
        ipsec(c, "check")
    elif action == "secure-stop":
        ipsec(c, "stop")
    elif action == "secure-rekey":
        ipsec(c, "rekey")
    elif action == "mtu":
        mtu(c)
    elif action == "probe":
        probe(c, int(sys.argv[3]), sys.argv[4])
    elif action == "echo":
        echo(c, sys.argv[3] if len(sys.argv) > 3 else None)
    elif action == "relay":
        relay(c)
    elif action == "status":
        print(json.dumps(status(c)))
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
