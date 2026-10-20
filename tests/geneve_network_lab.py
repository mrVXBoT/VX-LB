"""Real Geneve + IPsec kernel lab and dataplane test across network namespaces.

Usage:
    python3 tests/geneve_network_lab.py

Requirements for execution:
- Root access or unshare user/netns privileges.
- Linux kernel with 'geneve' module loaded.
- strongSwan 'charon' binary installed (typically /usr/lib/ipsec/charon).
- iproute2 ('ip', 'ss'), iptables, and tcpdump.

When prerequisites are met, this script executes:
1. Two isolated child network namespaces connected via veth link (no host mutation).
2. Runs geneve_agent.py and isolated strongSwan charon instances over private VICI sockets.
3. Transmits TCP and UDP data across the private IP link (10.205.0.1 <-> 10.205.0.2).
4. Verifies established IPsec SAs and monitors increasing XFRM byte counters.
5. Deliberately terminates SAs / flushes XFRM state and verifies traffic ceases without raw Geneve leak.
6. Cleans up all test interfaces, firewall rules, daemon processes, and namespaces.

If prerequisites are not met on the host, the script explicitly reports the
environment limitation rather than forging a false success result.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENT = str(ROOT / "core" / "geneve_agent.py")


def check_prerequisites():
    issues = []
    # 1. Check charon binary
    charon_bin = os.environ.get("LD_BP_CHARON_BIN")
    if not charon_bin:
        for candidate in ["/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon", shutil.which("charon")]:
            if candidate and os.path.exists(candidate):
                charon_bin = candidate
                break
    if not charon_bin or not os.path.exists(charon_bin):
        issues.append("strongSwan 'charon' binary not found (checked /usr/lib/ipsec/charon)")

    # 2. Check geneve module
    lsmod = subprocess.run(["lsmod"], capture_output=True, text=True)
    if "geneve" not in lsmod.stdout:
        issues.append("Kernel module 'geneve' is not loaded in host kernel")

    # 3. Check iptables and tcpdump
    for tool in ["ip", "iptables", "tcpdump"]:
        if not shutil.which(tool):
            issues.append(f"Required binary '{tool}' is missing")

    # 4. Check user privileges / unshare
    if os.geteuid() != 0:
        apparmor_restrict = pathlib.Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        if apparmor_restrict.exists() and apparmor_restrict.read_text().strip() == "1":
            issues.append("Unprivileged user namespace clone is restricted by AppArmor")

    return charon_bin, issues


def run(*args):
    try:
        return subprocess.check_output(list(args), text=True, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.output) from error


def main():
    if not os.environ.get("LD_BP_LAB_HOST_NETNS") or os.readlink("/proc/self/ns/net") == os.environ["LD_BP_LAB_HOST_NETNS"] or os.geteuid() != 0:
        charon_bin, issues = check_prerequisites()
        if issues:
            print("================================================================================")
            print("GENEVE + IPSEC REAL KERNEL LAB: PREREQUISITE CHECK FAILED")
            print("================================================================================")
            for issue in issues:
                print(f" - [LIMITATION] {issue}")
            print("\nExplicit Limitation Statement:")
            print("This environment does not have root access, pre-loaded 'geneve' module, or")
            print("strongSwan 'charon' binary. Real kernel namespace testing must be performed on")
            print("a prepared testbed or container with CAP_NET_ADMIN and strongSwan installed.")
            print("================================================================================")
            sys.exit(77)

        # Re-execute in isolated user/network namespace if permitted
        env = dict(os.environ, LD_BP_LAB_HOST_NETNS=os.readlink("/proc/self/ns/net"))
        sys.exit(subprocess.call(["unshare", "-Urn", sys.executable, __file__, "--inside"], env=env))

    # Inside isolated namespace
    charon_bin, issues = check_prerequisites()
    if issues:
        print("Cannot run inside: " + "; ".join(issues))
        sys.exit(1)

    children = []
    workers = []
    with tempfile.TemporaryDirectory(prefix="ldbp-geneve-lab-") as folder:
        try:
            print("1. Creating isolated child namespaces...")
            for _ in range(2):
                children.append(subprocess.Popen(["unshare", "-n", "sleep", "120"]))
            pids = [str(p.pid) for p in children]

            for pid in pids:
                for _ in range(100):
                    if os.readlink("/proc/" + pid + "/ns/net") != os.readlink("/proc/self/ns/net"):
                        break
                    time.sleep(0.01)
                else:
                    raise RuntimeError("Child namespace did not start")

            def ns(index, *args):
                return run(
                    "nsenter", "-t", pids[index], "-n", "--",
                    "env", "LD_BP_VICI_SOCKET=" + folder + "/run-" + str(index) + "/charon.vici",
                    *args
                )

            run("ip", "link", "add", "gnv-a", "type", "veth", "peer", "name", "gnv-b")
            for index, link in enumerate(("gnv-a", "gnv-b")):
                run("ip", "link", "set", link, "netns", pids[index])
                ns(index, "ip", "link", "set", "lo", "up")
                ns(index, "ip", "link", "set", link, "up")
                ns(index, "ip", "addr", "add", "192.0.2." + str(index + 1) + "/30", "dev", link)
                ns(index, "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
                ns(index, "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
                ns(index, "iptables", "-P", "INPUT", "DROP")

            print("2. Spawning isolated charon instances...")
            bwrap = os.environ.get("LD_BP_LAB_BWRAP", "bwrap")
            for index in range(2):
                run_dir = folder + "/run-" + str(index)
                pathlib.Path(run_dir).mkdir()
                conf = folder + "/strongswan-" + str(index) + ".conf"
                pathlib.Path(conf).write_text(
                    "charon {\n"
                    " load = random nonce openssl kernel-netlink socket-default vici\n"
                    " filelog {\n stdout {\n default = 1\n flush_line = yes\n }\n }\n"
                    " plugins {\n vici {\n socket = unix:///run/charon.vici\n }\n }\n"
                    "}\n"
                )
                log = open(folder + "/charon-" + str(index) + ".log", "w+")
                proc = subprocess.Popen(
                    [
                        "nsenter", "-t", pids[index], "-n", "--",
                        bwrap, "--die-with-parent", "--bind", "/", "/", "--bind", run_dir, "/run",
                        "--ro-bind", conf, "/etc/strongswan.conf",
                        "--setenv", "STRONGSWAN_CONF", "/etc/strongswan.conf",
                        charon_bin, "--debug-lib", "1", "--debug-cfg", "1", "--debug-ike", "1"
                    ],
                    stdout=log, stderr=log
                )
                workers.append(proc)
                for _ in range(200):
                    if pathlib.Path(run_dir + "/charon.vici").exists():
                        break
                    if proc.poll() is not None:
                        log.seek(0)
                        raise RuntimeError(log.read())
                    time.sleep(0.02)
                else:
                    log.seek(0)
                    raise RuntimeError("Private charon socket did not start: " + log.read())

            configs = []
            paths = []
            for index in range(2):
                c = dict(
                    owner="ldbp-geneve-v1",
                    interface="gni0123456789",
                    role="iran" if index == 0 else "kharej",
                    local="192.0.2." + str(index + 1),
                    remote="192.0.2." + str(2 - index),
                    private="10.205.0." + str(index + 1),
                    peer="10.205.0." + str(2 - index),
                    vni=1000,
                    dst_port=6081,
                    mtu=1400,
                    ports=[22500],
                    security={"mode": "ipsec", "psk": "c" * 64, "reqid": 123456},
                )
                configs.append(c)
                p = folder + "/" + str(index) + ".json"
                paths.append(p)
                pathlib.Path(p).write_text(json.dumps(c))
                ns(index, "python3", AGENT, "preflight", p)
                ns(index, "python3", AGENT, "up", p)

            print("3. Initiating IPsec and verifying SA establishment...")
            ns(0, "python3", AGENT, "secure-start", paths[0])
            for index in range(2):
                ns(index, "python3", AGENT, "secure-check", paths[index])

            # Monitor underlay traffic
            capture = folder + "/underlay.pcap"
            cap = subprocess.Popen(
                ["nsenter", "-t", pids[0], "-n", "--", "tcpdump", "-Z", "root", "-U", "-i", "gnv-a", "-w", capture, "udp port 6081 or ip proto 50"],
                stdout=open(folder + "/capture.log", "w"), stderr=subprocess.STDOUT
            )
            workers.append(cap)
            time.sleep(0.2)

            print("4. Transmitting TCP and UDP data over private IP link...")
            backend = """import socket,threading,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],22500));s.listen()
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind((sys.argv[1],22500))
def udp():
 while True:
  data,addr=u.recvfrom(65535);u.sendto(data,addr)
threading.Thread(target=udp,daemon=True).start()
print('READY',flush=True)
while True:
 c,_=s.accept()
 def handle(c):
  with c:
   while True:
    data=c.recv(65536)
    if not data:break
    c.sendall(data)
 threading.Thread(target=handle,args=(c,),daemon=True).start()
"""
            for index in range(2):
                server_proc = subprocess.Popen(["nsenter", "-t", pids[index], "-n", "--", "python3", "-u", "-c", backend, configs[index]['private']], stdout=subprocess.PIPE, text=True)
                workers.append(server_proc)
                assert server_proc.stdout.readline().strip() == "READY"

            def xfrm_bytes(index):
                output = ns(index, 'ip', '-s', 'xfrm', 'state')
                assert 'rfc4106(gcm(aes))' in output
                return sum(map(int, re.findall(r'(\d+)\(bytes\)', output)))
            before = [xfrm_bytes(i) for i in range(2)]
            # Probe TCP and UDP
            for index in range(2):
                ns(index, "python3", AGENT, "probe", paths[index], "22500", "nonce-geneve-test-"+str(index))
            print("   -> PASS: TCP/UDP data passed in both initiation directions through the private IP link.")

            print("5. Inspecting XFRM states and verifying increasing byte counters...")
            after = [xfrm_bytes(i) for i in range(2)]
            assert all(a > b for a, b in zip(after, before)), (before, after)
            print("   -> PASS: Established SA verified with active XFRM byte counters.")

            print("6. SA termination and verifying prevention of unencrypted bypass...")
            for index in range(2):
                ns(index, "python3", AGENT, "secure-stop", paths[index])
                ns(index, "ip", "xfrm", "state", "flush")
                ns(index, "ip", "xfrm", "policy", "flush")

            # With SA terminated, traffic must fail and plaintext must be dropped
            try:
                ns(0, "python3", AGENT, "probe", paths[0], "22500", "fail-nonce")
            except RuntimeError:
                pass
            else:
                raise AssertionError("Traffic passed after IPsec SAs and policies were flushed!")

            cap.terminate()
            cap.wait(timeout=5)
            # Inspect tcpdump output: raw port 6081 must not appear unencrypted
            raw = subprocess.run(["tcpdump", "-Z", "root", "-n", "-r", capture, "udp port 6081 and not ip proto 50"], capture_output=True, text=True, check=True).stdout
            assert len(raw.strip()) == 0, f"Leaked plaintext Geneve packets detected: {raw}"
            print("   -> PASS: SA termination stopped traffic; no plaintext Geneve leaked.")

            print("7. Cleaning up test resources...")
            for index in range(2):
                ns(index, "python3", AGENT, "down", paths[index])
            print("   -> PASS: Cleaned up test interfaces and firewall rules.")

            print("=== Geneve + IPsec Real Kernel Network Lab Passed Successfully ===")
        finally:
            for w in workers + children:
                if w.poll() is None:
                    w.terminate()
            for w in workers + children:
                try:
                    w.wait(timeout=3)
                except Exception:
                    w.kill()


if __name__ == "__main__":
    main()
