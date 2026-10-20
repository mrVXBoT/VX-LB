import paramiko
import socket
import time
import secrets
import os
import warnings
from typing import Tuple, Optional
from core.validation import shquote

# Security: the BackPack installer is fetched from a third-party repo at a
# mutable branch. Override with VX_LB_BACKPACK_INSTALL_URL after auditing the
# script, or vendor a pinned release tarball with a SHA256 check.
BACKPACK_INSTALL_URL = os.environ.get(
    "VX_LB_BACKPACK_INSTALL_URL",
    "https://raw.githubusercontent.com/AminMGMT/BackPack/main/install.sh",
)

# VX-LB's own known_hosts file for Trust-On-First-Use (TOFU) host key pinning.
_KNOWN_HOSTS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ssh_known_hosts"
)


class _TOFUHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-On-First-Use: store unknown host keys, reject changed ones.

    paramiko itself raises BadHostKeyException when a *known* host presents a
    *different* key, so this policy only fires on first encounter -- the key
    is saved and every later connection is verified against it.
    """

    def missing_host_key(self, client, hostname, key):
        warnings.warn(
            f"VX-LB: trusting new SSH host key {key.get_name()} for {hostname} "
            f"(first encounter, TOFU). Fingerprint: {':'.join('%02x' % b for b in key.get_fingerprint())}"
        )
        client.get_host_keys().add(hostname, key.get_name(), key)
        try:
            os.makedirs(os.path.dirname(_KNOWN_HOSTS_FILE), exist_ok=True)
            client.save_host_keys(_KNOWN_HOSTS_FILE)
        except Exception:
            pass

class SSHManager:
    def __init__(
        self,
        ip: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        private_key: Optional[str] = None,
        timeout: int = 10,
    ):
        self.ip = ip.strip()
        self.port = int(port)
        self.username = username.strip()
        self.password = password
        self.key_path = os.path.expanduser(key_path) if key_path else None
        self.private_key = private_key
        self.timeout = timeout
        self.client: Optional[paramiko.SSHClient] = None

    @classmethod
    def from_server(cls, server_dict: dict, timeout: int = 10):
        return cls(
            ip=server_dict.get("ip", ""),
            port=int(server_dict.get("port") or server_dict.get("ssh_port") or 22),
            username=server_dict.get("username", "root"),
            password=server_dict.get("password"),
            key_path=server_dict.get("key_path"),
            private_key=server_dict.get("private_key"),
            timeout=timeout,
        )

    def connect(self) -> Tuple[bool, str]:
        """Retry transient handshakes without retrying rejected credentials or keys."""
        for attempt in range(3):
            ok, message = self._connect_once()
            if ok or not message.startswith("Server connection error:"):
                return ok, message
            if attempt < 2:
                time.sleep(attempt + 1)
        return False, message

    def _connect_once(self) -> Tuple[bool, str]:
        client = None
        connection = None
        try:
            client = paramiko.SSHClient()
            # Load system keys + VX-LB's TOFU store; unknown hosts are pinned
            # on first use, changed keys are rejected (MITM protection).
            try:
                client.load_system_host_keys()
            except Exception:
                pass
            try:
                if os.path.exists(_KNOWN_HOSTS_FILE):
                    client.load_host_keys(_KNOWN_HOSTS_FILE)
            except Exception:
                pass
            client.set_missing_host_key_policy(_TOFUHostKeyPolicy())
            family = socket.AF_INET6 if ':' in self.ip else socket.AF_INET
            connection = socket.socket(family, socket.SOCK_STREAM)
            connection.settimeout(self.timeout)
            if hasattr(socket, 'TCP_MAXSEG'):
                # Avoid MTU black holes during SSH key exchange and SFTP uploads.
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG,
                                      1200 if family == socket.AF_INET6 else 1360)
            connection.connect((self.ip, self.port))

            key_filename = None
            pkey = None
            if self.key_path and os.path.isfile(self.key_path):
                key_filename = self.key_path
            elif self.private_key:
                import io
                for pkey_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                    try:
                        pkey = pkey_class.from_private_key(io.StringIO(self.private_key))
                        break
                    except Exception:
                        pass

            client.connect(
                hostname=self.ip,
                sock=connection,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=key_filename,
                pkey=pkey,
                timeout=self.timeout,
                banner_timeout=15,
                auth_timeout=15,
                look_for_keys=(key_filename is None and pkey is None and not self.password),
                allow_agent=(key_filename is None and pkey is None and not self.password),
            )
            self.client = client
            client.get_transport().set_keepalive(20)
            return True, "Connection established successfully"
        except paramiko.AuthenticationException:
            return False, "Authentication failed: invalid username, password, or SSH key"
        except paramiko.BadHostKeyException:
            return False, "Host key verification failed: server identity changed"
        except (OSError, EOFError, paramiko.SSHException) as e:
            return False, f"Server connection error: {str(e)}"
        except Exception as e:
            return False, f"Unknown error: {str(e)}"
        finally:
            if client is not None and self.client is not client:
                client.close()
                if connection is not None:
                    connection.close()

    def close(self):
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

    def execute(self, cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Executes a command and returns exit_code, stdout, stderr."""
        for attempt in range(2):
            transport = self.client.get_transport() if self.client else None
            if not transport or not transport.is_active():
                self.close()
                ok, msg = self.connect()
                if not ok:
                    return -1, "", msg

            channel = None
            try:
                stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
                channel = stdout.channel
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                code = channel.recv_exit_status()
                return code, out, err
            except Exception as e:
                self.close()
                if attempt == 1:
                    return -1, "", str(e)
                time.sleep(0.5)
            finally:
                if channel:
                    try:
                        channel.close()
                    except Exception:
                        pass

    def is_alive(self) -> bool:
        """Quick check if SSH server is responding."""
        ok, _ = self.connect()
        if ok:
            self.close()
            return True
        return False

    def find_free_port(self, start_range: int = 22000, end_range: int = 58000) -> int:
        """Finds a verified free TCP/UDP port on the remote machine."""
        check_script = f"""python3 -c '
import socket, random
def is_free(p):
    for proto in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        try:
            s = socket.socket(socket.AF_INET, proto)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", p))
            s.close()
        except Exception:
            return False
    return True

ports = list(range({start_range}, {end_range}))
random.shuffle(ports)
for p in ports:
    if is_free(p):
        print(p)
        break
'"""
        code, out, _ = self.execute(check_script)
        if code == 0 and out.strip().isdigit():
            return int(out.strip())

        # Fallback to random guessing using ss/netstat
        for _ in range(20):
            cand = secrets.randbelow(end_range - start_range) + start_range
            c, o, _ = self.execute(f"ss -tuln | grep -q ':{cand} ' || echo 'free'")
            if "free" in o:
                return cand

        return 34567

    def upload_binary(self, local_path: str, remote_path: str, mode: int = 0o755) -> bool:
        """Publish a complete binary atomically, keeping partial uploads unusable."""
        if not os.path.isfile(local_path):
            return False
        remote_dir = "/".join(remote_path.split("/")[:-1])
        temporary_path = remote_path + ".upload-" + secrets.token_hex(8)
        if remote_dir:
            code, _, _ = self.execute(f"mkdir -p {shquote(remote_dir)}")
            if code != 0:
                return False
        sftp = None
        try:
            # A larger receive window avoids one small SSH window per WAN RTT.
            sftp = paramiko.SFTPClient.from_transport(
                self.client.get_transport(), window_size=16 * 1024 * 1024,
                max_packet_size=256 * 1024,
            )
            sftp.get_channel().settimeout(60)
            sftp.put(local_path, temporary_path)
            if sftp.stat(temporary_path).st_size != os.path.getsize(local_path):
                return False
            sftp.chmod(temporary_path, mode)
            code, _, _ = self.execute(
                f"mv -f {shquote(temporary_path)} {shquote(remote_path)}"
            )
            return code == 0
        except Exception:
            return False
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception:
                    pass
            self.execute(f"rm -f {shquote(temporary_path)}")

    def ensure_backpack_installed(self) -> Tuple[bool, str]:
        """Checks if BackPack binary exists at /usr/local/bin/backpack, installs if missing.
        
        Prioritizes bundled offline binary in bin/ for air-gapped / wartime survival.
        """
        code, out, _ = self.execute("[ -x /usr/local/bin/backpack ] && /usr/local/bin/backpack --help >/dev/null 2>&1 && echo 'installed'")
        if "installed" in out:
            return True, "BackPack is already installed"

        # 1. Offline Air-Gapped installation from bundled bin/
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        _, arch_raw, _ = self.execute("uname -m")
        remote_arch = arch_raw.strip().lower()
        arch_dir = "x86_64" if ("x86_64" in remote_arch or "amd64" in remote_arch) else ("aarch64" if ("aarch64" in remote_arch or "arm64" in remote_arch) else remote_arch)

        candidate_paths = [
            os.path.join(base_dir, "bin", arch_dir, "backpack"),
            os.path.join(base_dir, "bin", "backpack"),
            os.path.join(base_dir, "data", "binaries", arch_dir, "backpack"),
            os.path.join(base_dir, "data", "binaries", "backpack"),
        ]

        for candidate in candidate_paths:
            if os.path.exists(candidate) and os.path.isfile(candidate):
                uploaded = self.upload_binary(candidate, "/usr/local/bin/backpack", mode=0o755)
                if uploaded:
                    c, o, _ = self.execute("[ -x /usr/local/bin/backpack ] && /usr/local/bin/backpack --help >/dev/null 2>&1 && echo 'installed'")
                    if "installed" in o:
                        return True, "BackPack installed from local bundled binary (Air-gapped / Offline)"

        # 2. Online fallback as last resort if local bundled binary not present
        install_cmd = f"bash <(curl -fsSL {shquote(BACKPACK_INSTALL_URL)})"
        code, out, err = self.execute(install_cmd, timeout=120)

        # Verify
        c, o, _ = self.execute("[ -x /usr/local/bin/backpack ] && /usr/local/bin/backpack --help >/dev/null 2>&1 && echo 'installed'")
        if "installed" in o:
            return True, "BackPack installed successfully"
        return False, f"Failed to install BackPack: {err or out}"

    def write_file(self, remote_path: str, content: str) -> bool:
        """Writes content to a remote file."""
        encoded_content = content.encode("utf-8")
        remote_dir = "/".join(remote_path.split("/")[:-1])
        if remote_dir:
            self.execute(f"mkdir -p {shquote(remote_dir)}")
        sftp = None
        try:
            sftp = self.client.open_sftp()
            with sftp.file(remote_path, "w") as f:
                f.write(encoded_content)
            try:
                # Token-bearing configs must not be world-readable (M7).
                sftp.chmod(remote_path, 0o600)
            except Exception:
                pass
            return True
        except Exception:
            # Fallback via base64 in shell
            import base64
            b64 = base64.b64encode(encoded_content).decode("ascii")
            remote_dir = "/".join(remote_path.split("/")[:-1])
            cmd = f"mkdir -p {shquote(remote_dir)} && echo '{b64}' | base64 -d > {shquote(remote_path)} && chmod 600 {shquote(remote_path)}"
            c, _, _ = self.execute(cmd)
            return c == 0
        finally:
            if sftp:
                try:
                    sftp.close()
                except Exception:
                    pass

    def ensure_conn_monitor_installed(self) -> Tuple[bool, str]:
        """
        Ensures /usr/local/bin/vxlb-conn-monitor.py and its systemd service
        are deployed, enabled, and running on the remote node.
        """
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        script_path = os.path.join(base_dir, "scripts", "vxlb-conn-monitor.py")

        if not os.path.exists(script_path):
            return False, f"Local script not found at {script_path}"

        with open(script_path, "r", encoding="utf-8") as f:
            script_content = f.read()

        # 1. Upload script
        ok = self.write_file("/usr/local/bin/vxlb-conn-monitor.py", script_content)
        if not ok:
            return False, "Failed to upload vxlb-conn-monitor.py"

        self.execute("chmod +x /usr/local/bin/vxlb-conn-monitor.py")

        # 2. Deploy systemd unit
        service_content = """[Unit]
Description=BackPack Connection Telemetry Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/vxlb-conn-monitor.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        ok_srv = self.write_file("/etc/systemd/system/vxlb-conn-monitor.service", service_content)
        if not ok_srv:
            return False, "Failed to write vxlb-conn-monitor.service"

        # 3. Reload and restart service
        self.execute("systemctl daemon-reload && systemctl enable vxlb-conn-monitor.service && systemctl restart vxlb-conn-monitor.service")

        # 4. Verify status
        time.sleep(1)
        c, out, _ = self.execute("systemctl is-active vxlb-conn-monitor.service")
        if out.strip() == "active":
            return True, "vxlb-conn-monitor installed and running"
        return False, f"vxlb-conn-monitor service status: {out.strip()}"
