"""Each GOST profile must carry a TCP payload to the published backend port.

The bundled gost 3.0.0-rc10 binary is the one installed on the servers. A
profile whose generated command does not echo fails this test instead of
failing after a live transport change.
"""
import os
import socket
import subprocess
import threading
import time
import unittest

from core import gost_engine as gost

BINARY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "x86_64", "gost")
PASSWORD = "secretpass"
CERT = "/tmp/gost-lab/c.pem"
KEY = "/tmp/gost-lab/k.pem"


def _echo(port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(20)
    while True:
        client, _ = server.accept()
        try:
            client.sendall(b"ECHO:" + client.recv(64))
        except OSError:
            pass
        client.close()


def _ensure_cert():
    if os.path.isfile(CERT) and os.path.isfile(KEY):
        return
    os.makedirs(os.path.dirname(CERT), exist_ok=True)
    subprocess.check_call([
        "openssl", "req", "-new", "-newkey", "rsa:2048", "-days", "2", "-nodes", "-x509",
        "-subj", "/CN=www.speedtest.net", "-keyout", KEY, "-out", CERT,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class GostProfileForwardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(BINARY):
            raise unittest.SkipTest("bundled gost binary is absent")
        _ensure_cert()

    def test_every_profile_echoes_tcp(self):
        names = list(gost.PROFILES)
        base = 25000
        for index, name in enumerate(names):
            threading.Thread(target=_echo, args=(base + index * 10,), daemon=True).start()
        time.sleep(0.2)
        failed = []
        for index, name in enumerate(names):
            backend = base + index * 10
            outer = backend + 1
            client = backend + 2
            tls = (CERT, KEY) if gost.PROFILES[name].get("tls") else None
            server_url = gost._server_listen_url(name, outer, PASSWORD, tls).replace(f":{outer}", f"127.0.0.1:{outer}", 1)
            node = {"gost": {"profile": name, "port": outer, "password": PASSWORD, "binary": BINARY, "host": "/tmp/gost-lab/x"}}
            cmd = gost._cmd(object(), node, "client", outside_ip="127.0.0.1", ports=[str(backend)])
            cmd = [part.replace(f":{backend}/127.0.0.1:{backend}", f"127.0.0.1:{client}/127.0.0.1:{backend}") for part in cmd]
            server = subprocess.Popen([BINARY, "-L", server_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)
            forwarder = subprocess.Popen([BINARY, *cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            try:
                sock = socket.create_connection(("127.0.0.1", client), 2)
                sock.settimeout(2)
                sock.sendall(b"ping")
                data = sock.recv(32)
                if data != b"ECHO:ping":
                    failed.append(f"{name}={data!r}")
            except Exception as error:
                failed.append(f"{name}={type(error).__name__}")
            finally:
                forwarder.terminate()
                server.terminate()
                forwarder.wait(timeout=2)
                server.wait(timeout=2)
        self.assertEqual(failed, [])


if __name__ == "__main__":
    unittest.main()
