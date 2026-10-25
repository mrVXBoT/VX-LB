"""Unit tests for server health/diagnostics additions (SSHManager.diagnose,
storage.update_server_telemetry, /api/servers/test)."""
import json
import threading
import time
import unittest
from contextlib import nullcontext
from http.client import HTTPConnection
from unittest.mock import MagicMock, patch
from core import ssh_client, storage, web_server as web


class DiagnoseTests(unittest.TestCase):
    def _ssh(self, ok=True):
        ssh = ssh_client.SSHManager("192.0.2.1", 22, "root")
        ssh.connect = MagicMock(return_value=(ok, "" if ok else "auth failed"))
        ssh.execute = MagicMock(side_effect=lambda cmd, timeout=30: (0, "value", ""))
        ssh.close = MagicMock()
        return ssh

    def test_diagnose_reachable(self):
        d = self._ssh().diagnose()
        self.assertTrue(d["reachable"])
        self.assertIn("latency_ms", d)
        self.assertEqual(d["os"], "value")
        self.assertEqual(d["arch"], "value")

    def test_diagnose_unreachable(self):
        d = self._ssh(ok=False).diagnose()
        self.assertFalse(d["reachable"])
        self.assertEqual(d["error"], "auth failed")
        self.assertNotIn("os", d)

    def test_diagnose_recorded_host_cmd_failure(self):
        ssh = ssh_client.SSHManager("192.0.2.1", 22, "root")
        ssh.connect = MagicMock(return_value=(True, ""))
        ssh.execute = MagicMock(return_value=(1, "", "boom"))
        ssh.close = MagicMock()
        d = ssh.diagnose()
        self.assertTrue(d["reachable"])
        self.assertEqual(d["os"], "")


class TcpCcTests(unittest.TestCase):
    def _ssh(self):
        ssh = ssh_client.SSHManager("192.0.2.1", 22, "root")
        ssh.execute = MagicMock(return_value=(0, "bbr\n", ""))
        ssh.write_file = MagicMock(return_value=True)
        ssh.close = MagicMock()
        return ssh

    def test_tcp_cc_status(self):
        ssh = self._ssh()
        st = ssh.tcp_cc_status()
        self.assertEqual(st["cc"], "bbr")
        self.assertTrue(st["bbr_available"])
        self.assertEqual(st["default_qdisc"], "bbr")

    def test_set_tcp_cc(self):
        ssh = self._ssh()
        st = ssh.set_tcp_cc("bbr", "fq")
        self.assertEqual(st["cc"], "bbr")
        ssh.write_file.assert_called_once()
        path = ssh.write_file.call_args[0][0]
        self.assertTrue(path.endswith("99-vxlb-bbr.conf"))


class UpdateServerTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.data = {"iran_servers": [{"ip": "192.0.2.1", "name": "s1"}], "kharej_servers": []}

        def fake_atomic(callback):
            callback(self.data)

        self.patches = [
            patch.object(storage, "load_data", side_effect=lambda: self.data),
            patch.object(storage, "atomic_update", side_effect=fake_atomic),
            patch.object(storage, "_atomic_write_json", side_effect=lambda path, data: None),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_update_server_telemetry_merges(self):
        ok = storage.update_server_telemetry("iran", "192.0.2.1", {
            "health": "ok", "last_seen": 123, "last_latency_ms": 4.2,
        })
        self.assertTrue(ok)
        rec = self.data["iran_servers"][0]
        self.assertEqual(rec["health"], "ok")
        self.assertEqual(rec["last_seen"], 123)
        self.assertEqual(rec["last_latency_ms"], 4.2)

    def test_update_server_telemetry_missing(self):
        self.assertFalse(storage.update_server_telemetry("iran", "203.0.113.9", {"health": "ok"}))


class WebServerTestEndpointTests(unittest.TestCase):
    def setUp(self):
        self.data = {"iran_servers": [{"ip": "192.0.2.1", "name": "s1",
                                        "port": 22, "username": "root"}],
                      "kharej_servers": [], "pools": {}}

        def fake_atomic(callback):
            callback(self.data)

        def fake_update_server_telemetry(stype, ip, fields):
            for s in self.data.get(stype + "_servers", []):
                if s.get("ip") == ip:
                    s.update(fields)
                    return True
            return False

        self.patches = [
            patch.object(web, "load_data", side_effect=lambda: self.data),
            patch.object(web, "get_servers", side_effect=lambda t: self.data.get(t + "_servers", [])),
            patch.object(web, "atomic_update", side_effect=fake_atomic),
            patch.object(web, "update_server_telemetry", side_effect=fake_update_server_telemetry),
            patch.object(web, "mutation_lock", side_effect=nullcontext),
            patch.object(web, "routing_lock", side_effect=nullcontext),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

        self.server = web.ThreadedHTTPServer(("127.0.0.1", 0), web.LDWebRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.token = "health-test-token"
        web.AUTH_TOKENS[self.token] = time.time() + 3600
        self.addCleanup(web.AUTH_TOKENS.pop, self.token, None)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None):
        conn = HTTPConnection("127.0.0.1", self.server.server_port)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"}
        data = json.dumps(body) if body is not None else None
        conn.request(method, path, data, headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            return resp.status, json.loads(raw)
        except Exception:
            return resp.status, raw

    def test_servers_test_endpoint_reachable(self):
        fake_ssh = MagicMock()
        fake_ssh.diagnose.return_value = {
            "reachable": True, "latency_ms": 5.2, "os": "Ubuntu 22.04",
            "arch": "x86_64", "cpu": "4", "load": "0.1 0.2 0.3",
            "mem": "1000 200 800", "disk": "20G 2G 18G 10%",
        }
        with patch.object(web.SSHManager, "from_server", return_value=fake_ssh):
            status, body = self.request("POST", "/api/servers/test", {"type": "iran", "ip": "192.0.2.1"})
        self.assertEqual(status, 200)
        self.assertTrue(body["reachable"])
        self.assertEqual(body["health"], "ok")
        self.assertEqual(body["arch"], "x86_64")
        self.assertEqual(self.data["iran_servers"][0]["health"], "ok")

    def test_servers_test_endpoint_unreachable(self):
        fake_ssh = MagicMock()
        fake_ssh.diagnose.return_value = {"reachable": False, "latency_ms": 0, "error": "timeout"}
        with patch.object(web.SSHManager, "from_server", return_value=fake_ssh):
            status, body = self.request("POST", "/api/servers/test", {"type": "iran", "ip": "192.0.2.1"})
        self.assertEqual(status, 200)
        self.assertFalse(body["reachable"])
        self.assertEqual(body["health"], "err")

    def test_servers_test_endpoint_missing(self):
        status, body = self.request("POST", "/api/servers/test", {"type": "iran", "ip": "203.0.113.9"})
        self.assertEqual(status, 404)

    def test_servers_cc_status(self):
        fake_ssh = MagicMock()
        fake_ssh.tcp_cc_status.return_value = {"cc": "bbr", "default_qdisc": "fq", "bbr_available": True}
        with patch.object(web.SSHManager, "from_server", return_value=fake_ssh):
            status, body = self.request("POST", "/api/servers/cc", {"type": "iran", "ip": "192.0.2.1", "action": "status"})
        self.assertEqual(status, 200)
        self.assertEqual(body["status"]["cc"], "bbr")

    def test_servers_cc_enable(self):
        fake_ssh = MagicMock()
        fake_ssh.tcp_cc_status.return_value = {"cc": "cubic", "default_qdisc": "pfifo_fast", "bbr_available": True}
        fake_ssh.set_tcp_cc.return_value = {"cc": "bbr", "default_qdisc": "fq", "bbr_available": True}
        with patch.object(web.SSHManager, "from_server", return_value=fake_ssh):
            status, body = self.request("POST", "/api/servers/cc", {"type": "iran", "ip": "192.0.2.1", "action": "enable"})
        self.assertEqual(status, 200)
        self.assertTrue(body["enabled"])
        self.assertEqual(body["status"]["cc"], "bbr")
        self.assertEqual(self.data["iran_servers"][0]["cc_before"], "cubic")


if __name__ == "__main__":
    unittest.main()


if __name__ == "__main__":
    unittest.main()
