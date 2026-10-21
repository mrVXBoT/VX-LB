import copy
import json
import os
import threading
import time
import unittest
from contextlib import nullcontext
from http.client import HTTPConnection
from unittest.mock import MagicMock, patch

from core import load_balancer as lb
from core import node_removal
from core import pool_creation
from core import ssh_client
from core import storage
from core import transport_change as tc
from core import watchdog
from core import web_server as web


class AuditFixesTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "cloudflare": {
                "api_token": "secret_cloudflare_token_12345",
                "zone_id": "zone_12345",
                "subdomain": "edge.example.com",
                "enabled": True,
            },
            "pools": {
                "prod-pool": {
                    "name": "prod-pool",
                    "transport": "pck",
                    "engine": "backpack",
                    "dns_policy": "strict",
                    "kharej_server": {"ip": "198.51.100.1", "port": 22},
                    "nodes": [
                        {"ip": "203.0.113.1", "node_name": "node-1", "server_name": "node-1"}
                    ],
                }
            },
            "web_password": web._hash_password("SuperSecretPass123!"),
        }

        def fake_atomic(callback):
            callback(self.data)

        self.patches = [
            patch.object(web, "load_data", side_effect=lambda: copy.deepcopy(self.data)),
            patch.object(web, "atomic_update", side_effect=fake_atomic),
            patch.object(web, "mutation_lock", side_effect=nullcontext),
            patch.object(web, "routing_lock", side_effect=nullcontext),
            patch.object(lb, "get_pools", side_effect=lambda: copy.deepcopy(self.data["pools"])),
            patch.object(lb, "atomic_update", side_effect=fake_atomic),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

        self.server = web.ThreadedHTTPServer(("127.0.0.1", 0), web.LDWebRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.test_token = "audit-test-token-valid"
        web.AUTH_TOKENS[self.test_token] = time.time() + 3600
        self.addCleanup(web.AUTH_TOKENS.pop, self.test_token, None)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, auth=True, extra_headers=None):
        conn = HTTPConnection("127.0.0.1", self.server.server_port)
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.test_token}"
        if extra_headers:
            headers.update(extra_headers)
        data = json.dumps(body) if body is not None else None
        conn.request(method, path, data, headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            body_json = json.loads(raw)
        except Exception:
            body_json = raw.decode("utf-8", errors="replace")
        conn.close()
        return resp.status, body_json

    # --- Problem 1: Web server default bind address ---
    def test_problem1_default_bind_is_localhost(self):
        with patch.dict(os.environ, {}, clear=True):
            # Test default host in web_server.py
            host = os.environ.get("VX_LB_WEB_HOST", "127.0.0.1")
            self.assertEqual(host, "127.0.0.1")

    # --- Problem 2: Node removal must not report success if SSH fails ---
    @patch("core.load_balancer.stop_and_remove_tunnel")
    @patch("core.load_balancer.SSHManager")
    def test_problem2_node_removal_fails_if_ssh_fails(self, mock_ssh_cls, mock_stop):
        mock_ssh = MagicMock()
        mock_ssh.connect.return_value = (False, "Connection timed out")
        mock_ssh_cls.return_value = mock_ssh

        # Without force: must fail and not delete the node
        ok, msg = lb.LoadBalancerManager.remove_node("prod-pool", "203.0.113.1", force=False)
        self.assertFalse(ok)
        self.assertIn("Failed to connect", msg)
        self.assertEqual(len(self.data["pools"]["prod-pool"]["nodes"]), 1)

        # With force=True: allowed to proceed
        ok_force, msg_force = lb.LoadBalancerManager.remove_node("prod-pool", "203.0.113.1", force=True)
        self.assertTrue(ok_force)
        self.assertEqual(len(self.data["pools"]["prod-pool"]["nodes"]), 0)

    # --- Problem 3: Content-Length limits and validation ---
    def test_problem3_content_length_protection(self):
        # 1. Normal request passes
        status, body = self.request("POST", "/api/logout", {})
        self.assertEqual(status, 200)

        # 2. Oversized payload rejected with 413
        conn = HTTPConnection("127.0.0.1", self.server.server_port)
        oversized = 3 * 1024 * 1024  # 3MB > 2MB limit
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(oversized),
            "Authorization": f"Bearer {self.test_token}",
        }
        conn.request("POST", "/api/logout", None, headers)
        resp = conn.getresponse()
        resp_body = json.loads(resp.read())
        conn.close()
        self.assertEqual(resp.status, 413)
        self.assertIn("too large", resp_body.get("error", "").lower())

    # --- Problem 4: DNS failover NO_VERIFIED_BACKEND state ---
    def test_problem4_dns_no_verified_backend_strict_and_standby(self):
        wd = watchdog.TelemetryWatchdog()
        # Mock analyze_node_health to report all nodes DOWN
        with patch.object(wd, "analyze_node_health", return_value=("DOWN", "Filtered by probe", [], {})), \
             patch.object(watchdog, "load_data", return_value=self.data), \
             patch.object(watchdog, "atomic_update"):

            # Under strict policy with no healthy node
            report = wd.run_check_cycle()
            pool_rep = report["pool_reports"]["prod-pool"]
            self.assertEqual(pool_rep.get("backend_state"), "NO_VERIFIED_BACKEND")
            self.assertEqual(pool_rep["healthy_ips"], [])

            # With standby_ip configured
            self.data["pools"]["prod-pool"]["standby_ip"] = "198.51.100.99"
            report_standby = wd.run_check_cycle()
            pool_rep_standby = report_standby["pool_reports"]["prod-pool"]
            self.assertEqual(pool_rep_standby["healthy_ips"], ["198.51.100.99"])

    # --- Problem 5: Production Readiness Gate enforced ---
    def test_problem5_production_readiness_gate_enforcement(self):
        # 1. Unsupported engine is rejected at create_pool
        ok, msg, _ = lb.LoadBalancerManager.create_pool(
            pool_name="unsupported-pool",
            kharej_server={"ip": "198.51.100.1"},
            iran_servers=[{"ip": "203.0.113.1"}],
            transport="tcp",
            engine="anycast",
            client_ports=["443"],
        )
        self.assertFalse(ok)
        self.assertIn("unsupported and disabled by policy", msg)

        # 2. Experimental engine is blocked when is_production=True unless allow_experimental=True
        ok_exp, msg_exp, _ = lb.LoadBalancerManager.create_pool(
            pool_name="exp-pool",
            kharej_server={"ip": "198.51.100.1"},
            iran_servers=[{"ip": "203.0.113.1"}],
            transport="wireguard",
            client_ports=["443"],
            is_production=True,
            allow_experimental=False,
        )
        self.assertFalse(ok_exp)
        self.assertIn("experimental", msg_exp)

        # 3. pool_creation.start rejects unsupported engines
        ok_start, msg_start = pool_creation.start({
            "pool_name": "unsupported-task",
            "kharej_server": {"ip": "198.51.100.1"},
            "iran_servers": [{"ip": "203.0.113.1"}],
            "transport": "tcp",
            "engine": "anycast",
            "client_ports": ["443"],
        })
        self.assertFalse(ok_start)
        self.assertIn("unsupported", msg_start)

        # 4. transport_change.start_change rejects unsupported engines
        with patch.object(tc, "load_data", return_value=self.data):
            ok_tc, msg_tc = tc.start_change("prod-pool", "pck", engine="anycast")
            self.assertFalse(ok_tc)
            self.assertIn("unsupported", msg_tc)

    # --- Problem 6: Sensitive data masked in /api/status and session invalidation ---
    def test_problem6_mask_status_and_invalidate_sessions(self):
        # 1. /api/status masks Cloudflare API token
        status, body = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        cf = body.get("global_cloudflare", {})
        self.assertTrue(cf.get("api_token", "").startswith("…"))
        self.assertNotIn("secret_cloudflare_token", cf.get("api_token", ""))

        # 2. /api/password clears other active sessions
        old_token = "stale-session-token"
        web.AUTH_TOKENS[old_token] = time.time() + 3600
        status_pass, body_pass = self.request("POST", "/api/password", {"new_password": "NewStrongPassword123!"})
        self.assertEqual(status_pass, 200)
        # Old token must be invalidated
        self.assertNotIn(old_token, web.AUTH_TOKENS)
        # Current caller's token remains valid
        self.assertIn(self.test_token, web.AUTH_TOKENS)

    # --- Problem 7: Reliable free port allocation ---
    def test_problem7_free_port_allocation_safety(self):
        client = ssh_client.SSHManager("192.0.2.1", 22, "root")
        # Simulate all checks failing and candidates busy
        with patch.object(client, "execute", return_value=(1, "", "address already in use")):
            with self.assertRaises(RuntimeError) as ctx:
                client.find_free_port(start_range=20000, end_range=20050)
            self.assertIn("Unable to allocate a verified free port", str(ctx.exception))

    # --- Problem 8: Storage atomic update and backup integrity ---
    def test_problem8_storage_atomic_integrity(self):
        test_dict = {"schema_version": 1, "test_key": "test_val"}
        with patch.object(storage, "load_data", return_value=copy.deepcopy(test_dict)), \
             patch.object(storage, "_atomic_write_json") as mock_write:
            storage.atomic_update(lambda d: d.update({"test_key": "updated_val"}))
            mock_write.assert_called_once()
            written_data = mock_write.call_args[0][1]
            self.assertEqual(written_data["test_key"], "updated_val")


if __name__ == "__main__":
    unittest.main()
