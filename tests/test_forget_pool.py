"""Tests for the 'delete pool without cleanup' (forget_pool) capability."""
import json
import threading
import time
import unittest
from contextlib import nullcontext
from http.client import HTTPConnection
from unittest.mock import patch
from core import load_balancer as lb
from core import web_server as web


class ForgetPoolTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "pools": {
                "test-pool": {
                    "name": "test-pool",
                    "transport": "rathole",
                    "engine": "rathole",
                    "kharej_server": {"ip": "198.51.100.1", "port": 22},
                    "client_ports": ["2264"],
                    "nodes": [
                        {"ip": "203.0.113.1", "node_name": "rath1", "engine": "rathole"},
                        {"ip": "203.0.113.2", "node_name": "rath2", "engine": "rathole"},
                    ],
                }
            },
            "node_telemetry": {"test-pool:203.0.113.1": {}},
            "watchdog_status": {"pool_reports": {"test-pool": {}}},
            "pool_tasks": {"test-pool": {"status": "failed"}},
        }

        def fake_atomic(callback):
            callback(self.data)

        self.patches = [
            patch.object(lb, "get_pools", side_effect=lambda: self.data["pools"]),
            patch.object(lb, "atomic_update", side_effect=fake_atomic),
            patch.object(lb, "storage_delete_pool", side_effect=lambda name: self.data["pools"].pop(name, None)),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def test_forget_pool_removes_pool_and_records_cleanup(self):
        ok, msg = lb.LoadBalancerManager.forget_pool("test-pool")
        self.assertTrue(ok)
        self.assertNotIn("test-pool", self.data["pools"])
        self.assertNotIn("test-pool", self.data["pool_tasks"])
        pending = self.data.get("pending_node_cleanup", {})
        self.assertEqual(len(pending), 2)
        records = list(pending.values())
        self.assertTrue(all(r["pool"] == "test-pool" for r in records))
        self.assertEqual({r["ip"] for r in records}, {"203.0.113.1", "203.0.113.2"})
        self.assertTrue(all(r["status"] == "unverified" for r in records))
        self.assertNotIn("test-pool:203.0.113.1", self.data["node_telemetry"])
        self.assertNotIn("test-pool", self.data["watchdog_status"]["pool_reports"])

    def test_forget_pool_missing(self):
        ok, msg = lb.LoadBalancerManager.forget_pool("nope")
        self.assertFalse(ok)


class ForgetPoolWebTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "pools": {
                "test-pool": {
                    "name": "test-pool",
                    "transport": "rathole",
                    "engine": "rathole",
                    "kharej_server": {"ip": "198.51.100.1", "port": 22},
                    "client_ports": ["2264"],
                    "nodes": [{"ip": "203.0.113.1", "node_name": "rath1"}],
                }
            }
        }

        def fake_atomic(callback):
            callback(self.data)

        self.patches = [
            patch.object(web, "load_data", side_effect=lambda: self.data),
            patch.object(web, "atomic_update", side_effect=fake_atomic),
            patch.object(web, "get_pools", side_effect=lambda: self.data["pools"]),
            patch.object(web, "mutation_lock", side_effect=nullcontext),
            patch.object(web, "routing_lock", side_effect=nullcontext),
            patch.object(lb, "atomic_update", side_effect=fake_atomic),
            patch.object(lb, "get_pools", side_effect=lambda: self.data["pools"]),
            patch("core.pool_tasks.start", return_value=(True, {"id": "x"})),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

        self.server = web.ThreadedHTTPServer(("127.0.0.1", 0), web.LDWebRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.token = "forget-test-token"
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

    def test_delete_endpoint_forget_true(self):
        status, body = self.request("POST", "/api/pools/delete", {"pool": "test-pool", "forget": True})
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        self.assertNotIn("test-pool", self.data["pools"])

    def test_delete_endpoint_normal_still_uses_task(self):
        status, body = self.request("POST", "/api/pools/delete", {"pool": "test-pool"})
        self.assertEqual(status, 202)
        self.assertTrue(body["accepted"])
        self.assertIn("test-pool", self.data["pools"])


if __name__ == "__main__":
    unittest.main()
