import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from unittest.mock import patch

import core.storage as storage
from core.watchdog import TelemetryWatchdog


SPEC = importlib.util.spec_from_file_location(
    "connection_monitor", Path(__file__).resolve().parents[1] / "scripts/bp-conn-monitor.py"
)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class EndSimulation(BaseException):
    pass


def simulate_monitor(samples):
    """Feed actual ss text through the monitor without SSH, sleeping or log writes."""
    position = [0]
    events = []

    def read_sockets():
        sample = samples[position[0]]
        if sample is None:
            return ""
        queue, received, acknowledged = sample
        return (
            f"ESTAB 0 {queue} 192.0.2.1:8443 192.0.2.20:40000\n"
            f" cubic bytes_received:{received} bytes_acked:{acknowledged} retrans:0/0\n"
        )

    def advance(_):
        position[0] += 1
        if position[0] == len(samples):
            raise EndSimulation()

    with patch.object(monitor, "get_sockets", side_effect=read_sockets), \
         patch.object(monitor.time, "time", side_effect=lambda: float(position[0])), \
         patch.object(monitor.time, "sleep", side_effect=advance), \
         patch.object(monitor, "log_event", side_effect=lambda event, *args: events.append(event)):
        try:
            monitor.monitor_loop()
        except EndSimulation:
            pass
    return events


class MonitorRecoveryTests(unittest.TestCase):
    healthy = [(0, 6000, 6000), (0, 7000, 7000), (0, 8000, 8000)]
    stalled = [(100, 8000, 8000)] * 5

    def test_recovery_is_logged_once_after_fresh_ack_progress(self):
        samples = self.healthy + self.stalled + [(0, 9000, 9000), (0, 10000, 10000)] * 2
        self.assertEqual(simulate_monitor(samples), [
            "USER_CONNECT", "USER_SESSION_ACTIVE", "TRANSPORT_STALL_DETECTED", "USER_SESSION_ACTIVE"
        ])

    def test_empty_queue_without_new_acks_does_not_prove_recovery(self):
        events = simulate_monitor(self.healthy + self.stalled + [(0, 8000, 8000)] * 3)
        self.assertEqual(events.count("USER_SESSION_ACTIVE"), 1)

    def test_recovered_connection_can_stall_again(self):
        samples = self.healthy + self.stalled + [(0, 9000, 9000), (0, 10000, 10000)]
        events = simulate_monitor(samples + [(100, 10000, 10000)] * 5)
        self.assertEqual(events.count("TRANSPORT_STALL_DETECTED"), 2)

    def test_unrecovered_stall_is_not_clean_on_close(self):
        events = simulate_monitor(self.healthy + self.stalled + [None])
        self.assertEqual(events[-1], "SESSION_CLOSED_STALLED")

    def test_recovered_session_closes_cleanly(self):
        events = simulate_monitor(self.healthy + self.stalled + [(0, 9000, 9000), (0, 10000, 10000), None])
        self.assertEqual(events[-1], "SESSION_CLOSED_NORMAL")

    def test_byte_totals_alone_do_not_prove_clean_close(self):
        self.assertEqual(simulate_monitor([(0, 20000, 20000), None])[-1], "SESSION_CLOSED_INCOMPLETE")

    def test_continuous_ack_progress_is_not_a_stall(self):
        events = simulate_monitor([(100, 6000 + i * 1000, 6000 + i * 1000) for i in range(8)])
        self.assertNotIn("TRANSPORT_STALL_DETECTED", events)

    def test_same_peer_on_two_ports_keeps_both_connections(self):
        text = "\n".join(
            f"ESTAB 0 0 192.0.2.1:{port} 192.0.2.20:40000\n cubic bytes_received:6000"
            for port in (443, 8443)
        )
        sockets = monitor.parse_sockets(text)
        self.assertEqual({info["port"] for info in sockets.values()}, {"443", "8443"})


class CanaryRoutingTests(unittest.TestCase):
    def test_canary_is_used_instead_of_filtered_fallback(self):
        nodes = [{"ip": "192.0.2.1", "server_name": "filtered"},
                 {"ip": "192.0.2.2", "server_name": "canary"}]
        data = {"pools": {"A": {
            "nodes": nodes, "client_ports": ["8443"], "dns_policy": "permissive",
            "cloudflare": {"enabled": True, "api_token": "fake", "zone_id": "fake", "subdomain": "a.example.test"}
        }}}
        watchdog = TelemetryWatchdog()
        with patch("core.watchdog.load_data", return_value=data), \
             patch.object(watchdog, "analyze_node_health", side_effect=[
                 ("FILTERED", "test", [], {}), ("CANARY", "test", [], {})
             ]), patch("core.watchdog.CloudflareManager") as cloudflare:
            cloudflare.return_value.sync_subdomain.return_value = {}
            report = watchdog.run_check_cycle()
        cloudflare.return_value.sync_subdomain.assert_called_once_with(
            "a.example.test", ["192.0.2.2"], proxied=False, ttl=60
        )
        self.assertEqual(report["pool_reports"]["A"]["healthy_ips"], ["192.0.2.2"])

    def test_shared_nodes_keep_pool_dns_independent(self):
        nodes = [{"ip": "192.0.2.1", "server_name": "one"}, {"ip": "192.0.2.2", "server_name": "two"}]
        data = {"pools": {name: {
            "nodes": nodes, "client_ports": [port], "dns_policy": "permissive",
            "cloudflare": {"enabled": True, "api_token": name, "zone_id": name, "subdomain": name.lower() + ".example.test"}
        } for name, port in (("A", "8443"), ("B", "443"))}}
        watchdog = TelemetryWatchdog()
        statuses = ["FILTERED", "CANARY", "HEALTHY", "FILTERED"]
        with patch("core.watchdog.load_data", return_value=data), \
             patch.object(watchdog, "analyze_node_health", side_effect=[(s, "test", [], {}) for s in statuses]), \
             patch("core.watchdog.CloudflareManager") as cf:
            cf.return_value.sync_subdomain.return_value = {}
            report = watchdog.run_check_cycle()
        self.assertEqual(report["pool_reports"]["A"]["healthy_ips"], ["192.0.2.2"])
        self.assertEqual(report["pool_reports"]["B"]["healthy_ips"], ["192.0.2.1"])
        self.assertEqual([call.args for call in cf.call_args_list], [("A", "A"), ("B", "B")])


class PrivateStorageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        root = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.directory = Path(root) / "data"
        for name, value in {
            "DATA_DIR": str(self.directory), "INVENTORY_FILE": str(self.directory / "inventory.json"),
            "LOCK_FILE": str(self.directory / "inventory.lock"), "LOG_FILE": str(self.directory / "watchdog.log")
        }.items():
            self.stack.enter_context(patch.object(storage, name, value))

    def test_files_private_even_with_permissive_umask(self):
        old_umask = os.umask(0)
        try:
            storage.save_pool("A", {"name": "A"})
            storage.save_pool("B", {"name": "B"})
        finally:
            os.umask(old_umask)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for name in ("inventory.json", "inventory.json.bak1", "inventory.lock"):
            self.assertEqual(stat.S_IMODE((self.directory / name).stat().st_mode), 0o600)
        backup = json.loads((self.directory / "inventory.json.bak1").read_text())
        self.assertIn("A", backup["pools"])
        self.assertNotIn("B", backup["pools"])

    def test_existing_permissive_files_are_repaired_without_data_loss(self):
        self.directory.mkdir(mode=0o755)
        content = {"pools": {"A": {"name": "A"}}}
        for name in ("inventory.json", "inventory.json.bak", "inventory.lock", "watchdog.log"):
            path = self.directory / name
            path.write_text(json.dumps(content))
            path.chmod(0o666)
        self.assertEqual(storage.load_data(), content)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for path in self.directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_concurrent_updates_preserve_all_pools(self):
        with ThreadPoolExecutor(max_workers=6) as executor:
            list(executor.map(lambda i: storage.save_pool(str(i), {"name": str(i)}), range(30)))
        self.assertEqual(len(storage.get_pools()), 30)
        self.assertFalse(list(self.directory.glob(".tmp_*")))


if __name__ == "__main__":
    unittest.main()
