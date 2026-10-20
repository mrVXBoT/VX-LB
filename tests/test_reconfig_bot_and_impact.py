"""Tests for Reconfig Bot, IPv6 prerequisites, Route collisions, and Mutation Impact.

Coverage:
- Subnet collision detection against host routes & bidirectional routing verification
- Native IPv6 prerequisites validation
- Panel-controllable reconfig bot with audit logs, pause/resume, rollback, and strict opt-in notifications
- Mutation impact estimation (downtime risk, affected ports, DNS impact)
"""
import copy
import ipaddress
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from core.resource_allocator import check_server_routes_collision, ResourceReservationManager
from core.private_link_manager import PrivateLinkManager
from core.reconfig_bot import (
    ReconfigBot, BOT_STATE_IDLE, BOT_STATE_RUNNING,
    BOT_STATE_PAUSED, BOT_STATE_ROLLED_BACK
)

class TestReconfigAndImpact(unittest.TestCase):

    def setUp(self):
        self.tmp_data = {
            "custom_links": {
                "test-link": {
                    "link_name": "test-link",
                    "link_id": "link-12345678",
                    "engine_id": "wireguard",
                    "status": "planned",
                    "tunnel_port": 51820,
                    "mtu": 1420,
                    "iran_server": {"ip": "192.0.2.1", "private_ip": "10.100.0.1"},
                    "kharej_server": {"ip": "198.51.100.1", "private_ip": "10.100.0.2"},
                    "private_subnet": "10.100.0.0/30",
                    "reservation_owner": "link_test-link",
                    "port_forwarding_rules": [{"listen_port": 8443, "target_port": 8443}]
                }
            },
            "pools": {
                "test-pool": {
                    "pool_name": "test-pool",
                    "transport": "stealth",
                    "ports": [443, 80],
                    "nodes": [{"name": "node-1", "ip": "192.0.2.10"}]
                }
            },
            "resource_reservations": {
                "link_test-link": {
                    "pool_name": "link_test-link",
                    "engine_id": "wireguard",
                    "host_ports": {"192.0.2.1": [51820], "198.51.100.1": [51820]},
                    "interfaces": ["pl_12345678"],
                    "ipv4_subnet": "10.100.0.0/30",
                    "ipv6_subnet": None,
                    "vni": None,
                    "route_table": None
                }
            },
            "reconfig_bot": {},
            "reconfig_audit_logs": []
        }

    # Route collision detection
    def test_check_server_routes_collision(self):
        routes = [
            "default via 192.168.1.1 dev eth0 onlink",
            "10.0.0.0/8 dev eth1 proto kernel scope link src 10.0.0.5",
            "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.50"
        ]
        # 10.100.0.0/30 overlaps with 10.0.0.0/8
        has_coll, msg = check_server_routes_collision("10.100.0.0/30", routes)
        self.assertTrue(has_coll)
        self.assertIn("تداخل روت", msg)

        # 172.16.0.0/30 does not overlap with any of the routes
        has_coll, msg = check_server_routes_collision("172.16.0.0/30", routes)
        self.assertFalse(has_coll)
        self.assertIsNone(msg)

    def test_verify_bidirectional_routes(self):
        ssh_ir = MagicMock()
        ssh_kh = MagicMock()

        # Success case
        ssh_ir.execute.return_value = (0, "10.100.0.2 dev wg0 src 10.100.0.1 uid 0\n    cache", "")
        ssh_kh.execute.return_value = (0, "10.100.0.1 dev wg0 src 10.100.0.2 uid 0\n    cache", "")

        ok, details = PrivateLinkManager.verify_bidirectional_routes(
            ssh_ir, ssh_kh, "10.100.0.1", "10.100.0.2", interface="wg0"
        )
        self.assertTrue(ok)
        self.assertTrue(details["bidirectional_valid"])

        # Failure case: reverse route missing
        ssh_kh.execute.return_value = (2, "", "RTNETLINK answers: Network is unreachable")
        ok, details = PrivateLinkManager.verify_bidirectional_routes(
            ssh_ir, ssh_kh, "10.100.0.1", "10.100.0.2", interface="wg0"
        )
        self.assertFalse(ok)
        self.assertFalse(details["bidirectional_valid"])

    # Native IPv6 prerequisites
    def test_validate_profile_ipv6_prerequisites(self):
        # geneve_gre6_native requires native IPv6
        ok, err = PrivateLinkManager.validate_profile_ipv6_prerequisites(
            "geneve_gre6_native",
            {"ip": "192.0.2.1"},
            {"ip": "198.51.100.1"}
        )
        self.assertFalse(ok)
        self.assertIn("نیازمند آدرس Native IPv6 است", err)

        # Valid IPv6 endpoints for geneve_gre6_native
        ok, err = PrivateLinkManager.validate_profile_ipv6_prerequisites(
            "geneve_gre6_native",
            {"ip": "2001:db8::1"},
            {"ip": "2001:db8::2"}
        )
        self.assertTrue(ok)
        self.assertIsNone(err)

        # WireGuard supports both IPv4 and IPv6
        ok, err = PrivateLinkManager.validate_profile_ipv6_prerequisites(
            "wireguard",
            {"ip": "192.0.2.1"},
            {"ip": "198.51.100.1"}
        )
        self.assertTrue(ok)

    # Reconfiguration lifecycle
    @patch("core.reconfig_bot.load_data")
    @patch("core.reconfig_bot.atomic_update")
    def test_reconfig_bot_lifecycle(self, mock_atomic, mock_load):
        storage = copy.deepcopy(self.tmp_data)
        mock_load.side_effect = lambda: storage
        def fake_atomic(fn):
            fn(storage)
        mock_atomic.side_effect = fake_atomic

        # Check initial status
        st = ReconfigBot.get_status()
        self.assertEqual(st["state"], BOT_STATE_IDLE)
        self.assertFalse(st["paused"])

        # Trigger reconfig
        res = ReconfigBot.trigger_reconfig("test-link", "link", {"mtu": 1400})
        self.assertEqual(res["status"], "started")
        self.assertEqual(storage["reconfig_bot"]["state"], BOT_STATE_RUNNING)

        # Pause
        p_res = ReconfigBot.pause()
        self.assertTrue(p_res["paused"])
        self.assertEqual(storage["reconfig_bot"]["state"], BOT_STATE_PAUSED)

        # Resume
        r_res = ReconfigBot.resume()
        self.assertTrue(r_res["resumed"])
        self.assertEqual(storage["reconfig_bot"]["state"], BOT_STATE_RUNNING)

        # Mutate link state
        storage["custom_links"]["test-link"]["mtu"] = 9999

        # Rollback
        rb_res = ReconfigBot.rollback()
        self.assertTrue(rb_res["success"])
        self.assertEqual(storage["custom_links"]["test-link"]["mtu"], 1420)
        self.assertEqual(storage["reconfig_bot"]["state"], BOT_STATE_ROLLED_BACK)

        # Verify audit logs were persisted
        logs = ReconfigBot.get_audit_logs()
        actions = [l["action"] for l in logs]
        self.assertIn("TRIGGER_RECONFIG", actions)
        self.assertIn("PAUSE_RECONFIG", actions)
        self.assertIn("RESUME_RECONFIG", actions)
        self.assertIn("ROLLBACK_RECONFIG", actions)

    @patch("core.reconfig_bot.load_data")
    @patch("core.reconfig_bot.atomic_update")
    def test_strict_notification_opt_in(self, mock_atomic, mock_load):
        storage = copy.deepcopy(self.tmp_data)
        mock_load.side_effect = lambda: storage
        def fake_atomic(fn):
            fn(storage)
        mock_atomic.side_effect = fake_atomic

        # Notification when not opted in MUST fail closed
        notif = ReconfigBot.notify("test_event", "Hello alert")
        self.assertFalse(notif["sent"])
        self.assertIn("عدم پیکربندی صریح", notif["reason"])

        # Enabling notifications must not claim delivery without an implementation.
        ReconfigBot.configure_notifications(True, webhook_url="https://example.com/webhook")
        notif = ReconfigBot.notify("test_event", "Hello alert")
        self.assertFalse(notif["sent"])
        self.assertEqual(notif["channel"], "webhook")
        self.assertIn("پیاده‌سازی نشده", notif["reason"])

        ReconfigBot.configure_notifications(True, bot_token="test-token", chat_id="123")
        notif = ReconfigBot.notify("test_event", "Hello alert")
        self.assertFalse(notif["sent"])
        self.assertEqual(notif["channel"], "telegram")
        self.assertIn("پیاده‌سازی نشده", notif["reason"])

        ReconfigBot.configure_notifications(True)
        notif = ReconfigBot.notify("test_event", "Hello alert")
        self.assertFalse(notif["sent"])
        self.assertIn("مقداردهی نشده", notif["reason"])

    # Mutation impact estimation
    @patch("core.private_link_manager.load_data")
    def test_estimate_mutation_impact(self, mock_load):
        mock_load.return_value = self.tmp_data

        # Link MTU change: momentary_reconnect
        impact = PrivateLinkManager.estimate_mutation_impact("link", "test-link", {"mtu": 1360})
        self.assertEqual(impact["downtime_risk"], "momentary_reconnect")
        self.assertEqual(impact["estimated_downtime_seconds"], 1)
        self.assertIn(51820, impact["affected_ports"])
        self.assertTrue(impact["dns_impact"]["preserved"])

        # Link engine change: disruptive
        impact_disrupt = PrivateLinkManager.estimate_mutation_impact("link", "test-link", {"engine_id": "vxlan"})
        self.assertEqual(impact_disrupt["downtime_risk"], "disruptive")
        self.assertEqual(impact_disrupt["estimated_downtime_seconds"], 20)
        self.assertTrue(len(impact_disrupt["breaking_changes"]) > 0)

        # Pool transport change: service_restart
        impact_pool = PrivateLinkManager.estimate_mutation_impact("pool", "test-pool", {"transport": "quic"})
        self.assertEqual(impact_pool["downtime_risk"], "service_restart")
        self.assertEqual(impact_pool["estimated_downtime_seconds"], 8)
        self.assertIn(443, impact_pool["affected_ports"])
        self.assertTrue(impact_pool["dns_impact"]["preserved"])

if __name__ == "__main__":
    unittest.main()
