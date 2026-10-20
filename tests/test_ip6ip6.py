"""Comprehensive unit and integration tests for IP6IP6 (IPv6-in-IPv6) adapter and tools.

Covers:
- IP6IP6
- IPv6 endpoint address validation, reachability, and kernel return route checking
- IPv6-primary private addressing (/126 IPv6 and optional dual-stack /30 IPv4)
- MTU bounds enforcement (1280..1460, default 1420; minimum 1280 per RFC 8200)
- Scoped routing dev interface (/128 and /32) with strict preservation of default routes and SSH
- Inherent cleartext declaration: unencrypted, unauthenticated, non-obfuscated
- Complete BaseTunnelAdapter lifecycle: install, configure, start, stop, status, probe, modify, rollback, clean
"""
import copy
import ipaddress
import secrets
import unittest
from unittest.mock import MagicMock, patch

from core.adapter_registry import get_adapter
from core.capabilities import get_capability
from core import ip6ip6
from core.ipv6_tunnel_tools import (
    CLEARTEXT_WARNING,
    allocate_tunnel_ips,
    check_ipv6_reachability,
    check_kernel_prerequisites,
    parse_link_telemetry,
    synthesize_status,
    validate_ipv6_address,
    validate_mtu,
)
from core.kernel_tunnels_adapter import Ip6Ip6Adapter


class Ip6Ip6AdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("ip6ip6")
        self.iran_node = {
            "ip": "2001:db8:10::1",
            "node_name": "ir_ip6_node",
        }
        self.kharej_server = {
            "ip": "2001:db8:20::2",
            "server_name": "kh_ip6_server",
        }
        self.pool_config = {
            "mtu": 1420,
            "ipv6_subnet": "fd00:1db0:66:20::/126",
            "ipv4_subnet": "10.206.20.0/30",
            "enable_dual_stack": True,
        }

    def test_ip6ip6_capability_registration(self):
        """Verify IP6IP6 capabilities in machine-readable catalog."""
        self.assertIsNotNone(self.adapter)
        self.assertEqual(self.adapter.engine_id, "ip6ip6")

        cap = get_capability("ip6ip6")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.layer, "L3")
        self.assertIn("ipv6", cap.address_families)
        self.assertFalse(cap.requires_encryption)
        self.assertEqual(cap.encryption_type, "none")
        self.assertEqual(cap.default_mtu, 1280)
        self.assertIn("ip6_tunnel", cap.kernel_requirements)

    def test_ipv6_endpoint_validation(self):
        """Verify endpoint validation accepts valid IPv6 and rejects invalid, link-local, multicast, loopback."""
        valid_ips = [
            "2001:db8::1",
            "2606:4700:4700::1001",
            "fd00:abcd:1234::1",
        ]
        for ip in valid_ips:
            res = validate_ipv6_address(ip)
            self.assertTrue(bool(res))

        # Scope ID stripping
        self.assertEqual(validate_ipv6_address("2001:db8::1%eth0"), "2001:db8::1")

        invalid_ips = [
            "::1",                 # loopback
            "fe80::1ff:fe00:1",    # link-local
            "ff02::1",             # multicast
            "::",                  # unspecified
            "::ffff:192.0.2.1",    # IPv4-mapped IPv6 rejected for native outer tunnel
            "10.0.0.1",            # IPv4 not allowed for outer underlay
            "invalid-ip",
            None,
        ]
        for bad_ip in invalid_ips:
            with self.assertRaises(ValueError):
                validate_ipv6_address(bad_ip)

        # Local and remote cannot be identical
        same_node = {"ip": "2001:db8::1"}
        with self.assertRaises(ValueError):
            self.adapter.configure(same_node, same_node, {})

    def test_return_route_verification(self):
        """Verify return route checking in kernel routing table."""
        mock_ssh = MagicMock()

        # Valid route exists
        mock_ssh.execute.return_value = (0, "2001:db8:20::2 via 2001:db8:10::1 dev eth0 metric 1024", "")
        ok_route, msg_route = ip6ip6.check_return_route(mock_ssh, "2001:db8:20::2")
        self.assertTrue(ok_route)
        self.assertIn("valid route", msg_route.lower())

        # Unreachable route
        mock_ssh.execute.return_value = (0, "unreachable 2001:db8:20::2 dev lo metric 1024", "")
        ok_unreach, msg_unreach = ip6ip6.check_return_route(mock_ssh, "2001:db8:20::2")
        self.assertFalse(ok_unreach)
        self.assertIn("unreachable", msg_unreach.lower())

        # Command failure
        mock_ssh.execute.return_value = (1, "", "RTNETLINK answers: Network is unreachable")
        ok_fail, msg_fail = ip6ip6.check_return_route(mock_ssh, "2001:db8:20::2")
        self.assertFalse(ok_fail)
        self.assertIn("failed", msg_fail.lower())

    def test_mtu_bounds_rfc8200_enforcement(self):
        """Verify IP6IP6 MTU constraints (minimum 1280 per RFC 8200, max 1460, default 1420)."""
        # Valid MTUs
        self.assertEqual(ip6ip6.validate_ip6ip6_mtu(1280), 1280)
        self.assertEqual(ip6ip6.validate_ip6ip6_mtu(1420), 1420)
        self.assertEqual(ip6ip6.validate_ip6ip6_mtu(1460), 1460)

        # Invalid MTUs (< 1280 violates IPv6 minimum RFC 8200 requirement)
        for bad_mtu in [1279, 1200, 1461, 1500, 576, "fast", None]:
            with self.assertRaises(ValueError):
                ip6ip6.validate_ip6ip6_mtu(bad_mtu)

    def test_configure_generates_valid_spec_and_scoped_routes(self):
        """Verify configure produces expected systemd units, IPv6 primary /126 IPs, and scoped routes."""
        cfg = self.adapter.configure(self.iran_node, self.kharej_server, self.pool_config)

        self.assertEqual(cfg["engine"], "ip6ip6")
        self.assertEqual(cfg["mode"], "ip6tnl")
        self.assertEqual(cfg["tunnel_submode"], "ip6ip6")
        self.assertEqual(cfg["mtu"], 1420)
        self.assertEqual(cfg["local_ip"], "2001:db8:10::1")
        self.assertEqual(cfg["remote_ip"], "2001:db8:20::2")
        self.assertTrue(cfg["interface"].startswith("lip6-"))
        self.assertLessEqual(len(cfg["interface"]), 15)

        # Existing test contract compatibility:
        self.assertIn("ip link add", cfg["unit_script"])
        self.assertIn("type ip6tnl mode ip6ip6", cfg["unit_script"])

        # Address families specification
        self.assertEqual(cfg["address_families"]["external"], "ipv6")
        self.assertIn("ipv6", cfg["address_families"]["internal"])

        # Point-to-point addressing
        priv = cfg["private_addressing"]
        self.assertEqual(priv["iran_ipv6"], "fd00:1db0:66:20::1")
        self.assertEqual(priv["kharej_ipv6"], "fd00:1db0:66:20::2")
        self.assertEqual(priv["iran_ipv4"], "10.206.20.1")
        self.assertEqual(priv["kharej_ipv4"], "10.206.20.2")

        # Verify systemd service content: strictly host routes dev interface, no default route replacement
        ir_unit = cfg["iran_service_unit"]
        self.assertLess(ir_unit.index(f"ip link set {cfg['interface']} up"), ir_unit.index("ip -6 route replace"))
        self.assertIn(f"ip -6 route replace {priv['kharej_ipv6']}/128 dev {cfg['interface']}", ir_unit)
        self.assertIn(f"ip route replace {priv['kharej_ipv4']}/32 dev {cfg['interface']}", ir_unit)
        self.assertNotIn("default via", ir_unit)
        self.assertNotIn("0.0.0.0/0", ir_unit)

        # Security declaration: inherently cleartext
        self.assertFalse(cfg["security"]["requires_encryption"])
        self.assertEqual(cfg["security"]["encryption_type"], "none")
        self.assertTrue(cfg["security"]["cleartext"])
        self.assertIn("SECURITY NOTICE", cfg["security"]["warning"])

    def test_install_prerequisites_check(self):
        """Verify install checks kernel module ip6_tunnel, return route, and IPv6 reachability."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "2001:db8:20::2 via 2001:db8:10::1 dev eth0", "")

        ok, msg = self.adapter.install(mock_ssh, "iran", {"remote_ip": "2001:db8:20::2"})
        self.assertTrue(ok)
        self.assertIn("verified", msg.lower())

        # Failure when module or return route missing
        mock_ssh.execute.return_value = (1, "", "modprobe: FATAL: Module ip6_tunnel not found")
        ok_fail, msg_fail = self.adapter.install(mock_ssh, "iran", {})
        self.assertFalse(ok_fail)
        self.assertIn("missing", msg_fail.lower())

    def test_start_and_stop_lifecycle(self):
        """Verify start and stop invoke proper systemctl commands."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "", "")

        ok_start, _ = self.adapter.start(mock_ssh, "lip6-irnode1")
        self.assertTrue(ok_start)
        cmd_start = mock_ssh.execute.call_args[0][0]
        self.assertIn("systemctl enable", cmd_start)
        self.assertIn("systemctl restart", cmd_start)
        self.assertIn("ldbp-ip6ip6-lip6-irnode1.service", cmd_start)

        mock_ssh.reset_mock()
        mock_ssh.execute.return_value = (0, "", "")
        ok_stop, _ = self.adapter.stop(mock_ssh, "ldbp-ip6ip6-lip6-irnode1.service")
        self.assertTrue(ok_stop)
        cmd_stop = mock_ssh.execute.call_args[0][0]
        self.assertIn("systemctl stop", cmd_stop)
        self.assertIn("systemctl disable", cmd_stop)
        self.assertIn("ldbp-ip6ip6-lip6-irnode1.service", cmd_stop)

    def test_status_query_and_telemetry_synthesis(self):
        """Verify status reports active service and interface telemetry."""
        mock_ssh = MagicMock()
        link_output = """42: lip6-test@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UP mode DEFAULT group default
    link/tunnel6 2001:db8:10::1 peer 2001:db8:20::2
    RX:  bytes packets errors dropped overrun mcast
         45000     300      0       0       0     0
    TX:  bytes packets errors dropped carrier collsns
         41000     280      0       0       0     0"""

        def mock_exec(cmd):
            if "systemctl is-active" in cmd:
                return (0, "active\n", "")
            if "ip -d -s link show" in cmd:
                return (0, link_output, "")
            return (0, "", "")

        mock_ssh.execute.side_effect = mock_exec

        st = self.adapter.status(mock_ssh, "lip6-test")
        self.assertEqual(st["engine"], "ip6ip6")
        self.assertEqual(st["status"], "UP")
        self.assertEqual(st["details"]["state"], "UP")
        self.assertEqual(st["details"]["mtu"], 1420)
        self.assertEqual(st["details"]["rx_bytes"], 45000)
        self.assertEqual(st["details"]["tx_bytes"], 41000)
        self.assertFalse(st["security"]["requires_encryption"])

    def test_probe_nonce_exchange(self):
        """Verify probe performs active bidirectional nonce check."""
        mock_ir = MagicMock()
        mock_kh = MagicMock()

        mock_ir.execute.return_value = (0, "PASS:11.80\n", "")
        mock_kh.execute.return_value = (0, "", "")

        res = self.adapter.probe(mock_ir, mock_kh, [42892], kharej_private_ip="fd00:1db0:66:20::2")
        self.assertTrue(res["passed"])
        self.assertEqual(res["latency_ms"], 11.80)
        self.assertTrue(res["details"]["nonce_verified"])

        # Probe failure
        mock_ir.execute.return_value = (1, "FAIL:NO_REPLY", "Packet dropped")
        res_fail = self.adapter.probe(mock_ir, mock_kh, [42892], kharej_private_ip="fd00:1db0:66:20::2")
        self.assertFalse(res_fail["passed"])
        self.assertIn("failed", res_fail["error"].lower())

    def test_modify_and_rollback_transactional(self):
        """Verify MTU modification and rollback with backup unit and failure protection."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "", "")

        # Valid modification
        ok_mod, msg_mod = self.adapter.modify("test_pool", {
            "ssh": mock_ssh,
            "interface": "lip6-test",
            "mtu": 1380,
        })
        self.assertTrue(ok_mod)
        self.assertIn("1380", msg_mod)

        # Invalid MTU modification (< 1280 violates RFC 8200)
        ok_bad, msg_bad = self.adapter.modify("test_pool", {
            "ssh": mock_ssh,
            "interface": "lip6-test",
            "mtu": 1200,
        })
        self.assertFalse(ok_bad)
        self.assertIn("invalid", msg_bad.lower())

        # Rollback
        ok_rb, msg_rb = self.adapter.rollback("test_pool", {
            "ssh": mock_ssh,
            "interface": "lip6-test",
            "mtu": 1420,
        })
        self.assertTrue(ok_rb)
        self.assertIn("1420", msg_rb)

    def test_fail_closed_clean(self):
        """Verify clean removes interface, services, config files, and executes daemon-reload."""
        mock_ssh = MagicMock()
        # Interface deleted: ip link show returns non-zero (1)
        mock_ssh.execute.side_effect = lambda cmd: (1, "", "Device does not exist") if "ip link show" in cmd else (0, "", "")

        ok, msg = self.adapter.clean(mock_ssh, "lip6-test")
        self.assertTrue(ok)
        self.assertIn("cleaned successfully", msg)

        # Fail-closed check: if interface still exists after del, clean must return False
        mock_ssh.execute.side_effect = lambda cmd: (0, "42: lip6-test: ...", "")
        ok_fail, msg_fail = self.adapter.clean(mock_ssh, "lip6-test")
        self.assertFalse(ok_fail)
        self.assertIn("still present", msg_fail.lower())

    def test_multi_connection_distinct_interfaces_and_subnets(self):
        """Verify multiple IP6IP6 tunnels from same Iran node to different Kharej servers do not collide."""
        kh1 = {"ip": "2001:db8:20::2", "server_name": "kh_ip6_alpha"}
        kh2 = {"ip": "2001:db8:30::3", "server_name": "kh_ip6_beta"}

        cfg1 = self.adapter.configure(self.iran_node, kh1, {})
        cfg2 = self.adapter.configure(self.iran_node, kh2, {})

        # Interfaces must not collide
        self.assertNotEqual(cfg1["interface"], cfg2["interface"])
        self.assertNotEqual(cfg1["service_name"], cfg2["service_name"])
        # Private IP subnets must not collide
        self.assertNotEqual(cfg1["private_addressing"]["ipv6_subnet"], cfg2["private_addressing"]["ipv6_subnet"])

    def test_status_reports_internal_dual_stack_when_present(self):
        """Verify status detects whether dual-stack IPv4 is present on interface."""
        mock_ssh = MagicMock()
        # Output containing inet 10.206.x.x
        link_output_dual = """42: lip6-test@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UP
    link/tunnel6 2001:db8:10::1 peer 2001:db8:20::2
    inet 10.206.1.1/30 scope global lip6-test
    inet6 fd00:1db0:66:1::1/126 scope global lip6-test
    RX:  bytes packets errors dropped overrun mcast
         1000     10      0       0       0     0
    TX:  bytes packets errors dropped carrier collsns
         1000     10      0       0       0     0"""

        def mock_exec(cmd):
            if "systemctl is-active" in cmd:
                return (0, "active\n", "")
            if "ip -d -s link show" in cmd:
                return (0, link_output_dual, "")
            return (0, "", "")

        mock_ssh.execute.side_effect = mock_exec
        st = self.adapter.status(mock_ssh, "lip6-test")
        self.assertIn("ipv4", st["address_families"]["internal"])
        self.assertIn("ipv6", st["address_families"]["internal"])

    def test_install_role_and_bidirectional_reachability(self):
        """Verify install resolves remote IP based on role and checks return route + reachability."""
        from core.ipv6_tunnel_tools import check_bidirectional_ipv6_reachability
        mock_ir = MagicMock()
        mock_kh = MagicMock()
        mock_ir.execute.return_value = (0, "2 packets received", "")
        mock_kh.execute.return_value = (0, "2 packets received", "")

        ok_bi, msg_bi = check_bidirectional_ipv6_reachability(mock_ir, mock_kh, "2001:db8:10::1", "2001:db8:20::2")
        self.assertTrue(ok_bi)
        self.assertIn("verified", msg_bi.lower())

        # Test install role Kharej checking Iran IP
        mock_kh.execute.side_effect = lambda cmd: (0, "2001:db8:10::1 via eth0", "")
        ok_inst, _ = self.adapter.install(mock_kh, "kharej", {"iran_ip": "2001:db8:10::1"})
        self.assertTrue(ok_inst)

    def test_modify_and_rollback_with_service_identifier(self):
        """Verify modify and rollback accept full service names without corrupting interface paths."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "", "")

        ok_mod, msg_mod = self.adapter.modify("pool_test", {
            "ssh": mock_ssh,
            "interface": "ldbp-ip6ip6-lip6-test.service",
            "mtu": 1380,
        })
        self.assertTrue(ok_mod)
        self.assertIn("1380", msg_mod)

        ok_rb, msg_rb = self.adapter.rollback("pool_test", {
            "ssh": mock_ssh,
            "interface": "ldbp-ip6ip6-lip6-test.service",
            "mtu": 1420,
        })
        self.assertTrue(ok_rb)
        self.assertIn("1420", msg_rb)


if __name__ == "__main__":
    unittest.main()
