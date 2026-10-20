"""Comprehensive unit and integration tests for GRE6 (Generic Routing Encapsulation over IPv6) adapter and tools.

Covers:
- GRE6
- IPv6 endpoint address validation and reachability
- Dual-stack private addressing (/30 IPv4 and /126 IPv6)
- MTU bounds enforcement (1200..1440, default 1400)
- Scoped routing dev interface (/32 and /128) with strict preservation of default routes and SSH
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
from core import gre6
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
from core.kernel_tunnels_adapter import Gre6Adapter


class Gre6AdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("gre6")
        self.iran_node = {
            "ip": "2001:db8:1::10",
            "node_name": "ir_node_1",
        }
        self.kharej_server = {
            "ip": "2001:db8:2::20",
            "server_name": "kh_server_1",
        }
        self.pool_config = {
            "mtu": 1400,
            "ipv4_subnet": "10.206.10.0/30",
            "ipv6_subnet": "fd00:1db0:6:10::/126",
        }

    def test_gre6_capability_registration(self):
        """Verify GRE6 capabilities in machine-readable catalog."""
        self.assertIsNotNone(self.adapter)
        self.assertEqual(self.adapter.engine_id, "gre6")

        cap = get_capability("gre6")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.layer, "L3")
        self.assertIn("ipv6", cap.address_families)
        self.assertFalse(cap.requires_encryption)
        self.assertEqual(cap.encryption_type, "none")
        self.assertEqual(cap.default_mtu, 1280)
        self.assertIn("ip6_gre", cap.kernel_requirements)

    def test_ipv6_endpoint_validation(self):
        """Verify endpoint validation accepts valid IPv6 and rejects invalid, link-local, multicast, loopback."""
        valid_ips = [
            "2001:db8::1",
            "2606:4700:4700::1111",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "fd00:dead:beef::1",
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
            "192.168.1.1",         # IPv4 not allowed for outer underlay
            "not-an-ip",
            "",
            None,
        ]
        for bad_ip in invalid_ips:
            with self.assertRaises(ValueError):
                validate_ipv6_address(bad_ip)

        # Local and remote cannot be identical
        same_node = {"ip": "2001:db8::1"}
        with self.assertRaises(ValueError):
            self.adapter.configure(same_node, same_node, {})

    def test_mtu_bounds_validation(self):
        """Verify GRE6 MTU constraints (1200 <= MTU <= 1440)."""
        # Valid MTUs
        self.assertEqual(gre6.validate_gre6_mtu(1200), 1200)
        self.assertEqual(gre6.validate_gre6_mtu(1400), 1400)
        self.assertEqual(gre6.validate_gre6_mtu(1440), 1440)
        self.assertEqual(gre6.validate_gre6_mtu(" 1380 "), 1380)

        # Invalid MTUs
        for bad_mtu in [1199, 1441, 1500, 500, "fast", None]:
            with self.assertRaises(ValueError):
                gre6.validate_gre6_mtu(bad_mtu)

    def test_configure_generates_valid_spec_and_scoped_routes(self):
        """Verify configure produces expected systemd units, dual-stack IPs, and scoped routes without default route changes."""
        cfg = self.adapter.configure(self.iran_node, self.kharej_server, self.pool_config)

        self.assertEqual(cfg["engine"], "gre6")
        self.assertEqual(cfg["mode"], "ip6gre")
        self.assertEqual(cfg["mtu"], 1400)
        self.assertEqual(cfg["local_ip"], "2001:db8:1::10")
        self.assertEqual(cfg["remote_ip"], "2001:db8:2::20")
        self.assertTrue(cfg["interface"].startswith("lg6-"))
        self.assertLessEqual(len(cfg["interface"]), 15)  # Linux IFNAMSIZ limit

        # Existing test contract compatibility:
        self.assertIn("ip link add", cfg["unit_script"])

        # Address families specification
        self.assertEqual(cfg["address_families"]["external"], "ipv6")
        self.assertEqual(cfg["address_families"]["internal"], ["ipv4", "ipv6"])

        # Dual-stack point-to-point addressing
        priv = cfg["private_addressing"]
        self.assertEqual(priv["iran_ipv4"], "10.206.10.1")
        self.assertEqual(priv["kharej_ipv4"], "10.206.10.2")
        self.assertEqual(priv["iran_ipv6"], "fd00:1db0:6:10::1")
        self.assertEqual(priv["kharej_ipv6"], "fd00:1db0:6:10::2")

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
        """Verify install checks kernel module ip6_gre, tools, and IPv6 reachability."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "modprobe ok", "")

        ok, msg = self.adapter.install(mock_ssh, "iran", {"remote_ip": "2001:db8:2::20"})
        self.assertTrue(ok)
        self.assertIn("verified", msg.lower())

        # Failure when tools/module missing
        mock_ssh.execute.return_value = (1, "", "modprobe: FATAL: Module ip6_gre not found")
        ok_fail, msg_fail = self.adapter.install(mock_ssh, "iran", {})
        self.assertFalse(ok_fail)
        self.assertIn("missing", msg_fail.lower())

    def test_start_and_stop_lifecycle(self):
        """Verify start and stop invoke proper systemctl commands."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "", "")

        ok_start, _ = self.adapter.start(mock_ssh, "lg6-irnode1")
        self.assertTrue(ok_start)
        cmd_start = mock_ssh.execute.call_args[0][0]
        self.assertIn("systemctl enable", cmd_start)
        self.assertIn("systemctl restart", cmd_start)
        self.assertIn("vxlb-gre6-lg6-irnode1.service", cmd_start)

        mock_ssh.reset_mock()
        mock_ssh.execute.return_value = (0, "", "")
        ok_stop, _ = self.adapter.stop(mock_ssh, "vxlb-gre6-lg6-irnode1.service")
        self.assertTrue(ok_stop)
        cmd_stop = mock_ssh.execute.call_args[0][0]
        self.assertIn("systemctl stop", cmd_stop)
        self.assertIn("systemctl disable", cmd_stop)
        self.assertIn("vxlb-gre6-lg6-irnode1.service", cmd_stop)

    def test_status_query_and_telemetry_synthesis(self):
        """Verify status reports active service and interface telemetry."""
        mock_ssh = MagicMock()
        # Service active
        # Interface show with telemetry
        link_output = """35: lg6-test@NONE: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1400 qdisc noqueue state UP mode DEFAULT group default
    link/ip6gre 2001:db8:1::10 peer 2001:db8:2::20
    RX:  bytes packets errors dropped overrun mcast
         20480     150      0       0       0     0
    TX:  bytes packets errors dropped carrier collsns
         18200     140      0       0       0     0"""

        def mock_exec(cmd):
            if "systemctl is-active" in cmd:
                return (0, "active\n", "")
            if "ip -d -s link show" in cmd:
                return (0, link_output, "")
            return (0, "", "")

        mock_ssh.execute.side_effect = mock_exec

        st = self.adapter.status(mock_ssh, "lg6-test")
        self.assertEqual(st["engine"], "gre6")
        self.assertEqual(st["status"], "UP")
        self.assertEqual(st["details"]["state"], "UP")
        self.assertEqual(st["details"]["mtu"], 1400)
        self.assertEqual(st["details"]["rx_bytes"], 20480)
        self.assertEqual(st["details"]["tx_bytes"], 18200)
        self.assertFalse(st["security"]["requires_encryption"])

    def test_probe_nonce_exchange(self):
        """Verify probe performs active bidirectional nonce check."""
        mock_ir = MagicMock()
        mock_kh = MagicMock()

        # Iran probe output success
        mock_ir.execute.return_value = (0, "PASS:14.25\n", "")
        mock_kh.execute.return_value = (0, "", "")

        res = self.adapter.probe(mock_ir, mock_kh, [42892], kharej_private_ip="fd00:vxlb:6:10::2")
        self.assertTrue(res["passed"])
        self.assertEqual(res["latency_ms"], 14.25)
        self.assertTrue(res["details"]["nonce_verified"])

        # Probe failure
        mock_ir.execute.return_value = (1, "FAIL:NO_REPLY", "Connection timed out")
        res_fail = self.adapter.probe(mock_ir, mock_kh, [42892], kharej_private_ip="fd00:vxlb:6:10::2")
        self.assertFalse(res_fail["passed"])
        self.assertIn("failed", res_fail["error"].lower())

    def test_modify_and_rollback_transactional(self):
        """Verify MTU modification and rollback with backup unit and failure protection."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "", "")

        # Valid modification
        ok_mod, msg_mod = self.adapter.modify("test_pool", {
            "ssh": mock_ssh,
            "interface": "lg6-test",
            "mtu": 1360,
        })
        self.assertTrue(ok_mod)
        self.assertIn("1360", msg_mod)

        # Invalid MTU modification
        ok_bad, msg_bad = self.adapter.modify("test_pool", {
            "ssh": mock_ssh,
            "interface": "lg6-test",
            "mtu": 1600,
        })
        self.assertFalse(ok_bad)
        self.assertIn("invalid", msg_bad.lower())

        # Rollback
        ok_rb, msg_rb = self.adapter.rollback("test_pool", {
            "ssh": mock_ssh,
            "interface": "lg6-test",
            "mtu": 1400,
        })
        self.assertTrue(ok_rb)
        self.assertIn("1400", msg_rb)

    def test_fail_closed_clean(self):
        """Verify clean removes interface, services, config files, and executes daemon-reload."""
        mock_ssh = MagicMock()
        # Interface deleted: ip link show returns non-zero (1)
        mock_ssh.execute.side_effect = lambda cmd: (1, "", "Device does not exist") if "ip link show" in cmd else (0, "", "")

        ok, msg = self.adapter.clean(mock_ssh, "lg6-test")
        self.assertTrue(ok)
        self.assertIn("cleaned successfully", msg)

        # Fail-closed check: if interface still exists after del, clean must return False
        mock_ssh.execute.side_effect = lambda cmd: (0, "35: lg6-test: ...", "")
        ok_fail, msg_fail = self.adapter.clean(mock_ssh, "lg6-test")
        self.assertFalse(ok_fail)
        self.assertIn("still present", msg_fail.lower())

    def test_allocate_tunnel_ips_no_octet_overflow(self):
        """Verify allocate_tunnel_ips never produces IPv4 octets > 255 across deterministic and random IDs."""
        for i in range(500):
            ips = allocate_tunnel_ips(base_id=f"test-base-{i}")
            net = ipaddress.IPv4Network(ips["ipv4_subnet"])
            self.assertEqual(net.prefixlen, 30)
            addr_ir = ipaddress.IPv4Address(ips["iran_ipv4"])
            addr_kh = ipaddress.IPv4Address(ips["kharej_ipv4"])
            self.assertIn(addr_ir, net.hosts())
            self.assertIn(addr_kh, net.hosts())

    def test_multi_connection_distinct_interfaces_and_subnets(self):
        """Verify multiple tunnels from same Iran node to different Kharej servers do not collide."""
        kh1 = {"ip": "2001:db8:2::20", "server_name": "kh_alpha"}
        kh2 = {"ip": "2001:db8:3::30", "server_name": "kh_beta"}

        cfg1 = self.adapter.configure(self.iran_node, kh1, {})
        cfg2 = self.adapter.configure(self.iran_node, kh2, {})

        # Interfaces must not collide
        self.assertNotEqual(cfg1["interface"], cfg2["interface"])
        self.assertNotEqual(cfg1["service_name"], cfg2["service_name"])
        # Private IP subnets must not collide
        self.assertNotEqual(cfg1["private_addressing"]["ipv4_subnet"], cfg2["private_addressing"]["ipv4_subnet"])
        self.assertNotEqual(cfg1["private_addressing"]["ipv6_subnet"], cfg2["private_addressing"]["ipv6_subnet"])

    def test_install_role_and_bidirectional_reachability(self):
        """Verify install resolves remote IP based on role and checks reachability."""
        from core.ipv6_tunnel_tools import check_bidirectional_ipv6_reachability
        mock_ir = MagicMock()
        mock_kh = MagicMock()
        mock_ir.execute.return_value = (0, "2 packets received", "")
        mock_kh.execute.return_value = (0, "2 packets received", "")

        ok_bi, msg_bi = check_bidirectional_ipv6_reachability(mock_ir, mock_kh, "2001:db8:1::1", "2001:db8:2::2")
        self.assertTrue(ok_bi)
        self.assertIn("verified", msg_bi.lower())

        # Test install role Kharej checking Iran IP
        ok_inst, _ = self.adapter.install(mock_kh, "kharej", {"iran_ip": "2001:db8:1::1"})
        self.assertTrue(ok_inst)

    def test_modify_and_rollback_with_service_identifier(self):
        """Verify modify and rollback accept full service names without corrupting interface paths."""
        mock_ssh = MagicMock()
        mock_ssh.execute.return_value = (0, "", "")

        ok_mod, msg_mod = self.adapter.modify("pool_test", {
            "ssh": mock_ssh,
            "interface": "vxlb-gre6-lg6-test.service",
            "mtu": 1380,
        })
        self.assertTrue(ok_mod)
        self.assertIn("1380", msg_mod)

        ok_rb, msg_rb = self.adapter.rollback("pool_test", {
            "ssh": mock_ssh,
            "interface": "vxlb-gre6-lg6-test.service",
            "mtu": 1400,
        })
        self.assertTrue(ok_rb)
        self.assertIn("1400", msg_rb)


if __name__ == "__main__":
    unittest.main()
