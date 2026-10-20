"""Unit and integration test suite for dedicated VXLAN adapter and tools.

Covers:
- BaseTunnelAdapter contract compliance
- RFC 7348 parameter validation (VNI 1..16777215, UDP port 1..65535, MTU 576..1450, IFNAMSIZ <= 15)
- Three reference methods from Azumi67 source:
  1. Point-to-Point Unicast (P2P)
  2. VXLAN Bridge Setup with Remote IP Pointing (Bridge + IP Pointing)
  3. FDB VXLAN with Bridge (RFC 7348 Unicast FDB)
- Multi-Server & FDB management
- Lifecycle operations (install, configure, start, stop, status, probe, modify, rollback, clean)
- Safety: Protection of existing routes, SSH, and system bridges (docker0, br0)
- Security transparency: Explicit raw unencrypted overlay confirmation
"""
import copy
import re
import unittest
from unittest.mock import Mock, patch

from core.adapter_interface import BaseTunnelAdapter
from core.capabilities import get_capability
from core.vxlan_adapter import VxlanDedicatedAdapter
from core.vxlan_tools import (
    DEFAULT_VXLAN_PORT,
    DEFAULT_VXLAN_VNI,
    DEFAULT_VXLAN_MTU,
    VXLAN_METHOD_P2P,
    VXLAN_METHOD_BRIDGE_POINTIP,
    VXLAN_METHOD_FDB_BRIDGE,
    validate_vni,
    validate_port,
    validate_mtu,
    validate_ip,
    validate_ip_network_or_interface,
    validate_vxlan_method,
    make_vxlan_iface,
    make_bridge_name,
    is_system_or_protected_bridge,
    generate_vxlan_scripts,
)


class VxlanAdapterTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        for field, value in {
            "DATA_DIR": folder.name,
            "INVENTORY_FILE": str(Path(folder.name) / "inventory.json"),
            "LOCK_FILE": str(Path(folder.name) / "inventory.lock"),
            "LOG_FILE": str(Path(folder.name) / "watchdog.log"),
        }.items():
            target = patch("core.storage." + field, value)
            target.start()
            self.addCleanup(target.stop)
        self.adapter = VxlanDedicatedAdapter()
        self.iran_node = {
            "node_name": "node_ir_01",
            "ip": "198.51.100.10",
        }
        self.kharej_server = {
            "name": "server_kh_01",
            "ip": "203.0.113.20",
        }
        self.pool_config = {
            "pool_name": "vx_test_pool",
            "vni": 2000,
            "tunnel_port": 4789,
            "mtu": 1400,
            "iran_private_ip": "10.200.1.1/30",
            "kharej_private_ip": "10.200.1.2/30",
            "vxlan_method": "p2p",
            "peers": ["203.0.113.20", "203.0.113.21"],
        }

    def test_adapter_contract_and_capabilities(self):
        """Adapter inherits BaseTunnelAdapter and has accurate RFC 7348 capabilities."""
        self.assertIsInstance(self.adapter, BaseTunnelAdapter)
        self.assertEqual(self.adapter.engine_id, "vxlan")
        caps = self.adapter.capabilities
        self.assertEqual(caps.layer, "L2")
        self.assertFalse(caps.requires_encryption)
        self.assertEqual(caps.encryption_type, "none")
        self.assertIn("vxlan", caps.kernel_requirements)
        self.assertIn("bridge", caps.kernel_requirements)

    def test_vni_validation(self):
        """VNI must be 24-bit unsigned integer (1..16777215)."""
        self.assertEqual(validate_vni(1), 1)
        self.assertEqual(validate_vni(1000), 1000)
        self.assertEqual(validate_vni(16777215), 16777215)

        for invalid in [0, -1, 16777216, "abc", None]:
            with self.assertRaises(ValueError):
                validate_vni(invalid)

    def test_port_validation(self):
        """UDP port must be 1..65535."""
        self.assertEqual(validate_port(4789), 4789)
        self.assertEqual(validate_port(5513), 5513)

        for invalid in [0, -5, 65536, "udp", None]:
            with self.assertRaises(ValueError):
                validate_port(invalid)

    def test_mtu_validation(self):
        """MTU must be 576..1450 bytes considering 50-byte VXLAN overhead."""
        self.assertEqual(validate_mtu(1400), 1400)
        self.assertEqual(validate_mtu(1450), 1450)
        self.assertEqual(validate_mtu(576), 576)

        for invalid in [500, 1451, 1500, "jumbo", None]:
            with self.assertRaises(ValueError):
                validate_mtu(invalid)

    def test_ip_and_cidr_validation(self):
        """Validates IPv4 and IPv6 public and CIDR private addresses."""
        self.assertEqual(validate_ip("1.2.3.4"), "1.2.3.4")
        self.assertEqual(validate_ip("2001:db8::1"), "2001:db8::1")
        with self.assertRaises(ValueError):
            validate_ip("999.999.999.999")

        self.assertEqual(validate_ip_network_or_interface("10.200.1.1/30"), "10.200.1.1/30")
        self.assertEqual(validate_ip_network_or_interface("2001:db8::1/64"), "2001:db8::1/64")
        with self.assertRaises(ValueError):
            validate_ip_network_or_interface("10.200.1.1/35")

    def test_device_name_length_limit(self):
        """Interface and bridge names must strictly adhere to Linux IFNAMSIZ <= 15 chars."""
        long_id = "very_long_node_name_exceeding_limits_12345"
        iface = make_vxlan_iface(long_id)
        br = make_bridge_name(long_id)

        self.assertLessEqual(len(iface), 15)
        self.assertLessEqual(len(br), 15)
        self.assertTrue(iface.startswith("vx-"))
        self.assertTrue(br.startswith("br-vx-"))

    def test_reference_method_1_p2p(self):
        """Method 1 (P2P): Direct unicast without Linux bridge."""
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = VXLAN_METHOD_P2P
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)

        self.assertEqual(res["method"], "p2p")
        self.assertIsNone(res["bridge_name"])
        start_script = res["iran_scripts"]["start"]

        # Check exact commands from Azumi reference
        self.assertIn("type vxlan id 2000", start_script)
        self.assertIn("local 198.51.100.10", start_script)
        self.assertIn("remote 203.0.113.20", start_script)
        self.assertIn("dstport 4789", start_script)
        self.assertIn(f"ip addr add 10.200.1.1/30 dev {res['interface']}", start_script)
        # Ensure bridge is NOT created in P2P mode
        self.assertNotIn("type bridge", start_script)

    def test_reference_method_2_bridge_pointip(self):
        """Method 2 (Bridge + IP Pointing): Remote IP specified, enslaved to bridge."""
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = VXLAN_METHOD_BRIDGE_POINTIP
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)

        self.assertEqual(res["method"], "bridge_pointip")
        self.assertIsNotNone(res["bridge_name"])
        start_script = res["iran_scripts"]["start"]

        self.assertIn("type bridge", start_script)
        self.assertIn("type vxlan id 2000", start_script)
        self.assertIn("remote 203.0.113.20", start_script)
        self.assertIn(f"ip link set {res['interface']} master {res['bridge_name']}", start_script)
        self.assertIn(f"ip addr add 10.200.1.1/30 dev {res['bridge_name']}", start_script)

    def test_reference_method_3_fdb_bridge(self):
        """Method 3 (FDB with Bridge): Unicast flooding via FDB, no fixed remote on link."""
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = VXLAN_METHOD_FDB_BRIDGE
        conf["nolearning"] = True
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)

        self.assertEqual(res["method"], "fdb_bridge")
        start_script = res["iran_scripts"]["start"]

        self.assertIn("type vxlan id 2000", start_script)
        self.assertIn("nolearning", start_script)
        # Unicast 00:00:00:00:00:00 FDB entry
        self.assertIn("bridge fdb append to 00:00:00:00:00:00 dst 203.0.113.20", start_script)
        self.assertIn("bridge fdb append to 00:00:00:00:00:00 dst 203.0.113.21", start_script)
        self.assertIn(f"ip addr add 10.200.1.1/30 dev {res['bridge_name']}", start_script)

    def test_multi_server_fdb_management(self):
        """Multi-server peer addition and deletion via FDB entries."""
        mock_ssh = Mock()
        mock_ssh.execute.return_value = (0, "", "")

        # Add peer
        ok, msg = self.adapter.add_fdb_peer(mock_ssh, "vx-test", "203.0.113.50")
        self.assertTrue(ok)
        mock_ssh.execute.assert_called_with(
            "bridge fdb append to 00:00:00:00:00:00 dst 203.0.113.50 dev vx-test"
        )

        # Delete peer
        ok, msg = self.adapter.del_fdb_peer(mock_ssh, "vx-test", "203.0.113.50")
        self.assertTrue(ok)
        mock_ssh.execute.assert_called_with(
            "bridge fdb del to 00:00:00:00:00:00 dst 203.0.113.50 dev vx-test"
        )

        # List peers
        mock_ssh.execute.return_value = (
            0,
            "00:00:00:00:00:00 dst 203.0.113.50 self permanent\n00:00:00:00:00:00 dst 203.0.113.51 self permanent\n",
            "",
        )
        peers = self.adapter.list_fdb_peers(mock_ssh, "vx-test")
        self.assertEqual(peers, ["203.0.113.50", "203.0.113.51"])

    def test_system_bridge_preservation(self):
        """Never touch or delete existing system bridges (docker0, br0, virbr0)."""
        self.assertTrue(is_system_or_protected_bridge("docker0"))
        self.assertTrue(is_system_or_protected_bridge("br0"))
        self.assertTrue(is_system_or_protected_bridge("virbr0"))
        self.assertTrue(is_system_or_protected_bridge("my-custom-bridge"))
        # Only br-vx-* is recognized as dedicated owned bridge
        self.assertFalse(is_system_or_protected_bridge("br-vx-node1"))

    def test_protected_bridge_rejection_in_generation(self):
        """Rejects attempts to enslave or delete protected system bridges."""
        with self.assertRaises(ValueError):
            generate_vxlan_scripts(
                method="bridge_pointip",
                iface="vx-test",
                vni=1000,
                port=4789,
                mtu=1400,
                local_ip="198.51.100.10",
                remote_ip="203.0.113.20",
                private_ip_cidr="10.200.1.1/30",
                bridge_name="docker0",
            )

        # Also via adapter configure
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = "bridge_pointip"
        conf["bridge_name"] = "br0"
        with self.assertRaises(ValueError):
            self.adapter.configure(self.iran_node, self.kharej_server, conf)

    def test_custom_dedicated_bridge_support(self):
        """Allows valid dedicated bridge names prefixed with br-vx-."""
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = "bridge_pointip"
        conf["bridge_name"] = "br-vx-custom"
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)
        self.assertEqual(res["bridge_name"], "br-vx-custom")
        self.assertIn("ip link add br-vx-custom type bridge", res["iran_scripts"]["start"])

    def test_fdb_loop_prevention_excludes_local_ip(self):
        """Ensures local underlay IP is excluded from FDB destinations to prevent loops."""
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = VXLAN_METHOD_FDB_BRIDGE
        conf["peers"] = ["198.51.100.10", "203.0.113.20", "203.0.113.21"]
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)
        ir_script = res["iran_scripts"]["start"]

        # Iran local IP (198.51.100.10) must NEVER be an FDB destination on Iran host
        self.assertNotIn("bridge fdb append to 00:00:00:00:00:00 dst 198.51.100.10", ir_script)
        self.assertIn("bridge fdb append to 00:00:00:00:00:00 dst 203.0.113.20", ir_script)
        self.assertIn("bridge fdb append to 00:00:00:00:00:00 dst 203.0.113.21", ir_script)

    def test_underlay_device_inclusion(self):
        """Supports explicit binding to underlay physical interface."""
        conf = copy.deepcopy(self.pool_config)
        conf["underlay_dev"] = "eth1"
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)
        self.assertIn("dev eth1 dstport", res["iran_scripts"]["start"])

    def test_cleanup_fail_closed_and_safe(self):
        """Cleanup removes only dedicated VXLAN resources, preserving system bridges and routes."""
        mock_ssh = Mock()
        mock_ssh.execute.side_effect = [(0, "clean", ""), (1, "", "")]

        ok, msg = self.adapter.clean(mock_ssh, "vx-node1")
        self.assertTrue(ok)

        # Verify command executed on host
        cmd_executed = mock_ssh.execute.call_args_list[0][0][0]
        self.assertIn("ip link del vx-node1", cmd_executed)
        self.assertIn("ip link del br-vx-node1", cmd_executed)
        self.assertNotIn("docker0", cmd_executed)
        self.assertNotIn("ip route flush", cmd_executed)
        self.assertNotIn("default via", cmd_executed)
        self.assertIn("-relay.service", cmd_executed)

    def test_cleanup_keeps_failure_when_interface_survives(self):
        mock_ssh = Mock()
        mock_ssh.execute.return_value = (0, "", "")
        ok, message = self.adapter.clean(mock_ssh, "vx-node1")
        self.assertFalse(ok)
        self.assertIn("still exists", message)

    def test_failed_node_removal_keeps_pool_ownership(self):
        from core import vxlan_adapter
        with patch.object(vxlan_adapter, "get_pools", return_value={"qa": {"nodes": [{"ip": "192.0.2.1"}]}}), \
             patch.object(vxlan_adapter, "remove", return_value=(False, "SSH unavailable")), \
             patch.object(vxlan_adapter, "delete_pool") as discard:
            ok, message = vxlan_adapter.remove_pool("qa")
        self.assertFalse(ok)
        self.assertIn("SSH unavailable", message)
        discard.assert_not_called()

    def test_identifier_normalization_across_operations(self):
        """All lifecycle methods normalize identifiers uniformly."""
        mock_ssh = Mock()
        mock_ssh.execute.return_value = (0, "active\n", "")

        for ident in ["node1", "vx-node1", "vxlb-vxlan-vx-node1.service", "vxlb-vx-node1.service"]:
            ok, _ = self.adapter.start(mock_ssh, ident)
            self.assertTrue(ok)
            self.assertIn("vxlb-vxlan-vx-node1.service", mock_ssh.execute.call_args[0][0])

            ok, _ = self.adapter.stop(mock_ssh, ident)
            self.assertTrue(ok)
            self.assertIn("vxlb-vxlan-vx-node1.service", mock_ssh.execute.call_args[0][0])

    def test_lifecycle_operations(self):
        """Test install, start, stop, status, modify, rollback, probe."""
        mock_ssh = Mock()
        mock_ssh.execute.return_value = (0, "active", "")

        # Install
        ok, msg = self.adapter.install(mock_ssh, "iran", {})
        self.assertTrue(ok)

        # Start
        ok, msg = self.adapter.start(mock_ssh, "vx-node1")
        self.assertTrue(ok)

        # Stop
        ok, msg = self.adapter.stop(mock_ssh, "vx-node1")
        self.assertTrue(ok)

        # Status
        mock_ssh.execute.side_effect = [
            (0, "active\n", ""),  # is-active
            (0, "vx-node1: <BROADCAST,MULTICAST,UP> mtu 1400\n", ""),  # link show
            (0, "00:00:00:00:00:00 dst 203.0.113.20\n", ""),  # fdb show
            (0, "RX: bytes 1024 packets 10\nTX: bytes 1024 packets 10\n", ""),  # -s link show
        ]
        status = self.adapter.status(mock_ssh, "vx-node1")
        self.assertEqual(status["status"], "UP")
        self.assertTrue(status["details"]["service_active"])
        self.assertEqual(status["details"]["fdb_entries_count"], 1)

        # Modify with mock SSH
        mock_ssh.execute.side_effect = None
        mock_ssh.execute.return_value = (0, "", "")
        ok, msg = self.adapter.modify("test_pool", {"mtu": 1350, "dst_port": 5000, "interface": "vx-test"}, ssh=mock_ssh)
        self.assertTrue(ok)
        self.assertIn("ip link set dev vx-test mtu 1350", mock_ssh.execute.call_args[0][0])

        bad_ok, _ = self.adapter.modify("test_pool", {"mtu": 9000})
        self.assertFalse(bad_ok)

        # Rollback
        ok, msg = self.adapter.rollback("test_pool", {"mtu": 1400, "interface": "vx-test"}, ssh=mock_ssh)
        self.assertTrue(ok)
        self.assertIn("ip link set dev vx-test mtu 1400", mock_ssh.execute.call_args[0][0])

        bad_rb, _ = self.adapter.rollback("test_pool", {"mtu": 9000})
        self.assertFalse(bad_rb)

        # Probe without live SSH must honestly fail closed
        probe_offline = self.adapter.probe("10.200.1.1", "10.200.1.2")
        self.assertFalse(probe_offline["passed"])
        self.assertIn("requires live connected SSH session", probe_offline["error"])

        # Probe with connected mock SSH
        mock_ssh.execute.return_value = (0, "rtt min/avg/max/mdev = 1.200/2.400/3.500/0.400 ms", "")
        probe_live = self.adapter.probe("10.200.1.1", "10.200.1.2", ports=[80], ssh=mock_ssh)
        self.assertTrue(probe_live["passed"])
        self.assertEqual(probe_live["latency_ms"], 2.4)

    def test_security_disclaimer_raw_unencrypted(self):
        """Configuration must return explicit raw unencrypted overlay flag."""
        conf = self.adapter.configure(self.iran_node, self.kharej_server, self.pool_config)
        self.assertEqual(conf["security_disclaimer"], "RAW_UNENCRYPTED_OVERLAY")

    def test_identifier_with_uppercase_and_special_chars(self):
        """Identifier normalization handles mixed-case and unusual leading chars safely."""
        mock_ssh = Mock()
        mock_ssh.execute.return_value = (0, "active\n", "")

        for ident in ["Node_IR_01", "-node1", "_node2", "NODE-TEST"]:
            ok, _ = self.adapter.start(mock_ssh, ident)
            self.assertTrue(ok)

        # configure with uppercase node_name
        ir_node = {"node_name": "Node_IR_01", "ip": "198.51.100.10"}
        conf = self.adapter.configure(ir_node, self.kharej_server, self.pool_config)
        self.assertTrue(conf["interface"].startswith("vx-"))

    def test_is_system_or_protected_bridge_none_and_empty(self):
        """is_system_or_protected_bridge returns True for None and empty string without crashing."""
        self.assertTrue(is_system_or_protected_bridge(None))
        self.assertTrue(is_system_or_protected_bridge(""))
        self.assertTrue(is_system_or_protected_bridge("   "))

    def test_validate_dedicated_bridge_empty_and_none(self):
        """validate_dedicated_bridge rejects empty or None bridge names with ValueError."""
        with self.assertRaises(ValueError):
            from core.vxlan_tools import validate_dedicated_bridge
            validate_dedicated_bridge(None)

        with self.assertRaises(ValueError):
            from core.vxlan_tools import validate_dedicated_bridge
            validate_dedicated_bridge("")

    def test_nomaster_in_stop_and_clean_scripts(self):
        """Stop and clean operations must unslave (nomaster) interfaces before deletion."""
        conf = copy.deepcopy(self.pool_config)
        conf["vxlan_method"] = "bridge_pointip"
        res = self.adapter.configure(self.iran_node, self.kharej_server, conf)
        stop_script = res["iran_scripts"]["stop"]
        self.assertIn("nomaster", stop_script)

        # In clean()
        mock_ssh = Mock()
        mock_ssh.execute.return_value = (0, "", "")
        self.adapter.clean(mock_ssh, "vx-node1")
        clean_cmd = mock_ssh.execute.call_args_list[0][0][0]
        self.assertIn("nomaster", clean_cmd)

    def test_modify_peers_validation(self):
        """modify validates peer IPs and rejects invalid ones."""
        ok, msg = self.adapter.modify("test_pool", {"peers": ["1.1.1.1", "invalid_ip"]})
        self.assertFalse(ok)
        self.assertIn("Invalid peer_ip address", msg)

    def test_registry_integration(self):
        """Global registry resolves 'vxlan' to VxlanDedicatedAdapter."""
        from core.adapter_registry import get_adapter, has_adapter
        self.assertTrue(has_adapter("vxlan"))
        ad = get_adapter("vxlan")
        self.assertIsInstance(ad, VxlanDedicatedAdapter)

    def test_supported_transports_includes_vxlan(self):
        """SUPPORTED_TRANSPORTS contains vxlan option with experimental tag."""
        from core.tunnel import SUPPORTED_TRANSPORTS
        found = any(v[0] == "vxlan" for v in SUPPORTED_TRANSPORTS.values())
        self.assertTrue(found)
        label = next(v[1] for v in SUPPORTED_TRANSPORTS.values() if v[0] == "vxlan")
        self.assertIn("آزمایشی", label)
        self.assertIn("بدون رمزنگاری", label)

    def test_relay_generation(self):
        """generate_relay_script_and_unit creates valid python script and systemd unit."""
        from core.vxlan_adapter import generate_relay_script_and_unit
        py_code, unit = generate_relay_script_and_unit("vx-test1", "10.204.1.2", ["2222", "443"])
        self.assertIn("10.204.1.2", py_code)
        self.assertIn("[2222, 443]", py_code)
        self.assertIn("vxlb-vx-test1-relay.py", unit)
        self.assertIn("vxlb-vxlan-vx-test1.service", unit)

    def test_pool_lifecycle_orchestration(self):
        """create, add, change_mtu, and remove_pool work together seamlessly."""
        from unittest.mock import patch
        from core.vxlan_adapter import create, remove, remove_pool, change_mtu, pool_status
        from core.storage import get_pools

        mock_ssh = Mock()
        mock_ssh.connect.return_value = (True, "Connected")
        mock_ssh.execute.side_effect = lambda command, **kw: (1, "", "") if command.startswith("ip link show dev ") else (0, "Active", "")
        mock_ssh.write_file.return_value = True

        with patch("core.private_link_health.probe_pair", return_value={"passed": True, "latency_ms": 1}), patch("core.vxlan_adapter.connect", return_value=mock_ssh), patch(
            "core.vxlan_adapter.load_data", return_value={"iran_servers": [{"ip": "198.51.100.10", "password": "pass"}]}
        ):
            # Test create
            kharej = {"name": "Kharej", "ip": "203.0.113.10", "port": 22, "password": "pass"}
            irans = [{"name": "Iran1", "ip": "198.51.100.10", "port": 22, "password": "pass"}]
            ok, msg, pool = create(
                name="test_vxlan_pool",
                kharej=kharej,
                servers=irans,
                ports=["8080"],
                vxlan_method="bridge_pointip",
                vni=2000,
                dst_port=4789,
                mtu=1400,
            )
            self.assertTrue(ok)
            self.assertEqual(pool["engine"], "vxlan")
            self.assertEqual(pool["vni"], 2000)
            self.assertEqual(len(pool["nodes"]), 1)
            self.assertEqual(pool["nodes"][0]["vxlan"]["method"], "bridge_pointip")

            # Test pool_status
            ok_st, _, st = pool_status("test_vxlan_pool")
            self.assertTrue(ok_st)
            self.assertIn("198.51.100.10", st)

            # Test change_mtu
            ok_mtu, msg_mtu = change_mtu("test_vxlan_pool", 1380)
            self.assertTrue(ok_mtu)
            self.assertEqual(get_pools()["test_vxlan_pool"]["vxlan_mtu"], 1380)

            # Test remove_pool
            ok_rem, msg_rem = remove_pool("test_vxlan_pool")
            self.assertTrue(ok_rem)
            self.assertNotIn("test_vxlan_pool", get_pools())


if __name__ == "__main__":
    unittest.main()
