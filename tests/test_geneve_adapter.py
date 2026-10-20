"""Unit tests for dedicated Geneve (RFC 8926) engine and adapter."""
import unittest
from unittest.mock import MagicMock

from core.adapter_registry import get_adapter
from core.geneve_adapter import GeneveDedicatedAdapter
from core.geneve_tools import (
    DEFAULT_GENEVE_MTU,
    DEFAULT_GENEVE_PORT,
    DEFAULT_GENEVE_VNI,
    GENEVE_CLEARTEXT_WARNING,
    GENEVE_METHOD_FDB_BRIDGE,
    GENEVE_METHOD_P2P,
    generate_geneve_scripts,
    is_system_or_protected_bridge,
    make_geneve_bridge_name,
    make_geneve_iface,
    validate_dedicated_bridge,
    validate_geneve_method,
    validate_geneve_mtu,
    validate_geneve_port,
    validate_vni,
)


class TestGeneveTools(unittest.TestCase):
    def test_vni_validation(self):
        self.assertEqual(validate_vni(1000), 1000)
        self.assertEqual(validate_vni("5000"), 5000)
        self.assertEqual(validate_vni(16777215), 16777215)
        with self.assertRaises(ValueError):
            validate_vni(0)
        with self.assertRaises(ValueError):
            validate_vni(16777216)
        with self.assertRaises(ValueError):
            validate_vni("invalid")

    def test_port_validation(self):
        self.assertEqual(validate_geneve_port(6081), 6081)
        self.assertEqual(validate_geneve_port("6081"), 6081)
        with self.assertRaises(ValueError):
            validate_geneve_port(0)
        with self.assertRaises(ValueError):
            validate_geneve_port(65536)

    def test_mtu_validation(self):
        self.assertEqual(validate_geneve_mtu(1400), 1400)
        self.assertEqual(validate_geneve_mtu(576), 576)
        self.assertEqual(validate_geneve_mtu(1460), 1460)
        with self.assertRaises(ValueError):
            validate_geneve_mtu(500)
        with self.assertRaises(ValueError):
            validate_geneve_mtu(1500)

    def test_method_validation(self):
        self.assertEqual(validate_geneve_method("p2p"), GENEVE_METHOD_P2P)
        self.assertEqual(validate_geneve_method("fdb_bridge"), GENEVE_METHOD_FDB_BRIDGE)
        with self.assertRaises(ValueError):
            validate_geneve_method("unsupported_method")

    def test_bridge_protection(self):
        self.assertTrue(is_system_or_protected_bridge("docker0"))
        self.assertTrue(is_system_or_protected_bridge("br0"))
        self.assertTrue(is_system_or_protected_bridge("virbr0"))
        self.assertFalse(is_system_or_protected_bridge("br-gnv-custom"))

        with self.assertRaises(ValueError):
            validate_dedicated_bridge("docker0")
        with self.assertRaises(ValueError):
            validate_dedicated_bridge("br0")

        self.assertEqual(validate_dedicated_bridge("br-gnv-node1"), "br-gnv-node1")

    def test_p2p_script_generation(self):
        up, down = generate_geneve_scripts(
            interface="gnv-test",
            vni=1000,
            dst_port=6081,
            mtu=1400,
            local_underlay_ip="192.0.2.1",
            remote_underlay_ip="198.51.100.2",
            method=GENEVE_METHOD_P2P,
            local_private_ip="10.201.1.1/30",
        )
        self.assertIn("type geneve id 1000 remote 198.51.100.2 dstport 6081", up)
        self.assertIn("ip addr add 10.201.1.1/30 dev gnv-test", up)
        self.assertIn("ip link set gnv-test mtu 1400", up)
        self.assertIn("ip link del gnv-test", down)

    def test_fdb_bridge_script_generation_and_loop_prevention(self):
        up, down = generate_geneve_scripts(
            interface="gnv-test",
            vni=2000,
            dst_port=6081,
            mtu=1400,
            local_underlay_ip="192.0.2.1",
            remote_underlay_ip="198.51.100.2",
            method=GENEVE_METHOD_FDB_BRIDGE,
            local_private_ip="10.201.1.1/30",
            bridge_name="br-gnv-test",
            fdb_peers=["198.51.100.2", "198.51.100.3", "192.0.2.1"],  # 192.0.2.1 is local underlay!
        )
        self.assertIn("ip link add br-gnv-test type bridge", up)
        self.assertIn("ip link set gnv-test master br-gnv-test", up)
        self.assertIn("bridge fdb append 00:00:00:00:00:00 dev gnv-test dst 198.51.100.2", up)
        self.assertIn("bridge fdb append 00:00:00:00:00:00 dev gnv-test dst 198.51.100.3", up)
        # Loop prevention: local underlay IP 192.0.2.1 must NOT be in FDB
        self.assertNotIn("dst 192.0.2.1", up)

        self.assertIn("ip link set gnv-test nomaster", down)
        self.assertIn("ip link del br-gnv-test", down)


class TestGeneveDedicatedAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("geneve")
        self.assertIsNotNone(self.adapter)
        self.assertIsInstance(self.adapter, GeneveDedicatedAdapter)

    def test_adapter_registration(self):
        self.assertEqual(self.adapter.engine_id, "geneve")
        self.assertEqual(self.adapter.capabilities.support_status, "experimental")

    def test_install(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "/bin/ip\n/bin/systemctl", "")
        ok, msg = self.adapter.install(ssh, "iran", {})
        self.assertTrue(ok)
        self.assertIn("verified", msg)

    def test_configure_p2p(self):
        iran_node = {"node_name": "node_ir1", "ip": "192.0.2.1"}
        kharej_server = {"ip": "198.51.100.2"}
        pool_config = {
            "method": "p2p",
            "vni": 1000,
            "mtu": 1400,
            "client_ports": [443, 8443],
        }

        conf = self.adapter.configure(iran_node, kharej_server, pool_config)
        self.assertEqual(conf["engine"], "geneve")
        self.assertEqual(conf["rfc"], "RFC 8926")
        self.assertEqual(conf["method"], "p2p")
        self.assertEqual(conf["vni"], 1000)
        self.assertEqual(conf["mtu"], 1400)
        self.assertTrue(conf["security"]["cleartext"])
        self.assertIn("هشدار امنیتی", conf["security"]["warning"])

        self.assertIn("type geneve id 1000 remote 198.51.100.2", conf["iran_config"]["up_script"])
        self.assertIn("443", conf["iran_config"]["relay_script"])

    def test_configure_fdb_bridge(self):
        iran_node = {"node_name": "node_ir1", "ip": "192.0.2.1"}
        kharej_server = {"ip": "198.51.100.2"}
        pool_config = {
            "method": "fdb_bridge",
            "vni": 2000,
            "mtu": 1420,
            "bridge_name": "br-gnv-p1",
            "fdb_peers": ["198.51.100.2", "198.51.100.3"],
        }

        conf = self.adapter.configure(iran_node, kharej_server, pool_config)
        self.assertEqual(conf["method"], "fdb_bridge")
        self.assertEqual(conf["bridge_name"], "br-gnv-p1")
        self.assertIn("master br-gnv-p1", conf["iran_config"]["up_script"])

    def test_start_stop_clean(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "active", "")

        ok, _ = self.adapter.start(ssh, "gnv-node1")
        self.assertTrue(ok)
        self.assertIn("systemctl enable", ssh.execute.call_args[0][0])

        ok, _ = self.adapter.stop(ssh, "gnv-node1")
        self.assertTrue(ok)
        self.assertIn("systemctl stop", ssh.execute.call_args[0][0])

        ok, _ = self.adapter.clean(ssh, "gnv-node1")
        self.assertTrue(ok)
        self.assertIn("ip link del", ssh.execute.call_args[0][0])

    def test_status(self):
        ssh = MagicMock()
        link_output = (
            "5: gnv-node1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1400 state UP\n"
            "    RX:  bytes packets errors dropped overrun mcast\n"
            "        2000      20      0       0       0       0\n"
            "    TX:  bytes packets errors dropped carrier collsns\n"
            "        3000      30      0       0       0       0\n"
        )
        ssh.execute.side_effect = [
            (0, "active\n", ""),
            (0, link_output, ""),
        ]

        status = self.adapter.status(ssh, "gnv-node1")
        self.assertEqual(status["engine"], "geneve")
        self.assertEqual(status["status"], "UP")
        self.assertTrue(status["security"]["cleartext"])

    def test_modify_and_rollback(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (0, "mtu 1400", ""),  # ip link show
            (0, "", ""),          # cp bak
            (0, "", ""),          # ip link set mtu
            (0, "", ""),          # sed script
        ]

        ok, msg = self.adapter.modify("pool_geneve", {"ssh": ssh, "interface": "gnv-node1", "mtu": 1360})
        self.assertTrue(ok)
        self.assertIn("MTU updated to 1360", msg)

        ssh.execute.side_effect = [
            (0, "", ""),  # ip link set mtu & cp
        ]
        ok_rb, msg_rb = self.adapter.rollback("pool_geneve", {"ssh": ssh, "interface": "gnv-node1", "mtu": 1400})
        self.assertTrue(ok_rb)
        self.assertIn("rolled back to MTU 1400", msg_rb)

    def test_fdb_peer_management_with_loop_prevention(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "", "")

        # Rejects local underlay IP as peer (loop prevention)
        ok_loop, msg_loop = self.adapter.add_fdb_peer(ssh, "gnv-node1", "192.0.2.1", local_underlay_ip="192.0.2.1")
        self.assertFalse(ok_loop)
        self.assertIn("loop prevention", msg_loop)

        # Adds remote peer successfully
        ok, msg = self.adapter.add_fdb_peer(ssh, "gnv-node1", "198.51.100.2", local_underlay_ip="192.0.2.1")
        self.assertTrue(ok)
        self.assertIn("bridge fdb append", ssh.execute.call_args[0][0])

        # Removes remote peer
        ok_del, msg_del = self.adapter.del_fdb_peer(ssh, "gnv-node1", "198.51.100.2")
        self.assertTrue(ok_del)
        self.assertIn("bridge fdb del", ssh.execute.call_args[0][0])

        # Lists FDB peers
        fdb_show = (
            "00:00:00:00:00:00 dst 198.51.100.2 self permanent\n"
            "00:00:00:00:00:00 dst 198.51.100.3 self permanent\n"
        )
        ssh.execute.return_value = (0, fdb_show, "")
        peers = self.adapter.list_fdb_peers(ssh, "gnv-node1")
        self.assertEqual(peers, ["198.51.100.2", "198.51.100.3"])


if __name__ == "__main__":
    unittest.main()
