"""Tests for 6TO4 Unicast (RFC 3056) Engine and Adapter."""
import unittest
from unittest.mock import MagicMock, call

from core.adapter_registry import get_adapter
from core.kernel_tunnels_adapter import SixToFourUnicastAdapter
from core.six_to_four import (
    check_6to4_prerequisites,
    configure_6to4_unicast_link,
    derive_6to4_address,
    ipv4_to_6to4_prefix,
    validate_6to4_mtu,
)


class TestSixToFourEngine(unittest.TestCase):
    def test_rfc3056_prefix_and_address_calculation(self):
        # 192.0.2.1 -> hex: c0 00 02 01 -> 2002:c000:0201::/48
        prefix = ipv4_to_6to4_prefix("192.0.2.1")
        self.assertEqual(prefix, "2002:c000:0201::/48")

        addr = derive_6to4_address("192.0.2.1", subnet_id=1, host_id=1)
        self.assertEqual(addr, "2002:c000:0201:1::1/64")

        # 198.51.100.2 -> hex: c6 33 64 02 -> 2002:c633:6402::/48
        prefix2 = ipv4_to_6to4_prefix("198.51.100.2")
        self.assertEqual(prefix2, "2002:c633:6402::/48")

        addr2 = derive_6to4_address("198.51.100.2", subnet_id=1, host_id=1)
        self.assertEqual(addr2, "2002:c633:6402:1::1/64")

    def test_mtu_validation(self):
        self.assertEqual(validate_6to4_mtu(1440), 1440)
        self.assertEqual(validate_6to4_mtu(1280), 1280)
        self.assertEqual(validate_6to4_mtu(1480), 1480)

        with self.assertRaises(ValueError):
            validate_6to4_mtu(1200)  # Below RFC 8200 minimum 1280
        with self.assertRaises(ValueError):
            validate_6to4_mtu(1500)  # Exceeds maximum 1480

    def test_configure_6to4_unicast_link(self):
        iran_node = {"node_name": "node_ir1", "ip": "192.0.2.1"}
        kharej_server = {"ip": "198.51.100.2"}
        pool_config = {
            "mtu": 1440,
            "client_ports": [8080, 8443],
            "ipv4_subnet": "10.200.1.0/30",
        }

        conf = configure_6to4_unicast_link(iran_node, kharej_server, pool_config)

        self.assertEqual(conf["engine"], "6to4_unicast")
        self.assertEqual(conf["rfc"], "RFC 3056")
        self.assertEqual(conf["mtu"], 1440)
        self.assertEqual(conf["underlay"]["iran_ip"], "192.0.2.1")
        self.assertEqual(conf["underlay"]["kharej_ip"], "198.51.100.2")

        # Check addressing
        self.assertEqual(conf["addressing"]["iran_6to4_prefix"], "2002:c000:0201::/48")
        self.assertEqual(conf["addressing"]["kharej_6to4_prefix"], "2002:c633:6402::/48")
        self.assertEqual(conf["addressing"]["iran_ipv6"], "2002:c000:0201:1::1/64")
        self.assertEqual(conf["addressing"]["kharej_ipv6"], "2002:c633:6402:1::1/64")
        self.assertEqual(conf["addressing"]["iran_ipv4"], "10.200.1.1/30")
        self.assertEqual(conf["addressing"]["kharej_ipv4"], "10.200.1.2/30")

        # Check security declaration
        self.assertTrue(conf["security"]["cleartext"])
        self.assertFalse(conf["security"]["requires_encryption"])

        # Check unit files
        ir_unit = conf["iran_config"]["unit"]
        self.assertIn("type sit local 192.0.2.1 remote 198.51.100.2 ttl 64", ir_unit)
        self.assertIn("2002:c000:0201:1::1/64", ir_unit)

        kh_unit = conf["kharej_config"]["unit"]
        self.assertIn("type sit local 198.51.100.2 remote 192.0.2.1 ttl 64", kh_unit)
        self.assertIn("2002:c633:6402:1::1/64", kh_unit)

        # Check client port relay
        self.assertIn("8080", conf["iran_config"]["relay_script"])
        self.assertIn("8443", conf["iran_config"]["relay_script"])

    def test_prerequisites_check(self):
        ssh = MagicMock()
        # modprobe, check bins, sysctl forwarding, ping
        ssh.execute.side_effect = [
            (0, "", ""),                     # modprobe sit
            (0, "/bin/ip\n/sbin/sysctl", ""),# which ip sysctl
            (0, "net.ipv6.conf.all.forwarding = 1", ""), # sysctl
            (0, "2 packets transmitted, 2 received", ""), # ping
        ]

        ok, msg = check_6to4_prerequisites(ssh, remote_ipv4="198.51.100.2")
        self.assertTrue(ok)
        self.assertIn("verified", msg)


class TestSixToFourUnicastAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("6to4_unicast")
        self.assertIsNotNone(self.adapter)
        self.assertIsInstance(self.adapter, SixToFourUnicastAdapter)

    def test_adapter_registration(self):
        self.assertEqual(self.adapter.engine_id, "6to4_unicast")
        self.assertEqual(self.adapter.capabilities.support_status, "experimental")

    def test_adapter_install(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (0, "", ""),
            (0, "/bin/ip\n/sbin/sysctl", ""),
            (0, "", ""),
            (0, "2 received", ""),
        ]
        ok, msg = self.adapter.install(ssh, "iran", {"remote_ip": "198.51.100.2"})
        self.assertTrue(ok)

    def test_adapter_start_stop_clean(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "active", "")

        ok, _ = self.adapter.start(ssh, "6to4-test")
        self.assertTrue(ok)
        self.assertIn("systemctl enable", ssh.execute.call_args[0][0])

        ok, _ = self.adapter.stop(ssh, "6to4-test")
        self.assertTrue(ok)
        self.assertIn("systemctl stop", ssh.execute.call_args[0][0])

        ok, _ = self.adapter.clean(ssh, "6to4-test")
        self.assertTrue(ok)
        self.assertIn("ip link del", ssh.execute.call_args[0][0])

    def test_adapter_status(self):
        ssh = MagicMock()
        link_output = (
            "6: 6to4-test: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1440 state UP\n"
            "    RX:  bytes packets errors dropped overrun mcast\n"
            "        1000      10      0       0       0       0\n"
            "    TX:  bytes packets errors dropped carrier collsns\n"
            "        1200      12      0       0       0       0\n"
        )
        ssh.execute.side_effect = [
            (0, "active\n", ""),  # is-active
            (0, link_output, ""),  # ip link show
        ]

        status = self.adapter.status(ssh, "6to4-test")
        self.assertEqual(status["engine"], "6to4_unicast")
        self.assertEqual(status["rfc"], "RFC 3056")
        self.assertEqual(status["status"], "UP")
        self.assertTrue(status["security"]["cleartext"])

    def test_adapter_modify_and_rollback(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (0, "mtu 1440", ""),  # ip link show
            (0, "", ""),          # cp bak
            (0, "", ""),          # ip link set mtu
            (0, "", ""),          # sed & daemon-reload
        ]

        ok, msg = self.adapter.modify("pool_6to4", {"ssh": ssh, "interface": "6to4-test", "mtu": 1400})
        self.assertTrue(ok)
        self.assertIn("MTU updated to 1400", msg)

        ssh.execute.side_effect = [
            (0, "", ""),  # ip link set mtu & restore bak
        ]
        ok_rb, msg_rb = self.adapter.rollback("pool_6to4", {"ssh": ssh, "interface": "6to4-test", "mtu": 1440})
        self.assertTrue(ok_rb)
        self.assertIn("rolled back to MTU 1440", msg_rb)


if __name__ == "__main__":
    unittest.main()
