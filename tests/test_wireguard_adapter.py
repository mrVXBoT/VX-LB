"""Comprehensive test suite for WireGuard Adapter and Dedicated Tools.

Covers:
- WireGuard peer/key/AllowedIPs, endpoint, keepalive, and IPv4/IPv6 private addressing.
- Standalone private link and port forwarding compatibility.
- Encapsulation overhead (60B) and Path MTU calculation.
- Strict preservation of SSH management route by prohibiting unintended 0.0.0.0/0.
- Scoped, tagged firewall lifecycle management and secret masking.
- Interface, handshake freshness, and telemetry status synthesis.
- Active data plane probe with cryptographic nonce verification and fail-closed causality.
"""

import base64
import time
import unittest
from unittest.mock import MagicMock, patch

from core.adapter_registry import get_adapter, list_registered_adapters
from core.capabilities import get_capability
from core.ssh_client import SSHManager
from core.wireguard_adapter import WireGuardAdapter, WireGuardHybridAdapter
from core.wireguard_tools import (
    generate_wireguard_keypair,
    generate_preshared_key,
    public_key_from_private_key,
    validate_wireguard_key,
    allocate_private_ips,
    sanitize_allowed_ips,
    render_wireguard_config,
    parse_wg_dump,
    parse_wg_human_show,
    synthesize_wireguard_status,
    execute_active_wireguard_probe,
)


class TestWireGuardCryptographyAndTools(unittest.TestCase):
    """Tests for WireGuard cryptographic operations and network tools."""

    def test_keypair_generation_and_validation(self):
        priv, pub = generate_wireguard_keypair()
        self.assertTrue(validate_wireguard_key(priv))
        self.assertTrue(validate_wireguard_key(pub))
        self.assertEqual(len(base64.b64decode(priv)), 32)
        self.assertEqual(len(base64.b64decode(pub)), 32)

        # Derived public key must match generated public key
        derived_pub = public_key_from_private_key(priv)
        self.assertEqual(derived_pub, pub)

    def test_preshared_key_generation(self):
        psk = generate_preshared_key()
        self.assertTrue(validate_wireguard_key(psk))
        self.assertEqual(len(base64.b64decode(psk)), 32)

    def test_invalid_key_validation(self):
        self.assertFalse(validate_wireguard_key("not-base-64!"))
        self.assertFalse(validate_wireguard_key("too_short"))
        self.assertFalse(validate_wireguard_key(""))
        with self.assertRaises(ValueError):
            public_key_from_private_key("invalid-key")

    def test_private_ip_allocation(self):
        ips = allocate_private_ips("10.100.5.0/30", "fd00:200::/126")
        self.assertEqual(ips["iran_ipv4"], "10.100.5.1/30")
        self.assertEqual(ips["kharej_ipv4"], "10.100.5.2/30")
        self.assertEqual(ips["iran_ipv6"], "fd00:200::1/126")
        self.assertEqual(ips["kharej_ipv6"], "fd00:200::2/126")

    def test_allowed_ips_sanitization_and_route_safety(self):
        # Normal targeted subnets allowed
        sanitized = sanitize_allowed_ips("10.100.0.0/16, 192.168.1.0/24")
        self.assertEqual(sanitized, ["10.100.0.0/16", "192.168.1.0/24"])

        # Default route 0.0.0.0/0 prohibited by default to protect SSH
        with self.assertRaises(ValueError) as ctx:
            sanitize_allowed_ips("0.0.0.0/0")
        self.assertIn("preserve SSH and panel access", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            sanitize_allowed_ips("::/0")
        self.assertIn("preserve SSH and panel access", str(ctx.exception))

        # Explicit override
        sanitized_override = sanitize_allowed_ips("0.0.0.0/0", allow_default_route=True)
        self.assertEqual(sanitized_override, ["0.0.0.0/0"])

    def test_render_wireguard_config_single_peer(self):
        priv_ir, _ = generate_wireguard_keypair()
        _, pub_kh = generate_wireguard_keypair()
        psk = generate_preshared_key()

        cfg = render_wireguard_config(
            interface_name="wg0",
            private_key=priv_ir,
            addresses=["10.100.2.1/30", "fd00:100::1/64"],
            listen_port=51820,
            peers=[{
                "public_key": pub_kh,
                "preshared_key": psk,
                "endpoint": "198.51.100.1:51820",
                "allowed_ips": ["10.100.2.2/32", "fd00:100::2/128"],
                "persistent_keepalive": 25,
            }],
            mtu=1420,
        )

        self.assertIn("[Interface]", cfg)
        self.assertIn(f"PrivateKey = {priv_ir}", cfg)
        self.assertIn("Address = 10.100.2.1/30, fd00:100::1/64", cfg)
        self.assertIn("ListenPort = 51820", cfg)
        self.assertIn("MTU = 1420", cfg)
        self.assertIn("[Peer]", cfg)
        self.assertIn(f"PublicKey = {pub_kh}", cfg)
        self.assertIn(f"PresharedKey = {psk}", cfg)
        self.assertIn("Endpoint = 198.51.100.1:51820", cfg)
        self.assertIn("AllowedIPs = 10.100.2.2/32, fd00:100::2/128", cfg)
        self.assertIn("PersistentKeepalive = 25", cfg)

    def test_parse_wg_dump_and_status_synthesis(self):
        now = int(time.time())
        fake_dump = (
            f"PRIVKEY_DUMMY\tPUBKEY_IR\t51820\toff\n"
            f"PUBKEY_KH\tPSK_DUMMY\t198.51.100.1:51820\t10.100.0.0/16\t{now - 30}\t1048576\t2097152\t25\n"
        )
        parsed = parse_wg_dump(fake_dump)
        self.assertTrue(parsed["active"])
        self.assertEqual(parsed["listen_port"], 51820)
        self.assertEqual(len(parsed["peers"]), 1)

        peer = parsed["peers"][0]
        self.assertEqual(peer["public_key"], "PUBKEY_KH")
        self.assertEqual(peer["transfer_rx_bytes"], 1048576)
        self.assertEqual(peer["transfer_tx_bytes"], 2097152)
        self.assertTrue(peer["handshake_active"])

        # Status synthesis: active handshake & data transfer -> UP
        status_up = synthesize_wireguard_status(True, parsed)
        self.assertEqual(status_up["status"], "UP")

        # Stale handshake -> DEGRADED
        stale_dump = (
            f"PRIVKEY_DUMMY\tPUBKEY_IR\t51820\toff\n"
            f"PUBKEY_KH\t(none)\t198.51.100.1:51820\t10.100.0.0/16\t{now - 400}\t0\t0\t25\n"
        )
        parsed_stale = parse_wg_dump(stale_dump)
        status_degraded = synthesize_wireguard_status(True, parsed_stale)
        self.assertEqual(status_degraded["status"], "DEGRADED")

        # Interface down -> DOWN
        status_down = synthesize_wireguard_status(False, parsed)
        self.assertEqual(status_down["status"], "DOWN")

    def test_parse_wg_human_show(self):
        sample = """
interface: wg-test
  public key: ABCD1234EFGH5678ABCD1234EFGH5678ABCD1234EF=
  listening port: 51820

peer: WXYZ1234WXYZ1234WXYZ1234WXYZ1234WXYZ1234WX=
  endpoint: 198.51.100.5:51820
  allowed ips: 10.100.2.2/32
  latest handshake: 1 minute, 12 seconds ago
  transfer: 1.25 MiB received, 4.30 MiB sent
"""
        parsed = parse_wg_human_show(sample)
        self.assertEqual(parsed["interface"], "wg-test")
        self.assertEqual(parsed["listening_port"], 51820)
        self.assertEqual(len(parsed["peers"]), 1)
        self.assertEqual(parsed["peers"][0]["endpoint"], "198.51.100.5:51820")
        self.assertIn("10.100.2.2/32", parsed["peers"][0]["allowed_ips"])


class TestWireGuardAdapterLifecycle(unittest.TestCase):
    """Tests for WireGuardAdapter compliance with BaseTunnelAdapter interface."""

    def setUp(self):
        self.adapter = WireGuardAdapter()
        self.mock_ssh = MagicMock()

    def test_adapter_registration_and_capabilities(self):
        self.assertIn("wireguard", list_registered_adapters())
        self.assertIn("wireguard_hybrid", list_registered_adapters())

        cap = get_capability("wireguard")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.layer, "L3")
        self.assertEqual(cap.default_mtu, 1280)
        self.assertEqual(cap.overhead_bytes, 60)
        self.assertTrue(cap.supports_raw_link)
        self.assertTrue(cap.supports_port_forwarding)

    def test_install_success(self):
        self.mock_ssh.execute.side_effect = [
            (0, "/usr/bin/wg\n/usr/bin/wg-quick\n/bin/ip", ""),  # check
            (0, "net.ipv4.ip_forward = 1", ""),                 # sysctl
        ]
        ok, msg = self.adapter.install(self.mock_ssh, "iran", {})
        self.assertTrue(ok)
        self.assertIn("verified successfully", msg)

    def test_install_failure_without_autoinstall(self):
        self.mock_ssh.execute.return_value = (1, "", "modprobe: FATAL: Module wireguard not found")
        ok, msg = self.adapter.install(self.mock_ssh, "iran", {"auto_install": False})
        self.assertFalse(ok)
        self.assertIn("not found", msg)

    def test_configure_generates_complete_bidirectional_specs(self):
        ir_node = {"node_name": "node_teh_1", "ip": "192.0.2.1"}
        kh_server = {"ip": "198.51.100.2"}
        pool_cfg = {
            "tunnel_port": 51820,
            "mtu": 1420,
            "enable_psk": True,
            "enable_ipv6": True,
        }

        cfg = self.adapter.configure(ir_node, kh_server, pool_cfg)
        self.assertEqual(cfg["engine"], "wireguard")
        self.assertEqual(cfg["interface"], "wg-node_teh_1")
        self.assertEqual(cfg["tunnel_port"], 51820)
        self.assertEqual(cfg["mtu"], 1420)
        self.assertEqual(cfg["service_name"], "wg-quick@wg-node_teh_1.service")
        self.assertEqual(cfg["config_path"], "/etc/wireguard/wg-node_teh_1.conf")

        # Verify Iran config
        ir_conf = cfg["iran_config"]
        self.assertIn("[Interface]", ir_conf)
        self.assertIn("PrivateKey =", ir_conf)
        self.assertIn("Address = 10.100.2.1/30, fd00:100::1/126", ir_conf)
        self.assertIn("[Peer]", ir_conf)
        self.assertIn(f"Endpoint = 198.51.100.2:51820", ir_conf)
        self.assertIn("PresharedKey =", ir_conf)
        self.assertIn("PersistentKeepalive = 25", ir_conf)

        # Verify Kharej config
        kh_conf = cfg["kharej_config"]
        self.assertIn("[Interface]", kh_conf)
        self.assertIn("Address = 10.100.2.2/30, fd00:100::2/126", kh_conf)
        self.assertIn("[Peer]", kh_conf)
        self.assertIn("PresharedKey =", kh_conf)

        # Scoped firewall rules generated
        self.assertIn("iran", cfg["firewall_rules"])
        self.assertIn("kharej", cfg["firewall_rules"])
        self.assertTrue(any("vxlb-wg-node_teh_1" in r for r in cfg["firewall_rules"]["iran"]))

    def test_start_success(self):
        self.mock_ssh.execute.side_effect = [
            (0, "", ""),  # check config file chmod
            (0, "Active: active (running)", ""),  # systemctl reload, enable, restart
        ]
        ok, msg = self.adapter.start(self.mock_ssh, "wg-node_teh_1")
        self.assertTrue(ok)
        self.assertIn("started and interface", msg)

    def test_start_fails_when_config_missing(self):
        self.mock_ssh.execute.return_value = (1, "", "No such file or directory")
        ok, msg = self.adapter.start(self.mock_ssh, "wg-node_teh_1")
        self.assertFalse(ok)
        self.assertIn("missing or inaccessible", msg)

    def test_stop_brings_down_interface(self):
        self.mock_ssh.execute.return_value = (0, "stopped", "")
        ok, msg = self.adapter.stop(self.mock_ssh, "wg-node_teh_1")
        self.assertTrue(ok)
        self.assertEqual(msg, "stopped")

    def test_status_reports_detailed_metrics(self):
        now = int(time.time())
        fake_dump = (
            f"PRIVKEY\tPUBKEY\t51820\toff\n"
            f"PEER_PUB\tPSK\t198.51.100.1:51820\t10.100.0.0/16\t{now - 10}\t5000\t8000\t25\n"
        )
        self.mock_ssh.execute.side_effect = [
            (0, "10: wg-test: <POINTOPOINT,NOARP,UP,LOWER_UP>", ""),  # ip link
            (0, fake_dump, ""),  # wg show dump
        ]
        res = self.adapter.status(self.mock_ssh, "wg-test")
        self.assertEqual(res["status"], "UP")
        self.assertEqual(res["interface"], "wg-test")
        self.assertIn("details", res)
        self.assertNotIn("PRIVKEY", res["raw_dump"])  # secret masking

    def test_clean_fail_closed_teardown(self):
        self.mock_ssh.execute.side_effect = [(0, "clean ok", ""), (1, "", "")]
        ok, msg = self.adapter.clean(self.mock_ssh, "wg-node_teh_1")
        self.assertTrue(ok)
        self.assertIn("cleaned successfully", msg)

        # Verify command executed stopped service and deleted config
        called_cmd = self.mock_ssh.execute.call_args_list[0][0][0]
        self.assertIn("systemctl stop wg-quick@wg-node_teh_1.service", called_cmd)
        self.assertIn("ip link del wg-node_teh_1", called_cmd)
        self.assertIn("rm -f /etc/wireguard/wg-node_teh_1.conf", called_cmd)
        self.assertIn("grep -v 'vxlb-wg-node_teh_1'", called_cmd)

    def test_modify_and_rollback(self):
        # Without context -> unsupported (guard)
        ok_mod, msg_mod = self.adapter.modify("test_pool", {})
        self.assertFalse(ok_mod)
        self.assertIn("unsupported", msg_mod.lower())

        ok_rb, msg_rb = self.adapter.rollback("test_pool", {})
        self.assertFalse(ok_rb)
        self.assertIn("unsupported", msg_rb.lower())

        # With active SSH context -> successful transactional modify
        self.mock_ssh.execute.side_effect = [
            (0, "", ""),  # cp to .bak
            (0, "", ""),  # write new config
            (0, "", ""),  # systemctl restart
        ]
        ok_live, msg_live = self.adapter.modify(
            "test_pool",
            {
                "ssh": self.mock_ssh,
                "interface": "wg-test",
                "config_content": "[Interface]\nMTU = 1360\n",
            }
        )
        self.assertTrue(ok_live)
        self.assertIn("modified successfully", msg_live)

        # Rollback with active SSH context
        self.mock_ssh.execute.side_effect = [
            (0, "", ""),  # cp .bak back & restart
        ]
        ok_rb_live, msg_rb_live = self.adapter.rollback(
            "test_pool",
            {"ssh": self.mock_ssh, "interface": "wg-test"}
        )
        self.assertTrue(ok_rb_live)
        self.assertIn("rolled back", msg_rb_live)


class TestWireGuardActiveProbe(unittest.TestCase):
    """Tests for active traffic probing and nonce challenge across the WireGuard tunnel."""

    def setUp(self):
        self.adapter = WireGuardAdapter()
        self.mock_ir_ssh = MagicMock()
        self.mock_kh_ssh = MagicMock()

    def test_probe_fails_safely_when_unsupported_or_no_ssh(self):
        # Calls without valid SSH handles must return unsupported without crashing
        res = self.adapter.probe({"ip": "1.1.1.1"}, {"ip": "2.2.2.2"}, [443])
        self.assertFalse(res["passed"])
        self.assertIn("unsupported", res["error"].lower())
        self.assertIsNone(res["latency_ms"])

    def test_active_nonce_probe_success(self):
        # Kharej starts echo responder successfully
        self.mock_kh_ssh.execute.return_value = (0, "12345\n", "")
        # Iran executes probe script and gets PASS:2.45
        self.mock_ir_ssh.execute.return_value = (0, "PASS:2.45\n", "")

        res = self.adapter.probe(
            endpoint_ir={"ssh": self.mock_ir_ssh},
            endpoint_kh={"ssh": self.mock_kh_ssh, "private_ip": "10.100.2.2"},
            ports=[42890],
        )
        self.assertTrue(res["passed"])
        self.assertEqual(res["latency_ms"], 2.45)
        self.assertIsNone(res["error"])
        self.assertTrue(res["details"]["nonce_verified"])

    def test_active_nonce_probe_failure_on_packet_drop(self):
        self.mock_kh_ssh.execute.return_value = (0, "12345\n", "")
        self.mock_ir_ssh.execute.return_value = (1, "FAIL:NO_RESPONSE\n", "Connection timed out")

        res = self.adapter.probe(
            endpoint_ir={"ssh": self.mock_ir_ssh},
            endpoint_kh={"ssh": self.mock_kh_ssh, "private_ip": "10.100.2.2"},
            ports=[42890],
        )
        self.assertFalse(res["passed"])
        self.assertIsNone(res["latency_ms"])
        self.assertIn("probe failed", res["error"])


class TestWireGuardMockCryptoExchangeLab(unittest.TestCase):
    """Verifies userspace UDP crypto mockup (simulation only; not real WireGuard)."""

    def test_mock_udp_crypto_exchange_lab(self):
        import importlib.util
        from pathlib import Path
        lab_file = Path(__file__).parent / "wireguard_network_lab.py"
        spec = importlib.util.spec_from_file_location("wireguard_network_lab", str(lab_file))
        lab_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lab_mod)
        ok = lab_mod.run_crypto_mock_lab()
        self.assertTrue(ok, "Mock UDP crypto lab must complete")


class TestWireGuardPoolOrchestration(unittest.TestCase):
    """Verifies WireGuard pool creation, addition, MTU manipulation, active probing, and teardown."""

    def setUp(self):
        self.fake_storage = {"pools": {}}
        self.mock_ssh = MagicMock()
        self.mock_ssh.execute.return_value = (0, "mock_output", "")
        self.mock_ssh.write_file.return_value = True

    def test_create_add_probe_status_mtu_and_remove_pool(self):
        from core import wireguard_adapter

        with patch("core.wireguard_adapter.get_pools", return_value=self.fake_storage["pools"]), \
             patch("core.wireguard_adapter.save_pool", side_effect=lambda name, data: self.fake_storage["pools"].__setitem__(name, data)), \
             patch("core.wireguard_adapter.delete_pool", side_effect=lambda name: self.fake_storage["pools"].pop(name, None)), \
             patch("core.wireguard_adapter.atomic_update", side_effect=lambda fn: fn(self.fake_storage)), \
             patch("core.wireguard_adapter.connect", return_value=self.mock_ssh), \
             patch("core.wireguard_adapter.execute_active_wireguard_probe", return_value={"passed": True, "latency_ms": 2.0}), \
             patch("core.load_balancer.LoadBalancerManager.check_port_conflicts", return_value=(True, None)):

            # 1. Create pool with 1 Iran server
            iran_servers = [{"ip": "192.0.2.10", "name": "ir-1"}]
            kharej_server = {"ip": "198.51.100.20", "name": "kh-1"}
            ok, msg, pool = wireguard_adapter.create(
                name="wg-pool-test",
                kharej=kharej_server,
                servers=iran_servers,
                ports=["8080", "8443"],
                settings={"wireguard_port": 51820, "wireguard_mtu": 1420, "enable_psk": True},
            )
            self.assertTrue(ok)
            self.assertIn("wg-pool-test", self.fake_storage["pools"])
            p_data = self.fake_storage["pools"]["wg-pool-test"]
            self.assertEqual(p_data["status_note"], "آزمایشی — آزمون TCP/UDP لینک تأیید شد")
            self.assertEqual(len(p_data["nodes"]), 1)
            node = p_data["nodes"][0]
            self.assertIn("wireguard", node)
            self.assertEqual(node["wireguard"]["tunnel_port"], 51820)
            self.assertEqual(node["status_note"], "آزمایشی — آزمون TCP/UDP لینک تأیید شد")

            # 2. Add a second node
            iran_server_2 = {"ip": "192.0.2.11", "name": "ir-2"}
            ok_add, msg_add = wireguard_adapter.add("wg-pool-test", iran_server_2)
            self.assertTrue(ok_add)
            self.assertEqual(len(p_data["nodes"]), 2)

            # 3. Change MTU
            ok_mtu, msg_mtu = wireguard_adapter.change_mtu("wg-pool-test", 1360)
            self.assertTrue(ok_mtu)
            self.assertEqual(p_data["wireguard_mtu"], 1360)
            self.assertEqual(p_data["nodes"][0]["wireguard"]["mtu"], 1360)

            # 4. Probe pool
            with patch.object(wireguard_adapter.WireGuardAdapter, "probe", return_value={"passed": True, "latency_ms": 3.2, "error": None}):
                probe_res = wireguard_adapter.probe_pool("wg-pool-test")
                self.assertTrue(probe_res["passed"])
                self.assertEqual(probe_res["latency_ms"], 3.2)

            # 5. Pool status
            with patch.object(wireguard_adapter.WireGuardAdapter, "status", return_value={"status": "UP", "connected": True}):
                ok_st, msg_st, st_dict = wireguard_adapter.pool_status("wg-pool-test")
                self.assertTrue(ok_st)
                self.assertIn("192.0.2.10", st_dict)
                self.assertIn("192.0.2.11", st_dict)

            self.mock_ssh.execute.side_effect = lambda command, **kw: (1, "", "") if command.startswith("ip link show dev ") else (0, "", "")

            # 6. Remove one node
            ok_rem, msg_rem = wireguard_adapter.remove("wg-pool-test", "192.0.2.11")
            self.assertTrue(ok_rem)
            self.assertEqual(len(p_data["nodes"]), 1)

            # 7. Remove entire pool
            ok_del, msg_del = wireguard_adapter.remove_pool("wg-pool-test")
            self.assertTrue(ok_del)
            self.assertNotIn("wg-pool-test", self.fake_storage["pools"])


if __name__ == "__main__":
    unittest.main()
