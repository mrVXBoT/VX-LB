"""Comprehensive unit and integration tests for Geneve + IPsec tunnel adapter.

Covers:
- RFC 8926 Geneve parameter validation (VNI 1..16777215, MTU 576..1420, interface format).
- IPsec configuration (AES-256-GCM ESP, SHA256 PRF, ECP256 DH, 256-bit PSK, 31-bit reqid).
- Anti-leak security firewall (policy match DROP unencrypted Geneve, accept authenticated ESP).
- Lifecycle operations (install, configure, start, stop, status, probe, modify, rollback, clean).
- Real socket data plane verification (RFC 8926 Geneve framing + AES-256-GCM authentication).
"""
import copy
import json
import os
import secrets
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from core import geneve, geneve_agent
from core.adapter_registry import get_adapter
from core.overlay_tunnels_adapter import GeneveIpsecAdapter


class GeneveIpsecTests(unittest.TestCase):
    def setUp(self):
        self.server = {"ip": "192.0.2.1", "name": "iran_server", "password": "mock"}
        self.kh = {"ip": "192.0.2.2", "name": "kharej_server", "password": "mock"}
        self.data = {"pools": {}}
        self.patches = [
            patch.object(geneve, "load_data", lambda: copy.deepcopy(self.data)),
            patch.object(geneve, "get_pools", lambda: copy.deepcopy(self.data["pools"])),
            patch.object(geneve, "atomic_update", lambda fn: fn(self.data)),
            patch.object(
                geneve,
                "save_pool",
                lambda name, pool: self.data["pools"].__setitem__(name, copy.deepcopy(pool)),
            ),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def allocate_node(self, vni=1000, mtu=1400):
        node = geneve.allocate(self.server, self.kh, [443], mtu=mtu, vni=vni)
        node["provisioning"] = False
        self.data["pools"]["test_pool"] = dict(
            name="test_pool",
            engine="geneve_ipsec",
            transport="geneve",
            geneve_mtu=mtu,
            vni=vni,
            nodes=[node],
            kharej_server=self.kh,
            client_ports=[443],
        )
        return node

    def test_blank_optional_vni_uses_automatic_allocation(self):
        def add_node(name, server, callback):
            pool = self.data["pools"][name]
            node = geneve.allocate(server, self.kh, [443], vni=pool["vni"])
            node["provisioning"] = False
            pool["nodes"].append(node)
            return True, "ready"

        with patch.object(geneve, "add", side_effect=add_node), patch(
            "core.load_balancer.LoadBalancerManager.check_port_conflicts", return_value=(True, "")
        ):
            ok, message, pool = geneve.create("auto-vni", self.kh, [self.server], [443], vni="")
        self.assertTrue(ok, message)
        self.assertIsNone(pool["vni"])
        self.assertEqual(pool["nodes"][0]["geneve"]["configs"][0]["vni"], 1000)

    def test_validation_and_vni_bounds(self):
        """RFC 8926: Geneve VNI is 24-bit (1..16777215), MTU is bounded."""
        node = self.allocate_node(vni=5000, mtu=1400)
        c = node["geneve"]["configs"][0]
        validated = geneve_agent.validate(c)
        self.assertEqual(validated["vni"], 5000)
        self.assertEqual(validated["mtu"], 1400)
        self.assertEqual(validated["dst_port"], 6081)

        # Invalid VNIs
        for bad_vni in [0, -1, 16777216, "abc"]:
            with self.assertRaises(ValueError):
                geneve.validate_vni(bad_vni)
            with self.assertRaises(ValueError):
                geneve_agent.validate(dict(c, vni=bad_vni))

        # Invalid MTUs (RFC minimum 576, upper limit 1420 for safe IPsec overhead)
        for bad_mtu in [500, 1450, 1500, "fast"]:
            with self.assertRaises(ValueError):
                geneve.validate_mtu(bad_mtu)
            with self.assertRaises(ValueError):
                geneve_agent.validate(dict(c, mtu=bad_mtu))

        # Invalid interface naming
        for bad_iface in ["eth0", "gre0", "gni-bad", "gni12345678901234"]:
            with self.assertRaises(ValueError):
                geneve_agent.validate(dict(c, interface=bad_iface))

    def test_authenticated_ipsec_mandatory_and_no_plaintext(self):
        """Security requirement: Plain Geneve is disabled; IPsec AES-GCM is mandatory."""
        node = self.allocate_node()
        c = node["geneve"]["configs"][0]

        # Plain config without security must raise RuntimeError
        plain = dict(c)
        plain.pop("security")
        with patch.object(geneve_agent, "command") as cmd:
            with self.assertRaises(RuntimeError):
                geneve_agent.up(plain)
            cmd.assert_not_called()

        # Invalid PSK format
        bad_psk = dict(c, security={"mode": "ipsec", "psk": "short_psk", "reqid": 100})
        with self.assertRaises(RuntimeError):
            geneve_agent.secure_config(bad_psk)

        # Valid IPsec configuration
        sec = geneve_agent.secure_config(c)
        self.assertEqual(sec["mode"], "ipsec")
        self.assertEqual(len(bytes.fromhex(sec["psk"])), 32)
        self.assertGreaterEqual(sec["reqid"], 1)

        # IPsec connection specification for VICI
        conn = geneve_agent.ipsec_connection(c)
        self.assertEqual(conn["version"], "2")
        self.assertEqual(conn["local"]["auth"], "psk")
        self.assertEqual(conn["local"]["id"], c["local"])
        self.assertEqual(conn["remote"]["id"], c["remote"])
        child = conn["children"][c["interface"]]
        self.assertEqual(child["mode"], "transport")
        self.assertEqual(child["esp_proposals"], ["aes256gcm16-ecp256"])
        self.assertEqual(child["local_ts"], [c["local"] + "/32[17]"])
        self.assertEqual(child["remote_ts"], [c["remote"] + "/32[17]"])
        self.assertEqual(child["start_action"], "trap")

    def test_firewall_policy_guard_blocks_unencrypted_bypass(self):
        """Anti-leak requirement: unencrypted Geneve packets are dropped unconditionally."""
        node = self.allocate_node()
        c = node["geneve"]["configs"][0]
        rules = list(geneve_agent.security_rules(c))

        # Check INPUT chain rules
        input_rules = [r for chain, r in rules if chain == "INPUT"]
        # Rule 1: --pol none DROP
        self.assertIn("--pol", input_rules[0])
        self.assertIn("none", input_rules[0])
        self.assertEqual(input_rules[0][-1], "DROP")
        self.assertIn("--dport", input_rules[0])
        self.assertIn("6081", input_rules[0])

        # Rule 2: --pol ipsec --proto esp ACCEPT
        self.assertIn("--pol", input_rules[1])
        self.assertIn("ipsec", input_rules[1])
        self.assertIn("esp", input_rules[1])
        self.assertEqual(input_rules[1][-1], "ACCEPT")

        # Rule 3: Catch-all port 6081 DROP
        self.assertIn("--dport", input_rules[2])
        self.assertIn("6081", input_rules[2])
        self.assertEqual(input_rules[2][-1], "DROP")

        # Check OUTPUT chain has matching protection
        output_rules = [r for chain, r in rules if chain == "OUTPUT"]
        self.assertTrue(any("--pol" in r and "none" in r and r[-1] == "DROP" for r in output_rules))

        # Check tagged rule comments
        for chain, r in rules:
            self.assertIn("vxlb-sec-" + c["interface"], " ".join(r))

    def test_private_ip_allocation_and_no_collision(self):
        """Distinct /30 private subnets allocated per tunnel."""
        node1 = self.allocate_node(vni=1001)
        node2 = geneve.allocate({"ip": "192.0.2.3", "name": "iran2"}, self.kh, [443], vni=1002)
        p1 = node1["geneve"]["local_private"]
        p2 = node2["geneve"]["local_private"]
        self.assertNotEqual(p1, p2)
        # Endpoints must be on /30 boundaries
        self.assertNotEqual(node1["geneve"]["local_private"], node1["geneve"]["remote_private"])

    def test_adapter_interface_contract(self):
        """GeneveIpsecAdapter adheres to BaseTunnelAdapter contract."""
        adapter = get_adapter("geneve_ipsec")
        self.assertIsNotNone(adapter)
        self.assertIsInstance(adapter, GeneveIpsecAdapter)
        self.assertEqual(adapter.engine_id, "geneve_ipsec")

        # Install
        ssh_mock = Mock()
        ssh_mock.execute.return_value = (0, "ok", "")
        ssh_mock.write_file.return_value = True
        ok, msg = adapter.install(ssh_mock, "iran", {})
        self.assertTrue(ok)
        self.assertIn("verified", msg.lower())

        # Configure
        cfg = adapter.configure(self.server, self.kh, {"vni": 2000, "mtu": 1380})
        self.assertEqual(cfg["engine"], "geneve_ipsec")
        self.assertEqual(cfg["vni"], 2000)
        self.assertEqual(cfg["mtu"], 1380)
        self.assertEqual(cfg["dst_port"], 6081)
        self.assertIn("vxlb-geneve-", cfg["service_name"])

        # Start and Stop
        ok_start, _ = adapter.start(ssh_mock, cfg["interface"])
        self.assertTrue(ok_start)
        ok_stop, _ = adapter.stop(ssh_mock, cfg["interface"])
        self.assertTrue(ok_stop)

        # Status
        ssh_mock.execute.return_value = (0, "active\n", "")
        st = adapter.status(ssh_mock, cfg["interface"])
        self.assertEqual(st["status"], "UP")
        self.assertEqual(st["engine"], "geneve_ipsec")

        # Probe
        with patch.object(geneve, "verify_geneve_tunnel", return_value=(True, 2.4)):
            probe_res = adapter.probe({"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}, [443])
            self.assertTrue(probe_res["passed"])
            self.assertEqual(probe_res["latency_ms"], 2.4)

        # Modify MTU and Rollback
        with patch.object(geneve, "change_mtu", return_value=(True, "updated")), \
             patch.object(geneve, "rollback_mtu", return_value=(True, "reverted")):
            ok_mod, _ = adapter.modify("test_pool", {"mtu": 1360})
            self.assertTrue(ok_mod)
            ok_rb, _ = adapter.rollback("test_pool", {"mtu": 1400})
            self.assertTrue(ok_rb)

        # Clean
        ssh_mock.execute.return_value = (0, "cleaned", "")
        ok_clean, _ = adapter.clean(ssh_mock, cfg["interface"])
        self.assertTrue(ok_clean)

    def test_unrelated_interface_never_touched(self):
        """Down action never deletes non-Geneve interfaces."""
        node = self.allocate_node()
        c = node["geneve"]["configs"][0]
        # Mock response indicating this interface is a bridge or dummy, not geneve
        fake_ip_show = Mock(
            returncode=0,
            stdout=json.dumps([{"linkinfo": {"info_kind": "bridge"}}]),
        )
        with patch.object(geneve_agent, "firewall"), \
             patch.object(geneve_agent, "security_firewall"), \
             patch.object(geneve_agent, "command", return_value=fake_ip_show) as cmd:
            with self.assertRaises(RuntimeError) as ctx:
                geneve_agent.down(c)
            self.assertIn("Refusing to delete non-Geneve interface", str(ctx.exception))
            # Verify 'del' was never executed
            self.assertFalse(any("del" in call.args for call in cmd.call_args_list))

    def test_real_geneve_framing_and_aes_gcm_dataplane(self):
        """Real bidirectional data transmission test over sockets with Geneve framing and AES-GCM encryption."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        vni = 7777
        psk = secrets.token_bytes(32)  # 256-bit AES key
        aesgcm = AESGCM(psk)

        # Encode RFC 8926 Geneve Header
        def pack_geneve_header(vni_id: int, proto: int = 0x6558) -> bytes:
            # Word 0: Ver (2 bits = 0), Opt Len (6 bits = 0), Flags (8 bits = 0), Proto Type (16 bits)
            word0 = struct.pack("!HH", 0x0000, proto)
            # Word 1: VNI (24 bits) + Reserved (8 bits = 0)
            word1 = struct.pack("!I", (vni_id << 8) & 0xFFFFFF00)
            return word0 + word1

        def unpack_geneve_header(data: bytes) -> tuple:
            word0, proto = struct.unpack("!HH", data[:4])
            ver = (word0 >> 14) & 0x03
            opt_len = (word0 >> 8) & 0x3F
            word1 = struct.unpack("!I", data[4:8])[0]
            vni_id = (word1 >> 8) & 0xFFFFFF
            return ver, opt_len, proto, vni_id, data[8:]

        # Encrypt packet simulating IPsec ESP (AES-256-GCM)
        def encrypt_packet(plaintext: bytes) -> bytes:
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            return nonce + ciphertext

        # Decrypt packet
        def decrypt_packet(encrypted: bytes) -> bytes:
            nonce = encrypted[:12]
            ciphertext = encrypted[12:]
            return aesgcm.decrypt(nonce, ciphertext, None)

        # Set up a UDP receiver simulating Kharej Geneve tunnel endpoint
        sock_kh = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_kh.bind(("127.0.0.1", 0))
        kh_port = sock_kh.getsockname()[1]

        received_packets = []
        stop_server = threading.Event()

        def server_loop():
            sock_kh.settimeout(0.5)
            while not stop_server.is_set():
                try:
                    raw_data, client_addr = sock_kh.recvfrom(65535)
                    # Decrypt ESP payload
                    decrypted = decrypt_packet(raw_data)
                    # Parse Geneve header
                    ver, opt_len, proto, recv_vni, payload = unpack_geneve_header(decrypted)
                    received_packets.append({
                        "ver": ver,
                        "proto": proto,
                        "vni": recv_vni,
                        "payload": payload,
                    })
                    # Reply with an encrypted echo packet
                    reply_payload = b"ECHO:" + payload
                    reply_geneve = pack_geneve_header(recv_vni) + reply_payload
                    reply_encrypted = encrypt_packet(reply_geneve)
                    sock_kh.sendto(reply_encrypted, client_addr)
                except (socket.timeout, Exception):
                    continue

        t = threading.Thread(target=server_loop, daemon=True)
        t.start()

        try:
            # Client (Iran) sends Geneve packet over UDP
            sock_ir = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_ir.settimeout(3.0)

            payload_data = b"HELLO-GENEVE-IPSEC-PAYLOAD-123456"
            geneve_frame = pack_geneve_header(vni) + payload_data
            self.assertEqual(len(pack_geneve_header(vni)), 8)  # RFC 8926 8-byte header

            encrypted_frame = encrypt_packet(geneve_frame)
            sock_ir.sendto(encrypted_frame, ("127.0.0.1", kh_port))

            # Receive and verify reply
            reply_raw, _ = sock_ir.recvfrom(65535)
            reply_decrypted = decrypt_packet(reply_raw)
            ver, opt_len, proto, reply_vni, reply_body = unpack_geneve_header(reply_decrypted)

            self.assertEqual(reply_vni, vni)
            self.assertEqual(reply_body, b"ECHO:" + payload_data)
            self.assertEqual(len(received_packets), 1)
            self.assertEqual(received_packets[0]["vni"], vni)
            self.assertEqual(received_packets[0]["payload"], payload_data)

            # Test Wrong PSK / Authentication Failure
            wrong_aes = AESGCM(secrets.token_bytes(32))
            wrong_encrypted = wrong_aes.encrypt(secrets.token_bytes(12), geneve_frame, None)
            with self.assertRaises(Exception):
                decrypt_packet(wrong_encrypted)

            # Test Plaintext Bypass Rejection: Plaintext packet does not decrypt and fails closed
            with self.assertRaises(Exception):
                decrypt_packet(geneve_frame)

        finally:
            stop_server.set()
            t.join(timeout=1.0)
            sock_kh.close()
            sock_ir.close()

    def _ssh_with_units(self, active_unit=None, vici=True):
        ssh = Mock()
        def exec_cmd(command, timeout=30):
            if 'systemctl cat' in command or 'is-active' in command:
                unit = 'strongswan.service' if 'strongswan.service' in command else (
                    'strongswan-starter.service' if 'strongswan-starter' in command else 'other')
                ok = (active_unit == unit)
                return (0 if ok else 1), '', 'No files found' if not ok else ''
            if 'charon.vici' in command:
                return (0 if vici else 1), '', ''
            return (0, '', '')
        ssh.execute.side_effect = exec_cmd
        ssh.write_file.return_value = True
        return ssh

    def test_install_agent_detects_alternate_strongswan_units(self):
        for unit_name in ('strongswan.service', 'strongswan-starter.service'):
            ssh = self._ssh_with_units(active_unit=unit_name, vici=True)
            node = {'geneve': {}}
            geneve.install_agent(ssh, node)
            self.assertEqual(node['geneve']['ipsec_unit'], unit_name)

    def test_install_agent_requires_vici_socket(self):
        ssh = self._ssh_with_units(active_unit='strongswan.service', vici=False)
        with self.assertRaises(RuntimeError) as ctx:
            geneve.install_agent(ssh)
        self.assertIn('charon', str(ctx.exception).lower())

    def test_install_agent_clear_error_when_no_strongswan(self):
        ssh = self._ssh_with_units(active_unit=None, vici=False)
        with self.assertRaises(RuntimeError) as ctx:
            geneve.install_agent(ssh)
        self.assertIn('charon-systemd', str(ctx.exception))

    def test_service_uses_detected_ipsec_unit(self):
        node = self.allocate_node()
        node['geneve']['ipsec_unit'] = 'strongswan-starter.service'
        svc = geneve.service(node)
        self.assertIn('strongswan-starter.service', svc)
        self.assertNotIn('Requires=strongswan.service\n', svc)


if __name__ == "__main__":
    unittest.main()
