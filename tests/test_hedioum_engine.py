"""Unit tests for the Hedioum Pool Tunnel engine (command building, modes, token flow)."""
import unittest
from unittest.mock import MagicMock, patch
from core import hedioum_engine as h


class HedioumEngineTests(unittest.TestCase):
    def test_modes_and_personas(self):
        self.assertEqual(h.MODES, ("socks", "tun", "gateway"))
        self.assertIn("auto", h.PERSONAS)
        self.assertEqual(h.normalize_mode("tun"), "tun")
        with self.assertRaises(ValueError):
            h.normalize_mode("bogus")

    def test_install_validation_offline_depot(self):
        ssh = MagicMock()
        ssh.execute.return_value = (1, "", "missing")
        ssh.upload_binary.return_value = False
        ok, msg = h.install_hedioum(ssh)
        self.assertFalse(ok)
        self.assertIn("Hedioum", msg)

    def test_setup_foreign_parses_token(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "Auth Token: abc123def456\n", "")
        token = h.setup_foreign(ssh, persona="auto", domain="vpn.example.com", move_ssh=True)
        self.assertEqual(token, "abc123def456")
        cmd = ssh.execute.call_args[0][0]
        self.assertIn("--persona auto", cmd)
        self.assertIn("--domain vpn.example.com", cmd)
        self.assertIn("--move-ssh", cmd)

    def test_setup_foreign_parses_real_v2_pairing_token(self):
        real_output = """[✓] Persona: devops (SSH backbone + 9 coherent mimics).
[✓] Foreign config written.
━━━ Hub onboarding ━━━
Paste THIS pairing token into the hub — it already carries the exit IP:
eyJ2IjoyLCJpcCI6IjE0My4yNDYuMTM4LjI0NSIsImF1dGgiOiJhZTBmMDI2N2ViMmZmNjllMmJlZWZiODRkZDVlNTA1NiJ9
(Raw auth key, for advanced/legacy setups only: ae0f0267eb2ff69e2beefb84dd5e5056)
"""
        ssh = MagicMock()
        ssh.execute.return_value = (0, real_output, "")
        token = h.setup_foreign(ssh, persona="devops")
        self.assertEqual(token, "eyJ2IjoyLCJpcCI6IjE0My4yNDYuMTM4LjI0NSIsImF1dGgiOiJhZTBmMDI2N2ViMmZmNjllMmJlZWZiODRkZDVlNTA1NiJ9")

    def test_setup_foreign_raises_without_token(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "no token here", "")
        with self.assertRaises(RuntimeError):
            h.setup_foreign(ssh)

    def test_setup_iran_command_modes(self):
        for mode in h.MODES:
            ssh = MagicMock()
            ssh.execute.return_value = (0, "", "")
            h.setup_iran(ssh, "alias1", "tok", 2255, mode, tun_dns=True)
            cmd = ssh.execute.call_args[0][0]
            self.assertIn(f"--alias alias1", cmd)
            self.assertIn(f"--socks-port {h.LOCAL_SOCKS_PORT}", cmd)
            self.assertIn("--socks-bind 127.0.0.1", cmd)
            self.assertNotIn("--socks-port 2255", cmd)
            if mode == "gateway":
                self.assertIn("--gateway", cmd)
                self.assertIn("--tun", cmd)
            elif mode == "tun":
                self.assertIn("--tun", cmd)
            else:
                self.assertNotIn("--tun", cmd)

    def test_tcp_bridge_speaks_socks_to_kharej_public_ip(self):
        program = h._bridge_program("31.57.24.207", [2255])
        self.assertIn("kharej = '31.57.24.207'", program)
        self.assertIn("ports = [2255]", program)
        self.assertIn('b"\\x05\\x01\\x00"', program)
        self.assertIn("127.0.0.1", program)
        self.assertNotIn("0.0.0.0", program.split("bind", 1)[0])

    def test_setup_iran_recovers_stale_foreign_config(self):
        # A node previously provisioned as egress/foreign refuses setup-iran with
        # "existing config role is \"foreign\", not iran". Recovery runs the binary's
        # standalone `--reset` (config wipe) then retries setup-iran without --reset.
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (1, "", 'existing config role is "foreign", not iran'),
            (0, "", ""),   # hedioum-tunnel --reset  (standalone)
            (0, "", ""),   # setup-iran retry
        ]
        h.setup_iran(ssh, "alias1", "tok", 2255, "socks")
        commands = [call_args[0][0] for call_args in ssh.execute.call_args_list]
        self.assertEqual(len(commands), 3)
        reset_cmds = [c for c in commands if "--reset" in c]
        self.assertEqual(len(reset_cmds), 1)
        self.assertNotIn("setup-iran", reset_cmds[0])  # reset is NOT a setup-iran flag
        setup_cmds = [c for c in commands if "setup-iran" in c]
        self.assertTrue(all("--reset" not in c for c in setup_cmds))

    def test_setup_iran_propagates_other_errors(self):
        ssh = MagicMock()
        ssh.execute.return_value = (1, "", "some unrelated failure")
        with self.assertRaises(RuntimeError):
            h.setup_iran(ssh, "alias1", "tok", 2255, "socks")
        self.assertFalse(any("--reset" in c[0][0] for c in ssh.execute.call_args_list))


    def test_create_validation(self):
        with patch.object(h, "get_pools", return_value={}):
            ok, msg, _ = h.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                   ["2255"], {"mode": "bad"})
            self.assertFalse(ok)
            self.assertIn("نامعتبر", msg)
            ok, msg, _ = h.create("p1", {"ip": "198.51.100.1"}, [{"ip": "192.0.2.1"}],
                                   ["2255"], {"mode": "socks", "persona": "notreal"})
            self.assertFalse(ok)
            self.assertIn("persona", msg)


if __name__ == "__main__":
    unittest.main()
