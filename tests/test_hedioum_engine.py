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
            self.assertIn("--socks-port 2255", cmd)
            self.assertIn("--socks-bind 0.0.0.0", cmd)
            if mode == "gateway":
                self.assertIn("--gateway", cmd)
                self.assertIn("--tun", cmd)
            elif mode == "tun":
                self.assertIn("--tun", cmd)
            else:
                self.assertNotIn("--tun", cmd)

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
