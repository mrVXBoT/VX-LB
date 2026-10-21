import unittest
from unittest.mock import MagicMock, patch
from core.adapter_registry import get_adapter
from core.slipstream_adapter import SlipstreamAdapter

class SlipstreamAdapterTests(unittest.TestCase):
    def setUp(self):
        self.adapter = get_adapter("slipstream")
        self.assertIsNotNone(self.adapter)
        self.assertIsInstance(self.adapter, SlipstreamAdapter)

    def test_capabilities_integration(self):
        caps = self.adapter.capabilities
        self.assertEqual(caps.engine_id, "slipstream")
        self.assertEqual(caps.layer, "L7")
        self.assertIn("tcp", caps.supported_protocols)
        self.assertIn("udp", caps.supported_protocols)
        self.assertTrue(caps.requires_external_domain)

    def test_installer_preserves_existing_binary_on_bad_download(self):
        import hashlib
        import shlex
        import subprocess
        import sys
        import tempfile
        from pathlib import Path
        ssh = MagicMock()
        # Local depot yields no usable binary, allow_download enables the
        # network fallback path exercised below.
        ssh.execute.side_effect = [
            (0, "x86_64", ""),  # uname -m
            (1, "", ""),        # sha256sum: destination missing
            (0, "", ""),        # remote download command
        ]
        with patch("os.path.isfile", return_value=False):
            self.assertTrue(self.adapter.install(ssh, "iran", {"allow_download": True})[0])
        # Extract the embedded python -c program from the remote download call.
        download_call = next(
            c for c in ssh.execute.call_args_list
            if "urlopen" in c[0][0]
        )
        script = shlex.split(download_call[0][0])[2]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source, destination = root / "download", root / "installed"
            source.write_bytes(b"new binary")
            destination.write_bytes(b"old binary")
            command = [sys.executable, "-c", script, source.as_uri(), "0" * 64, str(destination)]
            result = subprocess.run(command, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(destination.read_bytes(), b"old binary")
            self.assertEqual(list(root.glob(".vxlb-slipstream-*")), [])
            command[-2] = hashlib.sha256(source.read_bytes()).hexdigest()
            result = subprocess.run(command, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(destination.read_bytes(), b"new binary")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_installer_is_local_first_and_never_downloads_by_default(self):
        import hashlib
        import os
        ssh = MagicMock()
        # Remote destination missing; local bundled binary present.
        local = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "bin", "x86_64", "slipstream-client",
        )
        with open(local, "rb") as f:
            expected = hashlib.sha256(f.read()).hexdigest()
        ssh.execute.side_effect = [
            (0, "x86_64", ""),          # uname -m
            (1, "", ""),                # sha256sum: missing remotely
            (0, expected, ""),          # post-upload verify
        ]
        ssh.upload_binary.return_value = True
        ok, msg = self.adapter.install(ssh, "iran", {})
        self.assertTrue(ok, msg)
        ssh.upload_binary.assert_called_once()
        # No urlopen / download was invoked.
        self.assertFalse(any("urlopen" in str(c) for c in ssh.execute.call_args_list))

    def test_installer_refuses_to_download_when_no_local_binary(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (0, "x86_64", ""),
            (1, "", ""),
        ]
        with patch("os.path.isfile", return_value=False):
            ok, msg = self.adapter.install(ssh, "iran", {})
        self.assertFalse(ok)
        self.assertIn("strict offline", msg)
        # No download attempt was made.
        self.assertFalse(any("urlopen" in str(c) for c in ssh.execute.call_args_list))

    def test_configure_uses_official_commands_and_separate_secure_relay(self):
        from core.slipstream_deploy import identity_material
        pool = dict(domain="tunnel.example.com", client_ports=[443, 8443],
                    resolvers=["1.1.1.1:53"], dns_port=53, slipstream_id="a" * 16,
                    slipstream_relay_port=25001, slipstream_security=identity_material())
        node = dict(ip="192.0.2.1", slipstream_carrier_port=25002)
        result = self.adapter.configure(node, {"ip": "198.51.100.1"}, pool)
        server_units = "\n".join(value for key, value in result["server_files"].items() if key.endswith(".service"))
        client_units = "\n".join(value for key, value in result["client_files"].items() if key.endswith(".service"))
        self.assertIn("slipstream-server", server_units)
        self.assertIn("--target-address", server_units)
        self.assertIn("slipstream-client", client_units)
        self.assertIn("--resolver", client_units)
        self.assertNotIn(".toml", server_units + client_units)
        self.assertNotIn(pool["slipstream_security"]["server_key"], "\n".join(result["client_files"].values()))
        self.assertNotIn(pool["slipstream_security"]["client_key"], "\n".join(result["server_files"].values()))

    def test_dns_guard_binds_destination_address_without_claiming_local_dns(self):
        import json
        from core.slipstream_deploy import identity_material
        pool = dict(domain="tunnel.example.com", client_ports=[443], resolvers=["198.51.100.1:53"],
                    dns_port=53, slipstream_id="a" * 16, slipstream_relay_port=25001,
                    slipstream_dns_backend_port=25003, slipstream_runtime_version=3,
                    slipstream_security=identity_material())
        result = self.adapter.configure(dict(ip="192.0.2.1", slipstream_carrier_port=25002),
                                        {"ip": "198.51.100.1"}, pool)
        guard = next(json.loads(value) for path, value in result["server_files"].items()
                     if path.endswith("/guard.json"))
        self.assertEqual(guard["listen_host"], "198.51.100.1")
        self.assertEqual(guard["listen_port"], 53)
        self.assertEqual(guard["backend_port"], 25003)

    def test_start_and_stop_lifecycle(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "active", "")
        
        ok, msg = self.adapter.start(ssh, "test_node")
        self.assertTrue(ok)
        self.assertIn("started", msg)

        ok, msg = self.adapter.stop(ssh, "test_node")
        self.assertTrue(ok)
        self.assertIn("stopped", msg)

    def test_status_checks_systemd_and_listener(self):
        ssh = MagicMock()
        ssh.execute.side_effect = [
            (0, "active", ""),
            (0, "udp UNCONN 0 0 0.0.0.0:53", "")
        ]
        status = self.adapter.status(ssh, "test_node")
        self.assertEqual(status["status"], "DEGRADED")
        self.assertTrue(status["is_active"])
        self.assertTrue(status["dns_listener_detected"])

    def test_local_listener_does_not_prove_dns_data_path(self):
        ssh = MagicMock()
        ssh.execute.return_value = (0, "", "")
        for endpoint in (ssh, None, object()):
            result = self.adapter.probe(endpoint, None, [443])
            self.assertFalse(result["passed"])
            self.assertEqual(result["status"], "UNVERIFIED")
            self.assertIsNone(result["latency_ms"])
            self.assertEqual(result["protocols"], [])
        ssh.execute.assert_not_called()

    def test_clean_rejects_unknown_ownership(self):
        ssh = MagicMock()
        with patch("core.slipstream_adapter.get_pools", return_value={}):
            ok, _ = self.adapter.clean(ssh, "unknown")
        self.assertFalse(ok)
        ssh.execute.assert_not_called()
