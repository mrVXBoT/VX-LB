import json
import unittest
from unittest.mock import patch, MagicMock
from core import web_server as web

class ApiExtensionsTests(unittest.TestCase):
    def setUp(self):
        self.handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
        self.handler.headers = {}
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.wfile = MagicMock()
        self.handler._is_authenticated = MagicMock(return_value=True)

    def test_api_capabilities_endpoint(self):
        self.handler.path = "/api/capabilities"
        self.handler.do_GET()
        self.handler.send_response.assert_called_with(200)
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written.decode("utf-8"))
        self.assertIn("wireguard", data)
        self.assertIn("waterwall", data)
        self.assertEqual(data["6to4_anycast"]["support_status"], "unsupported")

    def test_api_links_endpoint(self):
        self.handler.path = "/api/links"
        fake_storage = {"custom_links": {"link1": {"engine_id": "wireguard", "mtu": 1420}}}
        with patch("core.web_server.load_data", return_value=fake_storage):
            self.handler.do_GET()
        self.handler.send_response.assert_called_with(200)
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written.decode("utf-8"))
        self.assertIn("link1", data)

    def test_api_logs_waterwall(self):
        fake_storage = {
            "pools": {
                "WPool": {
                    "nodes": [{"ip": "192.0.2.50", "engine": "waterwall", "node_name": "wnode"}]
                }
            }
        }
        mock_ssh = MagicMock()
        mock_ssh.connect.return_value = (True, "Connected")
        mock_ssh.execute.return_value = (0, "WaterWall active log line 1\nWaterWall active log line 2", "")

        self.handler.path = "/api/logs?ip=192.0.2.50"
        with patch("core.web_server.load_data", return_value=fake_storage), \
             patch("core.web_server.SSHManager", return_value=mock_ssh):
            self.handler.do_GET()

        self.handler.send_response.assert_called_with(200)
        cmd_executed = mock_ssh.execute.call_args[0][0]
        self.assertIn("waterwall", cmd_executed)

    def test_api_pools_composition_get(self):
        fake_storage = {
            "pools": {
                "P1": {
                    "transport": "wireguard",
                    "mtu": 1420
                }
            }
        }
        self.handler.path = "/api/pools/composition?pool=P1"
        with patch("core.web_server.load_data", return_value=fake_storage):
            self.handler.do_GET()
        self.handler.send_response.assert_called_with(200)
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written.decode("utf-8"))
        self.assertEqual(data["pool"], "P1")
        self.assertEqual(data["composition"]["network"]["type"], "wireguard")
        self.assertEqual(data["composition"]["encryption"]["type"], "noise")

    def test_api_pools_composition_validate_post(self):
        import io
        self.handler.path = "/api/pools/composition/validate"
        body = {
            "composition": {
                "engine": "gre_xhttp",
                "network": {"type": "gre_ipv4", "mtu": 1360},
                "encryption": {"type": "tls13", "cipher": "TLS_AES_128_GCM_SHA256"},
                "camouflage": {"type": "xhttp_grpc", "domain": "vpn.example.com"}
            }
        }
        raw = json.dumps(body).encode("utf-8")
        self.handler.rfile = io.BytesIO(raw)
        self.handler.headers = {"Content-Length": str(len(raw))}
        self.handler.do_POST()
        self.handler.send_response.assert_called_with(200)
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written.decode("utf-8"))
        self.assertTrue(data["valid"])

    def test_status_exposes_public_slipstream_settings_without_tls_private_keys(self):
        self.handler.path = '/api/status'
        pool = dict(engine='slipstream', transport='slipstream', nodes=[],
                    domain='tunnel.example.com', resolvers=['1.1.1.1:53'], dns_port=53,
                    rate_limit=1000, slipstream_runtime_version=3,
                    slipstream_security={'server_key': 'DO-NOT-EXPOSE-SERVER', 'client_key': 'DO-NOT-EXPOSE-CLIENT'})
        watchdog = MagicMock()
        watchdog.is_daemon_running.return_value = False
        watchdog.get_daemon_pid.return_value = None
        with patch('core.web_server.load_data', return_value={'pools': {'dns': pool}}), \
             patch('core.web_server.TelemetryWatchdog', return_value=watchdog), \
             patch('core.web_server.get_servers', return_value=[]), \
             patch('core.web_server.get_dashboard_domain_config', return_value={}):
            self.handler.do_GET()
        written = b''.join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written)
        self.assertEqual(data['pools'][0]['slipstream']['rate_limit'], 1000)
        self.assertEqual(data['pools'][0]['slipstream']['domain'], 'tunnel.example.com')
        self.assertNotIn(b'DO-NOT-EXPOSE', written)
