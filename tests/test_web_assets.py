"""Verify script delivery through the real HTTP handler, without starting services."""
from http.client import HTTPConnection
from pathlib import Path
import threading
import unittest
from core.web_server import LDWebRequestHandler, ThreadedHTTPServer


class WebAssetTests(unittest.TestCase):
    def test_redesigned_shell_scripts_are_served(self):
        server = ThreadedHTTPServer(('127.0.0.1', 0), LDWebRequestHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for name in ('copy.fa.js', 'app.js'):
                with self.subTest(asset=name):
                    connection = HTTPConnection('127.0.0.1', server.server_port)
                    connection.request('GET', '/' + name)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertIn('application/javascript', response.getheader('Content-Type'))
                    self.assertEqual(response.read(), (Path(__file__).resolve().parents[1] / 'web' / name).read_bytes())
                    connection.close()
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
