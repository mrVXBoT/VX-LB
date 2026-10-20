import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

class WebShutdownTests(unittest.TestCase):
    def test_foreground_server_exits_on_sigterm(self):
        with tempfile.TemporaryDirectory() as directory:
            code = '''import sys
from core import web_server as web
web.PID_FILE = sys.argv[1] + '/web.pid'
web.PORT_FILE = sys.argv[1] + '/web.port'
web.run_web_server(host='127.0.0.1', port=0)
'''
            child = subprocess.Popen([sys.executable, '-c', code, directory], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, cwd=Path(__file__).resolve().parents[1])
            try:
                for _ in range(50):
                    if (Path(directory) / 'web.pid').exists(): break
                    if child.poll() is not None: self.fail(child.stderr.read().decode())
                    time.sleep(.05)
                time.sleep(.1)
                child.terminate()
                self.assertEqual(child.wait(timeout=3), 0)
                self.assertFalse((Path(directory) / 'web.pid').exists())
            finally:
                if child.poll() is None: child.kill(); child.wait()
                child.stderr.close()
