"""
Operations tests for WaterWall:
- Data plane verification via waterwall.verify() with real probe helper execution
- Multi-tier health reporting in waterwall.health() (HEALTHY, DEGRADED, DOWN)
- Port mutation and transactional rollback in waterwall.change_ports()
- Resource cleanup and node removal in waterwall.clean() and waterwall.remove()
"""
import copy
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from core import waterwall, storage

ROOT_DIR = Path(__file__).resolve().parent.parent
HELPER_SCRIPT = str(ROOT_DIR / 'core' / 'waterwall_probe.py')


class LocalSubprocessChannel:
    def __init__(self, proc):
        self.proc = proc

    def shutdown_write(self):
        if self.proc.stdin:
            try:
                self.proc.stdin.close()
            except Exception:
                pass

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except Exception:
                self.proc.kill()


class LocalSubprocessStdout:
    def __init__(self, proc):
        self.proc = proc
        self.channel = LocalSubprocessChannel(proc)

    def readline(self):
        line = self.proc.stdout.readline()
        return line.decode() if isinstance(line, bytes) else line


class LocalMockSSH:
    """Mock SSH that can execute commands locally or simulate failures."""
    last_echo_port = None

    def __init__(self, service_active=True, journal_error='', mock_tunnel=True):
        self.service_active = service_active
        self.journal_error = journal_error
        self.mock_tunnel = mock_tunnel
        self.executed_commands = []
        self.written_files = {}
        self.client = MagicMock()
        self.client.exec_command = self._exec_command

    def execute(self, cmd, timeout=30):
        self.executed_commands.append(cmd)

        if 'systemctl is-active' in cmd:
            active = self.service_active() if callable(self.service_active) else self.service_active
            return (0, 'active\n', '') if active else (3, 'inactive\n', 'Service inactive')

        if 'journalctl' in cmd:
            return (0, self.journal_error, '')

        # Real command execution for python probe / echo
        if 'waterwall_probe' in cmd or 'vxlb-waterwall-probe' in cmd:
            # Replace helper with local script path
            cmd_run = cmd.replace('/usr/local/bin/vxlb-waterwall-probe', HELPER_SCRIPT)
            if 'probe' in cmd and self.mock_tunnel and LocalMockSSH.last_echo_port:
                parts = cmd_run.split()
                for i, p in enumerate(parts):
                    if p == 'probe' and i + 1 < len(parts) and parts[i+1].isdigit():
                        parts[i+1] = str(LocalMockSSH.last_echo_port)
                        cmd_run = ' '.join(parts)
                        break
            res = subprocess.run(cmd_run, shell=True, capture_output=True, text=True, timeout=timeout)
            return (res.returncode, res.stdout, res.stderr)

        if cmd.startswith('python3 -c'):
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return (res.returncode, res.stdout, res.stderr)

        return (0, '', '')

    def _exec_command(self, cmd, timeout=10):
        self.executed_commands.append(cmd)
        if 'echo' in cmd:
            parts = cmd.split()
            for i, p in enumerate(parts):
                if p == 'echo' and i + 1 < len(parts) and parts[i+1].isdigit():
                    LocalMockSSH.last_echo_port = int(parts[i+1])
                    break
        cmd_run = cmd.replace('/usr/local/bin/vxlb-waterwall-probe', HELPER_SCRIPT)
        proc = subprocess.Popen(
            cmd_run,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return (proc.stdin, LocalSubprocessStdout(proc), proc.stderr)

    def write_file(self, path, content):
        self.written_files[path] = content
        return True

    def close(self):
        pass


class WaterWallOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix='vxlb-ops-test-')
        self.tmp_path = Path(self.tmpdir.name)

        # Free ports for testing
        self.backend_port = socket_probe()
        self.probe_port = socket_probe()
        self.probe_backend_port = socket_probe()
        self.outer_port = socket_probe()

        self.pool_name = 'ww_pool_' + secrets.token_hex(4)
        self.node = {
            'node_name': 'ldw' + secrets.token_hex(8),
            'ip': '192.0.2.10',
            'waterwall': {
                'profile': {
                    'server_name': 'tunnel.test',
                    'certificate': str(self.tmp_path / 'cert.pem'),
                    'key': str(self.tmp_path / 'key.pem'),
                    'port': self.outer_port,
                    'binary': '/tmp/waterwall-bin/Waterwall'
                },
                'uuid_tcp': str(uuid.uuid4()),
                'uuid_udp': str(uuid.uuid4()),
                'outer_port': self.outer_port,
                'backend_port': self.backend_port,
                'probe_port': self.probe_port,
                'probe_ingress_port': self.probe_port,
                'probe_backend_port': self.probe_backend_port
            }
        }

        self.pool = {
            'name': self.pool_name,
            'transport': 'waterwall',
            'engine': 'waterwall',
            'camouflage': self.node['waterwall']['profile'],
            'kharej_server': {'ip': '198.51.100.1'},
            'client_ports': [str(self.backend_port)],
            'nodes': [self.node]
        }

        # Setup mock storage
        self.storage_data = {'pools': {self.pool_name: copy.deepcopy(self.pool)}}
        self.p_storage = patch('core.waterwall.get_pools', side_effect=lambda: copy.deepcopy(self.storage_data['pools']))
        self.p_atomic = patch('core.waterwall.atomic_update', side_effect=self._atomic_update)
        self.p_storage.start()
        self.p_atomic.start()

    def _atomic_update(self, callback):
        callback(self.storage_data)

    def tearDown(self):
        self.p_storage.stop()
        self.p_atomic.stop()
        self.tmpdir.cleanup()

    def test_verify_real_probe_execution_success(self):
        """Test waterwall.verify() actually launches the helper echo responder on Kharej
        and probe on Iran, successfully proving end-to-end data transfer."""
        iran_ssh = LocalMockSSH(service_active=True)
        kharej_ssh = LocalMockSSH(service_active=True)

        with patch.dict(os.environ, {'VX_LB_WATERWALL_PROBE_HELPER': HELPER_SCRIPT}):
            waterwall.verify(iran_ssh, kharej_ssh, self.node, ports=[self.backend_port])

        # Verify commands were executed
        kharej_echo_cmds = [c for c in kharej_ssh.executed_commands if 'echo' in c]
        self.assertTrue(len(kharej_echo_cmds) > 0, 'Kharej echo responder was not executed')

        iran_probe_cmds = [c for c in iran_ssh.executed_commands if 'probe' in c]
        self.assertTrue(len(iran_probe_cmds) > 0, 'Iran probe was not executed')

    def test_verify_fails_when_service_inactive(self):
        """Test waterwall.verify() fails fast if systemd service is inactive on either host."""
        iran_ssh = LocalMockSSH(service_active=False)
        kharej_ssh = LocalMockSSH(service_active=True)

        with self.assertRaises(RuntimeError) as ctx:
            waterwall.verify(iran_ssh, kharej_ssh, self.node, ports=[self.backend_port])

        self.assertIn('WaterWall service inactive on Iran', str(ctx.exception))

    def test_verify_fails_when_fatal_errors_in_journal(self):
        """Test waterwall.verify() fails if fatal error log is detected in journalctl."""
        iran_ssh = LocalMockSSH(service_active=True)
        kharej_ssh = LocalMockSSH(service_active=True, journal_error='FATAL Router: unhandled error')

        with self.assertRaises(RuntimeError) as ctx:
            waterwall.verify(iran_ssh, kharej_ssh, self.node, ports=[self.backend_port])

        self.assertIn('WaterWall errors on Kharej', str(ctx.exception))

    def test_health_levels_healthy_degraded_down(self):
        """Test waterwall.health() correctly differentiates:
        - HEALTHY: tunnel probe ok + user application port listening
        - DEGRADED: tunnel probe ok + user application port not listening
        - DOWN: tunnel probe failed or service down
        """
        ir_ssh = LocalMockSSH(service_active=True)
        kh_ssh = LocalMockSSH(service_active=True)

        with patch('core.waterwall.connect', side_effect=[ir_ssh, kh_ssh, ir_ssh, kh_ssh, ir_ssh, kh_ssh]):
            # 1. Start application listener on backend port -> HEALTHY
            import socket
            with socket.socket() as app_server:
                app_server.bind(('127.0.0.1', self.backend_port))
                app_server.listen(1)

                with patch.dict(os.environ, {'VX_LB_WATERWALL_PROBE_HELPER': HELPER_SCRIPT}):
                    status, reason, details = waterwall.health(self.pool_name, self.node, [self.backend_port])

                self.assertEqual(status, 'HEALTHY')
                self.assertEqual(details[str(self.backend_port)]['status'], 'HEALTHY')

            # 2. Application port closed -> DEGRADED (tunnel probe ok, but backend port inactive)
            with patch.dict(os.environ, {'VX_LB_WATERWALL_PROBE_HELPER': HELPER_SCRIPT}):
                status, reason, details = waterwall.health(self.pool_name, self.node, [self.backend_port])

            self.assertEqual(status, 'DEGRADED')
            self.assertEqual(details[str(self.backend_port)]['status'], 'DEGRADED')

            # 3. Tunnel broken / service down -> DOWN
            ir_broken = LocalMockSSH(service_active=False)
            with patch('core.waterwall.connect', side_effect=[ir_broken, kh_ssh]):
                status, reason, details = waterwall.health(self.pool_name, self.node, [self.backend_port])
            self.assertEqual(status, 'DOWN')

    def test_change_ports_success(self):
        """Test changing ports across the pool: updates configs, firewall, verifies, and commits."""
        ir_ssh = LocalMockSSH(service_active=True)
        kh_ssh = LocalMockSSH(service_active=True)

        new_ports = ['8080', '8443']
        with patch('core.waterwall.connect', side_effect=[ir_ssh, kh_ssh]), \
             patch('core.waterwall.write') as mock_write, \
             patch('core.waterwall.firewall') as mock_fw, \
             patch('core.waterwall.verify') as mock_ver, \
             patch('core.load_balancer.LoadBalancerManager.check_port_conflicts', return_value=(True, '')):

            ok, msg = waterwall.change_ports(self.pool_name, new_ports)
            self.assertTrue(ok, msg)
            self.assertEqual(self.storage_data['pools'][self.pool_name]['client_ports'], new_ports)
            self.assertEqual(self.storage_data['pools'][self.pool_name]['transport_change']['status'], 'succeeded')
            self.assertTrue(mock_ver.called)
            self.assertTrue(mock_write.called)
            self.assertTrue(mock_fw.called)

    def test_change_ports_rollback_on_failure(self):
        """Test port change rollback when a node fails verification:
        reverts config, restores original firewall, restarts service, verifies old ports, and records rolled_back."""
        node1 = copy.deepcopy(self.node)
        node2 = copy.deepcopy(self.node)
        node2['node_name'] = 'ldw' + secrets.token_hex(8)
        node2['ip'] = '192.0.2.11'
        self.storage_data['pools'][self.pool_name]['nodes'] = [node1, node2]

        ir_ssh1, kh_ssh1 = LocalMockSSH(service_active=True), LocalMockSSH(service_active=True)
        ir_ssh2, kh_ssh2 = LocalMockSSH(service_active=True), LocalMockSSH(service_active=True)

        verify_calls = []

        def fake_verify(ir, kh, node, ports):
            verify_calls.append((node['node_name'], ports))
            if node['node_name'] == node2['node_name'] and ports == ['8080']:
                raise RuntimeError('Simulated verification timeout on node2')

        with patch('core.waterwall.connect', side_effect=[ir_ssh1, kh_ssh1, ir_ssh2, kh_ssh2]), \
             patch('core.waterwall.write') as mock_write, \
             patch('core.waterwall.firewall'), \
             patch('core.waterwall.verify', side_effect=fake_verify), \
             patch('core.load_balancer.LoadBalancerManager.check_port_conflicts', return_value=(True, '')):

            ok, msg = waterwall.change_ports(self.pool_name, ['8080'])
            self.assertFalse(ok)
            self.assertIn('Simulated verification timeout on node2', msg)

            # Check job status set to rolled_back
            job = self.storage_data['pools'][self.pool_name]['transport_change']
            self.assertEqual(job['status'], 'rolled_back')

            # Check old ports preserved in storage
            self.assertEqual(self.storage_data['pools'][self.pool_name]['client_ports'], [str(self.backend_port)])

            # Confirm rollback verify was called for node1 with old ports
            rollback_verifies = [v for v in verify_calls if v[1] == [str(self.backend_port)]]
            self.assertTrue(len(rollback_verifies) > 0, 'Rollback verify was not executed for node1')

    def test_clean_and_remove_node(self):
        """Test clean() stops systemd unit and remove() deletes node from pool."""
        ir_ssh = LocalMockSSH(service_active=True)
        kh_ssh = LocalMockSSH(service_active=True)

        with patch('core.waterwall.connect', side_effect=[ir_ssh, kh_ssh]), \
             patch('core.waterwall.firewall') as mock_fw:
            ok, msg = waterwall.remove(self.pool_name, self.node['ip'])
            self.assertTrue(ok, msg)

            # Node should be removed from storage
            self.assertEqual(len(self.storage_data['pools'][self.pool_name]['nodes']), 0)

            # Clean commands (disable systemctl) must be executed
            ir_clean = any('systemctl disable --now' in c for c in ir_ssh.executed_commands)
            kh_clean = any('systemctl disable --now' in c for c in kh_ssh.executed_commands)
            self.assertTrue(ir_clean, 'Iran systemctl unit was not disabled')
            self.assertTrue(kh_clean, 'Kharej systemctl unit was not disabled')
            self.assertTrue(mock_fw.called, 'Firewall cleanup was not called')


def socket_probe():
    import socket
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port



class WaterWallAdapterLifecycleTests(unittest.TestCase):
    def setUp(self):
        from core.adapter_registry import get_adapter
        self.adapter = get_adapter("waterwall")
        self.assertIsNotNone(self.adapter)

    def test_adapter_retrieval_from_registry(self):
        """Verify WaterWallAdapter is registered and instantiated with engine_id='waterwall'."""
        self.assertEqual(self.adapter.engine_id, "waterwall")

    def test_adapter_integrated_lifecycle_pipeline(self):
        """Unit/contract lifecycle pipeline via get_adapter('waterwall') with mock SSH.

        Pipelines the actual output of configure() directly into:
        - writing generated config and unit files
        - start (using cfg or cfg['service_name'])
        - status (using cfg or cfg['service_name'])
        - probe (using cfg['node'] and configured client_ports with real probe helper)
        - modify (using configured node and pool, updating client_ports)
        - rollback (reverting to original configured client_ports)
        - stop (using cfg or cfg['service_name'])
        - clean (using cfg or cfg['node'])

        No service names or ports are guessed independently.
        Note: Real binary execution and operational tunnel verification are strictly
        tested in WaterWallRealBinaryExecutionTests, not here.
        """
        iran_ssh = LocalMockSSH(service_active=True)
        kharej_ssh = LocalMockSSH(service_active=True)

        # 1. Install prerequisites check
        ok_ir, msg_ir = self.adapter.install(iran_ssh, "iran", {"camouflage": {"binary": "/tmp/waterwall-bin/Waterwall"}})
        self.assertTrue(ok_ir, msg_ir)
        ok_kh, msg_kh = self.adapter.install(kharej_ssh, "kharej", {"camouflage": {"binary": "/tmp/waterwall-bin/Waterwall"}})
        self.assertTrue(ok_kh, msg_kh)

        # 2. Configure: iran node with IP, target kharej server, and pool configuration
        iran_node = {"ip": "192.0.2.10"}
        kharej_server = {"ip": "198.51.100.22"}
        configured_client_ports = ["2222", "8443"]
        pool_config = {
            "camouflage": {
                "server_name": "tunnel.test",
                "certificate": "/etc/ssl/certs/tunnel.crt",
                "key": "/etc/ssl/private/tunnel.key",
                "binary": "/tmp/waterwall-bin/Waterwall",
                "port": 443
            },
            "client_ports": configured_client_ports,
            "tunnel_port": 443
        }

        cfg = self.adapter.configure(iran_node, kharej_server, pool_config)
        self.assertEqual(cfg["engine"], "waterwall")
        self.assertTrue(re.fullmatch(r"ldw[0-9a-f]{16}", cfg["node_name"]))
        self.assertEqual(cfg["service_name"], f"{cfg['node_name']}.service")
        self.assertEqual(cfg["config_path"], f"/etc/vxlb/waterwall/{cfg['node_name']}.json")

        node = cfg["node"]
        service_name = cfg["service_name"]
        config_path = cfg["config_path"]
        systemd_unit = cfg["systemd_unit"]
        iran_chain = cfg["iran_chain"]

        # Verify loopback-only probe listener on independent port
        probe_listener = next(n for n in iran_chain["nodes"] if n["name"] == "tcp-udp-probe-listener")
        self.assertEqual(probe_listener["settings"]["address"], "127.0.0.1")
        self.assertEqual(probe_listener["settings"]["port"], cfg["probe_port"])
        self.assertNotIn(cfg["probe_port"], [int(p) for p in configured_client_ports])

        # Deploy the generated configuration and systemd unit files
        iran_ssh.write_file(config_path, json.dumps(iran_chain))
        iran_ssh.write_file(f"/etc/systemd/system/{service_name}", systemd_unit)
        kharej_ssh.write_file(f"/etc/systemd/system/{service_name}", systemd_unit)

        self.assertIn(config_path, iran_ssh.written_files)
        self.assertIn(f"/etc/systemd/system/{service_name}", iran_ssh.written_files)
        self.assertIn("ExecStart", systemd_unit)
        self.assertIn("Restart=", systemd_unit)

        # 3. Start using output of configure (testing both dict and service_name)
        ok_start, _ = self.adapter.start(iran_ssh, cfg)
        self.assertTrue(ok_start)
        expected_start = f"systemctl daemon-reload && systemctl enable {service_name} && systemctl restart {service_name}"
        self.assertIn(expected_start, iran_ssh.executed_commands)

        # 4. Status using output of configure
        status_info = self.adapter.status(iran_ssh, cfg)
        self.assertEqual(status_info["status"], "UP")
        self.assertEqual(status_info["service"], service_name)

        # 5. Probe using node and ports directly produced by configure()
        ports_to_probe = [int(p) for p in configured_client_ports]
        with patch.dict(os.environ, {"VX_LB_WATERWALL_PROBE_HELPER": HELPER_SCRIPT}):
            # Probe with explicit ports from configure
            probe_res = self.adapter.probe(iran_ssh, kharej_ssh, ports=ports_to_probe, node=node)
            self.assertTrue(probe_res["passed"], f"Probe failed: {probe_res}")
            self.assertIsNone(probe_res["error"])
            self.assertIsNotNone(probe_res["latency_ms"])

            # Probe with auto-resolved ports from node produced by configure
            probe_auto = self.adapter.probe({"ssh": iran_ssh, "node": node}, {"ssh": kharej_ssh})
            self.assertTrue(probe_auto["passed"])

        # 6. Modify & Rollback using the configured node in the pool
        pool_name = "pool_" + cfg["node_name"]
        pool_data = {
            "name": pool_name,
            "transport": "waterwall",
            "engine": "waterwall",
            "camouflage": pool_config["camouflage"],
            "kharej_server": kharej_server,
            "client_ports": configured_client_ports,
            "nodes": [node]
        }
        mock_db = {"pools": {pool_name: pool_data}}

        new_ports = ["9090", "9091"]
        with patch("core.waterwall.get_pools", return_value=mock_db["pools"]), \
             patch("core.waterwall.atomic_update", side_effect=lambda fn: fn(mock_db)), \
             patch("core.waterwall.connect", side_effect=[iran_ssh, kharej_ssh, iran_ssh, kharej_ssh]), \
             patch("core.waterwall.write"), \
             patch("core.waterwall.firewall"), \
             patch("core.waterwall.verify"), \
             patch("core.load_balancer.LoadBalancerManager.check_port_conflicts", return_value=(True, "")):

            # Modify ports to new ports
            ok_mod, msg_mod = self.adapter.modify(pool_name, {"ports": new_ports})
            self.assertTrue(ok_mod, msg_mod)
            self.assertEqual(mock_db["pools"][pool_name]["client_ports"], new_ports)

            # Rollback to original configured ports
            ok_rb, msg_rb = self.adapter.rollback(pool_name, {"ports": configured_client_ports})
            self.assertTrue(ok_rb, msg_rb)
            self.assertEqual(mock_db["pools"][pool_name]["client_ports"], configured_client_ports)

        # 7. Stop using output of configure
        ok_stop, _ = self.adapter.stop(iran_ssh, cfg)
        self.assertTrue(ok_stop)
        expected_stop = f"systemctl stop {service_name} && systemctl disable {service_name}"
        self.assertIn(expected_stop, iran_ssh.executed_commands)

        # 8. Clean using output of configure
        with patch("core.waterwall.clean") as mock_clean:
            ok_clean, msg_clean = self.adapter.clean(iran_ssh, cfg)
            self.assertTrue(ok_clean, msg_clean)
            mock_clean.assert_called_once_with(iran_ssh, node, iran=True)

    def test_adapter_install_failure_when_prereqs_missing(self):
        """Verify adapter.install fails when root or binary is missing."""
        mock_ssh_fail = LocalMockSSH(service_active=False)
        mock_ssh_fail.execute = MagicMock(return_value=(1, "", "binary not found"))
        ok_fail, msg_fail = self.adapter.install(mock_ssh_fail, "iran", {"camouflage": {"binary": "/nonexistent/Waterwall"}})
        self.assertFalse(ok_fail)
        self.assertIn("failed", msg_fail)

    def test_adapter_probe_failures_detected(self):
        """Verify adapter.probe detects service down, journal errors, and invalid arguments."""
        cfg = self.adapter.configure({}, {"ip": "198.51.100.22"}, {
            "camouflage": {"binary": "/tmp/waterwall-bin/Waterwall", "server_name": "tunnel.test", "port": 443},
            "client_ports": ["2222"]
        })
        node = cfg["node"]
        ports = [2222]

        # Case 1: Service inactive on Iran
        iran_down = LocalMockSSH(service_active=False)
        kharej_ok = LocalMockSSH(service_active=True)
        res_down = self.adapter.probe(iran_down, kharej_ok, ports=ports, node=node)
        self.assertFalse(res_down["passed"])
        self.assertIn("WaterWall service inactive", res_down["error"])

        # Case 2: Fatal error in journal
        iran_ok = LocalMockSSH(service_active=True)
        kharej_err = LocalMockSSH(service_active=True, journal_error="FATAL Router: unhandled error")
        res_err = self.adapter.probe(iran_ok, kharej_err, ports=ports, node=node)
        self.assertFalse(res_err["passed"])
        self.assertIn("WaterWall errors", res_err["error"])

        # Case 3: Invalid arguments / missing SSH sessions
        res_bad = self.adapter.probe("not-ssh", "not-ssh")
        self.assertFalse(res_bad["passed"])
        self.assertIn("requires", res_bad["error"])

    def test_adapter_modify_and_rollback_validation(self):
        """Verify adapter modify and rollback reject invalid parameters."""
        ok_bad, msg_bad = self.adapter.modify("pool_test", {"unsupported_key": 123})
        self.assertFalse(ok_bad)
        self.assertIn("only 'ports' supported", msg_bad)

        ok_rb_bad, msg_rb_bad = self.adapter.rollback("pool_test", {"other": 123})
        self.assertFalse(ok_rb_bad)
        self.assertIn("previous ports not provided", msg_rb_bad)

    def test_adapter_clean_error_handling(self):
        """Verify adapter.clean handles exceptions cleanly."""
        mock_ssh = LocalMockSSH(service_active=True)
        with patch("core.waterwall.clean", side_effect=RuntimeError("systemctl failure")):
            ok_fail, msg_fail = self.adapter.clean(mock_ssh, {"node_name": "ldw1234567812345678"})
            self.assertFalse(ok_fail)
            self.assertIn("systemctl failure", msg_fail)


class WaterWallRealBinaryExecutionTests(unittest.TestCase):
    """Real binary execution of WaterWall tunnel lifecycle and active probe verification.

    This suite executes the real WaterWall binary (/tmp/waterwall-bin/Waterwall),
    configures chains and core.json for both sides strictly using adapter.configure(),
    preserves active TLS 1.3 certificate verification (verify: True) by injecting
    the test root CA certificate into the binary's CA bundle,
    executes verification strictly through adapter.probe(...),
    and verifies that when the tunnel process is stopped while the Kharej backend remains alive,
    the probe strictly fails (fail-closed causality).
    """
    def setUp(self):
        from core.adapter_registry import get_adapter
        self.binary = "/tmp/waterwall-bin/Waterwall"
        self.unpacked_binary = "/tmp/Waterwall_unpacked"
        if not Path(self.binary).exists() or not Path(self.unpacked_binary).exists():
            raise unittest.SkipTest("WaterWall binary or unpacked binary not found")
        self.adapter = get_adapter("waterwall")

    @classmethod
    def _prepare_binary_with_ca(cls, unpacked_bin, ca_cert_path, target_bin_path):
        """Patch the first embedded CA root certificate in the unpacked binary with the given CA cert."""
        data = Path(unpacked_bin).read_bytes()
        target = b'##\n## Bundle of CA Root'
        idx = data.find(target)
        if idx == -1:
            raise ValueError(f"CA Root bundle marker not found in {unpacked_bin}")
        cert_start = data.find(b'-----BEGIN CERTIFICATE-----', idx)
        if cert_start == -1:
            raise ValueError(f"BEGIN CERTIFICATE not found after marker in {unpacked_bin}")
        cert_end = data.find(b'-----END CERTIFICATE-----', cert_start) + len(b'-----END CERTIFICATE-----')
        orig_len = cert_end - cert_start

        ca_data = Path(ca_cert_path).read_bytes()
        diff = orig_len - len(ca_data)
        if diff < 0:
            raise ValueError(f"CA certificate ({len(ca_data)} bytes) exceeds slot ({orig_len} bytes)")

        new_block = ca_data + (b'\n' + (b'#' * (diff - 1)) if diff > 0 else b'')
        assert len(new_block) == orig_len, f"Block length mismatch: {len(new_block)} != {orig_len}"

        new_data = data[:cert_start] + new_block + data[cert_end:]
        target_path = Path(target_bin_path)
        target_path.write_bytes(new_data)
        target_path.chmod(0o755)
        return str(target_path)

    def _generate_ca_and_cert(self, tmpdir, domain="tunnel.test"):
        ca_key = tmpdir / "ca.key"
        ca_cert = tmpdir / "ca.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(ca_key), "-out", str(ca_cert),
             "-days", "1", "-subj", "/CN=WaterWallTestRootCA"],
            check=True, capture_output=True
        )

        server_key = tmpdir / "server.key"
        server_csr = tmpdir / "server.csr"
        server_cert = tmpdir / "server.pem"
        subprocess.run(
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(server_key), "-out", str(server_csr),
             "-subj", f"/CN={domain}"],
            check=True, capture_output=True
        )

        ext_file = tmpdir / "server.ext"
        ext_file.write_text(f"subjectAltName=DNS:{domain}\n")

        subprocess.run(
            ["openssl", "x509", "-req", "-in", str(server_csr),
             "-CA", str(ca_cert), "-CAkey", str(ca_key),
             "-CAcreateserial", "-out", str(server_cert),
             "-days", "1", "-extfile", str(ext_file)],
            check=True, capture_output=True
        )
        return ca_cert, server_cert, server_key

    def test_real_binary_probe_and_fail_closed_on_tunnel_stop(self):
        """Execute real WaterWall processes from configure() output with active TLS verify, pass adapter.probe, and verify fail-closed causality."""
        with tempfile.TemporaryDirectory(prefix="vxlb-ww-real-") as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            ca_cert, server_cert, server_key = self._generate_ca_and_cert(tmpdir, domain="tunnel.test")

            # Patch Iran binary with test CA certificate to preserve TLS verification active (verify: True)
            iran_binary = self._prepare_binary_with_ca(self.unpacked_binary, ca_cert, tmpdir / "Waterwall_iran")

            outer_port = socket_probe()
            client_port = socket_probe()
            probe_ingress_port = socket_probe()
            probe_backend_port = socket_probe()
            backend_port = socket_probe()

            iran_node = {
                "ip": "127.0.0.1",
                "waterwall": {
                    "probe_port": probe_ingress_port,
                    "probe_backend_port": probe_backend_port,
                    "backend_port": backend_port
                }
            }
            kharej_server = {"ip": "127.0.0.1"}
            pool_config = {
                "tunnel_port": outer_port,
                "client_ports": [str(client_port)],
                "probe_port": probe_ingress_port,
                "probe_backend_port": probe_backend_port,
                "backend_port": backend_port,
                "camouflage": {
                    "server_name": "tunnel.test",
                    "certificate": str(server_cert),
                    "key": str(server_key),
                    "port": outer_port,
                    "binary": self.binary
                }
            }

            # 1. Generate full configurations via adapter
            cfg = self.adapter.configure(iran_node, kharej_server, pool_config)
            self.assertEqual(cfg["probe_ingress_port"], probe_ingress_port)
            self.assertEqual(cfg["probe_backend_port"], probe_backend_port)
            self.assertNotEqual(probe_ingress_port, probe_backend_port)
            self.assertNotEqual(probe_ingress_port, client_port)
            self.assertNotEqual(probe_backend_port, client_port)

            iran_chain = cfg["iran_chain"]
            kharej_chain = cfg["kharej_chain"]

            # Verify probe listener is strictly loopback (127.0.0.1) on probe_ingress_port
            probe_listener = next(n for n in iran_chain["nodes"] if n["name"] == "tcp-udp-probe-listener")
            self.assertEqual(probe_listener["settings"]["address"], "127.0.0.1")
            self.assertEqual(probe_listener["settings"]["port"], probe_ingress_port)

            # Verify probe destination is configured to probe_backend_port
            probe_vless = next(n for n in iran_chain["nodes"] if n["name"] == "tcp-vless-client-probe")
            self.assertEqual(probe_vless["settings"]["port"], probe_backend_port)

            # Ensure TLS verification remains strictly ACTIVE (verify: True)
            tls_clients = [n for n in iran_chain["nodes"] if n["type"] == "TlsClient"]
            self.assertTrue(len(tls_clients) > 0)
            for tc in tls_clients:
                self.assertEqual(tc["settings"]["verify"], True, "TLS verification must remain active")

            iran_chain_file = tmpdir / "iran_chain.json"
            kharej_chain_file = tmpdir / "kharej_chain.json"
            iran_core_file = tmpdir / "iran_core.json"
            kharej_core_file = tmpdir / "kharej_core.json"

            iran_chain_file.write_text(json.dumps(iran_chain, indent=2))
            kharej_chain_file.write_text(json.dumps(kharej_chain, indent=2))

            iran_core = dict(cfg["iran_core_config"])
            iran_core["configs"] = [str(iran_chain_file)]
            iran_core["log"] = {"path": str(tmpdir / "iran_log"), "level": "debug"}
            (tmpdir / "iran_log").mkdir(exist_ok=True)
            iran_core_file.write_text(json.dumps(iran_core, indent=2))

            kharej_core = dict(cfg["kharej_core_config"])
            kharej_core["configs"] = [str(kharej_chain_file)]
            kharej_core["log"] = {"path": str(tmpdir / "kharej_log"), "level": "debug"}
            (tmpdir / "kharej_log").mkdir(exist_ok=True)
            kharej_core_file.write_text(json.dumps(kharej_core, indent=2))

            kh_log = open(tmpdir / "kh.log", "w+")
            ir_log = open(tmpdir / "ir.log", "w+")

            kh_proc = subprocess.Popen([self.binary, f"--config:{kharej_core_file}"], stdout=kh_log, stderr=kh_log)
            ir_proc = subprocess.Popen([iran_binary, f"--config:{iran_core_file}"], stdout=ir_log, stderr=ir_log)

            app_backend = socket.socket()
            app_backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            app_backend.bind(('127.0.0.1', backend_port))
            app_backend.listen(1)

            try:
                time.sleep(0.5)
                self.assertIsNone(kh_proc.poll(), "Kharej WaterWall process failed to start")
                self.assertIsNone(ir_proc.poll(), "Iran WaterWall process failed to start")

                # 2. Setup SSH handles tracking actual process state (mock_tunnel=False to ensure packets traverse real binary)
                iran_ssh = LocalMockSSH(service_active=lambda: ir_proc.poll() is None, mock_tunnel=False)
                kharej_ssh = LocalMockSSH(service_active=lambda: kh_proc.poll() is None, mock_tunnel=False)

                # 3. Probe strictly through adapter.probe(...) with active TLS 1.3 verification
                res = self.adapter.probe(
                    {"ssh": iran_ssh, "node": cfg["node"]},
                    {"ssh": kharej_ssh},
                    node=cfg["node"]
                )
                self.assertTrue(res.get("passed"), f"Adapter probe failed through verified tunnel: {res.get('error')}")
                self.assertIsNone(res.get("error"))

                # 4. Causality Test: Stop the Iran tunnel process while keeping the Kharej backend ALIVE
                ir_proc.terminate()
                ir_proc.wait(timeout=2)
                time.sleep(0.3)

                # Verify Kharej application backend and Kharej tunnel remain alive
                self.assertIsNone(kh_proc.poll(), "Kharej WaterWall process must remain alive")
                with socket.socket() as probe_test_sock:
                    probe_test_sock.settimeout(1)
                    probe_test_sock.connect(('127.0.0.1', backend_port))

                # 5. Verify adapter.probe(...) strictly FAILS when tunnel is stopped
                res_fail_svc = self.adapter.probe(
                    {"ssh": iran_ssh, "node": cfg["node"]},
                    {"ssh": kharej_ssh},
                    node=cfg["node"]
                )
                self.assertFalse(res_fail_svc.get("passed"), "Adapter probe must fail when tunnel service is inactive")

                # Even if service monitoring was masked as active, packet traversal through dead tunnel fails closed
                iran_ssh_masked = LocalMockSSH(service_active=True, mock_tunnel=False)
                res_fail_net = self.adapter.probe(
                    {"ssh": iran_ssh_masked, "node": cfg["node"]},
                    {"ssh": kharej_ssh},
                    node=cfg["node"]
                )
                self.assertFalse(res_fail_net.get("passed"), "Adapter probe must fail when tunnel socket is dead")

            finally:
                app_backend.close()

                for proc in [ir_proc, kh_proc]:
                    if proc and proc.poll() is None:
                        proc.terminate()
                        proc.wait(timeout=2)

                kh_log.close()
                ir_log.close()


if __name__ == '__main__':
    unittest.main()





class CarrierMssTests(unittest.TestCase):
    def test_rules_are_scoped_and_cleanup_preserves_other_nodes(self):
        node = {'node_name': 'ldw' + 'a' * 16, 'waterwall': {'outer_port': 24443}}
        ssh = MagicMock()
        ssh.execute.return_value = (0, '', '')
        for iran, flag in ((True, '--dport'), (False, '--sport')):
            ssh.reset_mock()
            waterwall.firewall(ssh, node, ['18080'], iran)
            rules = [c.args[0] for c in ssh.execute.call_args_list if '-t mangle' in c.args[0]]
            self.assertEqual(len(rules), 1)
            self.assertIn(flag + ' 24443', rules[0])
            self.assertIn('--set-mss 1360', rules[0])
            self.assertIn('--comment ' + node['node_name'], rules[0])
        marker = node['node_name']
        own = f'-A OUTPUT -p tcp --sport 24443 -m comment --comment {marker} -j TCPMSS --set-mss 1360'
        foreign = '-A OUTPUT -p tcp -m comment --comment another-node -j TCPMSS --set-mss 1360'
        def execute(cmd, **kwargs):
            return (0, own + '\n' + foreign, '') if cmd.endswith('-S OUTPUT') else (0, '', '')
        ssh.reset_mock()
        ssh.execute.side_effect = execute
        waterwall.firewall(ssh, node, [], False, remove=True)
        deleted = [c.args[0] for c in ssh.execute.call_args_list if '-D OUTPUT' in c.args[0]]
        self.assertEqual(len(deleted), 1)
        self.assertIn(marker, deleted[0])
        self.assertNotIn('another-node', deleted[0])
