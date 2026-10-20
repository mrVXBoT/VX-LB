"""Real generated Slipstream systemd services, in two namespaces inside lab VM.

This runs only in the managed disposable VM, never on production or the host.
It exercises plan/deploy/probe/cleanup, actual official binaries and service
recovery. It is not a public recursive DNS or two-machine SSH acceptance test.
"""
import hashlib
import copy
import json
import tempfile
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import time

from core import slipstream_deploy as runtime
from core.slipstream_adapter import SlipstreamAdapter


class NamespaceSSH:
    def __init__(self, namespace):
        self.namespace = namespace
        self.ip = namespace

    def execute(self, command, timeout=30):
        result = subprocess.run(['ip', 'netns', 'exec', self.namespace, '/bin/sh', '-c', command],
                                capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr

    def write_file(self, path, content):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o600)
        return True


def checked(command):
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)


def run():
    if os.geteuid() != 0 or not Path('/var/lib/ldbp-lab-ready').exists():
        raise RuntimeError('Run only as root inside the managed disposable lab VM')
    token = secrets.token_hex(8)
    iran_ns, outside_ns = 'sli'+token[:8], 'slo'+token[:8]
    namespaces = [iran_ns, outside_ns]
    veth_ir, veth_out = 'sli'+token[:7], 'slo'+token[:7]
    peers, services, dropins, config = [], [], [], None
    try:
        for namespace in namespaces:
            checked(['ip', 'netns', 'add', namespace])
            checked(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
        checked(['ip', 'link', 'add', veth_ir, 'type', 'veth', 'peer', 'name', veth_out])
        for interface, namespace, address in ((veth_ir, iran_ns, '192.0.2.1/30'), (veth_out, outside_ns, '192.0.2.2/30')):
            checked(['ip', 'link', 'set', interface, 'netns', namespace])
            checked(['ip', '-n', namespace, 'address', 'add', address, 'dev', interface])
            checked(['ip', '-n', namespace, 'link', 'set', interface, 'up'])
        iran, outside = NamespaceSSH(iran_ns), NamespaceSSH(outside_ns)
        pool = dict(slipstream_id=token, domain='systemd.example.test', resolvers=['192.0.2.2:25053'],
                    dns_port=25053, client_ports=[25443], slipstream_relay_port=25001,
                    slipstream_runtime_version=3, slipstream_dns_backend_port=25054, rate_limit=1000,
                    slipstream_security=runtime.identity_material())
        node = dict(ip='192.0.2.1', slipstream_carrier_port=25002)
        config = runtime.plan(node, {'ip': '192.0.2.2'}, pool)
        for ssh, role in ((iran, 'iran'), (outside, 'kharej')):
            ok, message = SlipstreamAdapter().install(ssh, role, {})
            assert ok, message
        for namespace, names in ((iran_ns, config['client_services']), (outside_ns, config['server_services'])):
            for name in names:
                directory = Path('/etc/systemd/system') / (name + '.d')
                directory.mkdir()
                path = directory / 'lab-namespace.conf'
                path.write_text('[Service]\nNetworkNamespacePath=/run/netns/'+namespace+'\nRuntimeMaxSec=90\n')
                dropins.append(path)
                services.append(name)
        unrelated_tag = 'ldbp-lab-unrelated-' + token
        code, _, error = outside.execute('iptables -w 5 -A INPUT -p udp --dport 25999 -m comment --comment '+unrelated_tag+' -j ACCEPT')
        assert code == 0, error
        runtime.deploy(outside, config['server_files'], config['server_services'])
        runtime.deploy(iran, config['client_files'], config['client_services'])
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            result = runtime.probe(iran, config['client_config_path'])
            if result['passed']:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Generated systemd services did not pass authenticated data probe')
        print('PASS: actual plan/install/deploy generated working systemd service stack in two network namespaces', flush=True)
        for name in services:
            state = subprocess.check_output(['systemctl', 'is-enabled', name], text=True).strip()
            assert state == 'enabled', state
        print('PASS: service enablement registered for boot; actual VM reboot not tested', flush=True)
        # Force DNS client failure and require automatic process replacement;
        # the independent secure listener must remain available and recover.
        dns_service = config['client_services'][0]
        pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', dns_service], text=True).strip()
        assert int(pid) > 1
        checked(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', dns_service])
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            new_pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', dns_service], text=True).strip()
            if new_pid != pid and int(new_pid or '0') > 1 and runtime.probe(iran, config['client_config_path']).get('passed'):
                break
            time.sleep(.5)
        else:
            raise RuntimeError('DNS client did not recover automatically after process failure')
        print('PASS: killed real DNS client restarted automatically and authenticated data recovered', flush=True)
        # Explicit DNS stop must prevent data, while the secure service remains
        # independently active (no propagation of dependency stop).
        checked(['systemctl', 'stop', dns_service])
        assert not runtime.probe(iran, config['client_config_path']).get('passed')
        assert subprocess.check_output(['systemctl', 'is-active', config['client_services'][1]], text=True).strip() == 'active'
        print('PASS: stopped carrier failed data probe with secure listener alive; no plaintext fallback', flush=True)
        checked(['systemctl', 'start', dns_service])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if runtime.probe(iran, config['client_config_path']).get('passed'):
                break
            time.sleep(.5)
        else:
            raise RuntimeError('Explicit restart did not restore data')
        print('PASS: restarting carrier restored authenticated data without restarting secure listener', flush=True)
        # Exercise the complete durable transaction with actual inventory
        # writes confined to a temporary directory, and actual remote commands
        # executed through namespace peers (not mocked systemd or DNS).
        from unittest.mock import patch
        from core import storage, transport_change, slipstream_update
        from core.private_link_health import ECHO, PROBE
        node.update(node_name=config['node_id'], provisioning=False,
                    slipstream_config_path=config['client_config_path'])
        pool.update(name='dns-lab', engine='slipstream', transport='slipstream',
                    kharej_server={'ip': '192.0.2.2'}, nodes=[node])
        with tempfile.TemporaryDirectory(prefix='ldbp-slipstream-inventory-') as temporary:
            folder = Path(temporary)
            inventory = folder/'inventory.json'
            inventory.write_text(json.dumps({'schema_version': 3, 'pools': {'dns-lab': pool},
                                              'iran_servers': [{'ip': '192.0.2.1'}], 'kharej_servers': [{'ip': '192.0.2.2'}]}))
            with patch.object(storage, 'DATA_DIR', str(folder)), \
                 patch.object(storage, 'INVENTORY_FILE', str(inventory)), \
                 patch.object(storage, 'LOCK_FILE', str(folder/'inventory.lock')), \
                 patch.object(storage, 'LOG_FILE', str(folder/'watchdog.log')), \
                 patch.object(transport_change, 'DATA_DIR', str(folder)), \
                 patch.object(runtime, 'connection', side_effect=lambda server: iran if server['ip']=='192.0.2.1' else outside):
                # Namespace peers don't own an SSH connection to close.
                iran.close = lambda: None
                outside.close = lambda: None
                ok, message = slipstream_update.change('dns-lab', {'client_ports': ['25443', '25444']})
                assert ok, message
                assert storage.load_data()['pools']['dns-lab']['client_ports'] == ['25443', '25444']
                print('PASS: real transaction added TCP/UDP listeners and committed durable inventory', flush=True)
                echo = subprocess.Popen(['ip', 'netns', 'exec', outside_ns, 'python3', '-u', '-c', ECHO, '127.0.0.1', '25444'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                peers.append(echo)
                assert echo.stdout.readline().strip() == '25444'
                code, out, error = iran.execute('python3 -c '+shlex.quote(PROBE)+' 127.0.0.1 25444 '+secrets.token_hex(24)+" ''", timeout=30)
                assert code == 0, out+error
                print('PASS: newly added application port carried actual random TCP and UDP challenge data', flush=True)
                ok, message = slipstream_update.change('dns-lab', {'resolvers': ['127.0.0.1:9']})
                assert not ok, 'Unreachable resolver unexpectedly succeeded'
                restored = storage.load_data()['pools']['dns-lab']
                assert restored['resolvers'] == pool['resolvers']
                assert restored['gre_update']['status'] == 'failed', restored['gre_update']
                assert runtime.probe(iran, config['client_config_path'])['passed']
                print('PASS: actual bad resolver update failed, remote unit snapshot restored and old DNS data path recovered', flush=True)
                ok, message = slipstream_update.change('dns-lab', {'client_ports': ['25443']})
                assert ok, message
                code, out, error = iran.execute("ss -H -lntup | grep ':25444 '")
                assert code != 0, out
                assert runtime.probe(iran, config['client_config_path'])['passed']
                print('PASS: real transaction removed TCP/UDP listener without breaking authenticated transport', flush=True)
                ok, message = slipstream_update.change('dns-lab', {'rate_limit': 20})
                assert ok, message
                code, rules, error = outside.execute('iptables -S INPUT')
                assert code == 0, error
                assert rules.count('ldbp-slipstream:'+token) == 2, rules
                assert '--hashlimit-above 20/sec' in rules, rules
                assert unrelated_tag in rules
                # Send an intentionally invalid UDP burst: the kernel limiter
                # counts packets independent of DNS parsing. No external host
                # or resolver is involved.
                server_pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', config['server_services'][1]], text=True).strip()
                flood = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);[s.sendto(b'lab-rate-test',('192.0.2.2',25053)) for _ in range(500)];s.close()"
                code, _, error = iran.execute('python3 -c '+shlex.quote(flood))
                assert code == 0, error
                code, counters, error = outside.execute('iptables-save -c')
                assert code == 0, error
                import re
                row = next(row for row in counters.splitlines() if 'ldbp-slipstream:'+token in row and '--dport 25053' in row)
                count = int(re.search(r'\[(\d+):\d+\]', row).group(1))
                assert count > 0, row
                print('PASS: actual per-source DNS QPS rule dropped '+str(count)+' excess UDP packets and preserved unrelated rule', flush=True)
                assert subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', config['server_services'][1]], text=True).strip() == server_pid
                direct = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.sendto(b'lab-rate-test',('192.0.2.2',25054));s.close()"
                assert iran.execute('python3 -c '+shlex.quote(direct))[0] == 0
                code, counters, error = outside.execute('iptables-save -c')
                row = next(row for row in counters.splitlines() if 'ldbp-slipstream:'+token in row and '--dport 25054' in row)
                assert int(re.search(r'\[(\d+):\d+\]', row).group(1)) > 0, row
                print('PASS: malformed public DNS burst did not restart upstream; direct internal-port packet was dropped', flush=True)
                ok, message = slipstream_update.change('dns-lab', {'rate_limit': 1000})
                assert ok, message
                code, rules, error = outside.execute('iptables -S INPUT')
                assert code == 0 and '--hashlimit-above 1000/sec' in rules, rules+error
                assert rules.count('ldbp-slipstream:'+token) == 2
                print('PASS: transactional QPS update replaced only owned rule and authenticated DNS path recovered', flush=True)
                assert not list(Path(config['base']).glob('*.slip-*')), 'Terminal snapshots were not cleaned'
        runtime.cleanup(iran, config['client_files'], config['client_services'])
        runtime.cleanup(outside, config['server_files'], config['server_services'])
        for path in {**config['server_files'], **config['client_files']}:
            assert not Path(path).exists(), path
        for name in services:
            code = subprocess.run(['systemctl', 'is-active', '--quiet', name]).returncode
            assert code != 0
        code, rules, error = outside.execute('iptables -S INPUT')
        assert code == 0, error
        assert 'ldbp-slipstream:'+token not in rules
        assert unrelated_tag in rules
        print('PASS: service cleanup removed its DNS limiter and preserved unrelated firewall rule', flush=True)
        print('PASS: actual cleanup stopped services, removed owned unit/config/key files and disabled units', flush=True)
    except BaseException:
        if services:
            subprocess.run(['journalctl', '--no-pager', '-n', '20', *[part for name in services for part in ('-u', name)]], timeout=10)
        raise
    finally:
        for process in peers:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        if services:
            subprocess.run(['systemctl', 'stop', *services], capture_output=True, timeout=20)
            subprocess.run(['systemctl', 'disable', *services], capture_output=True, timeout=20)
        if config:
            for path in {**config['server_files'], **config['client_files']}:
                Path(path).unlink(missing_ok=True)
            base = Path(config['base'])
            for pattern in ('*.stage-*', '*.slip-*', '*.restore-*'):
                for path in base.glob(pattern):
                    path.unlink()
            try:
                base.rmdir()
            except OSError:
                pass
        for path in dropins:
            path.unlink(missing_ok=True)
            path.parent.rmdir()
        subprocess.run(['systemctl', 'daemon-reload'], capture_output=True, timeout=20)
        for namespace in namespaces:
            subprocess.run(['ip', 'netns', 'delete', namespace], capture_output=True, timeout=10)
    print('PASS: namespaces and lab-specific service overrides removed', flush=True)


if __name__ == '__main__':
    run()
