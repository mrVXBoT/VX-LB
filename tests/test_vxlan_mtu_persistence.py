"""Execute the real remote script against a sandboxed owned start script."""
import json
import subprocess
import sys
import pytest
from core.vxlan_adapter import VXLAN_MTU_SCRIPT


@pytest.mark.parametrize('bridge', [False, True])
def test_owned_mtu_changes_survive_service_restart(tmp_path, bridge):
    path = tmp_path / 'start.sh'
    text = '#!/bin/bash\nip link set dev vx-test mtu 1400\n'
    devices = ['vx-test']
    if bridge:
        devices.append('br-vx-test')
        text += 'ip link set dev br-vx-test mtu 1400\n'
    text += 'ip link set dev unrelated mtu 1500\n'
    path.write_text(text)
    path.chmod(0o755)
    for mtu in [1280, 1300, 1280]:
        result = subprocess.run([sys.executable, '-c', VXLAN_MTU_SCRIPT, str(path), str(mtu), json.dumps(devices)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        for device in devices:
            assert f'ip link set dev {device} mtu {mtu}' in path.read_text()
        assert 'ip link set dev unrelated mtu 1500' in path.read_text()
        assert path.stat().st_mode & 0o777 == 0o755
        assert sorted(p.name for p in tmp_path.iterdir()) == ['start.sh']


def test_missing_owned_directive_preserves_original_script(tmp_path):
    path = tmp_path / 'start.sh'
    original = '#!/bin/bash\nip link set dev unrelated mtu 1500\n'
    path.write_text(original)
    result = subprocess.run([sys.executable, '-c', VXLAN_MTU_SCRIPT, str(path), '1280', '["vx-test"]'], capture_output=True)
    assert result.returncode != 0
    assert path.read_text() == original


def test_partial_vxlan_update_preserves_inventory_and_restores_attempted_hosts(monkeypatch):
    from unittest.mock import MagicMock
    from core import vxlan_adapter as vxlan
    from core import kernel_relay_ports, private_link_health
    source, target = MagicMock(), MagicMock()
    node = {'ip': '192.0.2.1', 'vxlan': {'iface': 'vx-test', 'local_private': '10.204.1.1', 'remote_private': '10.204.1.2', 'mtu': 1280}}
    state = {'pools': {'qa': {'kharej_server': {'ip': '192.0.2.2'}, 'vxlan_mtu': 1280, 'nodes': [node]}}}
    calls = []
    def apply(ssh, node, mtu):
        calls.append((ssh, mtu))
        if ssh is target and mtu == 1288:
            raise RuntimeError('could not persist target MTU')
    sessions = iter([target, source])
    monkeypatch.setattr(vxlan, 'get_pools', lambda: state['pools'])
    monkeypatch.setattr(vxlan, 'atomic_update', lambda fn: fn(state))
    monkeypatch.setattr(vxlan, 'connect', lambda node: next(sessions))
    monkeypatch.setattr(vxlan, '_set_vxlan_endpoint_mtu', apply)
    monkeypatch.setattr(kernel_relay_ports, 'node_credentials', lambda node: node)
    monkeypatch.setattr(private_link_health, 'probe_pair', lambda *args: {'passed': True})
    ok, message = vxlan.change_mtu('qa', 1288)
    assert not ok
    assert 'restored MTU 1280' in message
    assert calls == [(source, 1288), (target, 1288), (target, 1280), (source, 1280)]
    assert state['pools']['qa']['vxlan_mtu'] == node['vxlan']['mtu'] == 1280
