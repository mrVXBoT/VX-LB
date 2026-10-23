import json
from unittest.mock import MagicMock,patch
import pytest
from core import paqet_probe as probe

NODE={'node_name':'node','paqet':{'probe_port':43000,'probe_backend_port':44000}}

def test_forwarding_includes_tcp_and_optional_loopback_probe():
    rules=probe.forward_rules(NODE,'192.0.2.2',['443'])
    assert [r['protocol'] for r in rules]==['tcp','tcp','udp']
    assert rules[0] == {'listen':'0.0.0.0:443','target':'192.0.2.2:443','protocol':'tcp'}
    assert all(r['listen']=='127.0.0.1:43000' and r['target']=='192.0.2.2:44000' for r in rules[1:])
    with pytest.raises(ValueError):probe.forward_rules(NODE,'192.0.2.2',['43000'])

@pytest.mark.parametrize('code,protocols,passed',[(0,['tcp','udp'],True),(1,['tcp','udp'],False),(0,['tcp'],False)])
def test_probe_uses_forwarded_ingress_and_closes_responder(code,protocols,passed):
    ir=MagicMock();kh=MagicMock();kh.ip='192.0.2.2';stdout=MagicMock();stdout.readline.side_effect=['44000\n','44000\n','44000\n','44000\n'];kh.client.exec_command.return_value=(None,stdout,None)
    ir.execute.return_value=(code,json.dumps({'passed':True,'latency_ms':3,'protocols':protocols}),'')
    if passed:assert probe.verify_data(ir,kh,NODE)['latency_ms']==3
    else:
        with pytest.raises(RuntimeError):probe.verify_data(ir,kh,NODE)
    assert '127.0.0.1 43000' in ir.execute.call_args.args[0]
    # ECHO must bind to all interfaces (0.0.0.0) so the Paqet raw-packet
    # server can deliver to the real server IP, not loopback only.
    assert '0.0.0.0' in kh.client.exec_command.call_args.args[0]
    stdout.channel.close.assert_called_once()


def test_active_systemd_without_challenge_is_not_verification():
    from core.paqet_adapter import verify
    ir=MagicMock();kh=MagicMock();ir.execute.side_effect=[(0,'active\n',''),(0,'','')];kh.execute.side_effect=[(0,'active\n',''),(0,'','')]
    with patch.object(probe,'verify_data',side_effect=RuntimeError('no data')):
        with pytest.raises(RuntimeError):verify(ir,kh,NODE,[443])


def test_node_without_probe_route_can_change_ports_without_probe():
    from core import paqet_adapter as adapter
    pool={'nodes':[{'ip':'192.0.2.1','paqet':{},'node_name':'paq_n1'}],'kharej_server':{'ip':'192.0.2.2'},'client_ports':['443']}
    ssh=MagicMock(); ssh.execute=MagicMock(return_value=(0,'active\n',''))
    pa=MagicMock(); pa.deploy_client_node=MagicMock(return_value=(True,'ok')); pa.build_systemd_unit=MagicMock(return_value='unit'); pa.build_iptables_setup_commands=MagicMock(return_value=['true']); pa.build_persistence_unit=MagicMock(return_value=('u','s','unit','script')); pa._forward_listen_ports=MagicMock(return_value=[])
    with patch.object(adapter,'get_pools',return_value={'p':pool}),patch.object(adapter,'connect',return_value=ssh),patch.object(adapter,'atomic_update'), \
         patch.object(adapter,'verify') as verify,patch.object(adapter,'PaqetAdapter',return_value=pa):
        assert adapter.change_ports('p',['8443'])[0] is True
        verify.assert_called()


def test_carrier_port_conflict_is_rejected_before_configuration():
    node={'paqet':{'tunnel_port':29999,'probe_port':43000,'probe_backend_port':44000}}
    with pytest.raises(ValueError,match='raw Paqet carrier'):
        probe.forward_rules(node,'192.0.2.2',['29999'])


def test_port_allocator_skips_live_socket_and_excluded_port():
    import socket,subprocess
    class LocalSSH:
        def execute(self,command):
            result=subprocess.run(command,shell=True,capture_output=True,text=True,timeout=5)
            return result.returncode,result.stdout,result.stderr
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        free=probe.reserve_probe_port(LocalSSH(),[],preferred=port,bind_host='0.0.0.0')
        assert free!=port
    second=probe.reserve_probe_port(LocalSSH(),[free],preferred=free,bind_host='0.0.0.0')
    assert second!=free
