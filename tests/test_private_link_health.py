"""Probe protocol tests use localhost only; these do not certify any tunnel engine."""
import json
import subprocess
import sys
from unittest.mock import MagicMock,patch
import pytest
from core import private_link_health as health


def test_tcp_udp_probe_scripts_echo_real_bytes_on_localhost():
    # Test the actual scripts, without claiming WireGuard/GRE/VXLAN integration.
    responder=subprocess.Popen([sys.executable,'-u','-c',health.ECHO,'127.0.0.1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        port=responder.stdout.readline().strip()
        assert port.isdigit()
        result=subprocess.run([sys.executable,'-c',health.PROBE,'127.0.0.1',port,'nonce-test',''],capture_output=True,text=True,timeout=10)
        assert result.returncode==0,result.stderr
        assert json.loads(result.stdout)['protocols']==['tcp','udp']
    finally:
        responder.stdin.close()
        responder.wait(timeout=3)

def test_probe_retries_transient_bringup_errors_until_ready():
    """First connects to a fresh kernel tunnel can hit transient OSErrors while
    ARP/peers resolve; the probe must retry instead of failing immediately."""
    import socket as _socket
    # Reserve a port that is guaranteed to refuse connections until the
    # (delayed) responder finally binds to it.
    with _socket.socket() as shoe:
        shoe.bind(('127.0.0.1', 0))
        shoe.listen(1)
        port = shoe.getsockname()[1]
    delayed_responder = subprocess.Popen(
        ['sh', '-c', 'sleep 2; exec "$1" -u -c "$2" "$3" "$4"', 'sh',
         sys.executable, health.ECHO, '127.0.0.1', str(port)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        # No responder yet: the old probe code died instantly with OSError
        # ECONNREFUSED; the retry-capable probe waits for the responder.
        result = subprocess.run(
            [sys.executable, '-c', health.PROBE, '127.0.0.1', str(port), 'nonce-test', ''],
            capture_output=True, text=True, timeout=20,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['protocols'] == ['tcp', 'udp']
    finally:
        delayed_responder.stdin.close()
        delayed_responder.wait(timeout=3)
        delayed_responder.kill()


@pytest.mark.parametrize('path_pass,relay_pass,destination_pass,expected',[(False,True,True,'DOWN'),(True,True,False,'DOWN'),(True,False,True,'DOWN'),(True,True,True,'HEALTHY')])
def test_listener_alone_can_never_make_node_healthy(path_pass,relay_pass,destination_pass,expected):
    node={'ip':'192.0.2.1','engine':'wireguard','wireguard':{'interface':'wg-test','local_private':'10.1.0.1','remote_private':'10.1.0.2'}}
    ir=MagicMock();kh=MagicMock();ir.execute.return_value=(0,json.dumps({'443':{'relay_owned':relay_pass,'destination_tcp':destination_pass}}),'')
    with patch.object(health,'get_pools',return_value={'p':{'kharej_server':{'ip':'192.0.2.2'}}}),patch.object(health,'node_credentials',side_effect=lambda n:n),patch.object(health,'connect',side_effect=[ir,kh]),patch.object(health,'probe_pair',side_effect=None if path_pass else RuntimeError('path failed'),return_value={'passed':True,'latency_ms':2}):
        status,_,details=health.health('p',node,['443'])
    assert status==expected
    if expected=='HEALTHY':assert details['443']['udp_application']=='UNVERIFIED'
    ir.close.assert_called_once();kh.close.assert_called_once()


def test_probe_failure_closes_responder_channel():
    target=MagicMock();source=MagicMock();stdout=MagicMock();stdout.readline.return_value='42891\n';target.client.exec_command.return_value=(None,stdout,None);source.execute.return_value=(1,'','failed')
    with pytest.raises(RuntimeError):health.probe_direction(source,target,'10.1.0.2','wg-test')
    stdout.channel.close.assert_called_once()


def test_geneve_probe_cannot_succeed_without_connected_endpoints():
    from core.geneve import verify_geneve_tunnel
    assert verify_geneve_tunnel({}, {})==(False,None)
    assert verify_geneve_tunnel(object(),object())==(False,None)


def test_relay_port_match_is_exact():
    rows=['tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("relay",pid=9,fd=3))',
          'udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("relay",pid=9,fd=4))',
          'tcp LISTEN 0 128 [::]:80 [::]:* users:(("relay",pid=9,fd=5))']
    def owns(port, proto):
        def port_of(addr):
            text=addr.rsplit(':',1)[-1]
            return text if text.isdigit() else ''
        return any(len(parts)>=5 and parts[0]==proto and port_of(parts[4])==str(port) and 'pid=9,' in row for row in rows for parts in [row.split()])
    assert owns(8080,'tcp')
    assert owns(80,'tcp')
    assert not any(row.split()[4].rsplit(':',1)[-1]=='80' and '8080' in row.split()[4] for row in rows)
    assert not owns(443,'tcp')
    assert owns(443,'udp')


def test_ready_control_channel_stays_in_strict_dns_while_idle_does_not():
    from contextlib import nullcontext
    from core.watchdog import TelemetryWatchdog
    data={'cloudflare':{'enabled':True,'api_token':'test','zone_id':'zone','subdomain':'example.test'},
          'pools':{'p':{'dns_policy':'strict','nodes':[{'ip':'192.0.2.1'},{'ip':'192.0.2.2'},{'ip':'192.0.2.9'}],'client_ports':['443']}}}
    watchdog=TelemetryWatchdog()
    with patch('core.watchdog.load_data',return_value=data),patch('core.watchdog.routing_lock',side_effect=nullcontext),patch.object(watchdog,'analyze_node_health',side_effect=[('READY','control up',[],{}),('HEALTHY','flow',[],{}),('IDLE','no proof',[],{})]),patch('core.watchdog.CloudflareManager') as manager:
        manager.return_value.sync_subdomain.return_value={'added':[],'deleted':[],'kept':['192.0.2.1','192.0.2.2']}
        manager.return_value.record_snapshot.return_value={}
        watchdog.run_check_cycle()
    manager.return_value.sync_subdomain.assert_called_once_with('example.test',['192.0.2.1','192.0.2.2'],proxied=False,ttl=60)


def test_unmonitored_engine_is_not_scored_as_backpack():
    from core.watchdog import TelemetryWatchdog
    watchdog=TelemetryWatchdog()
    with patch.object(watchdog,'save_node_telemetry') as save:
        status,reason,_,_=watchdog.analyze_node_health('p',{'ip':'192.0.2.8','engine':'wireguard_hybrid'},['443'])
    assert status=='UNMONITORED'
    assert 'BackPack' in reason
    assert save.call_args.args[2]=='UNMONITORED'


def test_default_dns_policy_does_not_route_listener_only_idle_nodes():
    from contextlib import nullcontext
    from core.watchdog import TelemetryWatchdog
    data={'cloudflare':{'enabled':True,'api_token':'test','zone_id':'zone','subdomain':'example.test'},'pools':{'p':{'nodes':[{'ip':'192.0.2.1'}],'client_ports':['443']}}}
    watchdog=TelemetryWatchdog()
    with patch('core.watchdog.load_data',return_value=data),patch('core.watchdog.routing_lock',side_effect=nullcontext),patch.object(watchdog,'analyze_node_health',return_value=('IDLE','untested',[],{})),patch('core.watchdog.CloudflareManager') as manager:
        report=watchdog.run_check_cycle()
    manager.return_value.sync_subdomain.assert_not_called()
    assert report['pool_reports']['p']['dns_policy']=='strict'
    assert report['pool_reports']['p']['cloudflare_sync']['status']=='SUSPENDED_NO_HEALTHY_NODES'
