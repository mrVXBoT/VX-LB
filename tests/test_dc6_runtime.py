"""DC6's three carriers require actual deployment and checked data before readiness."""
import copy
from unittest.mock import MagicMock, patch
import pytest
from core.dc6_adapter import DC6Adapter
from core import dc6_runtime as runtime
from core import dc6_firewall_agent as firewall


@pytest.mark.parametrize('carrier', ['ip6gre', 'ip6ip6', 'sit'])
def test_real_kernel_commands_and_private_families(carrier):
    addresses = ('192.0.2.1','192.0.2.2') if carrier=='sit' else ('2001:db8::1','2001:db8::2')
    conf = DC6Adapter().configure({'ip': addresses[0]}, {'ip': addresses[1]}, {'carrier_type': carrier})
    unit = conf['iran_service_unit']
    assert conf['mtu'] == 1280 and conf['mss_clamp'] == 1220
    assert unit.index('ip link set '+conf['interface']+' up') < unit.index('ip -6 route replace')
    assert 'ExecStartPre=' in unit and 'ExecStopPost=' in unit
    if carrier=='sit':
        assert 'mode sit local 192.0.2.1 remote 192.0.2.2 ttl 64' in unit
        assert conf['private_addressing']['iran_ipv4'] is None
        assert conf['address_families']['internal'] == ['ipv6']
    elif carrier=='ip6ip6':
        assert conf['private_addressing']['iran_ipv4'] is None
        assert conf['address_families']['internal'] == ['ipv6']
        assert 'ip -6 tunnel add' in unit and 'mode ip6ip6' in unit
        assert 'encaplimit none' in unit
    else:
        assert 'type ip6gre' in unit and 'encaplimit none' in unit
    for role in ['iran','kharej']:
        for tool, table, chain, rule in firewall.rules(conf[role+'_firewall']):
            assert 'ldbp-dc6:'+conf['interface'] in rule
            if table=='mangle':assert rule[-1] == '1220'


@pytest.mark.parametrize('carrier,addresses', [('sit',('2001:db8::1','2001:db8::2')),('ip6gre',('192.0.2.1','192.0.2.2')),('ip6ip6',('192.0.2.1','192.0.2.2'))])
def test_wrong_outer_family_rejected_before_any_service(carrier, addresses):
    with pytest.raises(ValueError):
        DC6Adapter().configure({'ip':addresses[0]}, {'ip':addresses[1]}, {'carrier_type':carrier})


@pytest.mark.parametrize('probe_pass,cleanup_fails', [(True,False),(False,False),(False,True)])
def test_large_data_challenge_and_cleanup_ownership(probe_pass, cleanup_fails):
    state = {'pools': {}}
    source, target = {'ip':'2001:db8::1'}, {'ip':'2001:db8::2'}
    real = DC6Adapter()
    adapter = MagicMock()
    adapter.install.return_value = (True,'ready')
    adapter.configure.side_effect = real.configure
    adapter.start.return_value = (True,'started')
    ssh = MagicMock()
    ssh.execute.return_value = (0,'','')
    def publish(path, text):
        assert state['pools']['qa']['nodes'][0]['provisioning'] is True
        return True
    ssh.write_file.side_effect = publish
    with patch('core.storage.get_pools', side_effect=lambda: state['pools']), \
         patch('core.storage.save_pool', side_effect=lambda name,pool: state['pools'].__setitem__(name,copy.deepcopy(pool))), \
         patch('core.storage.atomic_update', side_effect=lambda update: update(state)), \
         patch('core.load_balancer.LoadBalancerManager.check_port_conflicts', return_value=(True,'')), \
         patch('core.adapter_registry.get_adapter', return_value=adapter), \
         patch.object(runtime,'connect',return_value=ssh), \
         patch('core.private_link_health.probe_pair', side_effect=None if probe_pass else RuntimeError('large TCP failed'),return_value={'passed':True,'latency_ms':1}), \
         patch('core.native_ipv6_lifecycle.cleanup_endpoint', side_effect=RuntimeError('cleanup failed') if cleanup_fails else None):
        ok, message, pool = runtime.create('qa',target,[source],['443'])
    assert ok is probe_pass
    if probe_pass:
        assert pool['nodes'][0]['status']=='HEALTHY'
        assert pool['nodes'][0]['provisioning'] is False
    elif cleanup_fails:
        assert pool['nodes'][0]['status']=='FAILED'
        assert pool['nodes'][0]['provisioning'] is True
        assert 'cleanup failed' in pool['nodes'][0]['cleanup_error']
    else:
        assert pool['nodes']==[]


def test_firewall_cleanup_preserves_unrelated_ipv4_and_ipv6_rules(monkeypatch):
    calls=[]
    iface='dc6-0123456789'
    def command(tool,*args,**kwargs):
        calls.append((tool,*args))
        chain=args[-1]
        rows=f'-A {chain} -m comment --comment ldbp-dc6:{iface} -j ACCEPT\n-A {chain} -m comment --comment other-owner -j ACCEPT\n' if '-S' in args else ''
        return MagicMock(stdout=rows,returncode=0)
    monkeypatch.setattr(firewall,'command',command)
    firewall.remove({'interface':iface})
    deleted=[call for call in calls if '-D' in call]
    assert len(deleted)==6
    assert {call[0] for call in deleted}=={'iptables','ip6tables'}
    assert all('ldbp-dc6:'+iface in call and 'other-owner' not in call for call in deleted)
    assert not any('-F' in call or 'iptables-restore' in call for call in calls)


@pytest.mark.parametrize('carrier,addresses',[('sit',('2001:db8::1','2001:db8::2')),('ip6gre',('192.0.2.1','192.0.2.2'))])
def test_bad_address_family_never_saves_or_connects(carrier,addresses):
    with patch('core.storage.save_pool') as save,patch.object(runtime,'connect') as connect:
        ok,message,pool=runtime.create('qa',{'ip':addresses[1]},[{'ip':addresses[0]}],['443'],carrier=carrier)
    assert not ok and message and pool=={}
    save.assert_not_called()
    connect.assert_not_called()
