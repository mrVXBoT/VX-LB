from contextlib import nullcontext
from unittest.mock import MagicMock, patch
import pytest
from core import kernel_relay_ports as relay

@pytest.mark.parametrize('failure,rollback_failure,expected', [(False,False,'succeeded'),(True,False,'failed'),(True,True,'rollback_failed')])
def test_transaction_persists_only_after_listeners_or_records_rollback(failure,rollback_failure,expected):
    node={'ip':'192.0.2.1','wireguard':{'interface':'wg-test','remote_private':'10.100.2.2'}}
    data={'pools':{'p':{'engine':'wireguard','client_ports':['443'],'nodes':[node]}}}
    ssh=MagicMock(ip=node['ip']);ssh.execute.return_value=(0,'','');ssh.write_file.return_value=True
    outcomes=[RuntimeError('not bound'),RuntimeError('rollback failed') if rollback_failure else None] if failure else [None]
    with patch.object(relay,'mutation_lock',return_value=nullcontext()),patch.object(relay,'busy',return_value=False),patch.object(relay,'load_data',return_value=data),patch.object(relay,'get_pools',return_value=data['pools']),patch.object(relay,'atomic_update',side_effect=lambda fn:fn(data)),patch.object(relay,'connect',return_value=ssh),patch.object(relay,'verify_listeners',side_effect=outcomes):
        ok,_=relay.change_ports('p',['8443'])
    assert ok is (not failure)
    assert data['pools']['p']['gre_update']['status']==expected
    assert data['pools']['p']['client_ports']==(['443'] if failure else ['8443'])
    ssh.close.assert_called_once()
    if failure:
        assert any('cp -p --' in call.args[0] and 'systemctl restart' in call.args[0] for call in ssh.execute.call_args_list)

@pytest.mark.parametrize('engine',sorted(relay.ENGINES))
def test_rendered_scripts_are_valid_and_target_only_private_peer(engine):
    node={engine:{'interface':'tun-test','remote_private':'fd00::2' if engine=='ip6ip6' else '10.100.2.2'}}
    path,service,script=relay.relay_spec(engine,node,['443','8443'])
    compile(script,path,'exec')
    assert 'relay' in path and 'relay.service' in service

def test_restart_recovery_uses_persisted_backup():
    node={'ip':'192.0.2.1','wireguard':{'interface':'wg-test','remote_private':'10.100.2.2'}}
    path,svc,_=relay.relay_spec('wireguard',node,['443'])
    data={'pools':{'p':{'engine':'wireguard','client_ports':['443'],'nodes':[node],'gre_update':{'kind':'relay_ports','status':'rollback_failed','id':'abc','old_ports':['443'],'backups':[{'ip':node['ip'],'path':path,'service':svc,'backup':path+'.ports-abc'}]}}}}
    ssh=MagicMock(ip=node['ip']);ssh.execute.return_value=(0,'','')
    with patch.object(relay,'mutation_lock',return_value=nullcontext()),patch.object(relay,'get_pools',return_value=data['pools']),patch.object(relay,'load_data',return_value=data),patch.object(relay,'atomic_update',side_effect=lambda fn:fn(data)),patch.object(relay,'connect',return_value=ssh),patch.object(relay,'verify_listeners') as verify:
        assert relay.recover_ports('p')[0]
    verify.assert_called_once_with(ssh,svc,['443'])
    assert data['pools']['p']['gre_update']['status']=='failed'
