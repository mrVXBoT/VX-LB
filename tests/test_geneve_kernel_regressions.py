import json
from unittest.mock import MagicMock,patch
import pytest
from core import geneve_agent as agent

CONFIG={'owner':'ldbp-geneve-v1','role':'iran','interface':'gni1234','local':'192.0.2.1','remote':'192.0.2.2','private':'10.205.0.1','peer':'10.205.0.2','vni':1000,'dst_port':6081,'mtu':1400,'ports':[443],'security':{'mode':'ipsec','psk':'c'*64,'reqid':123}}


def test_teardown_requests_detailed_link_kind_and_keeps_guard_until_deletion():
    events=[]
    def command(*args,**kwargs):
        if 'show' in args:
            assert '-d' in args
            return MagicMock(returncode=0,stdout=json.dumps([{'linkinfo':{'info_kind':'geneve'}}]))
        if 'del' in args:events.append('delete_link')
        return MagicMock(returncode=0)
    with patch.object(agent,'command',side_effect=command),patch.object(agent,'firewall'),patch.object(agent,'ipsec'),patch.object(agent,'security_firewall',side_effect=lambda *a,**k:events.append('remove_guard')):
        agent.down(CONFIG)
    assert events==['delete_link','remove_guard']


def test_non_geneve_name_collision_keeps_guard_and_unrelated_device():
    with patch.object(agent,'command',return_value=MagicMock(returncode=0,stdout=json.dumps([{'linkinfo':{'info_kind':'dummy'}}]))) as command,patch.object(agent,'firewall') as firewall,patch.object(agent,'security_firewall') as guard:
        with pytest.raises(RuntimeError):agent.down(CONFIG)
    assert command.call_count==1
    firewall.assert_not_called();guard.assert_not_called()
