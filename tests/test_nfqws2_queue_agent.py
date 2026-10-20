"""Actual ownership evidence and narrow NFQUEUE mutation/rollback boundaries."""
from pathlib import Path
from types import SimpleNamespace
import pytest
from core import nfqws2_queue_agent as agent


def configuration():
    return dict(id='a'*32,peer='192.0.2.2',carrier_port=45100,queue=45101,incoming=True,binary='/opt/ldbp/nfqws2')


def result(code=0,text=''):return SimpleNamespace(returncode=code,stdout=text,stderr='')


def test_rules_are_limited_to_peer_port_and_generated_packets_skip_queue():
    rules=list(agent.rules(configuration()))
    assert [chain for chain,_ in rules]==['OUTPUT','INPUT']
    for _,rule in rules:
        assert '192.0.2.2' in rule and '45100' in rule
        assert '--queue-bypass' not in rule
        assert rule[rule.index('--queue-num')+1]=='45101'
        assert rule[rule.index('--mark')-1]=='!'
        assert rule[rule.index('--mark')+1]==agent.GENERATOR_MARK


def fake_proc(tmp_path,cmd_queue=45101,inode=123,portid=456):
    pid=78;root=tmp_path/'proc';(root/str(pid)/'fd').mkdir(parents=True)
    (root/str(pid)/'cmdline').write_bytes(b'/opt/ldbp/nfqws2\0'+('--qnum='+str(cmd_queue)).encode()+b'\0')
    (root/str(pid)/'fd'/'9').symlink_to('socket:['+str(inode)+']')
    (root/'net/netfilter').mkdir(parents=True)
    (root/'net/netfilter/nfnetlink_queue').write_text('45101 456 0 2 65535 0 0 12 1\n')
    (root/'net/netlink').write_text('sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n0000 12 '+str(portid)+' 0 0 0 0 2 0 123\n')
    return root


@pytest.mark.parametrize('mismatch',[None,'queue','socket','portid'])
def test_queue_is_healthy_only_when_unit_process_holds_its_actual_netlink_socket(tmp_path,monkeypatch,mismatch):
    root=fake_proc(tmp_path,cmd_queue=9 if mismatch=='queue' else 45101,inode=9 if mismatch=='socket' else 123,portid=999 if mismatch=='portid' else 456)
    monkeypatch.setattr(agent,'run',lambda args:result(text='78\n' if 'show' in args else ''))
    if mismatch:
        with pytest.raises(RuntimeError):agent.inspect(configuration(),str(root))
    else:
        status=agent.inspect(configuration(),str(root))
        assert status['verified'] and status['seen']==12 and status['owner_pid']==78
        assert status['portid']!=status['owner_pid']  # No invalid PID=netlink-port assumption.


def test_unproved_owner_prevents_all_firewall_mutation(monkeypatch):
    monkeypatch.setattr(agent,'wait_ready',lambda config:(_ for _ in ()).throw(RuntimeError('wrong queue owner')))
    calls=[];monkeypatch.setattr(agent,'iptables',lambda *args,**kwargs:calls.append(args))
    with pytest.raises(RuntimeError):agent.apply(configuration())
    assert not calls


def test_partial_apply_rolls_back_only_newly_inserted_rules(monkeypatch):
    monkeypatch.setattr(agent,'wait_ready',lambda config:{'verified':True})
    calls=[]
    def iptables(*args,**kwargs):
        calls.append(args)
        if args[0]=='-C':return result(1)
        if args[:2]==('-I','INPUT'):raise RuntimeError('insertion failed')
        return result()
    monkeypatch.setattr(agent,'iptables',iptables)
    with pytest.raises(RuntimeError,match='insertion failed'):agent.apply(configuration())
    deleted=[args for args in calls if args[0]=='-D']
    assert len(deleted)==1 and deleted[0][1]=='OUTPUT'


def test_remove_preserves_other_owner_and_checks_absence_without_live_daemon(monkeypatch):
    owned='-A OUTPUT -d 192.0.2.2 -m comment --comment ldbp-nfq:'+('a'*32)+' -j NFQUEUE --queue-num 45101'
    other='-A OUTPUT -m comment --comment ldbp-nfq:'+('b'*32)+' -j NFQUEUE --queue-num 45102'
    rows=[owned,other];calls=[]
    def iptables(*args,**kwargs):
        calls.append(args)
        if args[0]=='-S':return result(text='\n'.join(rows) if args[1]=='OUTPUT' else '')
        if args[0]=='-D':rows.remove(owned)
        return result()
    monkeypatch.setattr(agent,'iptables',iptables)
    assert agent.remove(configuration())['removed']
    assert rows==[other] and sum(args[0]=='-D' for args in calls)==1
    assert not any('-F' in args or '--queue-bypass' in args for args in calls)


def test_failed_rollback_is_not_reported_as_restored(monkeypatch):
    monkeypatch.setattr(agent,'wait_ready',lambda config:{'verified':True})
    def iptables(*args,**kwargs):
        if args[0]=='-C':return result(1)
        if args[:2]==('-I','INPUT'):raise RuntimeError('insertion failed')
        if args[0]=='-D':raise RuntimeError('removal failed')
        return result()
    monkeypatch.setattr(agent,'iptables',iptables)
    with pytest.raises(RuntimeError,match='rollback unverified'):agent.apply(configuration())


def test_existing_rule_survives_failed_addition(monkeypatch):
    monkeypatch.setattr(agent,'wait_ready',lambda config:{'verified':True});calls=[]
    def iptables(*args,**kwargs):
        calls.append(args)
        if args[0]=='-C':return result(0 if args[1]=='OUTPUT' else 1)
        if args[0]=='-I':raise RuntimeError('new rule failed')
        return result()
    monkeypatch.setattr(agent,'iptables',iptables)
    with pytest.raises(RuntimeError,match='new rule failed'):agent.apply(configuration())
    assert not any(args[0]=='-D' for args in calls)


def test_remove_requires_proven_absence_even_when_delete_command_succeeds(monkeypatch):
    owned='-A OUTPUT -m comment --comment ldbp-nfq:'+('a'*32)+' -j NFQUEUE --queue-num 45101'
    monkeypatch.setattr(agent,'iptables',lambda *args,**kwargs:result(text=owned if args[:2]==('-S','OUTPUT') else ''))
    with pytest.raises(RuntimeError,match='remains after removal'):agent.remove(configuration())


def test_invalid_incoming_flag_rejected_before_owner_or_firewall_work(monkeypatch):
    from unittest.mock import MagicMock
    owner=MagicMock();mutate=MagicMock()
    monkeypatch.setattr(agent,'wait_ready',owner);monkeypatch.setattr(agent,'iptables',mutate)
    config=configuration();config['incoming']='false'
    with pytest.raises(ValueError):agent.apply(config)
    owner.assert_not_called();mutate.assert_not_called()
