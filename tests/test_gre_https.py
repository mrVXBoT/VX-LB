import copy
import unittest
from unittest.mock import Mock, patch
from core import gre_https, gre_https_agent, https_tunnel


class GreHttpsTests(unittest.TestCase):
    def node(self):
        c=dict(owner='ldh'+'a'*16,interface='ldc'+'a'*10,role='iran',private='10.204.0.1',peer='10.204.0.2',
               key=123,mtu=1280,ports=['443'],receive_port=30001,carrier_port=30002)
        return {'node_name':c['owner'],'transport':'gre_xhttp','gre_https':[c,dict(c,role='kharej',private=c['peer'],peer=c['private'])],
                'https':{'profile':https_tunnel.profile('gre_xhttp',{'server_name':'tunnel.example.com'}),
                         'uuid':'a07a0763-eb20-4e5c-bb4a-6362d1443c45','path':'/secret','outer_port':8443,'probe_local':22252,'probe_remote':22251}}

    def test_carrier_is_loopback_udp_and_cannot_bypass_gre(self):
        n=self.node();a,b=https_tunnel.configs(n,'192.0.2.2',['443'])
        self.assertEqual([x['tag'] for x in a['inbounds']],['probe','gre-carrier'])
        carrier=a['inbounds'][1]
        self.assertEqual(carrier['listen'],'127.0.0.1')
        self.assertEqual(carrier['settings'],{'address':'127.0.0.1','port':30002,'network':'udp'})
        self.assertEqual(a['outbounds'][0]['streamSettings']['security'],'tls')
        self.assertFalse(a['outbounds'][0]['streamSettings']['tlsSettings']['allowInsecure'])
        self.assertNotIn('freedom',[x['protocol'] for x in a['outbounds']])
        self.assertEqual(b['outbounds'][0]['protocol'],'blackhole')
        self.assertEqual(b['routing']['rules'][0]['network'],'udp')
        self.assertNotIn('443', [rule['port'] for rule in b['routing']['rules']])

    def test_return_adapter_never_exposes_a_network_listener(self):
        c=self.node()['gre_https'][1];adapter=gre_https_agent.ReturnAdapter(c);transport=Mock();adapter.connection_made(transport)
        adapter.datagram_received(b'public',('192.0.2.1',4444));transport.sendto.assert_not_called()
        adapter.datagram_received(b'premature-return',('127.0.0.1',c['receive_port']));transport.sendto.assert_not_called()
        adapter.datagram_received(b'from-tls',('127.0.0.1',45678));transport.sendto.assert_called_with(b'from-tls',('127.0.0.1',c['receive_port']))
        adapter.datagram_received(b'from-gre',('127.0.0.1',c['receive_port']));transport.sendto.assert_called_with(b'from-gre',('127.0.0.1',45678))

    def test_invalid_owned_config_rejected(self):
        c=self.node()['gre_https'][0];gre_https_agent.validate(c)
        for key,value in [('owner','other'),('interface','eth0'),('private','192.0.2.1'),('peer','10.204.0.4'),('receive_port',443),('mtu',9000)]:
            with self.assertRaises(ValueError):gre_https_agent.validate(dict(c,**{key:value}))

    def test_foreign_fou_listener_is_never_deleted(self):
        c=self.node()['gre_https'][0];module=Mock();module.command.return_value.stdout='port 30001 ipproto 47 local 127.0.0.1'
        marker=Mock();marker.exists.return_value=False
        with patch.object(gre_https_agent,'owned',return_value=False),patch.object(gre_https_agent,'shared',return_value=module),patch.object(gre_https_agent,'marker',return_value=marker):
            with self.assertRaisesRegex(RuntimeError,'ownership'):gre_https_agent.down(c)
        self.assertEqual(module.command.call_count,1)
        marker.unlink.assert_not_called()

    def test_failed_fou_deletion_preserves_ownership_for_retry(self):
        c=self.node()['gre_https'][0];module=Mock();module.command.side_effect=[Mock(stdout='port 30001 ipproto 47 local 127.0.0.1'),RuntimeError('busy')]
        marker=Mock();marker.exists.return_value=True;marker.read_text.return_value=c['owner']
        with patch.object(gre_https_agent,'owned',return_value=False),patch.object(gre_https_agent,'shared',return_value=module),patch.object(gre_https_agent,'marker',return_value=marker):
            with self.assertRaisesRegex(RuntimeError,'busy'):gre_https_agent.down(c)
        marker.unlink.assert_not_called()

    def test_full_verification_requires_real_gre_probe(self):
        n=self.node();a,b=Mock(),Mock();b.client.exec_command.return_value=(None,Mock(),None)
        b.client.exec_command.return_value[1].readline.return_value='READY'
        with patch.object(https_tunnel,'execute'),patch.object(gre_https,'verify',side_effect=RuntimeError('GRE failed')) as check,patch.object(https_tunnel.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'GRE failed'):https_tunnel.verify(a,b,n)
            self.assertEqual(check.call_count,3)

    def test_deleting_plain_xhttp_never_touches_gre(self):
        n=self.node();n['transport']='xhttp'
        with patch.object(https_tunnel,'execute'),patch.object(https_tunnel,'firewall'),patch.object(gre_https,'clean') as clean:
            https_tunnel.clean(Mock(),n,['443'],True);clean.assert_not_called()

    def test_port_change_updates_gre_and_retains_lock_when_rollback_fails(self):
        n=self.node();n.update(ip='192.0.2.1',provisioning=False)
        pool={'name':'test','nodes':[n],'transport':'gre_xhttp','client_ports':['443'],'kharej_server':{'ip':'192.0.2.2'}}
        data={'pools':{'test':pool}}
        from core.load_balancer import LoadBalancerManager
        with patch.object(https_tunnel,'get_pools',lambda:copy.deepcopy(data['pools'])), \
             patch.object(https_tunnel,'atomic_update',lambda fn:fn(data)), \
             patch.object(LoadBalancerManager,'check_port_conflicts',return_value=(True,'')), \
             patch.object(https_tunnel,'connect',side_effect=[Mock(),Mock()]), \
             patch.object(https_tunnel,'test_config'),patch.object(https_tunnel,'execute'),patch.object(https_tunnel,'firewall'), \
             patch.object(gre_https,'update_ports',side_effect=[RuntimeError('bind failed'),RuntimeError('rollback unreachable')]) as update:
            self.assertFalse(https_tunnel.change_ports('test',['2053'])[0])
        self.assertEqual(update.call_count,2)
        self.assertEqual(update.call_args_list[0].args[-1],['2053'])
        self.assertEqual(update.call_args_list[1].args[-1],['443'])
        self.assertEqual(pool['client_ports'],['443'])
        self.assertEqual(pool['transport_change']['status'],'rollback_failed')


if __name__=='__main__':unittest.main()
