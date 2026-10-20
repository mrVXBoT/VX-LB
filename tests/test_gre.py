import copy
import json
import unittest
from unittest.mock import patch, Mock
from core import gre, gre_agent
from core.load_balancer import LoadBalancerManager
from core.transport_change import busy, start_change
from core.watchdog import TelemetryWatchdog


class GreTests(unittest.TestCase):
    def setUp(self):
        self.server={'ip':'192.0.2.1','name':'iran','password':'private'}
        self.kh={'ip':'192.0.2.2','name':'kharej','password':'private'}
        self.data={'pools':{}}
        self.patches=[patch.object(gre,'load_data',lambda:copy.deepcopy(self.data)),
                      patch.object(gre,'get_pools',lambda:copy.deepcopy(self.data['pools'])),
                      patch.object(gre,'atomic_update',lambda fn:fn(self.data)),
                      patch.object(gre,'save_pool',lambda name,pool:self.data['pools'].__setitem__(name,copy.deepcopy(pool)))]
        for p in self.patches:p.start();self.addCleanup(p.stop)

    def pool(self):
        node=gre.allocate(self.server,self.kh,['443'],1400);node['provisioning']=False
        self.data['pools']['one']=dict(name='one',engine='gre',transport='gre',gre_mtu=1400,nodes=[node],kharej_server=self.kh,client_ports=['443'])
        return node

    def test_validation_and_pool_routing(self):
        with patch.object(gre,'connect') as connect:
            for args in [('bad;name',self.kh,[self.server],['443'],1400),('one',self.kh,[self.server],['443'],'1;echo'),('one',self.kh,[self.server],['70000'],1400),('one',dict(self.kh,ip='::1'),[self.server],['443'],1400)]:
                self.assertFalse(gre.create(*args)[0])
            connect.assert_not_called()
        with patch.object(gre,'create',return_value=(True,'gre',{})) as create:
            self.assertTrue(LoadBalancerManager.create_pool('one',self.kh,[self.server],'gre',['443'],gre_mtu=1280)[0])
            self.assertEqual(create.call_args.args[4],1280)

    def test_allocator_and_agent_validation(self):
        node=self.pool();c=node['gre']['configs'][0]
        self.assertEqual(gre_agent.validate(c)['mtu'],1400)
        for patch_value in [{'interface':'gre0;rm -rf /'},{'owner':'other'},{'mtu':1500},{'local':'::1'},{'peer':c['private']},{'ports':[0]}]:
            with self.assertRaises(ValueError):gre_agent.validate(dict(c,**patch_value))
        second=gre.allocate(dict(self.server,ip='192.0.2.3'),self.kh,['443'],1400)
        self.assertNotEqual(second['gre']['local_private'],node['gre']['local_private'])
        self.assertIn('Type=oneshot',gre.service(node))
        self.assertIn(' relay ',gre.service(node,True))
        self.assertNotIn('backpack',gre.service(node))
        all_rules=' '.join(' '.join(r) for r in gre_agent.rules(c))
        self.assertNotIn('-p 47',all_rules)
        secure_rules = list(gre_agent.security_rules(c))
        self.assertEqual(secure_rules[0][0], 'INPUT')
        self.assertIn('--pol none', ' '.join(secure_rules[0][1]))
        self.assertEqual(secure_rules[0][1][-1], 'DROP')
        self.assertTrue(any(chain == 'OUTPUT' and '--pol none' in ' '.join(rule) for chain, rule in secure_rules))
        self.assertIn('ldbp-gre-',all_rules)
        self.assertNotIn('FORWARD',all_rules)

    def test_security_required_and_authentication_scoped(self):
        node = self.pool(); c = node['gre']['configs'][0]
        insecure = dict(c); insecure.pop('security')
        with patch.object(gre_agent, 'command') as command:
            with self.assertRaises(RuntimeError): gre_agent.up(insecure)
            command.assert_not_called()
        # Legacy configs remain parseable for removal, but cannot be started raw.
        self.assertEqual(gre_agent.validate(dict(insecure,mtu=1472))['mtu'],1472)
        with self.assertRaises(ValueError):gre_agent.secure_config(dict(c,mtu=1472))
        conn = gre_agent.ipsec_connection(c)
        self.assertEqual(conn['version'], '2')
        self.assertEqual(conn['remote']['id'], c['remote'])
        self.assertEqual(conn['local']['auth'], 'psk')
        child = conn['children'][c['interface']]
        self.assertEqual(child['esp_proposals'], ['aes256gcm16-ecp256'])
        self.assertEqual(child['remote_ts'], [c['remote']+'/32[47]'])
        self.assertEqual(child['start_action'], 'trap')
        self.assertEqual(len(bytes.fromhex(c['security']['psk'])), 32)
        self.assertEqual(c['security'], node['gre']['configs'][1]['security'])
        with self.assertRaises(ValueError): gre.allocate(self.server,self.kh,['443'],1400)

    def test_guard_precedes_link_and_survives_failed_ipsec(self):
        c=self.pool()['gre']['configs'][0]; order=[]
        with patch.object(gre_agent,'security_firewall',side_effect=lambda c:order.append('guard')), \
             patch.object(gre_agent,'ipsec',side_effect=RuntimeError('authentication failed')), \
             patch.object(gre_agent,'command') as command:
            with self.assertRaises(RuntimeError):gre_agent.up(c)
            self.assertEqual(order,['guard']);command.assert_not_called()

    def test_unrelated_interface_never_removed(self):
        c=self.pool()['gre']['configs'][0]
        response=Mock(returncode=0,stdout=json.dumps([{'linkinfo':{'info_kind':'dummy'}}]))
        with patch.object(gre_agent,'firewall'),patch.object(gre_agent,'command',return_value=response) as command:
            with self.assertRaises(RuntimeError):gre_agent.down(c)
            self.assertFalse(any('del' in call.args for call in command.call_args_list))

    def test_failed_install_cleans_both_and_preserves_other_members(self):
        self.data['pools']['one']=dict(name='one',engine='gre',transport='gre',gre_mtu=1400,nodes=[],kharej_server=self.kh,client_ports=['443'])
        sessions=[Mock(),Mock()]
        with patch.object(gre,'connect',side_effect=sessions),patch.object(gre,'install_agent'),patch.object(gre,'write'),patch.object(gre,'run_agent'),patch.object(gre,'execute'),patch.object(gre,'verify',side_effect=RuntimeError('data path failed')),patch.object(gre,'cleanup_endpoint') as cleanup,patch.object(LoadBalancerManager,'check_port_conflicts',return_value=(True,'')):
            self.assertFalse(gre.add('one',self.server)[0])
            self.assertEqual(cleanup.call_count,2)
            self.assertEqual(self.data['pools']['one']['nodes'],[])
            self.assertEqual(self.data['pools']['one']['node_additions'][self.server['ip']]['status'],'failed')
        for ssh in sessions:ssh.close.assert_called_once()

    def test_failed_cleanup_keeps_recoverable_membership(self):
        self.data['pools']['one']=dict(name='one',engine='gre',transport='gre',gre_mtu=1400,nodes=[],kharej_server=self.kh,client_ports=['443'])
        with patch.object(gre,'connect',side_effect=[Mock(),Mock()]),patch.object(gre,'install_agent'),patch.object(gre,'write'),patch.object(gre,'run_agent'),patch.object(gre,'execute'),patch.object(gre,'verify',side_effect=RuntimeError('probe')),patch.object(gre,'cleanup_endpoint',side_effect=RuntimeError('offline')),patch.object(LoadBalancerManager,'check_port_conflicts',return_value=(True,'')):
            self.assertFalse(gre.add('one',self.server)[0])
        self.assertTrue(self.data['pools']['one']['nodes'][0]['provisioning'])
        self.assertEqual(gre.health('one',self.data['pools']['one']['nodes'][0],['443'])[0],'DOWN')

    def test_remove_requires_both_connections_and_does_not_lie(self):
        node=self.pool()
        with patch.object(gre,'connect',side_effect=[Mock(),RuntimeError('kharej offline')]),patch.object(gre,'cleanup_endpoint') as cleanup:
            self.assertFalse(gre.remove('one',node['ip'])[0]);cleanup.assert_not_called()
        self.assertEqual(len(self.data['pools']['one']['nodes']),1)

    def test_mtu_commit_and_failed_rollback_lock(self):
        node=self.pool();pool=self.data['pools']['one']
        def begin(*args,**kwargs):pool['gre_update']={'status':'running','kind':'mtu'};return copy.deepcopy(pool)
        with patch.object(gre,'begin_update',side_effect=begin),patch.object(gre,'connect',side_effect=[Mock(),Mock()]),patch.object(gre,'write'),patch.object(gre,'run_agent'),patch.object(gre,'verify',return_value=True):
            self.assertTrue(gre.change_mtu('one',1280)[0])
        self.assertEqual(pool['gre_mtu'],1280)
        self.assertEqual(pool['nodes'][0]['gre']['configs'][1]['mtu'],1280)
        with patch.object(gre,'begin_update',side_effect=begin),patch.object(gre,'connect',side_effect=[Mock(),Mock()]),patch.object(gre,'write'),patch.object(gre,'run_agent',side_effect=RuntimeError('apply/restore failed')):
            self.assertFalse(gre.change_mtu('one',1200)[0])
        self.assertEqual(pool['gre_mtu'],1280)
        self.assertEqual(pool['gre_update']['status'],'rollback_failed')
        self.assertTrue(busy(self.data))
        self.assertIn('restore',pool['gre_update']['error'])

    def test_failed_recovery_never_unlocks_uncertain_state(self):
        self.pool();pool=self.data['pools']['one']
        def begin(*args,**kwargs):pool['gre_update']={'status':'running','kind':'mtu'};return copy.deepcopy(pool)
        with patch.object(gre,'begin_update',side_effect=begin),patch.object(gre,'connect',side_effect=RuntimeError('offline')):
            self.assertFalse(gre.change_mtu('one',1400,recovery=True)[0])
        self.assertEqual(pool['gre_update']['status'],'rollback_failed')
        self.assertTrue(busy(self.data))

    def test_watchdog_uses_gre_probe_and_not_backpack_control(self):
        node=self.pool()
        with patch.object(gre,'health',return_value=('HEALTHY','GRE TCP+UDP verified',{})),patch.object(TelemetryWatchdog,'save_node_telemetry') as save,patch('core.watchdog.control_connected') as backpack:
            self.assertEqual(TelemetryWatchdog().analyze_node_health('one',node,['443'])[0],'HEALTHY')
            backpack.assert_not_called();save.assert_called_once()

    def test_cross_engine_change_rejected_before_jobs(self):
        node=self.pool()
        with patch('core.transport_change.load_data',return_value=self.data),patch('core.transport_change.atomic_update') as update:
            self.assertFalse(start_change('one','tcp',background=False)[0]);update.assert_not_called()
        self.data['pools']['one']['transport']='tcp'
        with patch('core.transport_change.load_data',return_value=self.data):
            self.assertFalse(start_change('one','gre',background=False)[0])

    def test_web_create_accepts_gre_options_without_exposing_credentials(self):
        import io
        from core import web_server
        handler=object.__new__(web_server.LDWebRequestHandler)
        handler.path='/api/pools/create'
        body=json.dumps({'name':'one','transport':'gre','gre_mtu':1280,'client_ports':['443'],'iran_ips':[self.server['ip']],'kharej_ip':self.kh['ip']}).encode()
        handler.headers={'Content-Length':str(len(body))};handler.rfile=io.BytesIO(body)
        handler._is_authenticated=lambda:True
        results=[];handler._send_json=lambda value,status=200:results.append((value,status))
        from core import pool_creation
        with patch.object(web_server,'get_servers',side_effect=lambda role:[self.server] if role=='iran' else [self.kh]),patch.object(pool_creation,'start',return_value=(True,{'status':'queued','pool_name':'one'})) as start_mock:
            handler._do_POST()
        self.assertEqual(start_mock.call_args[0][0]['gre_mtu'],1280)
        self.assertEqual(start_mock.call_args[0][0]['transport'],'gre')
        self.assertEqual(results[0][1],202)
        self.assertNotIn('private',json.dumps(results[0][0]))
        self.assertTrue(results[0][0]['accepted'])

    def test_status_never_exposes_ipsec_psk(self):
        from core import web_server
        node=self.pool();secret=node['gre']['configs'][0]['security']['psk']
        handler=object.__new__(web_server.LDWebRequestHandler)
        handler.path='/api/status';handler._is_authenticated=lambda:True
        responses=[];handler._send_json=lambda value:responses.append(value)
        with patch.object(web_server,'load_data',return_value=self.data), \
             patch.object(web_server,'get_pools',return_value=self.data['pools']), \
             patch.object(web_server,'get_servers',return_value=[]), \
             patch.object(web_server,'get_dashboard_domain_config',return_value={}), \
             patch.object(web_server,'TelemetryWatchdog') as watchdog:
            watchdog.get_node_telemetry.return_value={}
            handler.do_GET()
        self.assertNotIn(secret,str(responses))
        self.assertEqual(responses[0]['pools'][0]['nodes'][0]['security'],'ipsec')
        self.assertNotIn('configs',responses[0]['pools'][0]['nodes'][0]['gre'])

    def test_restart_keeps_pending_gre_updates_visible(self):
        self.pool();self.data['pools']['one']['gre_update']={'status':'running','kind':'mtu'}
        gre.recover_interrupted()
        self.assertEqual(self.data['pools']['one']['gre_update']['status'],'rollback_failed')

if __name__=='__main__':unittest.main()
