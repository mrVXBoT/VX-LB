import copy
import shlex
import unittest
from contextlib import ExitStack, nullcontext
from unittest.mock import patch
from core import transport_change as change

class FakeSSH:
    def __init__(self): self.files={};self.closed=False;self.bad_restore=False
    def write_file(self,path,content):self.files[path]=content;return True
    def close(self):self.closed=True
    def command(self,command):
        if command.startswith('cat -- '):return self.files[shlex.split(command)[2]]
        if command.startswith('systemctl is-active'):return 'active'
        if command.startswith('systemctl restart'):return ''
        for segment in command.split(' && '):
            parts=shlex.split(segment)
            if parts[0]=='cp':
                if self.bad_restore and parts[-1].endswith('.vxlb-restore'):raise RuntimeError('restore unavailable')
                self.files[parts[-1]]=self.files[parts[-2]]
            elif parts[0]=='mv':self.files[parts[-1]]=self.files.pop(parts[-2])
        return ''

class RollingTransportTests(unittest.TestCase):
    def setUp(self):
        self.pool={'name':'A','transport':'pck','client_ports':['443'],'cloudflare':{'subdomain':'edge.test'},'nodes':[{'node_name':'a_ir1','ip':'192.0.2.1'},{'node_name':'a_ir2','ip':'192.0.2.2'}],'kharej_server':{'ip':'198.51.100.1'},'transport_change':{'repair':True,'id':'test','status':'queued','from':'pck','to':'stealth','changed':[],'total':2,'completed':0}}
        self.data={'pools':{'A':copy.deepcopy(self.pool)}}
        self.sessions={ip:FakeSSH() for ip in ('192.0.2.1','192.0.2.2','198.51.100.1')}
        for node in self.pool['nodes']:
            path='/etc/backpack/'+node['node_name']+'.toml'
            for ip in (node['ip'],'198.51.100.1'):
                self.sessions[ip].files[path]='transport = "pck"\ntoken = "unchanged-test-only"\nports = ["443"]\n'
        self.original={ip:copy.deepcopy(ssh.files) for ip,ssh in self.sessions.items()}
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(change,'load_data',side_effect=lambda:copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(change,'atomic_update',side_effect=lambda callback:callback(self.data)))
        self.stack.enter_context(patch.object(change,'mutation_lock',side_effect=nullcontext))
        self.stack.enter_context(patch.object(change,'connect',side_effect=lambda server:self.sessions[server['ip']]))
        self.stack.enter_context(patch.object(change,'check',side_effect=lambda ssh,cmd:ssh.command(cmd)))
        self.stack.enter_context(patch.object(change,'verify_control',return_value=True))
        self.stack.enter_context(patch.object(change,'install_and_verify',side_effect=self.install))

    def install(self, ir, kh, unit, path, contents):
        if ir.bad_restore: raise RuntimeError('restore unavailable')
        for ssh, content in zip((ir,kh),contents):ssh.files[path]=content
        return change.verify_flow(ir,kh,unit,self.pool['client_ports'])

    def assert_original(self):
        for ip,files in self.original.items():
            for path,content in files.items():self.assertEqual(self.sessions[ip].files[path],content)

    def test_success_preserves_pool_members_ports_tokens_and_dns(self):
        with patch.object(change,'verify_flow',return_value=True) as flow:change.run_change('A')
        pool=self.data['pools']['A'];self.assertEqual(pool['transport'],'stealth');self.assertEqual(pool['transport_change']['status'],'succeeded');self.assertEqual(flow.call_count,2)
        for key in ('nodes','client_ports','cloudflare','kharej_server'):self.assertEqual(pool[key],self.pool[key])
        for ip,files in self.original.items():
            for path,content in files.items():self.assertEqual(self.sessions[ip].files[path],content.replace('"pck"','"stealth"'))

    def test_second_node_failure_restores_both_sides_of_all_changed_nodes(self):
        with patch.object(change,'verify_flow',side_effect=[True,False,True,True]):change.run_change('A')
        self.assert_original();self.assertEqual(self.data['pools']['A']['transport'],'pck');self.assertEqual(self.data['pools']['A']['transport_change']['status'],'rolled_back')

    def test_unhealthy_original_route_never_receives_target_transport(self):
        self.data['pools']['A']['transport_change']['repair']=False
        with patch.object(change,'verify_flow',side_effect=[False,True]):change.run_change('A')
        self.assert_original()
        self.assertEqual(self.data['pools']['A']['transport_change']['status'],'rolled_back')
        self.assertIn('نوع جدید اعمال نشد',self.data['pools']['A']['transport_change']['error'])

    def test_preflight_failure_does_not_change_any_config(self):
        self.sessions['192.0.2.2'].files['/etc/backpack/a_ir2.toml']='transport = "tcp"\n'
        original=copy.deepcopy(self.sessions['192.0.2.1'].files['/etc/backpack/a_ir1.toml'])
        change.run_change('A')
        self.assertEqual(self.sessions['192.0.2.1'].files['/etc/backpack/a_ir1.toml'],original)
        self.assertEqual(self.data['pools']['A']['transport_change']['status'],'failed')

    def test_restore_failure_blocks_mutations_and_recovery_retries_original_backups(self):
        self.sessions['192.0.2.1'].bad_restore=True
        with patch.object(change,'verify_flow',return_value=False):change.run_change('A')
        self.assertEqual(self.data['pools']['A']['transport_change']['status'],'rollback_failed');self.assertTrue(change.busy(self.data))
        self.sessions['192.0.2.1'].bad_restore=False
        with patch.object(change,'verify_flow',return_value=True):change.run_change('A',recovering=True)
        self.assert_original();self.assertFalse(change.busy(self.data))

class FlowTests(unittest.TestCase):
    def test_wrong_owner_and_port_are_never_used_as_confirmation(self):
        output='ESTAB 0 0 192.0.2.1:443 203.0.113.1:5000 users:(("backpack",pid=123,fd=7))\n bytes_received:200 bytes_acked:300\n'
        self.assertEqual(change.counters(output,'999',{'443'}),{})
        self.assertEqual(change.counters(output,'123',{'8443'}),{})
        self.assertEqual(len(change.counters(output,'123',{'443'})),1)

    def test_fresh_two_way_flow_is_required_not_service_active_or_cumulative_counters(self):
        samples=[{('local','peer'):(1000,1000)},{('local','peer'):(1200,1200)}]
        with patch.object(change,'check',return_value='123'),patch.object(change,'active',return_value=True),patch.object(change,'counters',side_effect=samples),patch.object(change.time,'sleep'):
            self.assertTrue(change.verify_flow(object(),object(),'unit',['443']))
        with patch.object(change,'check',return_value='123'),patch.object(change,'active',return_value=True),patch.object(change,'counters',return_value={('local','peer'):(1000,1000)}),patch.object(change.time,'sleep'),patch.object(change.time,'monotonic',side_effect=[0,0,10,50]):
            self.assertFalse(change.verify_flow(object(),object(),'unit',['443']))

    def test_only_transport_setting_changes(self):
        config='[server]\ntransport = "pck" # keep comment\ntoken="pck"\nfallback_transports=["pck"]\n'
        new=change.replace_transport(config,'pck','stealth');self.assertIn('token="pck"',new);self.assertIn('fallback_transports=["pck"]',new)
        with self.assertRaises(RuntimeError):change.replace_transport(config,'tcp','stealth')

class UniversalTransportChangeTests(unittest.TestCase):
    def setUp(self):
        self.pool = {
            'name': 'P1',
            'transport': 'tcp',
            'engine': 'backpack',
            'client_ports': ['443'],
            'subdomain': 'lb.example.com',
            'dns_routing': {'mode': 'round_robin'},
            'nodes': [{'node_name': 'p1_ir1', 'ip': '192.0.2.1'}],
            'kharej_server': {'ip': '198.51.100.1'},
        }
        self.data = {
            'pools': {'P1': copy.deepcopy(self.pool)},
            'iran_servers': [{'ip': '192.0.2.1', 'name': 'ir-1'}],
            'kharej_servers': [{'ip': '198.51.100.1', 'name': 'kh-1'}],
        }

    def test_start_change_validation_cross_engine(self):
        with patch.object(change, 'load_data', side_effect=lambda: copy.deepcopy(self.data)), \
             patch.object(change, 'atomic_update', side_effect=lambda cb: cb(self.data)), \
             patch.object(change, 'routing_lock', side_effect=nullcontext), \
             patch.object(change, 'busy', return_value=False):
            # Identical transport rejected
            ok, msg = change.start_change('P1', 'tcp', background=False)
            self.assertFalse(ok)
            self.assertIn('برابر نوع فعلی', msg)

            # Invalid transport rejected
            ok, msg = change.start_change('P1', 'invalid_xyz', background=False)
            self.assertFalse(ok)
            self.assertIn('نامعتبر', msg)

            # Xray without domain rejected
            ok, msg = change.start_change('P1', 'xhttp', background=False)
            self.assertFalse(ok)
            self.assertIn('دامنهٔ TLS', msg)

            # Valid cross-engine transition to waterwall queued
            ok, msg = change.start_change('P1', 'waterwall', background=False)
            self.assertTrue(ok)

            # Valid cross-engine transition to paqet quantum queued
            ok, msg = change.start_change('P1', 'quantum', background=False)
            self.assertTrue(ok)

            # Valid cross-engine transition to xray with camouflage queued
            ok, msg = change.start_change('P1', 'xhttp', background=False, camouflage={'server_name': 'test.com'})
            self.assertTrue(ok)

    def test_universal_migration_success_preserves_dns_and_ports(self):
        job = {
            'id': 'test-job-1',
            'status': 'queued',
            'from': 'tcp',
            'to': 'waterwall',
            'from_engine': 'backpack',
            'to_engine': 'waterwall',
            'arguments': {'camouflage': {'server_name': 'ww.test.com'}},
        }
        self.data['pools']['P1']['transport_change'] = job

        mock_created_pool = {
            'name': 'P1',
            'transport': 'waterwall',
            'engine': 'waterwall',
            'client_ports': ['443'],
            'nodes': [{'ip': '192.0.2.1'}],
            'kharej_server': {'ip': '198.51.100.1'},
        }

        fake_ssh = FakeSSH()
        with patch.object(change, 'load_data', side_effect=lambda: copy.deepcopy(self.data)), \
             patch.object(change, 'atomic_update', side_effect=lambda cb: cb(self.data)), \
             patch.object(change, 'mutation_lock', side_effect=nullcontext), \
             patch.object(change, 'connect', return_value=fake_ssh), \
             patch.object(change, 'teardown_pool_runtime') as mock_td, \
             patch('core.load_balancer.LoadBalancerManager.create_pool', return_value=(True, 'created', mock_created_pool)) as mock_cp:
            change.run_change('P1')
            self.assertTrue(mock_td.called)
            self.assertTrue(mock_cp.called)
            p1 = self.data['pools']['P1']
            self.assertEqual(p1['transport'], 'waterwall')
            self.assertEqual(p1['subdomain'], 'lb.example.com')
            self.assertEqual(p1['dns_routing'], {'mode': 'round_robin'})
            self.assertEqual(p1['transport_change']['status'], 'succeeded')

    def test_universal_migration_failure_rolls_back(self):
        job = {
            'id': 'test-job-2',
            'status': 'queued',
            'from': 'tcp',
            'to': 'waterwall',
            'from_engine': 'backpack',
            'to_engine': 'waterwall',
            'arguments': {},
        }
        self.data['pools']['P1']['transport_change'] = job

        fake_ssh = FakeSSH()
        with patch.object(change, 'load_data', side_effect=lambda: copy.deepcopy(self.data)), \
             patch.object(change, 'atomic_update', side_effect=lambda cb: cb(self.data)), \
             patch.object(change, 'mutation_lock', side_effect=nullcontext), \
             patch.object(change, 'connect', return_value=fake_ssh), \
             patch.object(change, 'teardown_pool_runtime'), \
             patch('core.load_balancer.LoadBalancerManager.create_pool', side_effect=[(False, 'remote config failed', {}), (True, 'restored', copy.deepcopy(self.pool))]):
            change.run_change('P1')
            p1 = self.data['pools']['P1']
            self.assertEqual(p1['transport'], 'tcp')
            self.assertEqual(p1['transport_change']['status'], 'rolled_back')
            self.assertIn('remote config failed', p1['transport_change']['error'])

    def test_start_change_resolves_kernel_group_label(self):
        with patch.object(change, 'load_data', side_effect=lambda: copy.deepcopy(self.data)), \
             patch.object(change, 'atomic_update', side_effect=lambda cb: cb(self.data)), \
             patch.object(change, 'routing_lock', side_effect=nullcontext), \
             patch.object(change, 'busy', return_value=False):
            ok, msg = change.start_change('P1', 'gre', background=False, engine='kernel')
            self.assertTrue(ok, msg)
            job = self.data['pools']['P1']['transport_change']
            self.assertEqual(job['to_engine'], 'gre')
            self.assertEqual(job['status'], 'queued')


class KernelRollingChangeTests(unittest.TestCase):
    def setUp(self):
        self.pool = {
            'name': 'P1',
            'transport': 'tun',
            'engine': 'tun',
            'client_ports': ['443'],
            'subdomain': 'lb.example.com',
            'dns_routing': {'mode': 'round_robin'},
            'nodes': [
                {'node_name': 'p1_ir1', 'ip': '192.0.2.1', 'engine': 'tun'},
                {'node_name': 'p1_ir2', 'ip': '192.0.2.2', 'engine': 'tun'},
            ],
            'kharej_server': {'ip': '198.51.100.1'},
            'transport_change': {'id': 'k1', 'status': 'queued', 'from': 'tun', 'to': 'gre',
                                 'from_engine': 'tun', 'to_engine': 'gre', 'arguments': {},
                                 'changed': [], 'completed': 0, 'total': 2},
        }
        self.data = {'pools': {'P1': copy.deepcopy(self.pool)}}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(change, 'load_data', side_effect=lambda: copy.deepcopy(self.data)))
        self.stack.enter_context(patch.object(change, 'atomic_update', side_effect=lambda cb: cb(self.data)))
        self.stack.enter_context(patch.object(change, 'mutation_lock', side_effect=nullcontext))
        self.stack.enter_context(patch.object(change, 'connect', return_value=FakeSSH()))

    def _remove(self, name, node, engine, pool):
        ip = node.get('ip')
        def rm(data):
            data['pools'][name]['nodes'] = [n for n in data['pools'][name]['nodes'] if n.get('ip') != ip]
        rm(self.data)
        return True, ''

    def _deploy(self, name, server, callback=None):
        eng = self.data['pools'][name].get('engine', 'backpack')
        node = {'node_name': 'mig-' + str(server['ip']).replace('.', ''), 'ip': server['ip'],
                'engine': eng, 'transport': eng, 'provisioning': False, 'status': 'active'}
        self.data['pools'][name]['nodes'].append(node)
        return True, ''

    def test_kernel_success_preserves_ports_members_dns(self):
        with patch.object(change, '_remove_node_engine', side_effect=self._remove), \
             patch.object(change, '_deploy_node', side_effect=self._deploy):
            change.run_change('P1')
        p = self.data['pools']['P1']
        self.assertEqual(p['transport'], 'gre')
        self.assertEqual(p['engine'], 'gre')
        self.assertEqual(p['transport_change']['status'], 'succeeded')
        self.assertEqual(p['client_ports'], ['443'])
        self.assertEqual(p['kharej_server'], {'ip': '198.51.100.1'})
        self.assertEqual(p['subdomain'], 'lb.example.com')
        self.assertEqual(p['dns_routing'], {'mode': 'round_robin'})
        self.assertEqual(len(p['nodes']), 2)
        self.assertTrue(all(n['engine'] == 'gre' for n in p['nodes']))

    def test_kernel_failure_rolls_back_all_changed_nodes(self):
        deploy_calls = {'n': 0}
        def failing_deploy(name, server, callback=None):
            deploy_calls['n'] += 1
            if deploy_calls['n'] == 2:
                return False, 'boom'
            return self._deploy(name, server, callback)
        with patch.object(change, '_remove_node_engine', side_effect=self._remove), \
             patch.object(change, '_deploy_node', side_effect=failing_deploy):
            change.run_change('P1')
        p = self.data['pools']['P1']
        self.assertEqual(p['transport'], 'tun')
        self.assertEqual(p['engine'], 'tun')
        self.assertEqual(p['transport_change']['status'], 'rolled_back')
        self.assertEqual(len(p['nodes']), 2)
        self.assertTrue(all(n['engine'] == 'tun' for n in p['nodes']))

