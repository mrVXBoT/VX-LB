import copy
import json
import threading
import time
import unittest
from contextlib import nullcontext
from http.client import HTTPConnection
from unittest.mock import patch
from core import web_server as web
from core import transport_change as transport
from core.dns_routing import route_key
from core.watchdog import TelemetryWatchdog

CONFIG = {'api_token': 'test-only-token', 'zone_id': 'test-zone', 'subdomain': 'edge.example.test', 'enabled': True}

class DnsRouteApiTests(unittest.TestCase):
    def setUp(self):
        self.data = {'cloudflare': copy.deepcopy(CONFIG), 'pools': {'A': {'nodes': [{'ip': '192.0.2.1'}]}, 'B': {'nodes': [{'ip': '192.0.2.2'}]}}}
        def update(callback): callback(self.data)
        self.patches = [patch.object(transport, 'load_data', side_effect=lambda: copy.deepcopy(self.data)), patch.object(web, 'mutation_lock', side_effect=nullcontext), patch.object(web, 'load_data', side_effect=lambda: copy.deepcopy(self.data)), patch.object(web, 'atomic_update', side_effect=update), patch.object(web, 'routing_lock', side_effect=nullcontext), patch.object(web, 'CloudflareManager')]
        for p in self.patches: p.start(); self.addCleanup(p.stop)
        self.manager = web.CloudflareManager.return_value
        self.server = web.ThreadedHTTPServer(('127.0.0.1', 0), web.LDWebRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        web.AUTH_TOKENS['dns-test-only'] = time.time() + 60
        self.addCleanup(web.AUTH_TOKENS.pop, 'dns-test-only', None)
        self.addCleanup(self.server.server_close); self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, auth=True):
        connection = HTTPConnection('127.0.0.1', self.server.server_port)
        headers = {'Content-Type': 'application/json'}
        if auth: headers['Authorization'] = 'Bearer dns-test-only'
        connection.request(method, path, json.dumps(body) if body else None, headers)
        response = connection.getresponse(); result = (response.status, json.loads(response.read()), response.getheader('Cache-Control'))
        connection.close(); return result

    def test_removal_returns_accepted_job_and_blocks_duplicate_mutations(self):
        job = {'status':'queued', 'ip':'192.0.2.1', 'message':'queued'}
        with patch.object(web, 'start_node_removal', return_value=(True,job)):
            status, body, _ = self.request('POST','/api/pools/remove_node',{'pool':'A','iran_ip':'192.0.2.1'})
        self.assertEqual(status, 202)
        self.assertEqual(body['job'], job)
        self.data['pools']['A']['node_removals'] = {'192.0.2.1':job}
        self.assertEqual(self.request('POST','/api/pools/remove_node',{'pool':'A','iran_ip':'192.0.2.1'})[0],409)

    def test_all_subdomains_preview_is_read_only_and_requires_auth(self):
        self.manager.subdomain_records.return_value = {'success':True,'names':['ssh.example.test'],'records':[{'name':'ssh.example.test','content':'192.0.2.1','id':'private'}]}
        body={'api_token':'test','zone_id':'zone','subdomain':'example.test'}
        self.assertEqual(self.request('POST','/api/pools/cloudflare-preview',body,auth=False)[0],401)
        status,result,_=self.request('POST','/api/pools/cloudflare-preview',body)
        self.assertEqual(status,200)
        self.assertEqual(result['names'],['ssh.example.test'])
        self.assertNotIn('id',result['records'][0])
        self.manager.sync_subdomain.assert_not_called()

    def test_all_subdomains_activation_requires_current_reviewed_list(self):
        self.manager.subdomain_records.return_value={'success':True,'names':['ssh.example.test'],'records':[]}
        body={'pool':'A','api_token':'test','zone_id':'zone','subdomain':'*.example.test','scope':'all_subdomains'}
        with patch.object(web.LoadBalancerManager,'set_pool_cloudflare',return_value=(True,'saved')) as save:
            self.assertEqual(self.request('POST','/api/pools/cloudflare',body)[0],409)
            save.assert_not_called()
            body['confirmed_names']=['ssh.example.test']
            self.assertEqual(self.request('POST','/api/pools/cloudflare',body)[0],200)
            save.assert_called_once_with('A','test','zone','example.test',True,scope='all_subdomains')

    def test_manual_all_subdomains_route_does_not_accept_partial_sync(self):
        self.data['pools']['A']['cloudflare']={**CONFIG,'subdomain':'example.test','scope':'all_subdomains'}
        self.manager.record_snapshot.return_value={'success':True,'scope':'all_subdomains','names':['a.example.test','b.example.test'],'records':[{'name':'a.example.test','content':'192.0.2.1'},{'name':'b.example.test','content':'192.0.2.2'}]}
        self.assertEqual(self.request('POST','/api/pools/dns-route',{'pool':'A','mode':'manual','ip':'192.0.2.1'})[0],502)
        self.assertNotIn('dns_overrides',self.data)

    def test_restart_does_not_retry_terminal_failed_rollback(self):
        self.data['pools']['A']['transport_change'] = {'status':'rollback_failed'}
        with patch.object(transport.threading, 'Thread') as thread:
            transport.recover_changes()
        thread.assert_not_called()

    def test_force_clear_endpoint_is_reachable_while_rollback_failed(self):
        self.data['pools']['A']['transport_change'] = {'status':'rollback_failed'}
        with patch.object(web, 'force_clear_change', return_value=(True,'cleared')) as clear:
            status, body, _ = self.request('POST', '/api/pools/transport-force-clear', {'pool':'A','confirm':'abandon-A'})
        self.assertEqual(status,200)
        clear.assert_called_once_with('A')

    def test_settings_inherit_global_and_require_authentication(self):
        self.assertEqual(self.request('GET', '/api/pools/cloudflare?pool=A', auth=False)[0], 401)
        status, config, cache = self.request('GET', '/api/pools/cloudflare?pool=A')
        self.assertEqual(status, 200)
        self.assertEqual(config, {**CONFIG, "api_token": "…" + CONFIG["api_token"][-4:], "scope": "single"})
        self.assertNotIn(CONFIG["api_token"], json.dumps(config))
        self.assertEqual(cache, 'no-store')
        self.data['pools']['A']['cloudflare'] = {**CONFIG, 'zone_id': 'own-zone'}
        self.assertEqual(self.request('GET', '/api/pools/cloudflare?pool=A')[1]['zone_id'], 'own-zone')

    def test_active_transport_change_blocks_dns_mutation(self):
        self.data['pools']['A']['transport_change']={'status':'rollback_failed'}
        self.assertEqual(self.request('POST','/api/pools/dns-route',{'pool':'A','mode':'manual','ip':'192.0.2.1'})[0],409)
        self.manager.sync_subdomain.assert_not_called()

    def test_invalid_node_never_changes_dns(self):
        self.assertEqual(self.request('POST', '/api/pools/dns-route', {'pool':'A','mode':'manual','ip':'192.0.2.99'})[0],400)
        self.manager.sync_subdomain.assert_not_called()

    def test_read_failure_never_changes_dns(self):
        self.manager.record_snapshot.return_value = {'success':False,'records':[]}
        self.assertEqual(self.request('POST','/api/pools/dns-route',{'pool':'A','mode':'manual','ip':'192.0.2.1'})[0],502)
        self.manager.sync_subdomain.assert_not_called()

    def test_manual_verified_route_holds_shared_domain_and_can_restore_auto(self):
        self.manager.record_snapshot.return_value = {'success':True,'records':[{'content':'192.0.2.1'}]}
        self.manager.sync_subdomain.return_value = {'status':'SYNCED'}
        self.assertEqual(self.request('POST','/api/pools/dns-route',{'pool':'A','mode':'manual','ip':'192.0.2.1'})[0],200)
        key = route_key(CONFIG)
        self.assertEqual(self.data['dns_overrides'][key]['ip'],'192.0.2.1')
        self.assertEqual(self.data['watchdog_status']['pool_reports']['B']['source'],'manual')
        self.assertEqual(self.request('POST','/api/pools/dns-route',{'pool':'A','mode':'auto'})[0],200)
        self.assertNotIn(key,self.data['dns_overrides'])

    def test_partial_change_is_not_reported_as_success(self):
        self.manager.record_snapshot.return_value = {'success':True,'records':[{'content':'192.0.2.2'}]}
        self.manager.sync_subdomain.return_value = {'status':'SYNCED'}
        self.assertEqual(self.request('POST','/api/pools/dns-route',{'pool':'A','mode':'manual','ip':'192.0.2.1'})[0],502)
        self.assertNotIn('dns_overrides',self.data)

class ManualWatchdogTests(unittest.TestCase):
    def test_watchdog_keeps_manual_target_despite_other_healthy_node(self):
        data={'cloudflare':CONFIG,'dns_overrides':{route_key(CONFIG):{'ip':'192.0.2.1','version':'v1'}},'pools':{'A':{'nodes':[{'ip':'192.0.2.1'},{'ip':'192.0.2.2'}],'client_ports':['443']}}}
        watchdog=TelemetryWatchdog()
        with patch('core.watchdog.load_data',return_value=data), patch('core.watchdog.routing_lock',side_effect=nullcontext), patch.object(watchdog,'analyze_node_health',side_effect=[('FILTERED','test',[],{}),('HEALTHY','test',[],{})]), patch('core.watchdog.CloudflareManager') as manager:
            manager.return_value.sync_subdomain.return_value={}
            report=watchdog.run_check_cycle()
        manager.return_value.sync_subdomain.assert_called_once_with('edge.example.test',['192.0.2.1'],proxied=False,ttl=60)
        self.assertEqual(report['pool_reports']['A']['source'],'manual')
        self.assertEqual(report['pool_reports']['A']['override_version'],'v1')

    def test_watchdog_does_not_rewrite_dns_during_transport_change(self):
        data={'cloudflare':CONFIG,'pools':{'A':{'nodes':[{'ip':'192.0.2.1'}],'client_ports':['443'],'transport_change':{'status':'validating'}}}}
        watchdog=TelemetryWatchdog()
        with patch('core.watchdog.load_data',return_value=data),patch('core.watchdog.routing_lock',side_effect=nullcontext),patch.object(watchdog,'analyze_node_health',return_value=('HEALTHY','test',[],{})),patch('core.watchdog.CloudflareManager') as manager:
            watchdog.run_check_cycle()
        manager.assert_not_called()
