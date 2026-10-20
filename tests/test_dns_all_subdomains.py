import unittest
from unittest.mock import patch
from urllib.parse import urlparse,parse_qs
from core.cloudflare import CloudflareManager
from core.dns_routing import route_key,scope_conflict,snapshot_matches

class AllSubdomainsTests(unittest.TestCase):
    def manager(self, records):
        manager=CloudflareManager('fake','fake');manager.scope='all_subdomains'
        records=[dict(r) for r in records]
        def request(method,endpoint,data=None):
            if method=='GET':
                query=parse_qs(urlparse(endpoint).query)
                values=[r for r in records if r.get('type')=='A' and ('name' not in query or r['name']==query['name'][0])]
                return {'success':True,'result':values}
            if method=='POST':records.append({**data,'id':str(len(records)+20)});return {'success':True,'result':records[-1]}
            if method=='DELETE':records[:]=[r for r in records if r['id']!=endpoint[1:]];return {'success':True}
            if method=='PATCH':
                for r in records:
                    if r['id']==endpoint[1:]: r.update(data)
                return {'success':True}
        manager._request=request
        return manager,records
    def test_sync_all_a_subdomains_and_leave_apex_and_other_types(self):
        initial=[{'id':str(i),'name':name,'type':kind,'content':'192.0.2.10','proxied':True} for i,(name,kind) in enumerate([
          ('example.test','A'),('ssh.example.test','A'),('deep.ssh.example.test','A'),('*.example.test','A'),('alias.example.test','CNAME'),('ipv6.example.test','AAAA'),('other.test','A')])]
        m,records=self.manager(initial)
        result=m.sync_subdomain('example.test',['192.0.2.20'])
        self.assertEqual(result['status'],'SYNCED')
        self.assertEqual(result['names'],['*.example.test','deep.ssh.example.test','ssh.example.test'])
        self.assertTrue(snapshot_matches(m.record_snapshot('example.test'),['192.0.2.20']))
        for r in records:
            if r['name'] in result['names']:
                self.assertEqual(r['content'],'192.0.2.20');self.assertFalse(r['proxied'])
            else:self.assertEqual(r['content'],'192.0.2.10')
        records.append({'name':'new.example.test','id':'new','type':'A','content':'192.0.2.10'})
        self.assertEqual(m.sync_subdomain('example.test',['192.0.2.20'])['status'],'SYNCED')
        self.assertTrue(snapshot_matches(m.record_snapshot('example.test'),['192.0.2.20']))
    def test_pagination_error_prevents_all_writes(self):
        m=CloudflareManager('fake','fake');m.scope='all_subdomains'
        with patch.object(m,'_request',side_effect=[{'success':True,'result':[{'name':'ssh.example.test','type':'A'}],'result_info':{'total_pages':2}},{'success':False}]) as request:
            self.assertEqual(m.sync_subdomain('example.test',['192.0.2.20'])['status'],'ABORTED_DISCOVERY')
            self.assertTrue(all(c.args[0]=='GET' for c in request.call_args_list))
    def test_failed_add_never_deletes_last_record_of_any_name(self):
        m,records=self.manager([{'id':'1','name':'ssh.example.test','type':'A','content':'192.0.2.10'}])
        with patch.object(m,'add_a_record',return_value=(False,'failed')):
            self.assertEqual(m.sync_subdomain('example.test',['192.0.2.20'])['status'],'PARTIAL')
        self.assertEqual(records[0]['content'],'192.0.2.10')
    def test_snapshot_requires_each_name_not_union(self):
        snap={'success':True,'scope':'all_subdomains','names':['a.test','b.test'],'records':[{'name':'a.test','content':'192.0.2.20'},{'name':'b.test','content':'192.0.2.10'}]}
        self.assertFalse(snapshot_matches(snap,['192.0.2.20']))
    def test_scope_keys_and_conflicts(self):
        allcfg={'zone_id':'zone','subdomain':'example.test','scope':'all_subdomains','enabled':True}
        single={**allcfg,'subdomain':'ssh.example.test','scope':'single'}
        self.assertNotEqual(route_key(allcfg),route_key({**allcfg,'scope':'single'}))
        self.assertEqual(scope_conflict({'pools':{'other':{'cloudflare':single}}},'pool',allcfg),'other')
        self.assertIsNone(scope_conflict({'pools':{'other':{'cloudflare':{**single,'zone_id':'different'}}}},'pool',allcfg))

    def test_pool_save_rejects_overlap_with_inherited_global_config(self):
        from core.load_balancer import LoadBalancerManager
        data={'pools':{'new':{},'inherited':{}},'cloudflare':{'enabled':True,'zone_id':'zone','subdomain':'ssh.example.test'}}
        with patch('core.load_balancer.get_pools',return_value=data['pools']),patch('core.load_balancer.load_data',return_value=data),patch('core.load_balancer.save_pool') as save:
            ok,_=LoadBalancerManager.set_pool_cloudflare('new','fake','zone','example.test',scope='all_subdomains')
            self.assertFalse(ok)
            save.assert_not_called()
