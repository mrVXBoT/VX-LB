"""Adapter registry contract for owned HTTP/HTTPS CONNECT pools."""
import re
import shlex
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core import http_transport as runtime


class HttpConnectAdapter(BaseTunnelAdapter):
    def __init__(self, mode='http'):
        if mode not in runtime.MODES:raise ValueError('Invalid HTTP adapter mode')
        super().__init__(mode)

    def install(self, ssh, role, config):
        try:runtime.install(ssh);return True,'Python TLS1.3 HTTP runtime prerequisites verified'
        except Exception as error:return False,str(error)

    def configure(self, iran_node, kharej_server, pool_config):
        if not iran_node.get('http_connect'):raise ValueError('Owned HTTP allocation is required before configuration')
        return runtime.plan(iran_node,{**pool_config,'kharej_server':kharej_server})

    def start(self, ssh, identifier):
        return False,'Start requires the complete owned HTTP endpoint plan'

    def stop(self, ssh, identifier):
        return False,'Stop requires the complete owned HTTP endpoint plan'

    def status(self, ssh, identifier):
        if not re.fullmatch(r'ldbp-http-[0-9a-f]{32}-(client|server)(-carrier|-firewall)?\.service',str(identifier)):
            return {'status':'DOWN','details':{'error':'Invalid owned HTTP service'}}
        code,out,error=ssh.execute('systemctl is-active '+shlex.quote(identifier))
        return {'status':'UP' if code==0 and out.strip()=='active' else 'DOWN','details':{'path_verified':False,'error':error}}

    def probe(self, endpoint_ir, endpoint_kh, ports=None, **kwargs):
        try:return runtime.verify(endpoint_ir['ssh'],endpoint_kh['ssh'],kwargs['node'])
        except Exception as error:return {'passed':False,'latency_ms':None,'error':str(error)}

    def modify(self, pool_name, updates):
        if 'transport' in updates:return runtime.change_mode(pool_name,updates['transport'])
        if 'client_ports' in updates:return runtime.change_ports(pool_name,updates['client_ports'])
        return False,'No supported HTTP settings requested'

    def rollback(self, pool_name, previous_state):
        return False,'HTTP rollback is performed by its checked two-endpoint transaction'

    def clean(self, ssh, identifier, **kwargs):
        node,pool,role=kwargs.get('node'),kwargs.get('pool'),kwargs.get('role')
        if not node or not pool or role not in ['client','server']:return False,'Owned HTTP node, pool and endpoint role are required'
        try:
            if identifier!=node['node_name']:raise ValueError('HTTP cleanup ownership mismatch')
            plan=runtime.plan(node,pool);runtime.cleanup(ssh,plan[role+'_files'],plan[role+'_services'])
            return True,'Owned HTTP endpoint removed'
        except Exception as error:return False,str(error)


for mode in ['http','https']:register_adapter(HttpConnectAdapter(mode))
