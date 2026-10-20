"""Linux TUN adapter backed by BackPack's UDP/Noise L3 carrier."""
import re
import shlex
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core import tun_runtime as runtime

ENGINE_ID = 'tun'
DEFAULT_MTU = runtime.DEFAULT_MTU
MIN_MTU, MAX_MTU = 1200, 1420
validate_tun_mtu = runtime.validate_mtu
create, add, remove, remove_pool, health = runtime.create, runtime.add, runtime.remove, runtime.remove_pool, runtime.health


def identifier(value):
    if not re.fullmatch(r'lbt[0-9a-f]{10}', str(value)):
        raise ValueError('Invalid managed TUN interface')
    return value


class TunDedicatedAdapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__(ENGINE_ID)

    def install(self, ssh, role, config):
        try:
            runtime.install(ssh)
            return True, 'Linux TUN and authenticated L3 engine ready'
        except Exception as error:
            return False, str(error)

    def configure(self, iran_node, kharej_server, pool_config):
        node = runtime.allocate(iran_node, kharej_server, pool_config.get('mtu', DEFAULT_MTU),
                                int(pool_config.get('tunnel_port', 51830)))
        ports = pool_config.get('client_ports', [])
        iran_files, iran_services = runtime.artifacts(node, 'iran', ports)
        kharej_files, kharej_services = runtime.artifacts(node, 'kharej', ports)
        return dict(node=node, interface=node['tun']['interface'], mtu=node['tun']['mtu'],
                    iran_inner=node['tun']['local_private'], kharej_inner=node['tun']['remote_private'],
                    iran_files=iran_files, kharej_files=kharej_files,
                    iran_services=iran_services, kharej_services=kharej_services)

    def start(self, ssh, name):
        try:
            iface = identifier(name)
            runtime.execute(ssh, f'systemctl daemon-reload && systemctl enable --now ldbp-tun-{iface}.service')
            return True, 'TUN service started; data health requires a probe'
        except Exception as error:
            return False, str(error)

    def stop(self, ssh, name):
        try:
            runtime.execute(ssh, f'systemctl stop ldbp-tun-{identifier(name)}.service')
            return True, 'TUN service stopped'
        except Exception as error:
            return False, str(error)

    def status(self, ssh, name):
        try:
            iface = identifier(name)
            code, out, error = ssh.execute(f'ip -j -s link show dev {shlex.quote(iface)}')
            return {'status': 'UP' if code == 0 else 'DOWN', 'details': {'interface': iface, 'link': out, 'error': error, 'path_verified': False}}
        except Exception as error:
            return {'status': 'DOWN', 'details': {'error': str(error), 'path_verified': False}}

    def probe(self, endpoint_ir, endpoint_kh, ports=None, **kwargs):
        try:
            result = runtime.probe_pair(endpoint_ir['ssh'], endpoint_kh['ssh'], endpoint_ir['private_ip'],
                                        endpoint_kh['private_ip'], endpoint_ir['interface'])
            return result
        except Exception as error:
            return {'passed': False, 'latency_ms': None, 'error': str(error)}

    def modify(self, pool_name, updates):
        return False, 'TUN MTU changes require a verified two-endpoint reconfiguration'

    def rollback(self, pool_name, previous_state):
        return False, 'TUN rollback requires the owned endpoint configuration'

    def clean(self, ssh, name, **kwargs):
        node, role = kwargs.get('node'), kwargs.get('role')
        if not node or role not in ['iran', 'kharej']:
            return False, 'Owned TUN node and endpoint role are required for cleanup'
        try:
            if identifier(name) != node['tun']['interface']:
                raise ValueError('TUN cleanup identity mismatch')
            runtime.cleanup(ssh, node, role, kwargs.get('ports', []))
            return True, 'Owned TUN resources removed and verified'
        except Exception as error:
            return False, str(error)


register_adapter(TunDedicatedAdapter())
