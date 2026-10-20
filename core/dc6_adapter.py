"""Managed cleartext DC6 carriers: native GRE6/IP6IP6 and IPv4 SIT."""
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
from core.adapter_interface import BaseTunnelAdapter
from core.adapter_registry import register_adapter
from core.ipv6_tunnel_tools import CLEARTEXT_WARNING, allocate_tunnel_ips, render_scoped_service, validate_mtu, check_ipv6_reachability
from core.gre import write

ENGINE_ID = 'dc6'
DEFAULT_CARRIER = 'ip6gre'
SUPPORTED_CARRIERS = {'ip6gre', 'ip6ip6', 'sit'}
DEFAULT_MTU, MIN_MTU, MAX_MTU = 1280, 1280, 1440
DEFAULT_MSS = 1220
FIREWALL = '/usr/local/libexec/vxlb-dc6-firewall.py'


def validate_dc6_mtu(value):
    return validate_mtu(value, MIN_MTU, MAX_MTU, tunnel_type='DC6')


def validate_carrier_type(value):
    value = str(value or DEFAULT_CARRIER).strip().lower()
    if value not in SUPPORTED_CARRIERS:
        raise ValueError('DC6 carrier must be ip6gre, ip6ip6 or sit')
    return value


def interface(value):
    value = str(value).removeprefix('vxlb-dc6-').removesuffix('.service')
    if not re.fullmatch(r'dc6-[0-9a-f]{10}', value):
        raise ValueError('Invalid owned DC6 interface')
    return value


class DC6Adapter(BaseTunnelAdapter):
    def __init__(self):
        super().__init__(ENGINE_ID)

    def install(self, ssh, role, config):
        from core.dc6_runtime import validate_outer
        try:
            carrier = validate_carrier_type(config.get('carrier_type'))
            remote = validate_outer(config['remote_ip'], carrier)
            module = {'ip6gre': 'ip6_gre', 'ip6ip6': 'ip6_tunnel', 'sit': 'sit'}[carrier]
            code, _, error = ssh.execute(f'test "$(id -u)" = 0 && modprobe {module} && command -v python3 ip iptables ip6tables systemctl')
            if code:
                raise RuntimeError(error or 'DC6 kernel prerequisites missing')
            if carrier != 'sit':
                ok, message = check_ipv6_reachability(ssh, remote)
                if not ok:
                    raise RuntimeError(message)
            write(ssh, FIREWALL, Path(__file__).with_name('dc6_firewall_agent.py').read_text())
            return True, 'DC6 carrier prerequisites ready'
        except Exception as error:
            return False, str(error)

    def configure(self, iran_node, kharej_server, pool_config):
        from core.dc6_runtime import validate_outer
        carrier = validate_carrier_type(pool_config.get('carrier_type'))
        mtu = validate_dc6_mtu(pool_config.get('mtu', DEFAULT_MTU))
        mss = int(pool_config.get('mss_clamp', mtu-60))
        if not 536 <= mss <= mtu-60:
            raise ValueError('DC6 MSS does not fit the IPv6 private MTU')
        local, remote = validate_outer(iran_node['ip'], carrier), validate_outer(kharej_server['ip'], carrier)
        if local == remote:
            raise ValueError('DC6 endpoints must be different servers')
        iface = interface(pool_config.get('interface') or 'dc6-'+secrets.token_hex(5))
        ips = allocate_tunnel_ips(base_id=iface, ipv4_subnet=pool_config.get('ipv4_subnet'),
                                 ipv6_subnet=pool_config.get('ipv6_subnet'), prefix_v4='10.216', prefix_v6='fd00:1db0:d')
        if carrier in {'sit', 'ip6ip6'}:
            ips['iran_ipv4'] = ips['kharej_ipv4'] = ips['ipv4_subnet'] = None
        def command(source, destination):
            if carrier == 'ip6gre':
                return f'ip link add {iface} type ip6gre local {source} remote {destination} encaplimit none hoplimit 64'
            if carrier == 'ip6ip6':
                return f'ip -6 tunnel add {iface} mode ip6ip6 local {source} remote {destination} encaplimit none hoplimit 64'
            return f'ip tunnel add {iface} mode sit local {source} remote {destination} ttl 64'
        service = f'vxlb-dc6-{iface}.service'
        firewall_path = f'/etc/vxlb/dc6/{iface}-fw.json'
        def unit(source, destination, role):
            other = 'kharej' if role == 'iran' else 'iran'
            text = render_scoped_service(service, iface, command(source, destination), mtu,
                                         ips[role+'_ipv4'], ips[role+'_ipv6'], ips[other+'_ipv4'], ips[other+'_ipv6'])
            return text.replace('RemainAfterExit=yes', f'RemainAfterExit=yes\nExecStartPre=/usr/bin/python3 {FIREWALL} apply {firewall_path}\nExecStopPost=/usr/bin/python3 {FIREWALL} remove {firewall_path}')
        def firewall_config(destination, role):
            other = 'kharej' if role == 'iran' else 'iran'
            return dict(interface=iface, carrier_type=carrier, remote_ip=destination, mtu=mtu, mss=mss,
                        peer_v4=ips[other+'_ipv4'], peer_v6=ips[other+'_ipv6'])
        return dict(engine=ENGINE_ID, mode=carrier, carrier_type=carrier, interface=iface, mtu=mtu,
                    mss_clamp=mss, mss_rule=f'TCPMSS --set-mss {mss}', local_ip=local, remote_ip=remote,
                    service_name=service, config_path=f'/etc/vxlb/dc6/{iface}.json', firewall_path=firewall_path,
                    iran_firewall=firewall_config(remote, 'iran'), kharej_firewall=firewall_config(local, 'kharej'),
                    iran_service_unit=unit(local, remote, 'iran'), kharej_service_unit=unit(remote, local, 'kharej'),
                    private_addressing=ips,
                    address_families=dict(external='ipv4' if carrier=='sit' else 'ipv6', internal=['ipv6'] if carrier in {'sit','ip6ip6'} else ['ipv4','ipv6']),
                    security=dict(requires_encryption=False, encryption_type='none', cleartext=True, warning=CLEARTEXT_WARNING))

    def start(self, ssh, name):
        try:
            iface = interface(name)
            code, out, error = ssh.execute(f'systemctl daemon-reload && systemctl enable vxlb-dc6-{iface}.service && systemctl restart vxlb-dc6-{iface}.service')
            return code == 0, error or out
        except Exception as error:
            return False, str(error)

    def stop(self, ssh, name):
        try:
            code, out, error = ssh.execute(f'systemctl stop vxlb-dc6-{interface(name)}.service')
            return code == 0, error or out
        except Exception as error:
            return False, str(error)

    def status(self, ssh, name):
        try:
            iface = interface(name)
            code, out, error = ssh.execute(f'systemctl is-active vxlb-dc6-{iface}.service && ip -j -s link show dev {iface}')
            return dict(status='UP' if code==0 else 'DOWN', details=dict(raw=out, error=error, path_verified=False))
        except Exception as error:
            return dict(status='DOWN', details=dict(error=str(error), path_verified=False))

    def probe(self, endpoint_ir, endpoint_kh, ports=None, **kwargs):
        from core.private_link_health import probe_pair
        try:
            return probe_pair(endpoint_ir['ssh'], endpoint_kh['ssh'], endpoint_ir['private_ip'], endpoint_kh['private_ip'], endpoint_ir['interface'])
        except Exception as error:
            return dict(passed=False, latency_ms=None, error=str(error))

    def modify(self, pool_name, updates):
        return False, 'DC6 MTU edits require a verified two-endpoint reconfiguration'

    def rollback(self, pool_name, previous_state):
        return False, 'DC6 rollback requires owned endpoint state'

    def clean(self, ssh, name):
        try:
            iface = interface(name)
            service = f'vxlb-dc6-{iface}.service'
            path = f'/etc/vxlb/dc6/{iface}-fw.json'
            code, _, error = ssh.execute(f'if test -f /etc/systemd/system/{service}; then systemctl stop {service} && systemctl disable {service} || exit $?; fi; if systemctl is-active --quiet {service}; then exit 1; fi; if test -f {path}; then python3 {FIREWALL} remove {path} || exit $?; fi; if ip link show dev {iface} >/dev/null 2>&1; then ip link del dev {iface} || exit $?; fi; rm -f /etc/systemd/system/{service} /etc/vxlb/dc6/{iface}.json {path} || exit $?; systemctl daemon-reload')
            if code:
                raise RuntimeError(error or 'DC6 cleanup failed')
            code, _, _ = ssh.execute(f'ip link show dev {iface} >/dev/null 2>&1')
            if code != 1:
                raise RuntimeError('DC6 interface removal could not be verified')
            return True, 'Owned DC6 interface and firewall rules removed'
        except Exception as error:
            return False, str(error)


def create(name, kharej, servers, ports, mtu=DEFAULT_MTU, carrier=DEFAULT_CARRIER, callback=None):
    from core.dc6_runtime import create as deploy
    return deploy(name, kharej, servers, ports, mtu=mtu, callback=callback, carrier=carrier)


register_adapter(DC6Adapter())
