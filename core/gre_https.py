"""Compose a real kernel GRE link with the authenticated XHTTP UDP carrier.

Only loopback GRE-in-UDP is exposed to Xray. TLS replaces IPsec for this
separate mode; existing GRE/IPsec pools are never converted implicitly.
"""
import ipaddress
import json
import secrets
import shlex
from pathlib import Path
from core.storage import get_pools

AGENT = '/usr/local/libexec/vxlb-gre-https.py'


def config_path(node):
    from core.https_tunnel import path
    return path(node)+'.gre.json'


def units(node):
    from core.https_tunnel import unit
    return [unit(node).replace('.service', suffix+'.service') for suffix in ('-gre', '-relay')]


def allocate(node, sessions, ports):
    from core import https_tunnel as h
    used = {c['private'] for p in get_pools().values() for n in p.get('nodes', []) for c in n.get('gre_https', [])}
    for subnet in ipaddress.IPv4Network('10.204.0.0/16').subnets(new_prefix=30):
        a, b = map(str, subnet.hosts())
        if a not in used and b not in used: break
    else: raise ValueError('GRE HTTPS address pool exhausted')
    key = secrets.randbelow(4294967295)+1
    configs = []
    for i, ssh in enumerate(sessions):
        excluded = [*ports, node['https']['probe_local'], node['https']['probe_remote'], node['https']['outer_port']]
        receive = h.free_port(ssh, exclude=excluded)
        carrier = h.free_port(ssh, exclude=[*excluded, receive])
        configs.append(dict(owner=node['node_name'], interface='ldc'+node['node_name'][3:13],
                            role='iran' if i == 0 else 'kharej', private=a if i == 0 else b, peer=b if i == 0 else a,
                            key=key, mtu=1280, receive_port=receive, carrier_port=carrier, ports=ports))
    node['gre_https'] = configs


def carrier_configs(node, iran, outside):
    a, b = node['gre_https']
    # Remove all public dokodemo entries: user traffic must cross GRE first.
    iran['inbounds'] = [x for x in iran['inbounds'] if x['tag'] == 'probe']
    iran['inbounds'].append({'tag':'gre-carrier','listen':'127.0.0.1','port':a['carrier_port'], 'protocol':'dokodemo-door',
                             'settings':{'address':'127.0.0.1','port':b['carrier_port'],'network':'udp'}})
    # No direct application access through this authenticated account.
    outside['routing']['rules'] = [
        {'type':'field','inboundTag':['secure-in'],'ip':['127.0.0.1/32'],'port':str(b['carrier_port']),'network':'udp','outboundTag':'backend'},
        {'type':'field','inboundTag':['secure-in'],'ip':['127.0.0.1/32'],'port':str(node['https']['probe_remote']),'network':'tcp,udp','outboundTag':'backend'}]
    return iran, outside


def provision(sessions, node, ports):
    from core import https_tunnel as h
    for ssh, c in zip(sessions, node['gre_https']):
        h.execute(ssh, 'command -v ip && command -v ping && modprobe ip_gre && modprobe fou')
        h.write(ssh, AGENT, Path(__file__).with_name('gre_https_agent.py').read_text())
        h.write(ssh, '/usr/local/libexec/vxlb-gre-v1.py', Path(__file__).with_name('gre_agent.py').read_text())
        h.execute(ssh, 'test ! -e '+config_path(node)+' && test ! -e /etc/systemd/system/'+units(node)[0])
        c = dict(c, ports=ports)
        h.write(ssh, config_path(node), json.dumps(c))
        for relay in (False, True) if c['role'] == 'iran' else (False,):
            resource = units(node)[int(relay)]
            parent = units(node)[0] if relay else h.unit(node)
            service = f'''[Unit]
Description=VX-LB GRE inside authenticated HTTPS {'port relay' if relay else 'link'}
After=network-online.target {parent}
Requires={parent}
PartOf={parent}
[Service]
Type=simple
ExecStart=/usr/bin/python3 {AGENT} {'relay' if relay else 'serve'} {config_path(node)}
{'' if relay else 'ExecStopPost=/usr/bin/python3 '+AGENT+' down '+config_path(node)}
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
CapabilityBoundingSet={'CAP_NET_BIND_SERVICE' if relay else 'CAP_NET_ADMIN CAP_NET_RAW'}
ProtectHome=yes
ProtectSystem=strict
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
PrivateTmp=yes
ReadWritePaths=/run
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
'''
            h.write(ssh, '/etc/systemd/system/'+resource, service)
        h.execute(ssh, 'systemctl daemon-reload')
    # Start the remote return adapter first. The Iran keepalive establishes the
    # authenticated association before either-side data probes are accepted.
    for i in (1, 0): h.execute(sessions[i], 'systemctl enable --now '+units(node)[0])
    verify(*sessions, node)
    h.execute(sessions[0], 'systemctl enable --now '+units(node)[1])
    relay_ready(sessions[0], node, ports)


def verify(iran, outside, node):
    from core import https_tunnel as h
    import time
    error = None
    for attempt in range(3):
        try:
            for ssh in (iran, outside):
                h.execute(ssh, 'systemctl is-active --quiet '+units(node)[0])
                h.execute(ssh, 'python3 '+AGENT+' check '+config_path(node))
            for source, target in ((iran, outside), (outside, iran)):
                channel = None
                try:
                    _, out, _ = target.client.exec_command('python3 '+AGENT+' echo '+config_path(node), timeout=10)
                    channel = out.channel
                    port = out.readline().strip()
                    if not port.isdigit(): raise RuntimeError('GRE HTTPS echo did not start')
                    h.execute(source, 'python3 '+AGENT+' probe '+config_path(node)+' '+port+' '+secrets.token_hex(32), timeout=20)
                finally:
                    if channel: channel.close()
            return
        except RuntimeError as failure: error = failure; time.sleep(.5)
    raise error


def relay_ready(ssh, node, ports):
    from core import https_tunnel as h
    import time
    script = '''import subprocess,sys,json
pid=subprocess.check_output(['systemctl','show','--property=MainPID','--value',sys.argv[1]],text=True).strip()
assert pid.isdigit() and int(pid)>0
ports=set(map(int,json.loads(sys.argv[2])))
for mode in ['-ltnp','-lunp']:
 text=subprocess.check_output(['ss',mode],text=True)
 bound={int(x.split()[3].rsplit(':',1)[-1]) for x in text.splitlines()[1:] if 'pid='+pid+',' in x}
 assert ports.issubset(bound)
'''
    command = 'python3 -c '+shlex.quote(script)+' '+units(node)[1]+' '+shlex.quote(json.dumps(ports))
    for _ in range(10):
        if ssh.execute(command)[0] == 0: return
        time.sleep(.3)
    raise RuntimeError('GRE HTTPS relay did not bind all entry ports')


def update_ports(sessions, node, ports):
    from core import https_tunnel as h
    for ssh, c in zip(sessions, node['gre_https']): h.write(ssh, config_path(node), json.dumps(dict(c, ports=ports)))
    h.execute(sessions[0], 'systemctl restart '+units(node)[1])
    relay_ready(sessions[0], node, ports)


def clean(ssh, node, iran):
    from core import https_tunnel as h
    for resource in reversed(units(node) if iran else units(node)[:1]):
        h.execute(ssh, 'if test -f /etc/systemd/system/'+resource+'; then systemctl disable --now '+resource+'; fi')
    # Config may not have been published if preflight failed.
    h.execute(ssh, 'if test -f '+config_path(node)+'; then python3 '+AGENT+' down '+config_path(node)+'; fi')
    h.execute(ssh, 'rm -f '+config_path(node)+' '+' '.join('/etc/systemd/system/'+u for u in units(node))+' && systemctl daemon-reload')
