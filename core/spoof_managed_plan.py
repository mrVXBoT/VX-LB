"""Owned endpoint plans for packet profiles, pending lifecycle/wire acceptance.

Every profile uses the authenticated TCP/UDP relay through CONNECT. Packet
modification acts on the real outer TLS or HTTP flow; it must be independently
observed before the managed lifecycle can accept a node. No deployment entry
point is enabled by this module.
"""
import copy
import ipaddress
import json
from pathlib import Path
import shlex
from core import http_transport
from core.nfqws2_profiles import LIBRARY_DIRECTORY,build,MODES,number

LIBRARY = LIBRARY_DIRECTORY


def requires(text, parents):
    units=' '.join(parents)
    return text.replace('[Service]',f'After={units}\nRequires={units}\nPartOf={units}\n[Service]',1)


def plan(node,pool):
    mode=node.get('transport')
    if mode not in MODES or node.get('engine')!='spoof':
        raise ValueError('Owned managed packet profile required')
    spec=node['spoof'];identity=node['http_connect']['id']
    if spec.get('profile')!=mode:raise ValueError('Packet profile metadata does not match node')
    peer=str(ipaddress.IPv4Address(pool['kharej_server']['ip']))
    profile=build(mode,spec['queue'],node['http_connect']['public_port'],LIBRARY,
                  fake_sni=spec.get('fake_sni','www.shaparak.ir'),ttl_delta=spec.get('ttl_delta',3))
    shadow=copy.deepcopy(node)
    shadow['transport']=shadow['engine']='http' if profile.carrier=='http_connect' else 'https'
    result=http_transport.plan(shadow,pool)
    files=result['client_files'];base=result['base'];directory='/etc/vxlb/spoof/'+identity
    if mode=='hop-ttl-injection' and spec.get('fake_sni','www.shaparak.ir').lower()=='vxlb-http':
        raise ValueError('Fake SNI must differ from the authenticated carrier identity')
    queue_service='vxlb-spoof-'+identity+'-nfq.service'
    rules_service='vxlb-spoof-'+identity+'-queue.service'
    client_firewall,client_carrier,client_relay=result['client_services']
    files[directory+'/queue-agent.py']=Path(__file__).with_name('nfqws2_queue_agent.py').read_text()
    queue=dict(id=identity,peer=peer,carrier_port=node['http_connect']['public_port'],queue=spec['queue'],
               incoming=profile.incoming_queue,binary=LIBRARY+'/nfqws2')
    files[directory+'/queue.json']=json.dumps(queue)
    files[directory+'/wire.py']=Path(__file__).with_name('nfqws2_wire_agent.py').read_text()
    files[directory+'/wire.json']=json.dumps(dict(id=identity,profile=mode,local=node['ip'],peer=peer,carrier_port=node['http_connect']['public_port'],fake_sni=spec.get('fake_sni','www.shaparak.ir'),duration=20))
    arguments=[LIBRARY+'/nfqws2',*profile.arguments]
    nfq_unit=f'''[Unit]
Description=VX-LB owned packet engine
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart={' '.join(map(shlex.quote,arguments))}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
UMask=0077
TimeoutStopSec=20
[Install]
WantedBy=multi-user.target
'''
    files['/etc/systemd/system/'+queue_service]=requires(nfq_unit,[client_firewall])
    files['/etc/systemd/system/'+rules_service]=f'''[Unit]
Description=VX-LB owned peer-specific queue rules
After={queue_service}
Requires={queue_service}
PartOf={queue_service}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 {directory}/queue-agent.py apply {directory}/queue.json
ExecStopPost=/usr/bin/python3 {directory}/queue-agent.py remove {directory}/queue.json
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    services=[client_firewall,queue_service,rules_service]
    parents=[rules_service]
    if profile.carrier=='tls_records':
        record_port=number(spec['record_port'],1,65535,'TLS record helper port')
        reserved={int(value) for value in pool['client_ports']}
        reserved.update(int(node['http_connect'][key]) for key in ['probe_port','public_port','relay_backend_port','carrier_local_port'])
        if record_port in reserved:raise ValueError('TLS record helper port overlaps an owned listener')
        files[directory+'/records.py']=Path(__file__).with_name('tls_record_carrier.py').read_text()
        files[directory+'/records.json']=json.dumps(dict(listen_host='127.0.0.1',listen_port=record_port,remote_host=peer,remote_port=node['http_connect']['public_port']))
        record_service='vxlb-spoof-'+identity+'-records.service'
        files['/etc/systemd/system/'+record_service]=http_transport.unit(record_service,directory+'/records.py',directory+'/records.json',rules_service)
        services.append(record_service);parents.append(record_service)
        carrier=json.loads(files[base+'/client-carrier.json'])
        carrier.update(remote_host='127.0.0.1',remote_port=record_port)
        files[base+'/client-carrier.json']=json.dumps(carrier)
        firewall=json.loads(files[base+'/client-firewall.json'])
        firewall['extra_loopback_ports']=[record_port]
        files[base+'/client-firewall.json']=json.dumps(firewall)
    files['/etc/systemd/system/'+client_carrier]=requires(files['/etc/systemd/system/'+client_carrier],parents)
    services.extend([client_carrier,client_relay])
    result.update(client_services=services,packet_profile=profile,queue_config=queue,queue_directory=directory,
                  queue_service=queue_service,queue_rules_service=rules_service,trace_script=directory+'/wire.py',trace_config=directory+'/wire.json')
    return result
