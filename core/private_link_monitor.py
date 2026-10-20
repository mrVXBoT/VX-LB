"""Fresh standalone-link telemetry, distinct from persisted deployment state.

A running interface/handshake is never sufficient for HEALTHY: both directions
must pass TCP/UDP challenges. Results racing a mutation are discarded.
"""
import json
import shlex
import time
import threading

from core.storage import load_data, atomic_update
from core.transport_change import busy, connect
from core.private_link_runtime import endpoint
from core.private_link_health import probe_pair

INSPECT = '''import json,subprocess,sys
iface,service=sys.argv[1:]
def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=8)
link=run(['ip','-j','link','show','dev',iface])
active=run(['systemctl','is-active',service])
interfaces=json.loads(link.stdout) if link.returncode==0 else []
result={'interface_exists':bool(interfaces),'interface_up':bool(interfaces) and 'UP' in interfaces[0].get('flags',[]),'service_active':active.returncode==0 and active.stdout.strip()=='active'}
if result['interface_up']:
 handshake=run(['wg','show',iface,'latest-handshakes'])
 transfer=run(['wg','show',iface,'transfer'])
 result['last_handshake']=max([int(row.split()[1]) for row in handshake.stdout.splitlines() if len(row.split())==2] or [0])
 result['rx_bytes']=sum(int(row.split()[1]) for row in transfer.stdout.splitlines() if len(row.split())==3)
 result['tx_bytes']=sum(int(row.split()[2]) for row in transfer.stdout.splitlines() if len(row.split())==3)
print(json.dumps(result))
'''


def inspect_link(data, link):
    peers = {}
    result = dict(status='UNVERIFIED', checked_at=time.time(), endpoints={}, data_path=None)
    try:
        if link.get('engine_id') != 'wireguard' or link.get('status') != 'active':
            result['reason']='لینک نصب‌شدهٔ قابل پایش موجود نیست'
            return result
        iface=link['interface']
        import re
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', iface):
            raise ValueError('Invalid interface identity')
        for role in ('iran','kharej'):
            peer=peers[role]=connect(endpoint(data,link[role+'_server']['ip'],role))
            code,out,_=peer.execute('python3 -c '+shlex.quote(INSPECT)+' '+shlex.quote(iface)+' '+shlex.quote('wg-quick@'+iface+'.service'), timeout=20)
            if code:
                raise RuntimeError('Endpoint inspection incomplete')
            details=json.loads(out)
            if not isinstance(details, dict) or any(type(details.get(key)) is not bool for key in ('interface_up', 'service_active')):
                raise ValueError('Incomplete endpoint evidence')
            result['endpoints'][role]=details
            if details.get('interface_up') is not True or details.get('service_active') is not True:
                result.update(status='DOWN',reason='رابط یا سرویس یکی از دو سمت فعال نیست')
                return result
        try:
            challenge=probe_pair(peers['iran'],peers['kharej'],link['iran_server']['private_ip'],link['kharej_server']['private_ip'],iface)
            if challenge.get('passed') is not True or challenge.get('protocols')!=['tcp','udp'] or challenge.get('directions')!=['iran_to_kharej','kharej_to_iran']:
                raise ValueError('Incomplete path evidence')
            result.update(status='HEALTHY',reason='آزمون تازهٔ TCP/UDP در هر دو جهت موفق بود',data_path=challenge)
        except Exception:
            result.update(status='DEGRADED',reason='رابط‌ها فعال‌اند ولی عبور دادهٔ دوطرفه تأیید نشد')
    except Exception:
        result.update(status='UNVERIFIED',reason='دسترسی یا اطلاعات کافی برای تأیید سلامت موجود نیست')
    finally:
        for peer in peers.values():peer.close()
    return result


def check_cycle():
    data=load_data()
    if busy(data):return {}
    results={}
    for name,link in data.get('custom_links',{}).items():
        if link.get('status')!='active':continue
        if busy(load_data()):break
        result=inspect_link(data,link)
        def save(current):
            latest=current.get('custom_links',{}).get(name)
            if busy(current) or not latest or latest.get('link_id')!=link.get('link_id') or latest.get('status')!='active' or latest.get('runtime')!=link.get('runtime'):
                return
            latest['telemetry']=result
            results[name]=result
        atomic_update(save)
    return results


_cycle_lock=threading.Lock()

def schedule_cycle():
    data=load_data()
    if busy(data) or not any(link.get('status')=='active' for link in data.get('custom_links',{}).values()):
        return False
    if not _cycle_lock.acquire(blocking=False):
        return False
    def worker():
        try:check_cycle()
        finally:_cycle_lock.release()
    try:
        threading.Thread(target=worker,daemon=True,name='private-link-monitor').start()
    except Exception:
        _cycle_lock.release()
        return False
    return True
