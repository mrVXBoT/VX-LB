"""Ownership-scoped iptables cleanup for kernel tunnel engines.

Removes firewall rules previously installed by VX-LB's IPsec/monitoring layers
by their stable comment tags, even when the configuration that created them is
gone (e.g. after a rollback regenerated the reqid). Only rules carrying the
VX-LB tags for the given interface are touched, so installations from other
pools or admin rules are never modified.
"""
import shlex

PURGE_PROGRAM = '''import shlex,subprocess,sys
identifiers=sys.argv[1:]
tags=[]
for identifier in identifiers:
 tags.append('vxlb-sec-'+identifier)
 tags.append('vxlb-vx-'+identifier)
for chain in ('INPUT','OUTPUT','FORWARD'):
 out=subprocess.run(['iptables','-w','-S',chain],capture_output=True,text=True).stdout
 for line in out.splitlines():
  line=line.strip()
  prefix='-A '+chain+' '
  if not line.startswith(prefix):continue
  if not any(tag in line for tag in tags):continue
  subprocess.run(['iptables','-w','-D',chain]+shlex.split(line[len(prefix):]),stderr=subprocess.DEVNULL)
'''


PURGE_XFRM_PROGRAM = '''import subprocess,sys,re
l,r=sys.argv[1],sys.argv[2]
ipairs={(l+"/32",r+"/32"),(r+"/32",l+"/32")}
spairs={(l,r),(r,l)}
def run(argv):
 try:
  subprocess.run(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
 except Exception:pass
# Policies: parse `ip -j xfrm policy show` if possible else text.
def policies_json():
 try:
  out=subprocess.check_output(['ip','-j','xfrm','policy','show'],timeout=20)
  import json
  return json.loads(out)
 except Exception:
  return None
pj=policies_json()
if pj is not None:
 for p in pj:
  if str(p.get('dir','')).startswith('socket'):continue
  sel=p.get('sel') or {}
  src=sel.get('src');dst=sel.get('dst')
  if (src,dst) not in ipairs:continue
  cmd=['ip','xfrm','policy','del','src',src,'dst',dst]
  if sel.get('proto'):cmd+=['proto',sel['proto']]
  cmd+=['dir',p['dir']]
  run(cmd)
else:
 cur=None
 for ln in subprocess.run(['ip','xfrm','policy'],capture_output=True,text=True,timeout=20).stdout.splitlines():
  ln=ln.strip()
  if not ln:continue
  m=re.match(r'^src (\S+) dst (\S+)(?: proto (\S+))?',ln)
  if m:
   cur=(m.group(1),m.group(2),m.group(3))
   continue
  dm=re.match(r'^dir (\S+)',ln)
  if dm and cur and (cur[0],cur[1]) in ipairs:
   cmd=['ip','xfrm','policy','del','src',cur[0],'dst',cur[1]]
   if cur[2]:cmd+=['proto',cur[2]]
   cmd+=['dir',dm.group(1)]
   run(cmd)
# States
def states_json():
 try:
  out=subprocess.check_output(['ip','-j','xfrm','state','show'],timeout=20)
  import json
  return json.loads(out)
 except Exception:
  return None
sj=states_json()
if sj is not None:
 for st in sj:
  s=st.get('src');d=st.get('dst')
  if (s,d) not in spairs:continue
  cmd=['ip','xfrm','state','del','src',s,'dst',d,'proto',str(st.get('proto','esp'))]
  spi=st.get('spi')
  if spi is not None:cmd+=['spi','0x%x'%spi]
  run(cmd)
else:
 cur=None
 for ln in subprocess.run(['ip','xfrm','state'],capture_output=True,text=True,timeout=20).stdout.splitlines():
  ln=ln.strip()
  if not ln:continue
  m=re.match(r'^src (\S+) dst (\S+)',ln)
  if m:
   cur=(m.group(1),m.group(2));continue
  if cur and (cur[0],cur[1]) in spairs:
   sm=re.search(r'spi\s+(0x[0-9a-f]+)',ln)
   if sm:
    cmd=['ip','xfrm','state','del','src',cur[0],'dst',cur[1],'proto','esp','spi',sm.group(1)]
    run(cmd)
    cur=None
'''


def purge_kernel_engine_rules(ssh, *ifaces, timeout=30):
    """Best-effort removal of stale VX-LB kernel-engine firewall rule tags.

    Pass every interface identifier that could have produced rules on this
    host: the raw node name from older deployments and the normalized device
    name of the new one.
    """
    identifiers = [str(iface) for iface in ifaces if iface]
    if not identifiers:
        return 0
    try:
        _, out, _ = ssh.execute(
            'python3 -c ' + shlex.quote(PURGE_PROGRAM) + ' ' + ' '.join(shlex.quote(i) for i in identifiers),
            timeout=timeout,
        )
        try:
            return int(out.strip())
        except ValueError:
            return 0
    except Exception:
        return 0


def purge_xfrm_between_fast(local_ip, remote_ip):
    """Local (non-SSH) flush of XFRM policies/states between public endpoints."""
    import subprocess as _sp
    _sp.run(["python3", "-c", PURGE_XFRM_PROGRAM, str(local_ip), str(remote_ip)],
            timeout=30)


def purge_xfrm_between(ssh, local_ip, remote_ip, timeout=30):
    """Best-effort removal of stale IPsec XFRM policies/states between endpoints.

    A failed or rolled-back vxlan_ipsec run can leave a `proto udp` XFRM policy
    and its SA behind. Even after strongSwan is stopped (unload terminates the
    SA), the orphaned policy remains and forces every plain VXLAN UDP datagram
    between the two public IPs through ESP -> connect() fails with EHOSTUNREACH.
    This clears only policies/states whose src/dst match the public endpoint pair.
    """
    if not local_ip or not remote_ip:
        return 0
    try:
        _, out, _ = ssh.execute(
            'python3 -c ' + shlex.quote(PURGE_XFRM_PROGRAM) + ' ' + shlex.quote(str(local_ip)) + ' ' + shlex.quote(str(remote_ip)),
            timeout=timeout,
        )
        return 0
    except Exception:
        return 0
