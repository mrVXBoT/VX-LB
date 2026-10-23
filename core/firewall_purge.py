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
