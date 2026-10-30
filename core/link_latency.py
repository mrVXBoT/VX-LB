"""Round-trip time shown on every node card.

WatTunnel already publishes the protocol RTT (`srtt_ms`). Other engines either
time a handshake that crossed the tunnel or, for a TCP tunnel, read the kernel
RTT of the session toward the far server. A missing sample stays empty; the
management SSH session is never reported as the tunnel ping.
"""
import shlex


def positive_ms(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number <= 0 or number > 60000:
        return None
    return round(number, 1)


def extract(details):
    """Smallest positive latency_ms anywhere in a health-details tree."""
    found = []

    def walk(node):
        if not isinstance(node, dict):
            return
        sample = positive_ms(node.get('latency_ms'))
        if sample is not None:
            found.append(sample)
        for value in node.values():
            walk(value)

    walk(details)
    return min(found) if found else None


def stamp(details, latency_ms):
    """Copy one tunnel sample onto each per-port detail that has a status."""
    sample = positive_ms(latency_ms)
    if sample is None or not isinstance(details, dict):
        return details
    for value in details.values():
        if isinstance(value, dict) and 'status' in value and positive_ms(value.get('latency_ms')) is None:
            value['latency_ms'] = sample
    return details


_PEER_RTT = r'''import re,subprocess,sys
peer=sys.argv[1]
try:
 out=subprocess.check_output(["ss","-tin"],text=True,errors="replace")
except Exception:
 print(""); raise SystemExit
best=None
block=""
def take(text):
 global best
 if peer not in text.split("\n",1)[0]: return
 match=re.search(r"\brtt:([0-9.]+)", text)
 if not match: return
 value=float(match.group(1))
 if value>0 and (best is None or value<best): best=value
for line in out.splitlines():
 if line[:1] not in (" ","\t"):
  if block: take(block)
  block=line
 else:
  block+="\n"+line
if block: take(block)
print("" if best is None else round(best,1))
'''


def peer_tcp_rtt(ssh, peer):
    """Kernel RTT, in milliseconds, of an established TCP session to peer."""
    if not peer or ssh is None or not hasattr(ssh, 'execute'):
        return None
    code, out, _ = ssh.execute(
        'python3 -c ' + shlex.quote(_PEER_RTT) + ' ' + shlex.quote(str(peer)),
        timeout=8,
    )
    if code != 0 or not (out or '').strip():
        return None
    try:
        return positive_ms(float(out.strip().splitlines()[-1]))
    except ValueError:
        return None


def annotate(ssh, peer, details):
    """Attach the far-end TCP RTT when this health check did not time the path."""
    return stamp(details, peer_tcp_rtt(ssh, peer))
