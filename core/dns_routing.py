"""Serialize DNS changes across the web process and foreground watchdog."""
import fcntl
import os
import threading
from contextlib import contextmanager
from core.storage import DATA_DIR

_lock = threading.RLock()

@contextmanager
def routing_lock():
    with _lock:
        os.makedirs(DATA_DIR, mode=0o700, exist_ok=True)
        descriptor = os.open(os.path.join(DATA_DIR, 'dns-routing.lock'), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

def route_key(config):
    return config.get('zone_id', '').strip() + ':' + ('all:' if config.get('scope') == 'all_subdomains' else '') + config.get('subdomain', '').strip().lower()

def effective_config(data, name):
    return data.get('pools', {}).get(name, {}).get('cloudflare') or data.get('cloudflare') or {}

def scope_conflict(data, pool_name, config):
    for name in data.get('pools', {}):
        if name == pool_name: continue
        other = effective_config(data, name)
        if not other.get('enabled') or other.get('zone_id') != config.get('zone_id'): continue
        root = config.get('subdomain','').removeprefix('*.').lower()
        target = other.get('subdomain','').removeprefix('*.').lower()
        if (config.get('scope') == 'all_subdomains' and (target == root or target.endswith('.'+root))) or (other.get('scope') == 'all_subdomains' and (root == target or root.endswith('.'+target))):
            return name
    return None

def snapshot_matches(snapshot, ips):
    if not snapshot.get('success'): return False
    names = snapshot.get('names')
    if snapshot.get('scope') == 'all_subdomains':
        return bool(names) and all({r['content'] for r in snapshot.get('records',[]) if r['name'].lower() == name} == set(ips) for name in names)
    return {r['content'] for r in snapshot.get('records',[])} == set(ips)
