"""Checked deployment and owned cleanup for GRE6 and IP6IP6 links."""
import shlex
import re


def publish(ssh, path, content):
    if not ssh.write_file(path, content):
        raise RuntimeError('Could not write native IPv6 tunnel artifact: ' + path)


def cleanup_endpoint(ssh, adapter, interface, engine):
    if engine not in {'gre6', 'ip6ip6', 'dc6'}:
        raise ValueError('Invalid native IPv6 engine')
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', interface):
        raise ValueError('Invalid native IPv6 interface')
    service = f'vxlb-{engine}-{interface}-relay.service'
    code, _, error = ssh.execute(
        f'systemctl stop {shlex.quote(service)} 2>/dev/null || true; '
        f'systemctl disable {shlex.quote(service)} 2>/dev/null || true; '
        f'if systemctl is-active --quiet {shlex.quote(service)}; then exit 1; fi; '
        f'rm -f /etc/systemd/system/{shlex.quote(service)} /etc/vxlb/{shlex.quote(interface)}-relay.py; '
        'systemctl daemon-reload'
    )
    if code:
        raise RuntimeError('Native IPv6 relay cleanup failed: ' + error)
    ok, message = adapter.clean(ssh, interface)
    if not ok:
        raise RuntimeError(message)
