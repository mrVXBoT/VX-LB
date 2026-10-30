"""Read current-process control state without restarting or probing user ports."""
import re
import shlex


def control_connected(ssh, unit):
    command = 'systemctl show -p ActiveState -p MainPID -p ExecMainStartTimestamp ' + shlex.quote(unit)
    code, output, _ = ssh.execute(command)
    values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    pid = values.get('MainPID', '')
    if code or values.get('ActiveState') != 'active' or not pid.isdigit() or pid == '0':
        return False
    start = values.get('ExecMainStartTimestamp', '')
    if not start: return False
    code, logs, _ = ssh.execute('journalctl -u ' + shlex.quote(unit) + ' _PID=' + pid +
        ' --since ' + shlex.quote(start) + ' --no-pager -o cat --grep control -n 100', timeout=15)
    # Missing --grep support or an empty journal is not the same as "control closed".
    if code not in (0, 1):
        logs = ''
    events = [line for line in logs.splitlines() if re.search(
        r'control channel.*(?:established|closed)|failed.*control|failed to receive control', line, re.I)]
    if events:
        return bool(re.search(r'control channel.*established', events[-1], re.I))
    code, sockets, _ = ssh.execute('ss -H -tnp', timeout=15)
    if code not in (0, 1):
        return False
    token = 'pid=%s,' % pid
    return any(line.split()[:1] == ['ESTAB'] and token in line for line in sockets.splitlines() if line.split())
