import os
import subprocess
import pytest
import yaml

from core.paqet_adapter import (
    PaqetAdapter,
    validate_interface,
    validate_mac,
    validate_cipher,
    validate_kcp_mode,
    validate_tcp_flags,
    generate_paqet_secret,
    parse_gateway_route,
    build_forward_rule,
    SUPPORTED_CIPHERS,
    SUPPORTED_KCP_MODES,
)


def test_validation_interface():
    assert validate_interface("eth0") == "eth0"
    assert validate_interface("ens3") == "ens3"
    assert validate_interface("enx0c5b8f279a64") == "enx0c5b8f279a64"
    assert validate_interface("wg0") == "wg0"

    with pytest.raises(ValueError):
        validate_interface("eth0; rm -rf /")
    with pytest.raises(ValueError):
        validate_interface("eth 0")
    with pytest.raises(ValueError):
        validate_interface("eth0$HOME")


def test_validation_mac():
    assert validate_mac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff"
    assert validate_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert validate_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"

    with pytest.raises(ValueError):
        validate_mac("invalid_mac")
    with pytest.raises(ValueError):
        validate_mac("aa:bb:cc:dd:ee")
    with pytest.raises(ValueError):
        validate_mac("aa:bb:cc:dd:ee:ff:11")
    with pytest.raises(ValueError):
        validate_mac("aa:bb:cc:dd:ee:zz")


def test_validation_cipher():
    for c in ["aes", "aes-128", "aes-128-gcm", "salsa20", "sm4", "none"]:
        assert validate_cipher(c) == c

    with pytest.raises(ValueError):
        validate_cipher("invalid-cipher-name")


def test_validation_kcp_mode():
    for m in ["normal", "fast", "fast2", "fast3", "manual"]:
        assert validate_kcp_mode(m) == m

    with pytest.raises(ValueError):
        validate_kcp_mode("turbo_super_fast")


def test_validation_tcp_flags():
    assert validate_tcp_flags(["PA"]) == ["PA"]
    assert validate_tcp_flags(["s", "a"]) == ["S", "A"]
    assert validate_tcp_flags([]) == ["PA"]

    with pytest.raises(ValueError):
        validate_tcp_flags(["INVALID_FLAG"])


def test_generate_paqet_secret():
    secret = generate_paqet_secret()
    assert len(secret) == 64
    assert all(c in "0123456789abcdef" for c in secret)
    # Ensure successive calls yield unique keys
    assert secret != generate_paqet_secret()


def test_build_forward_rule():
    # TCP rule
    tcp_rule = build_forward_rule(listen="0.0.0.0:8080", target="127.0.0.1:80", protocol="tcp")
    assert tcp_rule["listen"] == "0.0.0.0:8080"
    assert tcp_rule["target"] == "127.0.0.1:80"
    assert tcp_rule["protocol"] == "tcp"

    # UDP rule
    udp_rule = build_forward_rule(listen="5353", target="1.1.1.1:53", protocol="udp")
    assert udp_rule["listen"] == "0.0.0.0:5353"
    assert udp_rule["target"] == "1.1.1.1:53"
    assert udp_rule["protocol"] == "udp"

    # Port normalization
    rule = build_forward_rule(listen="443", target="127.0.0.1:8443", protocol="TCP")
    assert rule["protocol"] == "tcp"
    assert rule["listen"] == "0.0.0.0:443"

    # Error cases
    with pytest.raises(ValueError, match="Invalid forward protocol"):
        build_forward_rule(listen="8080", target="127.0.0.1:80", protocol="icmp")

    with pytest.raises(ValueError):
        build_forward_rule(listen="invalid_port", target="127.0.0.1:80")

    with pytest.raises(ValueError):
        build_forward_rule(listen="8080", target="invalid_target_no_port")


def test_parse_gateway_route():
    route_sample = "default via 192.168.8.1 dev enx0c5b8f279a64 proto dhcp src 192.168.8.100 metric 100"
    neigh_sample = "192.168.8.1 dev enx0c5b8f279a64 lladdr ac:bd:70:b5:b4:90 REACHABLE\n192.168.8.5 dev enx0c5b8f279a64 lladdr 00:11:22:33:44:55 STALE"

    iface, gw_ip, mac = parse_gateway_route(route_sample, neigh_sample)
    assert iface == "enx0c5b8f279a64"
    assert gw_ip == "192.168.8.1"
    assert mac == "ac:bd:70:b5:b4:90"

    # Test prefix collision where another IP (e.g. 192.168.8.130) precedes 192.168.8.1
    neigh_collision = (
        "192.168.8.130 dev enx0c5b8f279a64 lladdr 11:22:33:44:55:66 REACHABLE\n"
        "192.168.8.1 dev enx0c5b8f279a64 lladdr ac:bd:70:b5:b4:90 REACHABLE\n"
    )
    iface2, gw_ip2, mac2 = parse_gateway_route(route_sample, neigh_collision)
    assert iface2 == "enx0c5b8f279a64"
    assert gw_ip2 == "192.168.8.1"
    assert mac2 == "ac:bd:70:b5:b4:90"


def test_paqet_server_config():
    adapter = PaqetAdapter()
    secret = generate_paqet_secret()

    cfg_dict, yaml_str = adapter.build_server_config(
        listen_port=9999,
        interface="eth0",
        server_ip="45.38.41.122",
        router_mac="aa:bb:cc:dd:ee:ff",
        secret_key=secret,
        cipher="aes-128-gcm",
        kcp_mode="fast",
        local_flags=["PA"],
    )

    # Validate dictionary structure
    assert cfg_dict["role"] == "server"
    assert cfg_dict["listen"]["addr"] == ":9999"
    assert cfg_dict["network"]["interface"] == "eth0"
    assert cfg_dict["network"]["ipv4"]["addr"] == "45.38.41.122:9999"
    assert cfg_dict["network"]["ipv4"]["router_mac"] == "aa:bb:cc:dd:ee:ff"
    assert cfg_dict["transport"]["protocol"] == "kcp"
    assert cfg_dict["transport"]["kcp"]["block"] == "aes-128-gcm"
    assert cfg_dict["transport"]["kcp"]["key"] == secret
    assert cfg_dict["transport"]["kcp"]["mode"] == "fast"

    # Validate YAML output can be parsed back identically
    parsed = yaml.safe_load(yaml_str)
    assert parsed == cfg_dict


def test_paqet_client_config():
    adapter = PaqetAdapter()
    secret = generate_paqet_secret()

    forwards = [
        {"listen": "0.0.0.0:8080", "target": "127.0.0.1:80", "protocol": "tcp"},
        {"listen": "0.0.0.0:5353", "target": "127.0.0.1:53", "protocol": "udp"},
    ]
    socks = [{"listen": "127.0.0.1:1080"}]

    cfg_dict, yaml_str = adapter.build_client_config(
        server_ip="45.38.41.122",
        server_port=9999,
        interface="ens3",
        client_ip="95.211.40.28",
        router_mac="11:22:33:44:55:66",
        secret_key=secret,
        forward_rules=forwards,
        socks5_rules=socks,
        cipher="aes-128-gcm",
        kcp_mode="fast",
    )

    assert cfg_dict["role"] == "client"
    assert cfg_dict["network"]["interface"] == "ens3"
    assert cfg_dict["network"]["ipv4"]["addr"] == "95.211.40.28:0"
    assert cfg_dict["server"]["addr"] == "45.38.41.122:9999"
    assert cfg_dict["transport"]["protocol"] == "kcp"
    assert cfg_dict["transport"]["kcp"]["key"] == secret

    # Check TCP and UDP forward rules
    assert len(cfg_dict["forward"]) == 2
    assert cfg_dict["forward"][0] == {"listen": "0.0.0.0:8080", "target": "127.0.0.1:80", "protocol": "tcp"}
    assert cfg_dict["forward"][1] == {"listen": "0.0.0.0:5353", "target": "127.0.0.1:53", "protocol": "udp"}

    parsed = yaml.safe_load(yaml_str)
    assert parsed == cfg_dict


def test_iptables_commands():
    adapter = PaqetAdapter()
    setup_cmds = adapter.build_iptables_setup_commands(9999)
    # 2 sysctl lines + 4 iptables per port
    assert len(setup_cmds) == 6
    assert any("INPUT -p tcp --dport 9999 -j DROP" in cmd for cmd in setup_cmds)
    assert any("PREROUTING -p tcp --dport 9999 -j NOTRACK" in cmd for cmd in setup_cmds)
    assert any("OUTPUT -p tcp --sport 9999 -j NOTRACK" in cmd for cmd in setup_cmds)
    assert any("OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP" in cmd for cmd in setup_cmds)
    assert any("tcp_rfc1337" in cmd for cmd in setup_cmds)

    teardown_cmds = adapter.build_iptables_teardown_commands(9999)
    assert len(teardown_cmds) == 4
    assert any("-D INPUT -p tcp --dport 9999 -j DROP" in cmd for cmd in teardown_cmds)
    assert any("-D PREROUTING -p tcp --dport 9999 -j NOTRACK" in cmd for cmd in teardown_cmds)
    assert any("-D OUTPUT -p tcp --sport 9999 -j NOTRACK" in cmd for cmd in teardown_cmds)
    assert any("-D OUTPUT -p tcp --sport 9999 --tcp-flags RST RST -j DROP" in cmd for cmd in teardown_cmds)

    setup_with_extra = adapter.build_iptables_setup_commands(9999, extra_ports=[30068, 30068])
    # dedupe + 2 sysctl + 4*2 iptables
    assert len(setup_with_extra) == 10
    assert sum("dport 30068" in c or "sport 30068" in c for c in setup_with_extra) == 4


def test_systemd_unit():
    adapter = PaqetAdapter(paqet_bin="/usr/local/bin/paqet", config_dir="/etc/paqet")
    unit = adapter.build_systemd_unit("test_tunnel")

    assert "Description=Paqet Raw-Packet Tunnel (test_tunnel)" in unit
    assert "ExecStart=/usr/local/bin/paqet run -c /etc/paqet/test_tunnel.yaml" in unit
    assert "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN" in unit
    assert "LimitNOFILE=1048576" in unit
    assert "Restart=always" in unit


def test_real_paqet_binary_integration():
    """
    Tests against the official downloaded paqet binary if present.
    Verifies version output, secret generator execution, and CLI response.
    """
    binary_path = "/tmp/paqet_test/paqet_linux_amd64"
    if not os.path.exists(binary_path):
        pytest.skip("Official paqet binary not found at /tmp/paqet_test/paqet_linux_amd64")

    # 1. Test version command
    v_proc = subprocess.run([binary_path, "version"], capture_output=True, text=True, check=True)
    assert "v1.0.0-alpha.21" in v_proc.stdout

    # 2. Test secret generator command
    s_proc = subprocess.run([binary_path, "secret"], capture_output=True, text=True, check=True)
    cli_secret = s_proc.stdout.strip()
    assert len(cli_secret) == 64
    assert all(c in "0123456789abcdef" for c in cli_secret)

    # 3. Test help output
    h_proc = subprocess.run([binary_path, "--help"], capture_output=True, text=True, check=True)
    assert "paqet is a bidirectional packet-level proxy" in h_proc.stdout


class MockSSHManager:
    """Mock SSH Manager to test remote deployment sequence without network I/O."""

    def __init__(self, ip="10.0.0.1", succeed=True):
        self.ip = ip
        self.succeed = succeed
        self.executed_commands = []

    def execute(self, cmd, timeout=30):
        self.executed_commands.append(cmd)
        if "ip route show default" in cmd:
            return 0, "default via 10.0.0.1 dev eth0 proto dhcp", ""
        if "ip neigh show" in cmd:
            return 0, "10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE", ""
        if "ip -4 addr show dev eth0" in cmd:
            return 0, "inet 10.0.0.2/24 brd 10.0.0.255 scope global eth0", ""
        if not self.succeed:
            return 1, "", "Mock execution failed"
        return 0, "OK", ""


def test_deploy_server_node_mock():
    adapter = PaqetAdapter()
    ssh = MockSSHManager()
    secret = generate_paqet_secret()

    ok, msg = adapter.deploy_server_node(
        ssh=ssh,
        tunnel_name="mock_srv",
        tunnel_port=9999,
        secret_key=secret,
        interface="eth0",
        router_mac="aa:bb:cc:dd:ee:ff",
        server_ip="10.0.0.2",
    )
    assert ok is True
    assert "deployed successfully" in msg
    assert any("systemctl restart paqet-mock_srv.service" in cmd for cmd in ssh.executed_commands)
    assert any("NOTRACK" in cmd for cmd in ssh.executed_commands)


def test_deploy_client_node_mock():
    adapter = PaqetAdapter()
    ssh = MockSSHManager()
    secret = generate_paqet_secret()
    forwards = [{"listen": "8080", "target": "127.0.0.1:80", "protocol": "tcp"}]

    ok, msg = adapter.deploy_client_node(
        ssh=ssh,
        tunnel_name="mock_clt",
        server_ip="10.0.0.2",
        tunnel_port=9999,
        secret_key=secret,
        forward_rules=forwards,
        interface="eth0",
        router_mac="aa:bb:cc:dd:ee:ff",
        client_ip="10.0.0.3",
    )
    assert ok is True
    assert "deployed successfully" in msg
    assert any("systemctl restart paqet-mock_clt.service" in cmd for cmd in ssh.executed_commands)


def test_teardown_node_mock():
    adapter = PaqetAdapter()
    ssh = MockSSHManager()

    ok, msg = adapter.teardown_node(ssh=ssh, tunnel_name="mock_srv", tunnel_port=9999)
    assert ok is True
    assert "torn down cleanly" in msg
    assert any("systemctl stop paqet-mock_srv.service" in cmd for cmd in ssh.executed_commands)
    assert any("-D PREROUTING" in cmd for cmd in ssh.executed_commands)


@pytest.mark.parametrize('role', ['client', 'server'])
def test_deployment_shell_writes_clean_yaml_and_runs_service(tmp_path, role):
    """Execute the generated shell: a broken heredoc can silently swallow startup."""
    commands = tmp_path / 'commands'
    commands.mkdir()
    calls = tmp_path / 'calls'
    for name in ('systemctl', 'iptables', 'sysctl'):
        stub = commands / name
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(calls) + '"\n')
        stub.chmod(0o755)
    units = tmp_path / 'units'
    units.mkdir()
    vxlb = tmp_path / 'vxlb'
    vxlb.mkdir()
    sysctl_d = tmp_path / 'sysctl.d'
    sysctl_d.mkdir()

    class ShellSSH:
        def execute(self, cmd, timeout=30):
            cmd = cmd.replace('/etc/systemd/system/', str(units) + '/')
            cmd = cmd.replace('/etc/vxlb/', str(vxlb) + '/')
            cmd = cmd.replace('/etc/sysctl.d/', str(sysctl_d) + '/')
            result = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True,
                                    env={**os.environ, 'PATH': str(commands) + ':' + os.environ['PATH']})
            return result.returncode, result.stdout, result.stderr

    adapter = PaqetAdapter()
    adapter.config_dir = str(tmp_path / 'configs')
    common = dict(ssh=ShellSSH(), tunnel_name='shell_test', tunnel_port=29999,
                  secret_key=generate_paqet_secret(), interface='eth0',
                  router_mac='aa:bb:cc:dd:ee:ff', server_ip='10.0.0.2',
                  kcp_tuning={'dshard': 10, 'pshard': 3})
    if role == 'client':
        ok, error = adapter.deploy_client_node(**common, client_ip='10.0.0.3',
            forward_rules=[{'listen': '8080', 'target': '127.0.0.1:80', 'protocol': 'tcp'}])
    else:
        ok, error = adapter.deploy_server_node(**common)
    assert ok, error
    config = yaml.safe_load((tmp_path / 'configs' / 'shell_test.yaml').read_text())
    assert config['role'] == role
    assert config['transport']['kcp']['dshard'] == 10
    assert config['transport']['kcp']['pshard'] == 3
    assert 'ExecStart=' in (units / 'paqet-shell_test.service').read_text()
    assert 'restart paqet-shell_test.service' in calls.read_text()
