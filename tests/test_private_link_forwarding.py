"""Tests for independent private link port forwarding."""
import copy
from contextlib import nullcontext
import pytest
from unittest.mock import MagicMock, patch

from core import private_link_forwarding as forwarding


@pytest.fixture
def active_link_state():
    link = {
        "link_id": "link-11223344",
        "link_name": "link_test",
        "engine_id": "wireguard",
        "status": "active",
        "interface": "pl_11223344",
        "private_subnet": "10.100.0.0/30",
        "tunnel_port": 51820,
        "mtu": 1400,
        "iran_server": {"ip": "192.0.2.1", "private_ip": "10.100.0.1"},
        "kharej_server": {"ip": "198.51.100.1", "private_ip": "10.100.0.2"},
        "port_forwarding_rules": [],
        "runtime": {"interface": "pl_11223344"},
    }
    data = {
        "custom_links": {"link_test": link},
        "iran_servers": [{"ip": "192.0.2.1", "name": "iran"}],
        "kharej_servers": [{"ip": "198.51.100.1", "name": "kharej"}],
    }
    mock_ssh = MagicMock()
    mock_ssh.execute.return_value = (0, "", "")
    mock_ssh.write_file.return_value = True

    with patch.object(forwarding, "load_data", side_effect=lambda: copy.deepcopy(data)), \
         patch.object(forwarding, "atomic_update", side_effect=lambda fn: fn(data)), \
         patch.object(forwarding, "mutation_lock", side_effect=lambda: nullcontext()), \
         patch.object(forwarding, "busy", return_value=False), \
         patch.object(forwarding, "connect", return_value=mock_ssh):
        yield data, mock_ssh


def test_rule_validation():
    # Valid rule formats
    assert forwarding.validate_rule({"listen_port": 8080, "target_port": 8080, "protocol": "tcp"}) == {
        "listen_port": 8080, "target_port": 8080, "protocol": "tcp"
    }
    assert forwarding.validate_rule({"port": "9000", "protocol": "BOTH"}) == {
        "listen_port": 9000, "target_port": 9000, "protocol": "both"
    }
    # Invalid ports or protocols
    with pytest.raises(ValueError, match="port"):
        forwarding.validate_rule({"listen_port": 0})
    with pytest.raises(ValueError, match="Protocol"):
        forwarding.validate_rule({"listen_port": 8080, "protocol": "invalid"})

    # Ruleset validation
    rules = [
        {"listen_port": 8080, "target_port": 8080, "protocol": "tcp"},
        {"listen_port": 8443, "target_port": 8443, "protocol": "udp"},
    ]
    validated = forwarding.validate_forwarding_rules(rules, excluded_ports=[51820])
    assert len(validated) == 2

    # Duplicate listen port
    with pytest.raises(ValueError, match="Duplicate"):
        forwarding.validate_forwarding_rules([
            {"listen_port": 8080, "protocol": "tcp"},
            {"listen_port": 8080, "protocol": "udp"},
        ])

    # Conflict with excluded/tunnel port
    with pytest.raises(ValueError, match="reserved or conflicts"):
        forwarding.validate_forwarding_rules([{"listen_port": 51820}], excluded_ports=[51820])


def test_render_relay_script_and_unit():
    rules = [{"listen_port": 8080, "target_port": 8080, "protocol": "both"}]
    script = forwarding.render_relay_script("10.100.0.2", rules)
    assert "PEER = '10.100.0.2'" in script
    assert "forward_tcp" in script
    assert "UdpRelay" in script

    unit = forwarding.render_relay_unit("ldbp-pl-link-11223344-relay.service", "/usr/local/bin/test.py", "pl_11223344")
    assert "Requires=wg-quick@pl_11223344.service" in unit
    assert "After=network.target wg-quick@pl_11223344.service" in unit
    assert "ExecStart=/usr/bin/python3 /usr/local/bin/test.py" in unit


def test_apply_forwarding_requires_active_link(active_link_state):
    data, mock_ssh = active_link_state
    data["custom_links"]["link_test"]["status"] = "planned"

    ok, msg = forwarding.apply_forwarding_rules("link_test", [{"listen_port": 8080}])
    assert not ok
    assert "must be in 'active' status" in msg
    mock_ssh.write_file.assert_not_called()


def test_apply_forwarding_lifecycle_success(active_link_state):
    data, mock_ssh = active_link_state
    rules = [
        {"listen_port": 8080, "target_port": 8080, "protocol": "both"},
        {"listen_port": 9000, "target_port": 9000, "protocol": "tcp"},
    ]

    with patch("core.kernel_relay_ports.verify_listeners", return_value=None) as verify_mock:
        ok, msg = forwarding.apply_forwarding_rules("link_test", rules)

    assert ok
    assert "activated" in msg
    assert mock_ssh.write_file.call_count == 2
    # Verify commands executed
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "systemctl daemon-reload" in commands
    assert "systemctl restart ldbp-pl-link-11223344-relay.service" in commands

    verify_mock.assert_called_once()
    assert verify_mock.call_args[0][2] == [8080, 9000]

    # Check stored metadata
    link = data["custom_links"]["link_test"]
    assert len(link["port_forwarding_rules"]) == 2
    relay = link["runtime"]["relay"]
    assert relay["service"] == "ldbp-pl-link-11223344-relay.service"
    assert relay["ports"] == [8080, 9000]
    assert relay["state"] == "active"


def test_apply_forwarding_rollback_on_listener_failure(active_link_state):
    data, mock_ssh = active_link_state
    rules = [{"listen_port": 8080, "target_port": 8080, "protocol": "both"}]

    with patch("core.kernel_relay_ports.verify_listeners", side_effect=RuntimeError("Ports not bound")):
        ok, msg = forwarding.apply_forwarding_rules("link_test", rules)

    assert not ok
    assert "Relay listener verification failed" in msg
    # Verify rollback commands executed
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "systemctl stop ldbp-pl-link-11223344-relay.service" in commands
    assert "rm -f" in commands
    assert data["custom_links"]["link_test"]["port_forwarding_rules"] == []


def test_remove_forwarding_lifecycle(active_link_state):
    data, mock_ssh = active_link_state
    # Set pre-existing relay
    link = data["custom_links"]["link_test"]
    link["port_forwarding_rules"] = [{"listen_port": 8080, "target_port": 8080, "protocol": "both"}]
    link["runtime"]["relay"] = {
        "service": "ldbp-pl-link-11223344-relay.service",
        "script": "/usr/local/bin/ldbp-pl-link-11223344-relay.py",
        "unit": "/etc/systemd/system/ldbp-pl-link-11223344-relay.service",
        "unit_sha256": "abcdef" * 10 + "1234",
        "ports": [8080],
        "state": "active",
    }
    # sha256 query matches
    mock_ssh.execute.return_value = (0, ("abcdef" * 10 + "1234") + "  /etc/systemd/system/ldbp-pl-link-11223344-relay.service\n", "")

    ok, msg = forwarding.remove_forwarding_rules("link_test")
    assert ok
    assert "removed" in msg

    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "systemctl stop ldbp-pl-link-11223344-relay.service" in commands
    assert "rm -f -- /usr/local/bin/ldbp-pl-link-11223344-relay.py" in commands

    assert data["custom_links"]["link_test"]["port_forwarding_rules"] == []
    assert "relay" not in data["custom_links"]["link_test"]["runtime"]


def test_remove_forwarding_guards_foreign_unit(active_link_state):
    data, mock_ssh = active_link_state
    link = data["custom_links"]["link_test"]
    link["port_forwarding_rules"] = [{"listen_port": 8080}]
    link["runtime"]["relay"] = {
        "service": "ldbp-pl-link-11223344-relay.service",
        "unit": "/etc/systemd/system/ldbp-pl-link-11223344-relay.service",
        "unit_sha256": "111111" * 10 + "1234",
    }
    # sha256 mismatch (foreign file)
    mock_ssh.execute.return_value = (0, ("999999" * 10 + "1234") + "  /etc/systemd/system/ldbp-pl-link-11223344-relay.service\n", "")

    ok, msg = forwarding.remove_forwarding_rules("link_test")
    assert not ok
    assert "foreign unit preserved" in msg
    assert data["custom_links"]["link_test"]["port_forwarding_rules"] != []
