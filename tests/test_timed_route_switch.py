"""Tests for timed default route switcher with watchdog rollback."""
import json
import pytest
from unittest.mock import MagicMock, patch

from core import timed_route_switch as trs
from core.private_link_manager import PrivateLinkManager


def test_validate_gateway_and_timeout():
    ip, to = trs.validate_gateway_and_timeout("10.100.0.2", 45)
    assert ip == "10.100.0.2"
    assert to == 45

    with pytest.raises(ValueError, match="Invalid gateway"):
        trs.validate_gateway_and_timeout("invalid_ip", 30)

    with pytest.raises(ValueError, match="Timeout"):
        trs.validate_gateway_and_timeout("10.100.0.2", 2)

    with pytest.raises(ValueError, match="Timeout"):
        trs.validate_gateway_and_timeout("10.100.0.2", 700)


def test_snapshot_detection_json():
    mock_ssh = MagicMock()
    json_output = json.dumps([{
        "dst": "default",
        "gateway": "192.168.1.1",
        "dev": "eth0",
        "metric": 100,
        "protocol": "dhcp"
    }])
    mock_ssh.execute.return_value = (0, json_output, "")
    snap = trs.get_current_default_route_snapshot(mock_ssh)
    assert snap["gateway"] == "192.168.1.1"
    assert snap["dev"] == "eth0"
    assert snap["metric"] == 100


def test_snapshot_detection_fallback_text():
    mock_ssh = MagicMock()
    # First JSON attempt fails, second text attempt succeeds
    mock_ssh.execute.side_effect = [
        (1, "", "unknown flag -j"),
        (0, "default via 192.168.1.1 dev eth0 metric 100", "")
    ]
    snap = trs.get_current_default_route_snapshot(mock_ssh)
    assert snap["gateway"] == "192.168.1.1"
    assert snap["dev"] == "eth0"
    assert snap["metric"] == 100


def test_execute_timed_route_switch_lifecycle():
    mock_ssh = MagicMock()
    mock_ssh.execute.side_effect = [
        (0, json.dumps([{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"}]), ""),  # snapshot
        (0, "", ""),  # mkdir
        (0, "", ""),  # rm confirm
        (0, "", ""),  # chmod script
        (0, "", ""),  # chmod unit
        (0, "", ""),  # systemctl restart
    ]
    mock_ssh.write_file.return_value = True

    result = trs.execute_timed_route_switch(mock_ssh, "10.100.0.2", 60, dev="pl_link1")
    assert result["status"] == "active"
    assert result["executed"] is True
    assert result["gateway_ip"] == "10.100.0.2"
    assert result["timeout_seconds"] == 60
    assert result["original_snapshot"]["gateway"] == "192.168.1.1"

    # Verify written files
    assert mock_ssh.write_file.call_count == 3  # snapshot, script, unit


def test_confirm_route_switch():
    mock_ssh = MagicMock()
    mock_ssh.execute.return_value = (0, "", "")

    ok, msg = trs.confirm_route_switch(mock_ssh)
    assert ok
    assert "confirmed" in msg
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "touch /etc/vxlb/route-watchdog.confirm" in commands
    assert "systemctl stop vxlb-route-watchdog.service" in commands


def test_rollback_route_switch():
    mock_ssh = MagicMock()
    mock_ssh.execute.return_value = (0, "", "")

    ok, msg = trs.rollback_route_switch(mock_ssh)
    assert ok
    assert "restored" in msg
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "restore" in commands
    assert "systemctl stop vxlb-route-watchdog.service" in commands


def test_manager_integration_staged_and_executed():
    mock_ssh = MagicMock()
    # 1. Staged preview mode
    staged = PrivateLinkManager.create_timed_default_route_switch(
        ssh_manager=mock_ssh,
        gateway_ip="10.100.0.2",
        timeout_seconds=45,
        execute=False
    )
    assert staged["status"] == "staged"
    assert staged["executed"] is False
    assert "ip route replace default via 10.100.0.2" in staged["script"]
    mock_ssh.execute.assert_not_called()

    # 2. Executed mode
    with patch("core.timed_route_switch.execute_timed_route_switch") as mock_exec:
        mock_exec.return_value = {"status": "active", "executed": True}
        executed = PrivateLinkManager.create_timed_default_route_switch(
            ssh_manager=mock_ssh,
            gateway_ip="10.100.0.2",
            timeout_seconds=45,
            execute=True,
            dev="pl_01"
        )
        assert executed["status"] == "active"
        assert executed["executed"] is True
        mock_exec.assert_called_once_with(mock_ssh, "10.100.0.2", 45, "pl_01")
