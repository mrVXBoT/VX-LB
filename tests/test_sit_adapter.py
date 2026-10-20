"""Unit tests for SIT / 6in4 (IPv6 over IPv4) tunnel adapter."""
import pytest
from unittest.mock import MagicMock, patch

from core.adapter_registry import get_adapter
from core.kernel_tunnels_adapter import SitAdapter
from core import sit


def test_sit_adapter_registered():
    adapter = get_adapter("sit")
    assert adapter is not None
    assert isinstance(adapter, SitAdapter)
    assert adapter.capabilities.engine_id == "sit"
    assert adapter.capabilities.layer == "L3"
    assert "ipv4" in adapter.capabilities.address_families
    assert "tcp" in adapter.capabilities.supported_protocols
    assert "udp" in adapter.capabilities.supported_protocols
    assert adapter.capabilities.requires_encryption is False


def test_sit_mtu_validation():
    assert sit.validate_sit_mtu(1440) == 1440
    assert sit.validate_sit_mtu(1280) == 1280
    assert sit.validate_sit_mtu(1480) == 1480

    with pytest.raises(ValueError, match="MTU"):
        sit.validate_sit_mtu(1200)

    with pytest.raises(ValueError, match="MTU"):
        sit.validate_sit_mtu(1500)


def test_check_sit_prerequisites():
    mock_ssh = MagicMock()
    mock_ssh.execute.side_effect = [
        (0, "", ""),  # modprobe sit
        (0, "/bin/ip /sbin/sysctl", ""),  # tools check
        (0, "", ""),  # sysctl setting
        (0, "rtt min/avg/max = 1.0/1.0/1.0 ms", ""),  # ping
    ]
    ok, msg = sit.check_sit_prerequisites(mock_ssh, "198.51.100.20")
    assert ok
    assert "prerequisites verified" in msg



def test_configure_sit_link():
    iran = {"ip": "192.0.2.10", "node_name": "ir_node"}
    kharej = {"ip": "198.51.100.20", "name": "kh_node"}
    pool_config = {
        "interface": "sit-test",
        "mtu": 1440,
        "client_ports": [8080, 8443],
    }

    cfg = sit.configure_sit_link(iran, kharej, pool_config)
    assert cfg["engine"] == "sit"
    assert cfg["interface"] == "sit-test"
    assert cfg["service_name"] == "vxlb-sit-sit-test.service"
    assert cfg["mtu"] == 1440
    assert cfg["underlay"]["iran_ip"] == "192.0.2.10"
    assert cfg["underlay"]["kharej_ip"] == "198.51.100.20"
    assert cfg["security"]["cleartext"] is True

    ir_unit = cfg["iran_config"]["unit"]
    assert "type sit local 192.0.2.10 remote 198.51.100.20 ttl 64" in ir_unit
    assert "ip link set sit-test mtu 1440" in ir_unit
    assert "ip link set sit-test up" in ir_unit

    kh_unit = cfg["kharej_config"]["unit"]
    assert "type sit local 198.51.100.20 remote 192.0.2.10 ttl 64" in kh_unit



def test_sit_adapter_lifecycle():
    adapter = SitAdapter()
    mock_ssh = MagicMock()
    mock_ssh.execute.return_value = (0, "active", "")

    ok, _ = adapter.start(mock_ssh, "sit-test")
    assert ok
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "systemctl restart vxlb-sit-sit-test.service" in commands

    mock_ssh.reset_mock()
    mock_ssh.execute.return_value = (0, "", "")
    ok, _ = adapter.stop(mock_ssh, "sit-test")
    assert ok
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "systemctl stop vxlb-sit-sit-test.service" in commands

    mock_ssh.reset_mock()
    mock_ssh.execute.return_value = (0, "", "")
    ok, _ = adapter.clean(mock_ssh, "sit-test")
    assert ok
    commands = " ".join(call.args[0] for call in mock_ssh.execute.call_args_list)
    assert "ip link del sit-test" in commands
    assert "rm -f /etc/systemd/system/vxlb-sit-sit-test.service" in commands


def test_sit_status():
    adapter = SitAdapter()
    mock_ssh = MagicMock()
    mock_ssh.execute.side_effect = [
        (0, "active\n", ""),  # is-active
        (0, "5: sit-test: <POINTOPOINT,NOARP,UP> mtu 1440\n    RX: bytes packets errors\n    1024 10 0\n    TX: bytes packets errors\n    2048 20 0", ""),  # ip -d -s link
    ]
    st = adapter.status(mock_ssh, "sit-test")
    assert st["status"] == "UP"
    assert st["engine"] == "sit"
    assert st["interface"] == "sit-test"
    assert st["security"]["cleartext"] is True
