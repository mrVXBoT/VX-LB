"""New kernel engines must never fall through to BackPack port mutations."""
from unittest.mock import patch
import pytest
from core.load_balancer import LoadBalancerManager

@pytest.mark.parametrize("engine", ["wireguard", "vxlan", "gre6", "ip6ip6"])
def test_kernel_port_changes_dispatch_to_own_relay(engine):
    with patch("core.load_balancer.get_pools", return_value={"pool": {"engine": engine, "client_ports": ["443", "8443"]}}), patch("core.kernel_relay_ports.change_ports", return_value=(True, "updated")) as change, patch("core.load_balancer.SSHManager") as ssh:
        assert LoadBalancerManager.add_client_ports("pool", ["9443"])[0]
        assert change.call_args.args == ("pool", ["443", "8443", "9443"])
        assert LoadBalancerManager.remove_client_port("pool", "443")[0]
        assert change.call_args.args == ("pool", ["8443"])
        ssh.assert_not_called()

def test_geneve_dispatches_both_port_mutations():
    with patch("core.load_balancer.get_pools", return_value={"pool": {"engine": "geneve", "client_ports": ["443", "8443"]}}), patch("core.geneve.change_ports", return_value=(True, "updated")) as change:
        assert LoadBalancerManager.add_client_ports("pool", ["9443"])[0]
        assert change.call_args.args == ("pool", ["443", "8443", "9443"])
        assert LoadBalancerManager.remove_client_port("pool", "443")[0]
        assert change.call_args.args == ("pool", ["8443"])
