"""Managed adapter contracts; no direct handshake or rule-presence health."""
from unittest.mock import MagicMock,patch
import pytest
from core.adapter_registry import get_adapter
from core.capabilities import is_engine_supported
from core.spoof_adapter import SpoofDedicatedAdapter,SPOOF_TRANSPORTS,create
from core.nfqws2_profiles import MODES


def test_registration_and_explicit_profile_capabilities():
    assert isinstance(get_adapter('spoof'),SpoofDedicatedAdapter)
    assert is_engine_supported('spoof')
    for mode in SPOOF_TRANSPORTS-{'spoof'}:
        assert is_engine_supported(mode) is (mode in MODES)


def test_configuration_requires_owned_allocation_not_legacy_firewall_recipe():
    with pytest.raises((ValueError,KeyError)):
        SpoofDedicatedAdapter().configure({'ip':'192.0.2.1'},{'ip':'192.0.2.2'},{'transport':'fake-sni'})


def test_unsupported_install_or_missing_endpoint_context_never_mutates_host():
    ssh=MagicMock();adapter=SpoofDedicatedAdapter()
    assert not adapter.install(ssh,'iran',{})[0]
    assert not adapter.start(ssh,'unowned')[0]
    assert not adapter.stop(ssh,'unowned')[0]
    assert not adapter.clean(ssh,'unowned')[0]
    ssh.execute.assert_not_called()


def test_status_uses_real_command_tuple_and_never_claims_verified_path():
    ssh=MagicMock();ssh.execute.return_value=(0,'active\n','')
    adapter=SpoofDedicatedAdapter()
    result=adapter.status(ssh,'ldbp-spoof-'+('a'*32)+'-nfq.service')
    assert result['status']=='UP' and result['details']['path_verified'] is False
    ssh.execute.reset_mock()
    assert adapter.status(ssh,'ldbp_spoof_oldtable')['status']=='DOWN'
    ssh.execute.assert_not_called()


def test_probe_requires_owned_node_and_cannot_turn_direct_connect_into_health():
    with patch('core.spoof_transport.verify') as verify:
        result=SpoofDedicatedAdapter().probe({'ip':'192.0.2.1'},{'ip':'192.0.2.2'},ports=[443])
    verify.assert_not_called()
    assert result['passed'] is False and result['latency_ms'] is None and result['verdict']=='UNVERIFIED'


def test_verified_data_and_packets_do_not_claim_dpi_evasion():
    with patch('core.spoof_transport.verify',return_value={'passed':True,'latency_ms':1}) as verify:
        result=SpoofDedicatedAdapter().probe({'ssh':'iran'},{'ssh':'kharej'},node={'owned':True})
    verify.assert_called_once()
    assert result['passed'] and result['verdict']=='DATA_VERIFIED' and result['evasion_verified'] is False


def test_create_supported_profile_delegates_to_managed_runtime():
    with patch('core.spoof_transport.create',return_value=(True,'verified',{})) as operation:
        assert create('packet',{'ip':'192.0.2.2'},[{'ip':'192.0.2.1'}],['8080'],transport='fake-sni')[0]
    operation.assert_called_once()
    assert operation.call_args.kwargs['transport']=='fake-sni'


def test_raw_profile_never_falls_back_to_a_different_managed_mode():
    with patch('core.spoof_transport.create') as operation:
        ok,message,pool=create('packet',{'ip':'192.0.2.2'},[{'ip':'192.0.2.1'}],['8080'],transport='hyperion-x')
    assert not ok and not pool and 'runtime' in message
    operation.assert_not_called()
