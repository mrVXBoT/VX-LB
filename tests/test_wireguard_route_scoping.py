from core.wireguard_adapter import WireGuardAdapter


def test_default_allowed_ips_do_not_claim_other_links_subnets():
    adapter=WireGuardAdapter()
    for subnet,peer,local in [('10.100.2.0/30','10.100.2.2','10.100.2.1'),('10.100.3.0/30','10.100.3.2','10.100.3.1')]:
        conf=adapter.configure({'ip':'192.0.2.1'},{'ip':'192.0.2.2'},{'ipv4_subnet':subnet,'enable_ipv6':True})
        assert f'AllowedIPs = {peer}/32, fd00:100::2/128' in conf['iran_config']
        assert f'AllowedIPs = {local}/32, fd00:100::1/128' in conf['kharej_config']
        assert '10.100.0.0/16' not in conf['iran_config']


def test_ipv6_outer_endpoint_is_bracketed():
    conf=WireGuardAdapter().configure({'ip':'2001:db8::1','is_server':True},{'ip':'2001:db8::2'},{})
    assert 'Endpoint = [2001:db8::2]:51820' in conf['iran_config']
    assert 'Endpoint = [2001:db8::1]:51820' in conf['kharej_config']
