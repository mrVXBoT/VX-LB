import copy
from unittest.mock import MagicMock, patch
import pytest
from core.resource_allocator import allocate_private_ipv4_subnet, allocate_private_ipv6_subnet, ResourceReservationManager as Resources
from core.private_link_manager import PrivateLinkManager as Links


def test_ipv4_allocation_skips_overlapping_supernet():
    assert allocate_private_ipv4_subnet(['10.100.0.0/24']) == '10.100.1.0/30'


def test_ipv6_allocation_jumps_over_large_overlap_without_enumeration():
    assert allocate_private_ipv6_subnet(['fd00:1db9::/64']) == 'fd00:1db9:0:1::/126'
    with pytest.raises(RuntimeError, match='exhausted'):
        allocate_private_ipv6_subnet(['fd00:1db9::/48'])


def test_identical_reservation_is_idempotent_and_cannot_be_silently_replaced():
    data = {}
    arguments = dict(pool_name='one', engine_id='wireguard', host_ports={'192.0.2.1': [51820]}, interface_names=['pl_test'], needs_ipv4_subnet=True)
    with patch('core.resource_allocator.atomic_update', side_effect=lambda function: function(data)):
        first = Resources.reserve_pool_resources(**arguments)
        assert Resources.reserve_pool_resources(**arguments) == first
        with pytest.raises(RuntimeError, match='released'):
            Resources.reserve_pool_resources(**{**arguments, 'host_ports': {'192.0.2.1': [51821]}})
    assert data['resource_reservations']['one'] == first


def test_matrix_late_port_collision_leaves_no_partial_links_or_reservations():
    data = {'resource_reservations': {'occupied': {'engine_id': 'other', 'host_ports': {'198.51.100.1': [51821]}, 'interfaces': []}}}
    previous = copy.deepcopy(data)
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        with pytest.raises(RuntimeError, match='collision'):
            Links.create_matrix_topology([{'ip': '192.0.2.1'}, {'ip': '192.0.2.2'}], [{'ip': '198.51.100.1'}], 'wireguard')
    assert data == previous


def test_duplicate_pairs_and_same_host_cannot_create_active_records():
    data = {}
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        with pytest.raises(ValueError, match='Duplicate'):
            Links.create_matrix_topology([{'ip': '192.0.2.1'}], [{'ip': '198.51.100.1'}], 'wireguard', [('192.0.2.1','198.51.100.1')]*2)
        with pytest.raises(ValueError, match='different'):
            Links.create_private_link('same', 'wireguard', {'ip': '192.0.2.1'}, {'ip': '192.0.2.1'})
    assert data == {}


def _iran(i):
    return {'ip': f'192.0.2.{i+1}', 'name': f'ir-{i+1}'}
def _khar(i):
    return {'ip': f'198.51.100.{i+1}', 'name': f'kh-{i+1}'}


def test_matrix_full_mesh_five_by_ten_builds_all_links_atomically():
    """selective N:M matrix at 5 Iran × 10 Kharej scale (metadata)."""
    data = {}
    irans = [_iran(i) for i in range(5)]
    khars = [_khar(i) for i in range(10)]
    pairs = [(ir['ip'], kh['ip']) for ir in irans for kh in khars]
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        with pytest.raises(ValueError, match='Full mesh'):
            Links.create_matrix_topology(irans, khars, 'wireguard')
        links = Links.create_matrix_topology(irans, khars, 'wireguard', pairs)
    assert len(links) == 50
    created = data.get('custom_links', {})
    assert len(created) == 50
    # Each pair lands on a unique link record with distinct host port and subnet.
    assert len({link['link_name'] for link in created.values()}) == 50
    pair_set = {(link['iran_server']['ip'], link['kharej_server']['ip']) for link in created.values()}
    assert pair_set == set(pairs)
    host_ports = [link['tunnel_port'] for link in created.values()]
    assert len(set(host_ports)) == 50


def test_matrix_topologies_one_to_one_many_to_one_one_to_many():
    """1:1, N:1, 1:M selective pair topologies."""
    data = {}
    irans = [_iran(i) for i in range(5)]
    khars = [_khar(i) for i in range(10)]

    # 1:1
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        links = Links.create_matrix_topology(irans, khars, 'wireguard', [(irans[0]['ip'], khars[0]['ip'])])
    assert len(links) == 1
    assert links[0]['iran_server']['ip'] == irans[0]['ip']
    assert links[0]['kharej_server']['ip'] == khars[0]['ip']

    # N:1 — five Irans to one Kharej.
    data.clear()
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        links = Links.create_matrix_topology(irans, khars, 'wireguard',
            [(ir['ip'], khars[0]['ip']) for ir in irans])
    assert len(links) == 5
    assert {link['kharej_server']['ip'] for link in links} == {khars[0]['ip']}
    assert {link['iran_server']['ip'] for link in links} == {ir['ip'] for ir in irans}

    # 1:M — one Iran to ten Kharej.
    data.clear()
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        links = Links.create_matrix_topology(irans, khars, 'wireguard',
            [(irans[0]['ip'], kh['ip']) for kh in khars])
    assert len(links) == 10
    assert {link['iran_server']['ip'] for link in links} == {irans[0]['ip']}
    assert {link['kharej_server']['ip'] for link in links} == {kh['ip'] for kh in khars}


def test_inventory_only_link_is_planned_and_name_collision_retains_old_record():
    data = {}
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        link = Links.create_private_link('one', 'wireguard', {'ip': '192.0.2.1'}, {'ip': '198.51.100.1'})
        assert link['status'] == 'planned'
        before = copy.deepcopy(data)
        with pytest.raises(ValueError, match='already exists'):
            Links.create_private_link('one', 'wireguard', {'ip': '192.0.2.1'}, {'ip': '198.51.100.1'})
        assert data == before


def test_status_and_installed_mtu_cannot_be_changed_by_metadata_only_edit():
    data = {'custom_links': {'one': {'status': 'active', 'mtu': 1400}}}
    with patch('core.private_link_manager.atomic_update', side_effect=lambda function: function(data)):
        for updates in ({'status': 'active'}, {'mtu': 1300}, {'interface': 'other'}):
            with pytest.raises(ValueError):
                Links.apply_link_mutation('one', updates)
    assert data['custom_links']['one'] == {'status': 'active', 'mtu': 1400}


@pytest.mark.parametrize('response', [(1, '', 'failed'), (0, '', ''), (0, 'net.ipv4.ip_forward = 0\nnet.ipv4.conf.all.rp_filter = 0', '')])
def test_preflight_does_not_succeed_when_sysctl_is_missing_or_disabled(response):
    ssh = MagicMock()
    ssh.execute.return_value = response
    assert Links.verify_preflight_sysctl(ssh)[0] is False
