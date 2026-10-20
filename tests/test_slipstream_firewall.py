"""Ownership, argument validation and removal contracts for DNS rate limiting."""
from unittest.mock import patch
import pytest
from core import slipstream_firewall as firewall

CONFIG = dict(id='a'*16, dns_port=25053, rate_limit=200)


def test_rule_only_drops_excess_dns_packets_and_never_accepts_or_flushes():
    rule = firewall.arguments(CONFIG)
    assert rule[rule.index('--dport')+1] == '25053'
    assert rule[rule.index('--hashlimit-above')+1] == '200/second'
    assert rule[rule.index('--hashlimit-burst')+1] == '400'
    assert rule[rule.index('--hashlimit-mode')+1] == 'srcip'
    assert rule[-1] == 'DROP'
    assert 'ACCEPT' not in rule and '-F' not in rule


def test_cleanup_finds_owned_old_rule_after_rate_and_port_were_changed():
    existing = '-A INPUT -p udp --dport 53 -m comment --comment ldbp-slipstream:'+'a'*16+' -j DROP\n'
    unrelated = '-A INPUT -p udp --dport 53 -m comment --comment other-service -j DROP\n'
    with patch.object(firewall, 'command', side_effect=[existing+unrelated, '']) as command:
        firewall.remove(CONFIG)
    assert command.call_count == 2
    deletion = command.call_args.args
    assert deletion[:2] == ('-D', 'INPUT')
    assert deletion[deletion.index('--dport')+1] == '53'
    assert 'other-service' not in deletion


@pytest.mark.parametrize('updates', [dict(id='bad;cmd'), dict(dns_port=0), dict(dns_port=65536),
                                     dict(rate_limit=0), dict(rate_limit=2001), dict(rate_limit=True), dict(rate_limit='1/second')])
def test_invalid_firewall_config_never_executes_a_command(updates):
    with patch.object(firewall, 'command') as command:
        with pytest.raises(ValueError):
            firewall.apply({**CONFIG, **updates})
    command.assert_not_called()
