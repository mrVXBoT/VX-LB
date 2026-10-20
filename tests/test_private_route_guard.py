import json
from unittest.mock import patch
import pytest
from core import private_route_guard as guard


def test_absent_guard_is_added_without_replacing_any_route():
    with patch.object(guard,'execute',side_effect=['[]','']) as execute:
        guard.guard('ensure','10.100.0.0/30')
    assert execute.call_args.args[0]==['route','add','blackhole','10.100.0.0/30','proto','242','metric','42760']


def test_existing_owned_guard_is_idempotent():
    rows=[{'dst':'10.100.0.0/30','type':'blackhole','protocol':'242','metric':42760}]
    with patch.object(guard,'execute',return_value=json.dumps(rows)) as execute:
        guard.guard('ensure','10.100.0.0/30')
    assert execute.call_count==1


def test_foreign_route_with_same_metric_is_never_replaced_or_removed():
    rows=[{'dst':'10.100.0.0/30','type':'unicast','protocol':'static','metric':42760}]
    for action in ('ensure','remove'):
        with patch.object(guard,'execute',return_value=json.dumps(rows)) as execute:
            with pytest.raises(RuntimeError,match='foreign'):
                guard.guard(action,'10.100.0.0/30')
        assert execute.call_count==1


def test_removal_targets_only_exact_owned_blackhole():
    rows=[{'dst':'10.100.0.0/30','type':'blackhole','protocol':242,'metric':42760},
          {'dst':'10.100.0.0/30','dev':'pl_test','protocol':'kernel'}]
    with patch.object(guard,'execute',side_effect=[json.dumps(rows),'']) as execute:
        guard.guard('remove','10.100.0.0/30')
    assert execute.call_args.args[0]==['route','del','blackhole','10.100.0.0/30','proto','242','metric','42760']


def test_supernet_is_not_accepted_for_guard():
    with patch.object(guard,'execute') as execute:
        with pytest.raises(ValueError):guard.guard('ensure','10.0.0.0/8')
    execute.assert_not_called()
