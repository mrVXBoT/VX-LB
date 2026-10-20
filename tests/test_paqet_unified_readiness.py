"""Unfinished unified operations must never report successful deployment."""
import pytest
from core.paqet_unified_adapter import PaqetUnifiedAdapter

def test_unimplemented_operations_fail_closed():
    adapter = PaqetUnifiedAdapter()
    assert adapter.install(None, "iran", {})[0] is False
    assert adapter.probe({}, {}, [])['passed'] is False
    assert adapter.modify("pool", {})[0] is False
    assert adapter.rollback("pool", {})[0] is False
    assert adapter.clean(None, "node")[0] is False
    with pytest.raises(NotImplementedError):
        adapter.configure({}, {}, {})
