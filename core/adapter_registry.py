"""Central registry for tunnel engine adapters in VX-LB.

Provides unified registration, lookup, and dispatch
for all tunnel adapters adhering to BaseTunnelAdapter.
"""
import logging
from typing import Dict, List, Optional
from core.adapter_interface import BaseTunnelAdapter
from core.capabilities import get_capability

logger = logging.getLogger("vxlb.adapter_registry")

_ADAPTER_REGISTRY: Dict[str, BaseTunnelAdapter] = {}

_BUILTINS_LOADED = False

def _ensure_builtins_loaded():
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    _BUILTINS_LOADED = True
    import core.backpack_adapter
    import core.gre_adapter
    import core.xhttp_adapter
    import core.waterwall_adapter
    import core.kernel_tunnels_adapter
    import core.overlay_tunnels_adapter
    import core.dc6_adapter
    import core.http_adapter
    import core.tun_adapter
    import core.wireguard_adapter
    import core.software_engines_adapter
    import core.slipstream_adapter
    import core.layered_tunnels
    import core.spoof_adapter
    from core.vxlan_adapter import VxlanDedicatedAdapter
    register_adapter(VxlanDedicatedAdapter())
    from core.geneve_adapter import GeneveDedicatedAdapter
    register_adapter(GeneveDedicatedAdapter())

def register_adapter(adapter: BaseTunnelAdapter) -> None:
    """Register an adapter instance in the global registry."""
    if not isinstance(adapter, BaseTunnelAdapter):
        raise TypeError(f"Adapter must inherit from BaseTunnelAdapter, got {type(adapter)}")
    engine_id = adapter.engine_id.lower().strip()
    _ADAPTER_REGISTRY[engine_id] = adapter
    logger.info(f"Registered tunnel adapter for engine '{engine_id}' ({adapter.display_name})")

def get_adapter(engine_id: str) -> Optional[BaseTunnelAdapter]:
    """Retrieve an adapter by engine identifier."""
    if not engine_id:
        return None
    _ensure_builtins_loaded()
    return _ADAPTER_REGISTRY.get(engine_id.lower().strip())

def has_adapter(engine_id: str) -> bool:
    """Check if an adapter is registered for the specified engine."""
    _ensure_builtins_loaded()
    return engine_id.lower().strip() in _ADAPTER_REGISTRY

def list_registered_adapters() -> List[str]:
    """List all currently registered engine IDs."""
    _ensure_builtins_loaded()
    return sorted(list(_ADAPTER_REGISTRY.keys()))

def get_all_adapters() -> Dict[str, BaseTunnelAdapter]:
    """Return a copy of the adapter mapping."""
    _ensure_builtins_loaded()
    return dict(_ADAPTER_REGISTRY)

