"""Unified adapter contract and abstract base class for VX-LB tunnel engines.

Standard lifecycle interface for installation, configuration,
service start/stop, status reporting, active traffic probing, configuration modification,
durable rollback, and complete resource cleanup.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, Any
from core.ssh_client import SSHManager
from core.capabilities import EngineCapabilities, get_capability

class BaseTunnelAdapter(ABC):
    """Abstract Base Class for all tunnel engine adapters."""

    def __init__(self, engine_id: str):
        self.engine_id = engine_id
        self._capabilities = get_capability(engine_id)
        if not self._capabilities:
            raise ValueError(f"No capabilities registered for engine '{engine_id}'")

    @property
    def capabilities(self) -> EngineCapabilities:
        return self._capabilities

    @property
    def name(self) -> str:
        return self.engine_id

    @property
    def display_name(self) -> str:
        return self._capabilities.display_name

    @abstractmethod
    def install(self, ssh: SSHManager, role: str, config: dict) -> Tuple[bool, str]:
        """Install prerequisites, binaries, kernel modules, or services on a host.
        
        Args:
            ssh: Connected SSHManager for target host.
            role: "iran" or "kharej".
            config: Engine-specific configuration dictionary.
            
        Returns:
            (success: bool, message: str)
        """
        pass

    @abstractmethod
    def configure(self, iran_node: dict, kharej_server: dict, pool_config: dict) -> dict:
        """Generate configuration specifications for both Iran and Kharej endpoints.
        
        Returns a dict containing configs, unit files, file paths, and allocated resources.
        """
        pass

    @abstractmethod
    def start(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Start the tunnel service / bring up interface.
        
        Returns:
            (success: bool, message: str)
        """
        pass

    @abstractmethod
    def stop(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Stop the tunnel service / bring down interface.
        
        Returns:
            (success: bool, message: str)
        """
        pass

    @abstractmethod
    def status(self, ssh: SSHManager, identifier: str) -> dict:
        """Query host for detailed status of interface, process, handshake, and telemetry.
        
        Returns dict with keys:
            status: "UP", "DOWN", "DEGRADED"
            details: dict of metrics/info
        """
        pass

    @abstractmethod
    def probe(self, endpoint_ir: Any, endpoint_kh: Any, ports: Optional[List[int]] = None, **kwargs) -> dict:
        """Perform active end-to-end data probe across the tunnel with nonce validation.
        
        Returns dict with:
            passed: bool
            latency_ms: float
            error: str
        """
        pass

    @abstractmethod
    def modify(self, pool_name: str, updates: dict) -> Tuple[bool, str]:
        """Modify parameters (MTU, ports, endpoints, keys) with transactional backup.
        
        Returns:
            (success: bool, message: str)
        """
        pass

    @abstractmethod
    def rollback(self, pool_name: str, previous_state: dict) -> Tuple[bool, str]:
        """Rollback configuration to previous state after failure.
        
        Returns:
            (success: bool, message: str)
        """
        pass

    @abstractmethod
    def clean(self, ssh: SSHManager, identifier: str) -> Tuple[bool, str]:
        """Tear down services, delete interfaces, flush firewall rules, and delete configs.
        
        Must guarantee fail-closed cleanup without swallowing stop errors.
        
        Returns:
            (success: bool, message: str)
        """
        pass
