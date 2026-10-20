"""Unit tests for layered and hybrid tunnel implementations."""

import pytest
from unittest.mock import MagicMock

from core.layered_tunnels import (
    calculate_geneve_gre6_native_mtu,
    calculate_geneve_gre6_ipv4_mtu,
    build_geneve_gre6_native_plan,
    build_geneve_gre6_ipv4_plan,
    build_wireguard_amnezia_plan,
    build_wireguard_udp2raw_plan,
    AmneziaWgParams,
    GeneveGre6NativeAdapter,
    GeneveGre6Ipv4Adapter,
    WireGuardAmneziaAdapter,
    WireGuardUdp2rawAdapter,
    GENEVE_GRE6_CLEARTEXT_WARNING,
)
from core.adapter_registry import get_adapter
from core.capabilities import get_capability
from core.firewall_lifecycle_manager import DependencyLifecycleManager


class TestGeneveGre6Native:
    """Tests for Geneve over Native IPv6 GRE6."""

    def test_mtu_and_overhead_calculation(self):
        total_overhead, gre6_mtu, geneve_mtu = calculate_geneve_gre6_native_mtu(1500)
        assert total_overhead == 74  # 44 (GRE6) + 30 (Geneve/UDP/Eth)
        assert gre6_mtu == 1456
        assert geneve_mtu == 1426

    def test_plan_dependency_and_teardown_order(self):
        plan = build_geneve_gre6_native_plan(
            identifier="test-g6gnv",
            iran_ipv6="2001:db8:1::1",
            kharej_ipv6="2001:db8:2::2",
            vni=2000,
            role="iran",
            base_mtu=1500,
        )
        assert plan.profile == "geneve_gre6_native"
        assert len(plan.layers) == 2
        # Setup order: underlay first, then overlay
        assert plan.setup_order == ["underlay_gre6", "overlay_geneve"]
        # Teardown order: overlay first, then underlay
        assert plan.teardown_order == ["overlay_geneve", "underlay_gre6"]
        assert plan.cleartext_warning == GENEVE_GRE6_CLEARTEXT_WARNING

        # Verify systemd dependency in unit content
        layer_gre6 = next(l for l in plan.layers if l.layer_id == "underlay_gre6")
        layer_geneve = next(l for l in plan.layers if l.layer_id == "overlay_geneve")
        assert layer_gre6.service_name in layer_geneve.unit_content
        assert "Requires=" in layer_geneve.unit_content

    def test_adapter_lifecycle(self):
        adapter = get_adapter("geneve_gre6_native")
        assert adapter is not None
        assert isinstance(adapter, GeneveGre6NativeAdapter)

        ir_node = {"node_name": "ir1", "ip": "2001:db8:1::1"}
        kh_server = {"server_name": "kh1", "ip": "2001:db8:2::2"}
        cfg = adapter.configure(ir_node, kh_server, {"pool_name": "lab-g6gnv", "vni": 2000})

        assert cfg["protocol"] == "geneve_gre6_native"
        assert cfg["plan_ir"].setup_order == ["underlay_gre6", "overlay_geneve"]
        assert cfg["warning"] == GENEVE_GRE6_CLEARTEXT_WARNING

        ssh = MagicMock()
        ssh.execute.return_value = (0, "active", "")
        st = adapter.status(ssh, "lab-g6gnv")
        assert st["status"] == "online"
        assert st["underlay_gre6"] == "up"
        assert st["overlay_geneve"] == "up"

        ok, msg = adapter.stop(ssh, "lab-g6gnv")
        assert ok is True
        # Verify Geneve stopped before GRE6
        cmd = ssh.execute.call_args[0][0]
        assert cmd.index("vxlb-layer-geneve-") < cmd.index("vxlb-layer-gre6-")


class TestGeneveGre6Ipv4:
    """Tests for 3-tier Geneve over GRE6 over IPv4 (SIT)."""

    def test_3tier_mtu_cascade(self):
        total_overhead, sit_mtu, gre6_mtu, geneve_mtu = calculate_geneve_gre6_ipv4_mtu(1500)
        assert total_overhead == 94  # 20 (SIT) + 44 (GRE6) + 30 (Geneve)
        assert sit_mtu == 1480
        assert gre6_mtu == 1436
        assert geneve_mtu == 1406

    def test_3tier_plan_and_reverse_teardown(self):
        plan = build_geneve_gre6_ipv4_plan(
            identifier="test-3tier",
            iran_ipv4="198.51.100.1",
            kharej_ipv4="203.0.113.2",
            vni=3000,
            role="iran",
            base_mtu=1500,
        )
        assert plan.profile == "geneve_gre6_ipv4"
        assert len(plan.layers) == 3
        # Setup: SIT carrier -> GRE6 -> Geneve
        assert plan.setup_order == ["layer0_sit", "layer1_gre6", "layer2_geneve"]
        # Teardown: Geneve -> GRE6 -> SIT
        assert plan.teardown_order == ["layer2_geneve", "layer1_gre6", "layer0_sit"]

        layer_sit = next(l for l in plan.layers if l.layer_id == "layer0_sit")
        layer_gre6 = next(l for l in plan.layers if l.layer_id == "layer1_gre6")
        layer_geneve = next(l for l in plan.layers if l.layer_id == "layer2_geneve")

        assert layer_sit.service_name in layer_gre6.unit_content
        assert layer_gre6.service_name in layer_geneve.unit_content

    def test_adapter_clean_order(self):
        adapter = get_adapter("geneve_gre6_ipv4")
        assert adapter is not None
        assert isinstance(adapter, GeneveGre6Ipv4Adapter)

        ssh = MagicMock()
        ssh.execute.return_value = (0, "", "")
        ok, msg = adapter.clean(ssh, "test-3tier")
        assert ok is True
        clean_cmd = ssh.execute.call_args[0][0]
        # Geneve before GRE6, GRE6 before SIT
        idx_gnv = clean_cmd.index("vxlb-layer-geneve-")
        idx_g6 = clean_cmd.index("vxlb-layer-gre6-")
        idx_sit = clean_cmd.index("vxlb-layer-sit-")
        assert idx_gnv < idx_g6 < idx_sit


class TestWireGuardHybrids:
    """Tests for WireGuard Hybrid combinations."""

    def test_amnezia_param_validation(self):
        # Valid params
        p = AmneziaWgParams(jc=5, jmin=60, jmax=800, s1=32, s2=48)
        p.validate()

        # Invalid Jc
        with pytest.raises(ValueError, match="AmneziaWG Jc"):
            AmneziaWgParams(jc=200).validate()

        # Invalid range
        with pytest.raises(ValueError, match="invalid junk size range"):
            AmneziaWgParams(jmin=900, jmax=200).validate()

    def test_amnezia_plan_and_adapter(self):
        adapter = get_adapter("wireguard_amnezia")
        assert adapter is not None
        assert isinstance(adapter, WireGuardAmneziaAdapter)

        ir_node = {"node_name": "ir1", "ip": "198.51.100.1"}
        kh_server = {"server_name": "kh1", "ip": "203.0.113.2"}
        cfg = adapter.configure(ir_node, kh_server, {"pool_name": "awg-lab", "port": 51820})

        assert cfg["protocol"] == "wireguard_amnezia"
        plan = cfg["plan_ir"]
        assert plan.recommended_mtu == 1420
        assert "Jc = 4" in plan.layers[0].up_script
        assert "PrivateKey =" in plan.layers[0].up_script

    def test_udp2raw_plan_and_teardown(self):
        adapter = get_adapter("wireguard_udp2raw")
        assert adapter is not None
        assert isinstance(adapter, WireGuardUdp2rawAdapter)

        ir_node = {"node_name": "ir1", "ip": "198.51.100.1"}
        kh_server = {"server_name": "kh1", "ip": "203.0.113.2"}
        cfg = adapter.configure(ir_node, kh_server, {"pool_name": "wgu2r-lab", "carrier_port": 40001})

        plan = cfg["plan_ir"]
        assert len(plan.layers) == 2
        assert plan.setup_order == ["carrier_udp2raw", "overlay_wireguard"]
        assert plan.teardown_order == ["overlay_wireguard", "carrier_udp2raw"]

        ssh = MagicMock()
        ssh.execute.return_value = (0, "", "")
        ok, msg = adapter.stop(ssh, "wgu2r-lab")
        assert ok is True
        stop_cmd = ssh.execute.call_args[0][0]
        # WireGuard must be stopped before udp2raw carrier
        assert stop_cmd.index("vxlb-wg-") < stop_cmd.index("vxlb-udp2raw-")


class TestDependencyTeardownSafety:
    """Tests for DependencyLifecycleManager blocking base link deletion when stacked."""

    def test_can_delete_link_with_stacked_dependency(self, monkeypatch):
        fake_storage = {
            "pools": {
                "pool1": {"carrier_link": "base_gre6_link"}
            },
            "custom_links": {
                "overlay_gnv": {"underlying_link": "base_gre6_link"}
            }
        }
        monkeypatch.setattr("core.firewall_lifecycle_manager.load_data", lambda: fake_storage)

        can_del, reasons = DependencyLifecycleManager.can_delete_link("base_gre6_link")
        assert can_del is False
        assert len(reasons) == 2
        assert any("pool1" in r for r in reasons)
        assert any("overlay_gnv" in r for r in reasons)

    def test_can_delete_link_without_dependencies(self, monkeypatch):
        fake_storage = {
            "pools": {},
            "custom_links": {
                "independent_link": {}
            }
        }
        monkeypatch.setattr("core.firewall_lifecycle_manager.load_data", lambda: fake_storage)

        can_del, reasons = DependencyLifecycleManager.can_delete_link("independent_link")
        assert can_del is True
        assert len(reasons) == 0
