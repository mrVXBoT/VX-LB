import unittest
from unittest.mock import MagicMock, patch
from core.capabilities import get_capability, list_all_capabilities, is_engine_supported
from core.adapter_registry import get_adapter, list_registered_adapters, has_adapter
from core.dependency_manifest import get_dependency_manifest, validate_binary_prerequisites
from core.resource_allocator import (
    ResourceReservationManager,
    allocate_private_ipv4_subnet,
    allocate_private_ipv6_subnet,
    allocate_vni,
    allocate_route_table_id,
)
from core.job_manager import DurableJobManager

class SharedInfrastructureTests(unittest.TestCase):
    def test_capabilities_registry(self):
        """Machine-readable capability registry with status and reasons."""
        cap_bp = get_capability("backpack")
        self.assertIsNotNone(cap_bp)
        self.assertEqual(cap_bp.support_status, "verified")
        self.assertIn("tcp", cap_bp.supported_protocols)

        cap_6to4_anycast = get_capability("6to4_anycast")
        self.assertIsNotNone(cap_6to4_anycast)
        self.assertEqual(cap_6to4_anycast.support_status, "unsupported")
        self.assertIn("RFC 7526", cap_6to4_anycast.status_reason)

        all_caps = list_all_capabilities()
        self.assertIn("wireguard", all_caps)
        self.assertIn("vxlan", all_caps)
        self.assertIn("geneve", all_caps)

    def test_adapter_registry_and_contracts(self):
        """Unified adapter contract and discovery."""
        import core.backpack_adapter
        import core.gre_adapter
        import core.xhttp_adapter
        import core.waterwall_adapter
        import core.paqet_unified_adapter

        registered = list_registered_adapters()
        for engine in ["backpack", "gre_ipv4", "xhttp", "waterwall", "paqet"]:
            self.assertIn(engine, registered)
            adapter = get_adapter(engine)
            self.assertIsNotNone(adapter)
            self.assertEqual(adapter.engine_id, engine)
            # Verify interface methods exist
            self.assertTrue(callable(getattr(adapter, "install")))
            self.assertTrue(callable(getattr(adapter, "configure")))
            self.assertTrue(callable(getattr(adapter, "start")))
            self.assertTrue(callable(getattr(adapter, "stop")))
            self.assertTrue(callable(getattr(adapter, "status")))
            self.assertTrue(callable(getattr(adapter, "probe")))
            self.assertTrue(callable(getattr(adapter, "modify")))
            self.assertTrue(callable(getattr(adapter, "rollback")))
            self.assertTrue(callable(getattr(adapter, "clean")))

    def test_dependency_manifests(self):
        """Pinned versions, licenses, architectures, and checksum validation."""
        xray_manifest = get_dependency_manifest("xray")
        self.assertIsNotNone(xray_manifest)
        self.assertEqual(xray_manifest.pinned_version, "v26.3.27")
        self.assertEqual(xray_manifest.license_spdx, "MPL-2.0")
        self.assertIn("x86_64", xray_manifest.architectures)

        ok, msg = validate_binary_prerequisites("xray", "x86_64")
        self.assertTrue(ok)

        ok_bad_arch, msg_bad = validate_binary_prerequisites("xray", "mips")
        self.assertFalse(ok_bad_arch)
        self.assertIn("not supported", msg_bad)

        # Bundled BackPack binaries now carry measured depot checksums so the
        # offline installer can verify them instead of trusting file presence.
        bp_manifest = get_dependency_manifest("backpack")
        self.assertIsNotNone(bp_manifest)
        self.assertEqual(bp_manifest.architectures["x86_64"]["sha256"], "ed03357f23b4ab63fb54f5e06f69778793c323ac099a4410660ad53f80e98107")
        self.assertTrue(bp_manifest.architectures["x86_64"]["is_verified"])
        self.assertEqual(bp_manifest.architectures["aarch64"]["sha256"], "62f2ad8b2c60feb573334ff64022cbda2e79792e1c735a3a59317230d0a29e1f")
        self.assertTrue(bp_manifest.architectures["aarch64"]["is_verified"])

    def test_resource_allocator_subnets_and_vni(self):
        """Resource allocation logic for /30, /126, VNIs, and route tables."""
        existing_v4 = ["10.100.0.0/30"]
        next_v4 = allocate_private_ipv4_subnet(existing_v4)
        self.assertEqual(next_v4, "10.100.0.4/30")

        existing_v6 = ["fd00:1db9::/126"]
        next_v6 = allocate_private_ipv6_subnet(existing_v6)
        self.assertEqual(next_v6, "fd00:1db9::4/126")

        existing_vni = [1000, 1001]
        next_vni = allocate_vni(existing_vni)
        self.assertEqual(next_vni, 1002)

        existing_tables = [100, 101]
        next_table = allocate_route_table_id(existing_tables)
        self.assertEqual(next_table, 102)

    def test_resource_reservations_collision_detection(self):
        """Atomic collision detection across host ports and interfaces."""
        fake_storage = {"resource_reservations": {}}
        with patch("core.resource_allocator.load_data", return_value=fake_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(fake_storage)):

            res1 = ResourceReservationManager.reserve_pool_resources(
                pool_name="PoolAlpha",
                engine_id="gre_ipv4",
                host_ports={"192.0.2.1": [8080, 8443]},
                interface_names=["gre-bp-alpha"],
                needs_ipv4_subnet=True,
                needs_vni=True,
            )
            self.assertEqual(res1["ipv4_subnet"], "10.100.0.0/30")
            self.assertEqual(res1["vni"], 1000)

            # Port collision attempt from PoolBeta
            with self.assertRaises(RuntimeError) as ctx:
                ResourceReservationManager.reserve_pool_resources(
                    pool_name="PoolBeta",
                    engine_id="backpack",
                    host_ports={"192.0.2.1": [8080]},  # Collision on 8080!
                    interface_names=["gre-bp-beta"],
                )
            self.assertIn("Port collision", str(ctx.exception))

            # Interface collision attempt
            with self.assertRaises(RuntimeError) as ctx2:
                ResourceReservationManager.reserve_pool_resources(
                    pool_name="PoolGamma",
                    engine_id="gre_ipv4",
                    host_ports={"192.0.2.1": [9090]},
                    interface_names=["gre-bp-alpha"],  # Collision on interface!
                )
            self.assertIn("Interface collision", str(ctx2.exception))

            # Release PoolAlpha
            released = ResourceReservationManager.release_pool_resources("PoolAlpha")
            self.assertTrue(released)
            self.assertNotIn("PoolAlpha", fake_storage["resource_reservations"])

    def test_durable_job_lifecycle(self):
        """Asynchronous durable jobs and daemon restart recovery."""
        fake_storage = {"persistent_jobs": {}}
        with patch("core.job_manager.load_data", return_value=fake_storage), \
             patch("core.job_manager.atomic_update", side_effect=lambda fn: fn(fake_storage)):

            job = DurableJobManager.create_job("pool_create", "PoolNew", {"engine": "wireguard"})
            jid = job["job_id"]
            self.assertEqual(job["status"], "queued")

            updated = DurableJobManager.update_job(jid, status="running", step="configuring_peers", completed_step="init")
            self.assertEqual(updated["status"], "running")
            self.assertEqual(updated["step"], "configuring_peers")
            self.assertIn("init", updated["steps_completed"])

            # Simulate daemon crash and restart recovery
            interrupted = DurableJobManager.recover_on_restart()
            self.assertEqual(len(interrupted), 1)
            self.assertEqual(interrupted[0]["status"], "failed")
            self.assertIn("restart", interrupted[0]["error"])
