"""E2E and Integration Test Suite: Composition and Multi-Server Matrix Routing.

Coverage:
- Tier 1: Feature Coverage (Composition decomposition, layer isolation, API endpoints, matrix link generation)
- Tier 2: Boundary & Corner Cases (Invalid layer combos, mismatched ciphers, MTU extremes, port boundaries, pool exhaustion, explosion guards)
- Tier 3: Cross-Feature Combinations (Stacked layers, shared Kharej nodes, schema migration pipelines, link mutation previews)
- Tier 4: Real-World Scenarios (Multi-Kharej 4-link selective mesh cluster, non-conflicting IP allocations, failover watchdog rollback)
"""
import copy
import ipaddress
import io
import json
import unittest
from unittest.mock import MagicMock, patch

from core import composition_schema
from core.composition_schema import (
    UnifiedComposition,
    NetworkLayerSpec,
    EncryptionLayerSpec,
    CamouflageLayerSpec,
    deconstruct_legacy_pool,
    validate_composition,
)
from core.resource_allocator import (
    ResourceReservationManager,
    allocate_private_ipv4_subnet,
    allocate_private_ipv6_subnet,
    allocate_vni,
    allocate_route_table_id,
    IPV4_POOL_START,
    IPV6_POOL_START,
)
from core.private_link_manager import (
    PrivateLinkManager,
    STANDARD_ETHERNET_MTU,
)
from core.schema_migration import (
    apply_migrations,
    migrate_v0_to_v1,
    migrate_v1_to_v2,
    migrate_v2_to_v3,
    CURRENT_SCHEMA_VERSION,
)
from core.telemetry_supervisor import TelemetrySupervisor
from core.validation import validate_port, validate_ports, validate_pool_name
from core import web_server as web


class TestCompositionAndMatrixE2E(unittest.TestCase):
    """End-to-end integration test suite for 3-layer composition and matrix routing."""

    def setUp(self):
        """Set up in-memory storage environment for isolated test execution."""
        self.mock_storage = {
            "schema_version": 3,
            "pools": {},
            "custom_links": {},
            "resource_reservations": {},
            "persistent_jobs": {},
        }
        self.handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
        self.handler.headers = {}
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.wfile = MagicMock()
        self.handler._is_authenticated = MagicMock(return_value=True)

    def _get_written_json(self):
        """Extract and parse written JSON payload from mock HTTP handler."""
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        return json.loads(written.decode("utf-8"))

    # =========================================================================
    # TIER 1: FEATURE COVERAGE
    # =========================================================================

    def test_tier1_composition_deconstruction_wireguard(self):
        """Verify legacy wireguard pool deconstruction into 3 orthogonal layers."""
        legacy_pool = {
            "transport": "wireguard",
            "engine": "wireguard",
            "mtu": 1420,
            "tunnel_port": 51820,
            "enable_psk": True,
        }
        comp = deconstruct_legacy_pool(legacy_pool)
        self.assertIsInstance(comp, UnifiedComposition)
        self.assertEqual(comp.engine, "wireguard")
        self.assertEqual(comp.network.type, "wireguard")
        self.assertEqual(comp.network.mtu, 1420)
        self.assertEqual(comp.network.port, 51820)
        self.assertEqual(comp.encryption.type, "noise")
        self.assertEqual(comp.encryption.cipher, "ChaCha20Poly1305")
        self.assertTrue(comp.encryption.has_psk)
        self.assertEqual(comp.camouflage.type, "none")

    def test_tier1_composition_deconstruction_gre_xhttp(self):
        """Verify compound gre_xhttp pool deconstructs into GRE + TLS1.3 + XHTTP."""
        legacy_pool = {
            "transport": "gre_xhttp",
            "engine": "gre_xhttp",
            "gre_mtu": 1360,
            "domain": "grpc.cdn.example.com",
            "resolvers": ["1.1.1.1:53", "8.8.8.8:53"],
        }
        comp = deconstruct_legacy_pool(legacy_pool)
        self.assertEqual(comp.network.type, "gre_ipv4")
        self.assertEqual(comp.network.mtu, 1360)
        self.assertEqual(comp.encryption.type, "tls13")
        self.assertEqual(comp.encryption.cipher, "TLS_AES_128_GCM_SHA256")
        self.assertEqual(comp.camouflage.type, "xhttp_grpc")
        self.assertEqual(comp.camouflage.domain, "grpc.cdn.example.com")
        self.assertEqual(comp.camouflage.resolvers, ["1.1.1.1:53", "8.8.8.8:53"])

    def test_tier1_composition_deconstruction_geneve_ipsec(self):
        """Verify geneve_ipsec deconstructs into Geneve L2/L3 overlay with IPsec encryption."""
        legacy_pool = {
            "transport": "geneve_ipsec",
            "engine": "geneve_ipsec",
            "vni": 5001,
            "mtu": 1380,
        }
        comp = deconstruct_legacy_pool(legacy_pool)
        self.assertEqual(comp.network.type, "geneve")
        self.assertEqual(comp.network.vni, 5001)
        self.assertEqual(comp.network.mtu, 1380)
        self.assertEqual(comp.encryption.type, "ipsec")
        self.assertEqual(comp.encryption.cipher, "AES_GCM_16_256")
        self.assertEqual(comp.camouflage.type, "none")

    def test_tier1_composition_deconstruction_slipstream(self):
        """Verify slipstream emergency fallback pool deconstructs into DNS delegation."""
        legacy_pool = {
            "transport": "slipstream",
            "engine": "slipstream",
            "domain": "tunnel.edge.test",
            "resolvers": ["9.9.9.9:53"],
            "rate_limit": 250,
            "mtu": 1200,
        }
        comp = deconstruct_legacy_pool(legacy_pool)
        self.assertEqual(comp.network.type, "slipstream")
        self.assertEqual(comp.network.mtu, 1200)
        self.assertEqual(comp.encryption.type, "none")
        legacy_pool["slipstream_security"] = {"server_cert": "configured"}
        self.assertEqual(deconstruct_legacy_pool(legacy_pool).encryption.type, "tls13")
        self.assertEqual(comp.camouflage.type, "dns_delegation")
        self.assertEqual(comp.camouflage.domain, "tunnel.edge.test")
        self.assertIsNone(comp.camouflage.rate_limit)
        legacy_pool["slipstream_runtime_version"] = 2
        self.assertEqual(deconstruct_legacy_pool(legacy_pool).camouflage.rate_limit, 250)

    def test_tier1_composition_layer_isolation(self):
        """Verify orthogonal separation: mutating camouflage does not contaminate network or encryption."""
        comp = UnifiedComposition(
            engine="custom",
            network=NetworkLayerSpec(type="direct", mtu=1400),
            encryption=EncryptionLayerSpec(type="tls13", cipher="TLS_AES_128_GCM_SHA256"),
            camouflage=CamouflageLayerSpec(type="xhttp_grpc", domain="test.com"),
        )
        comp_dict = comp.to_dict()
        self.assertIn("network", comp_dict)
        self.assertIn("encryption", comp_dict)
        self.assertIn("camouflage", comp_dict)
        self.assertEqual(set(comp_dict["network"].keys()), {"type", "overlay_family", "mtu", "vni", "port", "parameters"})
        self.assertEqual(set(comp_dict["encryption"].keys()), {"type", "cipher", "has_psk", "rekey_interval_s", "parameters"})
        self.assertEqual(set(comp_dict["camouflage"].keys()), {"type", "domain", "sni", "resolvers", "rate_limit", "parameters"})

    def test_tier1_api_pools_composition_endpoint(self):
        """Verify GET /api/pools/composition returns 3-layer composition object for pool."""
        storage = {
            "pools": {
                "AlphaPool": {
                    "transport": "wireguard",
                    "mtu": 1420,
                    "tunnel_port": 51820,
                }
            }
        }
        self.handler.path = "/api/pools/composition?pool=AlphaPool"
        with patch("core.web_server.load_data", return_value=storage):
            self.handler.do_GET()
        self.handler.send_response.assert_called_with(200)
        res = self._get_written_json()
        self.assertEqual(res["pool"], "AlphaPool")
        self.assertEqual(res["composition"]["network"]["type"], "wireguard")
        self.assertEqual(res["composition"]["encryption"]["type"], "noise")

    def test_tier1_api_composition_validate_endpoint_valid(self):
        """Verify POST /api/pools/composition/validate returns valid=True for compliant layers."""
        body = {
            "composition": {
                "engine": "gre_xhttp",
                "network": {"type": "gre_ipv4", "mtu": 1360},
                "encryption": {"type": "tls13", "cipher": "TLS_AES_128_GCM_SHA256"},
                "camouflage": {"type": "xhttp_grpc", "domain": "cdn.example.com"},
            }
        }
        raw = json.dumps(body).encode("utf-8")
        self.handler.path = "/api/pools/composition/validate"
        self.handler.rfile = io.BytesIO(raw)
        self.handler.headers = {"Content-Length": str(len(raw))}
        self.handler.do_POST()
        self.handler.send_response.assert_called_with(200)
        res = self._get_written_json()
        self.assertTrue(res["valid"])
        self.assertEqual(res["message"], "Composition is valid.")

    def test_tier1_matrix_single_link_generation(self):
        """Verify PrivateLinkManager.create_private_link creates an isolated active link record."""
        iran = {"ip": "192.0.2.10"}
        kharej = {"ip": "198.51.100.10"}
        with patch("core.private_link_manager.load_data", return_value=self.mock_storage), \
             patch("core.private_link_manager.atomic_update", side_effect=lambda fn: fn(self.mock_storage)), \
             patch("core.resource_allocator.load_data", return_value=self.mock_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(self.mock_storage)):

            link = PrivateLinkManager.create_private_link(
                link_name="link_ir1_kh1",
                engine_id="wireguard",
                iran_server=iran,
                kharej_server=kharej,
                params={"tunnel_port": 51820},
            )

        self.assertTrue(link["link_id"].startswith("link-"))
        self.assertEqual(link["status"], "planned")
        self.assertEqual(link["engine_id"], "wireguard")
        self.assertTrue(link["interface"].startswith("pl_") or link["interface"].startswith("pl-"))
        subnet = ipaddress.IPv4Network(link["private_subnet"])
        self.assertEqual(subnet.prefixlen, 30)
        self.assertEqual(link["iran_server"]["private_ip"], str(list(subnet.hosts())[0]))
        self.assertEqual(link["kharej_server"]["private_ip"], str(list(subnet.hosts())[1]))

    # =========================================================================
    # TIER 2: BOUNDARY & CORNER CASES
    # =========================================================================

    def test_tier2_invalid_layer_unencrypted_public_gre_forbidden(self):
        """Validate composition forbids raw unencrypted GRE on public IPv4."""
        comp = UnifiedComposition(
            engine="gre",
            network=NetworkLayerSpec(type="gre_ipv4", mtu=1400),
            encryption=EncryptionLayerSpec(type="none"),
            camouflage=CamouflageLayerSpec(type="none"),
        )
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("Raw unencrypted GRE on public IPv4 is forbidden", msg)

    def test_tier2_invalid_layer_xhttp_without_tls_forbidden(self):
        """Validate composition forbids XHTTP camouflage without TLS 1.3."""
        comp = UnifiedComposition(
            engine="gre_xhttp",
            network=NetworkLayerSpec(type="gre_ipv4", mtu=1360),
            encryption=EncryptionLayerSpec(type="none"),  # Missing TLS 1.3
            camouflage=CamouflageLayerSpec(type="xhttp_grpc", domain="cdn.example.com"),
        )
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("XHTTP camouflage requires TLS 1.3", msg)

    def test_tier2_invalid_layer_dns_without_domain_forbidden(self):
        """Validate composition forbids DNS delegation camouflage with empty domain."""
        comp = UnifiedComposition(
            engine="slipstream",
            network=NetworkLayerSpec(type="slipstream", mtu=1200),
            encryption=EncryptionLayerSpec(type="psk"),
            camouflage=CamouflageLayerSpec(type="dns_delegation", domain=None),
        )
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("DNS delegation requires a delegated domain name", msg)

    def test_tier2_vni_boundary_values(self):
        """Verify VNI boundary values: 1 and 16777215 valid; 0 and 16777216 invalid."""
        for vni in (1, 16777215):
            comp = UnifiedComposition(
                engine="geneve",
                network=NetworkLayerSpec(type="geneve", vni=vni),
                encryption=EncryptionLayerSpec(type="none"),
                camouflage=CamouflageLayerSpec(type="none"),
            )
            valid, _ = validate_composition(comp)
            self.assertTrue(valid, f"VNI {vni} should be valid")

        for bad_vni in (0, -1, 16777216):
            comp = UnifiedComposition(
                engine="geneve",
                network=NetworkLayerSpec(type="geneve", vni=bad_vni),
                encryption=EncryptionLayerSpec(type="none"),
                camouflage=CamouflageLayerSpec(type="none"),
            )
            valid, msg = validate_composition(comp)
            self.assertFalse(valid, f"VNI {bad_vni} should be invalid")
            self.assertIn("must be between 1 and 16777215", msg)

    def test_tier2_mtu_extreme_clamping_at_1200(self):
        """Verify path MTU calculation clamps at minimum 1200 even under extreme overhead."""
        rec_mtu = PrivateLinkManager.calculate_recommended_mtu(
            engine_id="gre_ipv4",
            underlying_engine="geneve",
            base_mtu=1300,
        )
        # base 1300 - (100 + 50) = 1150 -> clamped to 1200
        self.assertEqual(rec_mtu, 1200)

    def test_tier2_zero_and_negative_port_validation(self):
        """Verify validate_port rejects 0, negative values, and out-of-range numbers."""
        for bad_port in (0, -1, 65536, "0", "-500", "99999", "abc"):
            with self.assertRaises(ValueError):
                validate_port(bad_port)

        with self.assertRaises(ValueError):
            validate_ports(["443", "0", "8443"])

    def test_tier2_resource_reservation_port_collision(self):
        """Verify ResourceReservationManager raises RuntimeError on port collision."""
        fake_storage = {
            "resource_reservations": {
                "pool_a": {
                    "pool_name": "pool_a",
                    "host_ports": {"192.0.2.1": [51820]},
                    "interfaces": ["pl-linka"],
                }
            }
        }
        with patch("core.resource_allocator.load_data", return_value=fake_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(fake_storage)):

            with self.assertRaises(RuntimeError) as ctx:
                ResourceReservationManager.reserve_pool_resources(
                    pool_name="pool_b",
                    engine_id="wireguard",
                    host_ports={"192.0.2.1": [51820]},  # Collision on 192.0.2.1:51820
                    interface_names=["pl-linkb"],
                )
            self.assertIn("Port collision", str(ctx.exception))

    def test_tier2_resource_reservation_interface_collision(self):
        """Verify ResourceReservationManager raises RuntimeError on duplicate interface name."""
        fake_storage = {
            "resource_reservations": {
                "pool_a": {
                    "pool_name": "pool_a",
                    "host_ports": {"192.0.2.1": [51820]},
                    "interfaces": ["pl-common"],
                }
            }
        }
        with patch("core.resource_allocator.load_data", return_value=fake_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(fake_storage)):

            with self.assertRaises(RuntimeError) as ctx:
                ResourceReservationManager.reserve_pool_resources(
                    pool_name="pool_b",
                    engine_id="wireguard",
                    host_ports={"192.0.2.1": [51821]},
                    interface_names=["pl-common"],  # Duplicate interface
                )
            self.assertIn("Interface collision", str(ctx.exception))

    def test_tier2_subnet_pool_exhaustion_ipv4(self):
        """Verify allocate_private_ipv4_subnet raises RuntimeError when all /30s are taken."""
        small_pool = ipaddress.IPv4Network("10.100.0.0/28")  # 4 /30 subnets
        used = [str(s) for s in small_pool.subnets(new_prefix=30)]
        with patch("core.resource_allocator.IPV4_POOL_START", small_pool):
            with self.assertRaises(RuntimeError) as ctx:
                allocate_private_ipv4_subnet(used)
            self.assertIn("IPv4 private address pool exhausted", str(ctx.exception))

    def test_tier2_subnet_pool_exhaustion_ipv6(self):
        """Verify allocate_private_ipv6_subnet raises RuntimeError when all /126s are taken."""
        small_pool = ipaddress.IPv6Network("fd00:1db9::/124")  # 4 /126 subnets
        used = [str(s) for s in small_pool.subnets(new_prefix=126)]
        with patch("core.resource_allocator.IPV6_POOL_START", small_pool):
            with self.assertRaises(RuntimeError) as ctx:
                allocate_private_ipv6_subnet(used)
            self.assertIn("IPv6 private address pool exhausted", str(ctx.exception))

    def test_tier2_matrix_link_explosion_guard(self):
        """Verify creating >10 links without allow_full_mesh=True is blocked."""
        irans = [{"ip": f"192.0.2.{i}"} for i in range(1, 4)]    # 3 nodes
        kharejs = [{"ip": f"198.51.100.{i}"} for i in range(1, 5)] # 4 nodes -> 12 links
        with self.assertRaises(ValueError) as ctx:
            PrivateLinkManager.create_matrix_topology(
                iran_servers=irans,
                kharej_servers=kharejs,
                engine_id="wireguard",
                allow_full_mesh=False,
            )
        self.assertIn("Accidental full mesh explosion is blocked", str(ctx.exception))

    # =========================================================================
    # TIER 3: CROSS-FEATURE COMBINATIONS
    # =========================================================================

    def test_tier3_stacked_layers_path_mtu_discovery(self):
        """Verify overhead calculations across stacked hybrid layers (Geneve over GRE6)."""
        overhead_geneve = PrivateLinkManager.calculate_path_overhead("geneve")
        self.assertEqual(overhead_geneve, 50)

        overhead_hybrid = PrivateLinkManager.calculate_path_overhead("geneve", underlying_engine="gre6")
        self.assertEqual(overhead_hybrid, 50 + 64)

        rec_mtu = PrivateLinkManager.calculate_recommended_mtu("geneve", underlying_engine="gre6")
        self.assertEqual(rec_mtu, 1500 - 114)

    def test_tier3_matrix_links_shared_kharej_different_ports(self):
        """Verify multiple Iran nodes connecting to the same Kharej node receive distinct ports."""
        ir1 = {"ip": "192.0.2.1"}
        ir2 = {"ip": "192.0.2.2"}
        kh1 = {"ip": "198.51.100.1"}

        with patch("core.private_link_manager.load_data", return_value=self.mock_storage), \
             patch("core.private_link_manager.atomic_update", side_effect=lambda fn: fn(self.mock_storage)), \
             patch("core.resource_allocator.load_data", return_value=self.mock_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(self.mock_storage)):

            selected = [("192.0.2.1", "198.51.100.1"), ("192.0.2.2", "198.51.100.1")]
            links = PrivateLinkManager.create_matrix_topology(
                iran_servers=[ir1, ir2],
                kharej_servers=[kh1],
                engine_id="wireguard",
                selected_pairs=selected,
                params={"tunnel_port": 51820},
            )

        self.assertEqual(len(links), 2)
        # Subnets must not collide
        self.assertNotEqual(links[0]["private_subnet"], links[1]["private_subnet"])
        # Interfaces must not collide
        self.assertNotEqual(links[0]["interface"], links[1]["interface"])
        # Reservations must show ports 51820 and 51821 reserved on Kharej
        res = self.mock_storage["resource_reservations"]
        ports_ir1 = res["link_" + links[0]["link_name"]]["host_ports"]["198.51.100.1"]
        ports_ir2 = res["link_" + links[1]["link_name"]]["host_ports"]["198.51.100.1"]
        self.assertEqual(ports_ir1, [51820])
        self.assertEqual(ports_ir2, [51821])

    def test_tier3_schema_migration_v0_to_v3_pipeline(self):
        """Verify end-to-end migration from v0 legacy state to v3 populates composition."""
        v0_data = {
            "pools": {
                "Pool1": {"transport": "gre_xhttp", "gre_mtu": 1360, "domain": "cdn.test"},
                "Pool2": {"transport": "wireguard", "mtu": 1420, "enable_psk": True},
                "Pool3": {"transport": "slipstream", "domain": "tunnel.test"},
            }
        }
        migrated, was_modified = apply_migrations(v0_data)
        self.assertTrue(was_modified)
        self.assertEqual(migrated["schema_version"], 3)
        self.assertIn("custom_links", migrated)
        self.assertIn("resource_reservations", migrated)
        self.assertIn("persistent_jobs", migrated)

        # Pool 1 composition
        p1_comp = migrated["pools"]["Pool1"]["composition"]
        self.assertEqual(p1_comp["network"]["type"], "gre_ipv4")
        self.assertEqual(p1_comp["encryption"]["type"], "tls13")
        self.assertEqual(p1_comp["camouflage"]["type"], "xhttp_grpc")

        # Pool 2 composition
        p2_comp = migrated["pools"]["Pool2"]["composition"]
        self.assertEqual(p2_comp["network"]["type"], "wireguard")
        self.assertEqual(p2_comp["encryption"]["type"], "noise")

        # Pool 3 composition
        p3_comp = migrated["pools"]["Pool3"]["composition"]
        self.assertEqual(p3_comp["network"]["type"], "slipstream")
        self.assertEqual(p3_comp["camouflage"]["type"], "dns_delegation")

    def test_tier3_schema_migration_idempotence(self):
        """Verify applying schema migration twice produces identical result without modification."""
        v2_data = {
            "schema_version": 2,
            "custom_links": {"link_a": {"engine_id": "wireguard"}},
            "resource_reservations": {},
            "persistent_jobs": {},
            "pools": {
                "P1": {"transport": "vxlan", "vni": 100}
            }
        }
        migrated_1, was_mod_1 = apply_migrations(v2_data)
        self.assertTrue(was_mod_1)
        self.assertEqual(migrated_1["schema_version"], 3)

        migrated_2, was_mod_2 = apply_migrations(migrated_1)
        self.assertFalse(was_mod_2)
        self.assertEqual(migrated_1, migrated_2)

    def test_tier3_schema_migration_corrupted_pool_resilience(self):
        """Verify migration safely skips corrupted non-dict pool entries without crashing."""
        corrupted_data = {
            "schema_version": 1,
            "pools": {
                "ValidPool": {"transport": "wireguard"},
                "BrokenPool": None,
                "StringPool": "invalid",
            }
        }
        migrated, was_modified = apply_migrations(corrupted_data)
        self.assertTrue(was_modified)
        self.assertEqual(migrated["schema_version"], 3)
        self.assertIn("composition", migrated["pools"]["ValidPool"])

    def test_tier3_preview_and_apply_mutation_diff(self):
        """Verify preview_link_mutation creates accurate diff and flags potential downtime."""
        link_record = {
            "link_name": "test_link",
            "engine_id": "wireguard",
            "mtu": 1420,
            "status": "planned",
        }
        storage = {"custom_links": {"test_link": link_record}}

        with patch("core.private_link_manager.load_data", return_value=storage):
            preview = PrivateLinkManager.preview_link_mutation("test_link", {"mtu": 1360})
            self.assertTrue(preview["has_changes"])
            self.assertTrue(preview["potential_downtime"])
            self.assertEqual(preview["diff"]["mtu"]["current"], 1420)
            self.assertEqual(preview["diff"]["mtu"]["proposed"], 1360)

        with patch("core.private_link_manager.atomic_update", side_effect=lambda fn: fn(storage)):
            updated = PrivateLinkManager.apply_link_mutation("test_link", {"mtu": 1360})
            self.assertEqual(updated["mtu"], 1360)
            self.assertIn("updated_at", updated)

    # =========================================================================
    # TIER 4: REAL-WORLD SCENARIOS
    # =========================================================================

    def test_tier4_multi_kharej_cluster_selective_mesh(self):
        """Simulate 2 Iran x 3 Kharej cluster setup with a selective 4-link mesh topology."""
        iran_servers = [
            {"ip": "192.0.2.11", "name": "tehran-edge-1"},
            {"ip": "192.0.2.12", "name": "tabriz-edge-2"},
        ]
        kharej_servers = [
            {"ip": "198.51.100.21", "name": "frankfurt-relay-1"},
            {"ip": "198.51.100.22", "name": "amsterdam-relay-2"},
            {"ip": "198.51.100.23", "name": "helsinki-relay-3"},
        ]

        # 4 explicit pairs:
        # IR1 -> KH1 (Frankfurt)
        # IR1 -> KH2 (Amsterdam)
        # IR2 -> KH2 (Amsterdam)
        # IR2 -> KH3 (Helsinki)
        selected_pairs = [
            ("192.0.2.11", "198.51.100.21"),
            ("192.0.2.11", "198.51.100.22"),
            ("192.0.2.12", "198.51.100.22"),
            ("192.0.2.12", "198.51.100.23"),
        ]

        with patch("core.private_link_manager.load_data", return_value=self.mock_storage), \
             patch("core.private_link_manager.atomic_update", side_effect=lambda fn: fn(self.mock_storage)), \
             patch("core.resource_allocator.load_data", return_value=self.mock_storage), \
             patch("core.resource_allocator.atomic_update", side_effect=lambda fn: fn(self.mock_storage)):

            links = PrivateLinkManager.create_matrix_topology(
                iran_servers=iran_servers,
                kharej_servers=kharej_servers,
                engine_id="wireguard",
                selected_pairs=selected_pairs,
                params={"tunnel_port": 51820},
            )

        self.assertEqual(len(links), 4)

        # 1. Non-conflicting IP allocations: all 4 subnets must be distinct
        subnets = [link["private_subnet"] for link in links]
        self.assertEqual(len(set(subnets)), 4, "Subnets must be mutually exclusive")

        # 2. Check each subnet is a valid /30 with 2 distinct usable host IPs
        allocated_private_ips = set()
        for link in links:
            ir_ip = link["iran_server"]["private_ip"]
            kh_ip = link["kharej_server"]["private_ip"]
            self.assertNotEqual(ir_ip, kh_ip)
            self.assertNotIn(ir_ip, allocated_private_ips)
            self.assertNotIn(kh_ip, allocated_private_ips)
            allocated_private_ips.add(ir_ip)
            allocated_private_ips.add(kh_ip)

        # 3. All interface names must be unique
        ifaces = [link["interface"] for link in links]
        self.assertEqual(len(set(ifaces)), 4)

        # 4. Storage has all 4 links registered under custom_links
        stored_links = self.mock_storage["custom_links"]
        self.assertEqual(len(stored_links), 4)

    def test_tier4_timed_default_route_switch_rollback(self):
        """Simulate default route modification with timed automatic watchdog rollback."""
        mock_ssh = MagicMock()
        staged = PrivateLinkManager.create_timed_default_route_switch(
            ssh_manager=mock_ssh,
            gateway_ip="10.100.0.2",
            timeout_seconds=45,
        )
        self.assertEqual(staged["status"], "staged")
        self.assertEqual(staged["gateway_ip"], "10.100.0.2")
        self.assertEqual(staged["timeout_seconds"], 45)
        # Verify self-reverting script logic
        script = staged["script"]
        self.assertIn("ip route show default", script)
        self.assertIn("ip route replace default via 10.100.0.2", script)
        self.assertIn("sleep 45", script)
        self.assertIn("ip route replace default via $ORIG_GW", script)

    def test_tier4_cluster_failover_and_health_synthesis(self):
        """Simulate path degradation on primary link and layered health synthesis."""
        # 1. Primary link data path fails: overall status becomes DEGRADED
        layered_status_degraded = TelemetrySupervisor.build_layered_status(
            process_up=True,
            interface_up=True,
            handshake_up=True,
            route_up=True,
            dns_up=True,
            data_plane_up=False,  # Data plane dropped
        )
        self.assertEqual(layered_status_degraded["overall_status"], "DEGRADED")
        self.assertEqual(layered_status_degraded["layers"]["data_plane"], "DOWN")

        # 2. Complete interface drop: overall status becomes DOWN
        layered_status_down = TelemetrySupervisor.build_layered_status(
            process_up=True,
            interface_up=False,
            handshake_up=False,
            route_up=False,
            dns_up=False,
            data_plane_up=False,
        )
        self.assertEqual(layered_status_down["overall_status"], "DOWN")

        # 3. Healthy secondary backup link: overall status HEALTHY
        layered_status_healthy = TelemetrySupervisor.build_layered_status(
            process_up=True,
            interface_up=True,
            handshake_up=True,
            route_up=True,
            dns_up=True,
            data_plane_up=True,
        )
        self.assertEqual(layered_status_healthy["overall_status"], "HEALTHY")
        self.assertEqual(layered_status_healthy["layers"]["data_plane"], "UP")


if __name__ == "__main__":
    unittest.main()
