"""Unit tests for schema migration pipeline (v0 -> v1 -> v2 -> v3).


- Migration pipeline from legacy v0, v1, v2 to v3
- Population of 3-layer composition for pools lacking it
- Addition of matrix_links dictionary
- Preservation of all existing legacy fields
- Idempotence on already-migrated schemas
- Resilience against corrupted or missing structures
"""

import copy
import unittest

from core.schema_migration import (
    apply_migrations,
    CURRENT_SCHEMA_VERSION,
    migrate_v0_to_v1,
    migrate_v1_to_v2,
    migrate_v2_to_v3,
    MIGRATION_PIPELINE,
)
from core.composition import validate_composition


class SchemaMigrationTests(unittest.TestCase):
    def test_current_schema_version_is_3(self):
        self.assertEqual(CURRENT_SCHEMA_VERSION, 3)
        self.assertIn(0, MIGRATION_PIPELINE)
        self.assertIn(1, MIGRATION_PIPELINE)
        self.assertIn(2, MIGRATION_PIPELINE)

    def test_v0_to_v3_full_migration(self):
        legacy = {
            "pools": {
                "legacy_pck_pool": {
                    "nodes": [{"ip": "192.0.2.1"}],
                    "client_ports": ["443"],
                    "transport": "pck"
                },
                "gre_pool": {
                    "transport": "gre",
                    "gre_mtu": 1400
                },
                "waterwall_pool": {
                    "transport": "waterwall",
                    "camouflage": {"mode": "trojan", "password": "secret-pass-1234", "server_name": "tunnel.test"}
                }
            }
        }
        migrated, was_modified = apply_migrations(legacy)
        self.assertTrue(was_modified)
        self.assertEqual(migrated["schema_version"], 3)

        # v1 assertions: engine attribution and strict dns_policy
        self.assertEqual(migrated["pools"]["legacy_pck_pool"]["engine"], "backpack")
        self.assertEqual(migrated["pools"]["legacy_pck_pool"]["dns_policy"], "strict")
        self.assertEqual(migrated["pools"]["gre_pool"]["engine"], "gre_ipv4")
        self.assertEqual(migrated["pools"]["waterwall_pool"]["engine"], "waterwall")

        # v2 assertions: custom_links, resource_reservations, persistent_jobs
        self.assertIn("custom_links", migrated)
        self.assertIn("resource_reservations", migrated)
        self.assertIn("persistent_jobs", migrated)

        # v3 assertions: matrix_links initialized
        self.assertIn("matrix_links", migrated)
        self.assertIsInstance(migrated["matrix_links"], dict)

        # v3 assertions: 3-layer composition populated and valid
        pck_comp = migrated["pools"]["legacy_pck_pool"]["composition"]
        self.assertIn(pck_comp["transport"]["type"], ("tcp", "direct"))
        self.assertIn(pck_comp["camouflage"]["type"], ("pck", "none"))

        gre_comp = migrated["pools"]["gre_pool"]["composition"]
        self.assertIn(gre_comp["transport"]["type"], ("gre", "gre_ipv4"))
        self.assertEqual(gre_comp["encryption"]["type"], "ipsec")
        self.assertEqual(gre_comp["transport"]["mtu"], 1400)

        waterwall_comp = migrated["pools"]["waterwall_pool"]["composition"]
        self.assertEqual(waterwall_comp["network"]["type"], "direct")
        self.assertEqual(waterwall_comp["encryption"]["type"], "tls13")

        # Verify preservation of legacy fields
        self.assertEqual(migrated["pools"]["legacy_pck_pool"]["transport"], "pck")
        self.assertEqual(migrated["pools"]["legacy_pck_pool"]["nodes"], [{"ip": "192.0.2.1"}])
        self.assertEqual(migrated["pools"]["legacy_pck_pool"]["client_ports"], ["443"])
        self.assertEqual(migrated["pools"]["gre_pool"]["gre_mtu"], 1400)

    def test_v1_to_v3_migration(self):
        v1_data = {
            "schema_version": 1,
            "pools": {
                "wg_pool": {
                    "transport": "wireguard",
                    "engine": "wireguard",
                    "wireguard_mtu": 1420
                }
            }
        }
        migrated, was_modified = apply_migrations(v1_data)
        self.assertTrue(was_modified)
        self.assertEqual(migrated["schema_version"], 3)
        self.assertIn("custom_links", migrated)
        self.assertIn("resource_reservations", migrated)
        self.assertIn("persistent_jobs", migrated)
        self.assertIn("matrix_links", migrated)

        comp = migrated["pools"]["wg_pool"]["composition"]
        self.assertEqual(comp["transport"]["type"], "wireguard")
        self.assertIn(comp["encryption"]["type"], ("wireguard", "noise"))
        self.assertEqual(comp["transport"]["mtu"], 1420)

    def test_v2_to_v3_migration_direct(self):
        v2_data = {
            "schema_version": 2,
            "custom_links": {"link_a": {"name": "link_a"}},
            "resource_reservations": {"pool_1": {}},
            "persistent_jobs": {},
            "pools": {
                "geneve_pool": {
                    "name": "geneve_pool",
                    "transport": "geneve_ipsec",
                    "engine": "geneve_ipsec",
                    "vni": 2000,
                    "geneve_mtu": 1390
                }
            }
        }
        migrated = migrate_v2_to_v3(v2_data)
        self.assertEqual(migrated["schema_version"], 3)
        self.assertIn("matrix_links", migrated)
        self.assertEqual(migrated["matrix_links"], {})
        # Existing v2 fields preserved
        self.assertEqual(migrated["custom_links"], {"link_a": {"name": "link_a"}})

        comp = migrated["pools"]["geneve_pool"]["composition"]
        self.assertEqual(comp["transport"]["type"], "geneve")
        self.assertEqual(comp["encryption"]["type"], "ipsec")
        self.assertEqual(comp["transport"]["vni"], 2000)
        self.assertEqual(comp["transport"]["mtu"], 1390)

    def test_idempotence_on_v3_schema(self):
        v3_data = {
            "schema_version": 3,
            "pools": {
                "p1": {
                    "engine": "waterwall",
                    "transport": "waterwall",
                    "composition": {
                        "transport": {"type": "tcp", "layer": "L7", "mtu": 1500},
                        "encryption": {"type": "tls", "cipher": "tls13", "auth_mode": "sni", "enabled": True},
                        "camouflage": {"type": "waterwall", "mode": "vless_mux"}
                    }
                }
            },
            "custom_links": {},
            "resource_reservations": {},
            "persistent_jobs": {},
            "matrix_links": {}
        }
        original = copy.deepcopy(v3_data)
        migrated, was_modified = apply_migrations(v3_data)
        self.assertFalse(was_modified)
        self.assertEqual(migrated, original)

    def test_corrupted_and_edge_case_resilience(self):
        # Non-dict inputs
        res, mod = apply_migrations(None)
        self.assertIsNone(res)
        self.assertFalse(mod)

        res, mod = apply_migrations("not a dict")
        self.assertEqual(res, "not a dict")
        self.assertFalse(mod)

        # Empty dict (assumed v0)
        res, mod = apply_migrations({})
        self.assertTrue(mod)
        self.assertEqual(res["schema_version"], 3)
        self.assertEqual(res["matrix_links"], {})

        # Pools value is not a dict
        bad_pools = {"schema_version": 2, "pools": "corrupted"}
        migrated = migrate_v2_to_v3(bad_pools)
        self.assertEqual(migrated["schema_version"], 3)
        self.assertEqual(migrated["matrix_links"], {})

        # Pool item is not a dict
        bad_pool_item = {"schema_version": 2, "pools": {"invalid": "not-a-dict"}}
        migrated = migrate_v2_to_v3(bad_pool_item)
        self.assertEqual(migrated["schema_version"], 3)
        self.assertEqual(migrated["pools"]["invalid"], "not-a-dict")


if __name__ == "__main__":
    unittest.main()
