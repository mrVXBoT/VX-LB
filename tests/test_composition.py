import pytest
"""Unit tests for Unified Layer and Composition Data Model (Milestone 1).

Covers:
- Dataclasses: TransportLayer, EncryptionLayer, CamouflageLayer, PoolComposition
- Validation: validate_composition edge cases, MTU ranges, unencrypted GRE, VNI boundaries
- Bi-directional translation: legacy_transport_to_composition, composition_to_legacy_string
- Inference: infer_composition_from_pool
- Catalog: get_available_compositions validity
- API integration: GET /api/compositions and GET /api/status enrichment
"""

import json
import unittest
from unittest.mock import MagicMock, patch

from core.composition import (
    TransportLayer,
    EncryptionLayer,
    CamouflageLayer,
    PoolComposition,
    validate_composition,
    legacy_transport_to_composition,
    composition_to_legacy_string,
    infer_composition_from_pool,
    get_available_compositions,
)
from core import web_server as web


class CompositionDataclassTests(unittest.TestCase):
    def test_transport_layer_serialization(self):
        t = TransportLayer(type="gre", layer="L3", mtu=1400, vni=None, interface="gre0")
        d = t.to_dict()
        self.assertEqual(d["type"], "gre")
        self.assertEqual(d["layer"], "L3")
        self.assertEqual(d["mtu"], 1400)
        self.assertEqual(d["interface"], "gre0")
        self.assertIsNone(d["vni"])

        t2 = TransportLayer.from_dict(d)
        self.assertEqual(t, t2)

    def test_encryption_layer_serialization(self):
        e = EncryptionLayer(type="ipsec", cipher="aes_gcm_256", auth_mode="psk", enabled=True)
        d = e.to_dict()
        self.assertEqual(d["type"], "ipsec")
        self.assertEqual(d["cipher"], "aes_gcm_256")
        self.assertTrue(d["enabled"])

        e2 = EncryptionLayer.from_dict(d)
        self.assertEqual(e, e2)

        # None type default enabled is False
        e_none = EncryptionLayer.from_dict({"type": "none"})
        self.assertFalse(e_none.enabled)

    def test_camouflage_layer_serialization(self):
        c = CamouflageLayer(type="dns_subdomain", mode="delegated_ns", domain="dns.example.com", rate_limit=200, resolvers=["1.1.1.1"])
        d = c.to_dict()
        self.assertEqual(d["type"], "dns_subdomain")
        self.assertEqual(d["domain"], "dns.example.com")
        self.assertEqual(d["rate_limit"], 200)
        self.assertEqual(d["resolvers"], ["1.1.1.1"])

        c2 = CamouflageLayer.from_dict(d)
        self.assertEqual(c, c2)

    def test_pool_composition_structure_and_alias(self):
        comp = PoolComposition(
            transport=TransportLayer(type="wireguard", layer="L3", mtu=1420),
            encryption=EncryptionLayer(type="wireguard", cipher="chacha20poly1305", auth_mode="pubkey", enabled=True),
            camouflage=CamouflageLayer(type="none"),
        )
        # Check backward compatibility property alias
        self.assertEqual(comp.network, comp.transport)

        d = comp.to_dict()
        self.assertIn("transport", d)
        self.assertIn("encryption", d)
        self.assertIn("camouflage", d)
        # Check backward compatibility dict key
        self.assertIn("network", d)
        self.assertEqual(d["network"], d["transport"])

        comp2 = PoolComposition.from_dict(d)
        self.assertEqual(comp.transport, comp2.transport)
        self.assertEqual(comp.encryption, comp2.encryption)
        self.assertEqual(comp.camouflage, comp2.camouflage)

    def test_from_dict_with_network_alias(self):
        legacy_dict = {
            "network": {"type": "gre", "layer": "L3", "mtu": 1400},
            "encryption": {"type": "ipsec", "cipher": "aes_gcm_256"},
            "camouflage": {"type": "none"},
        }
        comp = PoolComposition.from_dict(legacy_dict)
        self.assertEqual(comp.transport.type, "gre")
        self.assertEqual(comp.transport.layer, "L3")


class CompositionValidationTests(unittest.TestCase):
    def test_valid_compositions(self):
        valid_cases = [
            legacy_transport_to_composition("gre"),
            legacy_transport_to_composition("geneve_ipsec"),
            legacy_transport_to_composition("geneve"),
            legacy_transport_to_composition("vxlan"),
            legacy_transport_to_composition("wireguard"),
            legacy_transport_to_composition("slipstream", domain="sub.example.com"),
            legacy_transport_to_composition("waterwall"),
            legacy_transport_to_composition("tcp"),
            legacy_transport_to_composition("pck"),
        ]
        for comp in valid_cases:
            valid, msg = validate_composition(comp)
            self.assertTrue(valid, f"Expected valid for {comp}, got: {msg}")

    def test_mtu_bounds_validation(self):
        # MTU too small (< 576)
        comp_small = legacy_transport_to_composition("gre")
        comp_small.transport.mtu = 500
        valid, msg = validate_composition(comp_small)
        self.assertFalse(valid)
        self.assertIn("Invalid MTU", msg)

        # MTU too large (> 9000)
        comp_large = legacy_transport_to_composition("gre")
        comp_large.transport.mtu = 9001
        valid, msg = validate_composition(comp_large)
        self.assertFalse(valid)
        self.assertIn("Invalid MTU", msg)

        # MTU valid boundary
        comp_bound = legacy_transport_to_composition("gre")
        comp_bound.transport.mtu = 576
        valid, _ = validate_composition(comp_bound)
        self.assertTrue(valid)

        comp_bound.transport.mtu = 9000
        valid, _ = validate_composition(comp_bound)
        self.assertTrue(valid)

    def test_unencrypted_gre_rejected(self):
        comp = PoolComposition(
            transport=TransportLayer(type="gre", layer="L3", mtu=1400),
            encryption=EncryptionLayer(type="none", enabled=False),
            camouflage=CamouflageLayer(type="none"),
        )
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("Raw unencrypted GRE", msg)

    def test_vni_bounds_validation(self):
        # Invalid 0 VNI
        comp = legacy_transport_to_composition("vxlan")
        comp.transport.vni = 0
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("VNI", msg)

        # Invalid > 16777215 VNI
        comp.transport.vni = 16777216
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("VNI", msg)

        # Valid VNI
        comp.transport.vni = 1000
        valid, _ = validate_composition(comp)
        self.assertTrue(valid)

    def test_dns_camouflage_requires_domain(self):
        comp = legacy_transport_to_composition("slipstream")
        comp.camouflage.domain = None
        valid, msg = validate_composition(comp)
        self.assertFalse(valid)
        self.assertIn("domain", msg.lower())

        comp.camouflage.domain = "ns.domain.com"
        valid, _ = validate_composition(comp)
        self.assertTrue(valid)

    def test_invalid_input_types(self):
        valid, msg = validate_composition("not a dict or comp")
        self.assertFalse(valid)
        self.assertIn("Expected PoolComposition or dict", msg)

        valid, msg = validate_composition({"transport": "bad"})
        self.assertFalse(valid)


class CompositionTranslationTests(unittest.TestCase):
    def test_bidirectional_roundtrip_all_monolithic_transports(self):
        transports = [
            "gre",
            "geneve_ipsec",
            "geneve",
            "vxlan",
            "wireguard",
            "waterwall",
            "slipstream",
            "gre6",
            "ip6ip6",
            "tcp",
            "udp",
            "wss",
            "pck",
            "stealth",
        ]
        for tr in transports:
            comp = legacy_transport_to_composition(tr)
            recovered = composition_to_legacy_string(comp)
            self.assertEqual(recovered, tr, f"Roundtrip failed for {tr}: got {recovered}")

    def test_infer_composition_from_pool_extracts_nested_data(self):
        pool = {
            "name": "geneve_test_pool",
            "transport": "geneve",
            "nodes": [
                {
                    "ip": "1.2.3.4",
                    "geneve": {"vni": 2500, "mtu": 1420, "interface": "gnv-node1"}
                }
            ]
        }
        inferred = infer_composition_from_pool(pool)
        self.assertEqual(inferred["transport"]["type"], "geneve")
        self.assertEqual(inferred["transport"]["vni"], 2500)
        self.assertEqual(inferred["transport"]["mtu"], 1420)
        self.assertEqual(inferred["transport"]["interface"], "gnv-node1")

    def test_infer_composition_preserves_existing_composition(self):
        existing = {
            "transport": {"type": "wireguard", "layer": "L3", "mtu": 1420},
            "encryption": {"type": "wireguard", "cipher": "chacha20poly1305", "auth_mode": "pubkey", "enabled": True},
            "camouflage": {"type": "none"}
        }
        pool = {
            "name": "wg_pool",
            "composition": existing
        }
        inferred = infer_composition_from_pool(pool)
        self.assertEqual(inferred["transport"]["type"], "wireguard")
        self.assertEqual(inferred["encryption"]["cipher"], "chacha20poly1305")

    def test_infer_composition_handles_corrupted_pool(self):
        self.assertIsInstance(infer_composition_from_pool(None), dict)
        self.assertIsInstance(infer_composition_from_pool("corrupted"), dict)
        self.assertIsInstance(infer_composition_from_pool({}), dict)


class CompositionCatalogTests(unittest.TestCase):
    def test_all_catalog_entries_are_valid(self):
        catalog = get_available_compositions()
        self.assertGreaterEqual(len(catalog), 10)
        ids = set()
        for item in catalog:
            self.assertIn("id", item)
            self.assertIn("name", item)
            self.assertIn("description", item)
            self.assertIn("composition", item)
            self.assertIn("schema", item)
            ids.add(item["id"])

            # Verify that every profile provided is valid (provide mock domain for slipstream)
            comp_dict = item["composition"]
            if comp_dict["camouflage"]["type"] in ("dns_subdomain", "dns_delegation") and not comp_dict["camouflage"]["domain"]:
                comp_dict["camouflage"]["domain"] = "example.com"
            valid, msg = validate_composition(comp_dict)
            self.assertTrue(valid, f"Catalog item {item['id']} is invalid: {msg}")

        self.assertIn("gre", ids)
        self.assertIn("geneve_ipsec", ids)
        self.assertIn("wireguard", ids)
        self.assertIn("slipstream", ids)
        self.assertIn("waterwall", ids)


class CompositionWebIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.handler = web.LDWebRequestHandler.__new__(web.LDWebRequestHandler)
        self.handler.headers = {}
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.wfile = MagicMock()
        self.handler._is_authenticated = MagicMock(return_value=True)

    def test_api_compositions_endpoint(self):
        self.handler.path = "/api/compositions"
        self.handler.do_GET()
        self.handler.send_response.assert_called_with(200)
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written.decode("utf-8"))
        self.assertIn("compositions", data)
        self.assertIn("schema_models", data)
        self.assertIsInstance(data["compositions"], list)
        self.assertGreater(len(data["compositions"]), 5)
        self.assertIn("TransportLayer", data["schema_models"])

    def test_api_status_includes_composition(self):
        fake_storage = {
            "pools": {
                "P1": {
                    "name": "P1",
                    "transport": "wireguard",
                    "engine": "wireguard",
                    "composition": {
                        "transport": {"type": "wireguard", "layer": "L3", "mtu": 1420},
                        "encryption": {"type": "wireguard", "cipher": "chacha20poly1305"},
                        "camouflage": {"type": "none"}
                    },
                    "nodes": []
                }
            }
        }
        self.handler.path = "/api/status"
        with patch("core.web_server.load_data", return_value=fake_storage):
            self.handler.do_GET()
        self.handler.send_response.assert_called_with(200)
        written = b"".join(call.args[0] for call in self.handler.wfile.write.call_args_list)
        data = json.loads(written.decode("utf-8"))
        self.assertIn("pools", data)
        pool = data["pools"][0]
        self.assertIn("composition", pool)
        self.assertEqual(pool["composition"]["transport"]["type"], "wireguard")


if __name__ == "__main__":
    unittest.main()


@pytest.mark.parametrize('mode',['http','https','tun','dc6','fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l7-header-mutation'])
def test_managed_transport_identity_survives_composition_roundtrip(mode):
    from core.composition import legacy_transport_to_composition,composition_to_legacy_string
    composition=legacy_transport_to_composition(mode)
    assert composition_to_legacy_string(composition)==mode
    if mode in ['fake-sni','split-tls','hop-ttl-injection','tcp-state-desync','l7-header-mutation']:
        assert composition.encryption.type=='tls' and composition.encryption.auth_mode=='mutual_tls'
