"""Unit tests for Production Readiness Gate and Audit Reporting."""
import unittest

from core.capabilities import (
    get_capability,
    get_engine_production_gate_report,
    is_engine_supported,
    validate_production_readiness,
)


class TestProductionReadinessGate(unittest.TestCase):
    def test_unsupported_engine_strictly_blocked_in_all_environments(self):
        # 6TO4 Anycast (RFC 7526) is deprecated and marked 'unsupported'
        ok_dev, msg_dev = validate_production_readiness("6to4_anycast", is_production=False)
        self.assertFalse(ok_dev)
        self.assertIn("unsupported", msg_dev)

        ok_prod, msg_prod = validate_production_readiness("6to4_anycast", is_production=True)
        self.assertFalse(ok_prod)
        self.assertIn("unsupported", msg_prod)

        # Even with allow_experimental=True, unsupported MUST remain blocked
        ok_override, msg_override = validate_production_readiness(
            "6to4_anycast", is_production=True, allow_experimental=True
        )
        self.assertFalse(ok_override)
        self.assertIn("unsupported", msg_override)

    def test_verified_engine_approved_directly(self):
        # Engines that completed production verification
        for eng in ["backpack", "gre_ipv4", "fake-sni", "split-tls", "hop-ttl-injection", "tcp-state-desync", "l7-header-mutation"]:
            ok, msg = validate_production_readiness(eng, is_production=True)
            self.assertTrue(ok, f"Verified engine {eng} failed production validation: {msg}")
            self.assertIn("verified", msg.lower())

    def test_fake_sni_approved_in_production(self):
        # fake-sni is promoted to verified; approved in production without requiring allow_experimental=True
        ok_prod, msg_prod = validate_production_readiness("fake-sni", is_production=True, allow_experimental=False)
        self.assertTrue(ok_prod, f"fake-sni must be approved in production without override: {msg_prod}")
        self.assertIn("verified", msg_prod.lower())

        ok_prod_default, msg_prod_default = validate_production_readiness("fake-sni", is_production=True)
        self.assertTrue(ok_prod_default, f"fake-sni must be approved in production by default: {msg_prod_default}")
        self.assertIn("verified", msg_prod_default.lower())

        ok_dev, msg_dev = validate_production_readiness("fake-sni", is_production=False)
        self.assertTrue(ok_dev, f"fake-sni must be approved in development: {msg_dev}")
        self.assertIn("verified", msg_dev.lower())

        # Whitespace and case tolerance
        ok_case, _ = validate_production_readiness("  FAKE-SNI  ", is_production=True)
        self.assertTrue(ok_case, "fake-sni should be resolved case-insensitively with trimmed whitespace")

        # Underscore alias tolerance
        ok_alias, msg_alias = validate_production_readiness("fake_sni", is_production=True)
        self.assertTrue(ok_alias, f"fake_sni alias should resolve to fake-sni: {msg_alias}")
        self.assertIn("verified", msg_alias.lower())

        cap = get_capability("fake-sni")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.support_status, "verified")
        self.assertTrue(cap.requires_encryption)
        self.assertEqual(cap.encryption_type, "tls13")
        self.assertEqual(cap.kernel_requirements, ["nfnetlink_queue", "iptables"])
        self.assertIn("verified", cap.status_reason.lower())

        # Capability resolution via underscore alias
        cap_alias = get_capability("fake_sni")
        self.assertEqual(cap, cap_alias)

        rep = get_engine_production_gate_report("fake-sni")
        self.assertTrue(rep["found"])
        self.assertEqual(rep["support_status"], "verified")
        self.assertTrue(rep["production_ready"])
        self.assertEqual(rep["disclaimers"], [])

        self.assertTrue(is_engine_supported("fake-sni"))

        # The spoof family label stays experimental; unfinished profiles stay unsupported.
        ok_family, msg_family = validate_production_readiness("spoof", is_production=True, allow_experimental=False)
        self.assertFalse(ok_family, msg_family)
        ok_unfinished, msg_unfinished = validate_production_readiness("l3-ip-spoof", is_production=True, allow_experimental=True)
        self.assertFalse(ok_unfinished, msg_unfinished)
        self.assertIn("unsupported", msg_unfinished)

    def test_experimental_engine_gating(self):
        # Experimental engines: permitted in dev/lab, blocked in prod unless allow_experimental=True
        for exp_eng in ["waterwall", "wireguard", "sit", "6to4_unicast", "geneve", "spoof", "candy-spoof", "parsaksh", "wattunnel"]:
            # In non-production (dev / staging / lab) -> Allowed
            ok_lab, msg_lab = validate_production_readiness(exp_eng, is_production=False)
            self.assertTrue(ok_lab, f"Experimental engine {exp_eng} should be permitted in non-production")

            # In production without override -> Blocked
            ok_prod, msg_prod = validate_production_readiness(exp_eng, is_production=True, allow_experimental=False)
            self.assertFalse(ok_prod, f"Experimental engine {exp_eng} must be blocked in production without override")
            self.assertIn("allow_experimental=True", msg_prod)

            # In production with explicit override -> Permitted
            ok_override, msg_override = validate_production_readiness(
                exp_eng, is_production=True, allow_experimental=True
            )
            self.assertTrue(ok_override, f"Experimental engine {exp_eng} should be permitted with explicit override")
            self.assertIn("explicit experimental override", msg_override)

    def test_unknown_engine_rejected(self):
        ok, msg = validate_production_readiness("non_existent_engine_xyz")
        self.assertFalse(ok)
        self.assertIn("Unknown", msg)

        # None and empty inputs should reject gracefully without unhandled exception
        ok_none, msg_none = validate_production_readiness(None)
        self.assertFalse(ok_none)
        self.assertIn("Unknown", msg_none)

        ok_empty, msg_empty = validate_production_readiness("")
        self.assertFalse(ok_empty)
        self.assertIn("Unknown", msg_empty)

    def test_engine_production_gate_report(self):
        rep_bp = get_engine_production_gate_report("backpack")
        self.assertTrue(rep_bp["found"])
        self.assertEqual(rep_bp["support_status"], "verified")
        self.assertTrue(rep_bp["production_ready"])
        self.assertTrue(rep_bp["requires_binary"])
        self.assertTrue(rep_bp["binary_verified"])

        rep_ww = get_engine_production_gate_report("waterwall")
        self.assertTrue(rep_ww["found"])
        self.assertEqual(rep_ww["support_status"], "experimental")
        self.assertFalse(rep_ww["production_ready"])
        self.assertTrue(rep_ww["requires_binary"])
        self.assertTrue(rep_ww["binary_verified"])

        rep_6to4 = get_engine_production_gate_report("6to4_unicast")
        self.assertTrue(rep_6to4["found"])
        self.assertEqual(rep_6to4["support_status"], "experimental")
        self.assertFalse(rep_6to4["production_ready"])
        self.assertFalse(rep_6to4["requires_binary"])
        # Cleartext disclaimer must be present for unencrypted 6to4
        self.assertTrue(any("Cleartext warning" in d for d in rep_6to4["disclaimers"]))

        rep_gnv = get_engine_production_gate_report("geneve")
        self.assertTrue(rep_gnv["found"])
        self.assertTrue(any("Cleartext warning" in d for d in rep_gnv["disclaimers"]))


if __name__ == "__main__":
    unittest.main()
