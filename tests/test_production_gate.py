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
        for eng in ["backpack", "gre_ipv4", "gre_xhttp", "xhttp"]:
            ok, msg = validate_production_readiness(eng, is_production=True)
            self.assertTrue(ok, f"Verified engine {eng} failed production validation: {msg}")
            self.assertIn("verified", msg.lower())

    def test_experimental_engine_gating(self):
        # Experimental engines: permitted in dev/lab, blocked in prod unless allow_experimental=True
        for exp_eng in ["waterwall", "wireguard", "sit", "6to4_unicast", "geneve"]:
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

    def test_engine_production_gate_report(self):
        rep_xhttp = get_engine_production_gate_report("xhttp")
        self.assertTrue(rep_xhttp["found"])
        self.assertEqual(rep_xhttp["support_status"], "verified")
        self.assertTrue(rep_xhttp["production_ready"])
        self.assertTrue(rep_xhttp["requires_binary"])
        self.assertTrue(rep_xhttp["binary_verified"])

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
