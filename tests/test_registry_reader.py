"""
tests/test_registry_reader.py
==============================
Unit tests for registry_reader utilities.
Runs on all platforms (winreg calls are stubbed on non-Windows).
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.registry_reader import hash_values


class TestHashValues(unittest.TestCase):
    def test_empty_dict_is_stable(self):
        h1 = hash_values({})
        h2 = hash_values({})
        self.assertEqual(h1, h2)

    def test_same_content_same_hash(self):
        d = {"Shell": "explorer.exe", "Userinit": "userinit.exe"}
        self.assertEqual(hash_values(d), hash_values(d))

    def test_different_values_different_hash(self):
        d1 = {"Shell": "explorer.exe"}
        d2 = {"Shell": "malware.exe"}
        self.assertNotEqual(hash_values(d1), hash_values(d2))

    def test_order_independent(self):
        """Hash must not depend on dict insertion order."""
        d1 = {"a": "1", "b": "2"}
        d2 = {"b": "2", "a": "1"}
        self.assertEqual(hash_values(d1), hash_values(d2))

    def test_returns_64_hex_chars(self):
        h = hash_values({"key": "value"})
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))


class TestStubBehavior(unittest.TestCase):
    """Verify stub returns safe empty results on non-Windows."""

    def test_read_key_values_returns_dict(self):
        from core.registry_reader import read_key_values
        result = read_key_values("HKEY_LOCAL_MACHINE", r"Software\Test")
        self.assertIsInstance(result, dict)

    def test_read_single_value_returns_tuple(self):
        from core.registry_reader import read_single_value
        data, reg_type = read_single_value(
            "HKEY_LOCAL_MACHINE", r"Software\Test", "TestValue"
        )
        # On non-Windows both are None; on Windows may return real data
        self.assertTrue(data is None or isinstance(data, str))


if __name__ == "__main__":
    unittest.main()
