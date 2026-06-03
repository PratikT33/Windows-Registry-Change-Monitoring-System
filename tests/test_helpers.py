"""
tests/test_helpers.py
=====================
Unit tests for utility helper functions.
"""

import sys
import os
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.helpers import (
    load_json, save_json, severity_color,
    is_suspicious_path, parse_log_file
)


class TestJsonHelpers(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.json")
            data = {"key": "value", "num": 42}
            self.assertTrue(save_json(path, data))
            loaded = load_json(path)
            self.assertEqual(loaded, data)

    def test_load_missing_returns_none(self):
        result = load_json("/nonexistent/path/file.json")
        self.assertIsNone(result)


class TestSeverityColor(unittest.TestCase):
    def test_known_severities(self):
        self.assertEqual(severity_color("HIGH"),   "#E24B4A")
        self.assertEqual(severity_color("MEDIUM"),  "#EF9F27")
        self.assertEqual(severity_color("LOW"),    "#378ADD")

    def test_unknown_returns_default(self):
        color = severity_color("UNKNOWN")
        self.assertIsNotNone(color)


class TestSuspiciousPath(unittest.TestCase):
    def test_appdata_exe_is_suspicious(self):
        path = r"C:\Users\user\AppData\Roaming\malware.exe"
        self.assertTrue(is_suspicious_path(path))

    def test_system32_exe_is_not_suspicious(self):
        path = r"C:\Windows\System32\svchost.exe"
        self.assertFalse(is_suspicious_path(path))

    def test_temp_bat_is_suspicious(self):
        path = r"C:\Users\user\AppData\Local\Temp\dropper.bat"
        self.assertTrue(is_suspicious_path(path))


class TestParseLogFile(unittest.TestCase):
    def test_parses_valid_lines(self):
        content = (
            "2024-11-15 09:14:02  ERROR     ALERT malware detected\n"
            "2024-11-15 09:15:00  INFO      Baseline check passed\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(content)
            fh_name = fh.name

        try:
            entries = parse_log_file(fh_name)
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[0]["level"], "ERROR")
            self.assertEqual(entries[1]["level"], "INFO")
        finally:
            os.unlink(fh_name)

    def test_missing_file_returns_empty(self):
        entries = parse_log_file("/nonexistent/file.log")
        self.assertEqual(entries, [])


if __name__ == "__main__":
    unittest.main()
