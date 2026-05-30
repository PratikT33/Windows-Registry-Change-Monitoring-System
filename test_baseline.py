"""
tests/test_baseline.py
======================
Tests for BaselineManager — capture and load logic.
"""

import sys
import os
import json
import tempfile
import unittest
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.baseline import BaselineManager


class TestBaselineManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.baseline_path = os.path.join(self.tmpdir, "baseline.json")
        self.logger = logging.getLogger("test")
        self.logger.addHandler(logging.NullHandler())

    def test_capture_creates_file(self):
        mgr = BaselineManager(self.baseline_path, self.logger)
        snapshot = mgr.capture()

        self.assertTrue(os.path.exists(self.baseline_path))
        self.assertIn("captured_at", snapshot)
        self.assertIn("keys", snapshot)

    def test_load_returns_none_if_missing(self):
        mgr = BaselineManager(
            os.path.join(self.tmpdir, "nonexistent.json"), self.logger
        )
        result = mgr.load()
        self.assertIsNone(result)

    def test_capture_and_load_roundtrip(self):
        mgr = BaselineManager(self.baseline_path, self.logger)
        captured = mgr.capture()
        loaded   = mgr.load()

        self.assertEqual(captured["captured_at"], loaded["captured_at"])
        self.assertEqual(set(captured["keys"]), set(loaded["keys"]))

    def test_snapshot_has_required_fields(self):
        mgr = BaselineManager(self.baseline_path, self.logger)
        snapshot = mgr.capture()

        for key_id, entry in snapshot["keys"].items():
            self.assertIn("label",    entry)
            self.assertIn("severity", entry)
            self.assertIn("values",   entry)
            self.assertIn("hash",     entry)


if __name__ == "__main__":
    unittest.main()
