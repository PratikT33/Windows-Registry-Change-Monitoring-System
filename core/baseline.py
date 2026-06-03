"""
core/baseline.py
================
Captures and persists a registry baseline snapshot.
The baseline is a JSON file with the structure:
{
  "captured_at": "<ISO timestamp>",
  "keys": {
    "<hive>\\<subkey>": {
      "values": {"ValueName": "data", ...},
      "hash":   "<sha256>"
    },
    ...
  }
}
"""

import json
import os
from datetime import datetime

from core.registry_reader import read_key_values, hash_values
from config import MONITORED_KEYS


class BaselineManager:
    def __init__(self, baseline_file: str, logger):
        self.baseline_file = baseline_file
        self.logger = logger

    # ------------------------------------------------------------------
    def capture(self) -> dict:
        """Scan all monitored keys and save the baseline to disk."""
        self.logger.info("Capturing registry baseline snapshot...")
        snapshot = {
            "captured_at": datetime.now().isoformat(),
            "keys": {},
        }

        for entry in MONITORED_KEYS:
            hive    = entry["hive"]
            subkey  = entry["subkey"]
            label   = entry["label"]
            key_id  = f"{hive}\\{subkey}"

            values = read_key_values(hive, subkey)
            snapshot["keys"][key_id] = {
                "label":    label,
                "severity": entry["severity"],
                "category": entry["category"],
                "values":   values,
                "hash":     hash_values(values),
            }
            self.logger.info(
                f"  [+] {label} — {len(values)} value(s) captured"
            )

        # Ensure output directory exists
        os.makedirs(os.path.dirname(self.baseline_file) or ".", exist_ok=True)

        with open(self.baseline_file, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2)

        self.logger.info(
            f"Baseline saved to '{self.baseline_file}' "
            f"({len(snapshot['keys'])} keys)"
        )
        return snapshot

    # ------------------------------------------------------------------
    def load(self) -> dict | None:
        """Load a previously saved baseline. Returns None if not found."""
        if not os.path.exists(self.baseline_file):
            self.logger.warning(
                f"No baseline found at '{self.baseline_file}'. "
                "Run with --mode baseline first."
            )
            return None

        with open(self.baseline_file, "r", encoding="utf-8") as fh:
            snapshot = json.load(fh)

        self.logger.info(
            f"Baseline loaded — captured at {snapshot.get('captured_at', 'unknown')}"
        )
        return snapshot
