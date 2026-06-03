"""
core/integrity.py
=================
One-shot integrity checker: compares current registry state to the baseline
and reports additions, deletions, and value modifications per key.
"""

from datetime import datetime
from core.baseline import BaselineManager
from core.registry_reader import read_key_values, hash_values
from config import MONITORED_KEYS


class IntegrityChecker:
    def __init__(self, baseline_file: str, logger):
        self.baseline_file = baseline_file
        self.logger = logger
        self._baseline_mgr = BaselineManager(baseline_file, logger)

    # ------------------------------------------------------------------
    def run(self) -> list[dict]:
        """
        Compare live registry to baseline.
        Returns list of change dicts:
          { key_id, label, severity, change_type, value_name, old, new, timestamp }
        """
        baseline = self._baseline_mgr.load()
        if baseline is None:
            return []

        changes = []
        ts = datetime.now().isoformat(timespec="seconds")

        self.logger.info("Running integrity check against baseline...")

        for entry in MONITORED_KEYS:
            hive   = entry["hive"]
            subkey = entry["subkey"]
            label  = entry["label"]
            sev    = entry["severity"]
            key_id = f"{hive}\\{subkey}"

            current_values  = read_key_values(hive, subkey)
            baseline_entry  = baseline["keys"].get(key_id, {})
            baseline_values = baseline_entry.get("values", {})
            baseline_hash   = baseline_entry.get("hash", "")

            # Quick hash check — skip detailed diff if nothing changed
            if hash_values(current_values) == baseline_hash:
                self.logger.info(f"  [OK] {label}")
                continue

            # Detailed diff
            all_names = set(current_values) | set(baseline_values)
            for name in sorted(all_names):
                old = baseline_values.get(name)
                new = current_values.get(name)

                if old == new:
                    continue

                if old is None:
                    change_type = "ADDED"
                elif new is None:
                    change_type = "DELETED"
                else:
                    change_type = "MODIFIED"

                change = {
                    "timestamp":   ts,
                    "key_id":      key_id,
                    "label":       label,
                    "severity":    sev,
                    "change_type": change_type,
                    "value_name":  name,
                    "old_value":   old,
                    "new_value":   new,
                }
                changes.append(change)

                self.logger.warning(
                    f"  [{sev}] {change_type}: {label} -> {name!r} "
                    f"old={old!r} new={new!r}"
                )

        if not changes:
            self.logger.info("Integrity check PASSED — no changes detected.")
        else:
            self.logger.warning(
                f"Integrity check FAILED — {len(changes)} change(s) detected."
            )

        return changes
