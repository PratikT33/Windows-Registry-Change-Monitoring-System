"""
core/monitor.py
===============
Continuous polling-based registry monitor.
Loads (or creates) a baseline, then polls all monitored keys at a fixed
interval and logs any additions, deletions, or value modifications.
"""

import time
import signal
import sys
from datetime import datetime

from core.baseline import BaselineManager
from core.integrity import IntegrityChecker
from core.malware_detector import MalwareDetector
from core.registry_reader import read_key_values, hash_values
from config import MONITORED_KEYS


class RegistryMonitor:
    def __init__(self, baseline_file: str, log_file: str, interval: int, logger):
        self.baseline_file = baseline_file
        self.log_file      = log_file
        self.interval      = interval
        self.logger        = logger
        self._running      = False

        self._baseline_mgr  = BaselineManager(baseline_file, logger)
        self._mal_detector  = MalwareDetector(logger)

    # ------------------------------------------------------------------
    def start(self):
        """Start the monitoring loop. Ctrl+C to stop."""
        # Load or auto-create baseline
        baseline = self._baseline_mgr.load()
        if baseline is None:
            self.logger.info("No baseline found — capturing one now...")
            baseline = self._baseline_mgr.capture()

        # Keep a live snapshot for delta detection
        live_snapshot = {
            key_id: entry["values"]
            for key_id, entry in baseline["keys"].items()
        }

        self._running = True
        signal.signal(signal.SIGINT,  self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

        self.logger.info(
            f"Monitor started — polling every {self.interval}s. "
            "Press Ctrl+C to stop."
        )

        while self._running:
            self._poll(live_snapshot)
            # Run malware pattern check every cycle
            self._mal_detector.check_all()

            for remaining in range(self.interval, 0, -1):
                if not self._running:
                    break
                time.sleep(1)

        self.logger.info("Monitor stopped.")

    # ------------------------------------------------------------------
    def _poll(self, live_snapshot: dict):
        """Single poll pass — compare current values to live snapshot."""
        ts = datetime.now().isoformat(timespec="seconds")
        any_change = False

        for entry in MONITORED_KEYS:
            hive   = entry["hive"]
            subkey = entry["subkey"]
            label  = entry["label"]
            sev    = entry["severity"]
            key_id = f"{hive}\\{subkey}"

            current = read_key_values(hive, subkey)
            previous = live_snapshot.get(key_id, {})

            if hash_values(current) == hash_values(previous):
                continue

            # Detailed diff
            all_names = set(current) | set(previous)
            for name in sorted(all_names):
                old = previous.get(name)
                new = current.get(name)
                if old == new:
                    continue

                any_change = True
                change_type = (
                    "ADDED"    if old is None else
                    "DELETED"  if new is None else
                    "MODIFIED"
                )

                msg = (
                    f"[{sev}] {change_type} | {label} | "
                    f"Value: {name!r} | "
                    f"Old: {old!r} | New: {new!r}"
                )

                if sev == "HIGH":
                    self.logger.error(f"ALERT  {msg}")
                elif sev == "MEDIUM":
                    self.logger.warning(f"WARN   {msg}")
                else:
                    self.logger.info(f"INFO   {msg}")

            # Update live snapshot
            live_snapshot[key_id] = current

        if not any_change:
            self.logger.debug(f"[{ts}] Poll complete — no changes.")

    # ------------------------------------------------------------------
    def _handle_stop(self, signum, frame):
        self.logger.info("Stop signal received.")
        self._running = False
