"""
modules/monitor.py
Poll all monitored registry keys and compare against the stored baseline.
Returns a list of ChangeRecord dicts for any additions, deletions, or modifications.
"""

from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Literal

from config import MONITORED_KEYS, MALWARE_PATTERNS
from modules.baseline import read_key
from modules.logger import log_alert, log_warn, log_info


ChangeType = Literal["ADDED", "DELETED", "MODIFIED"]


@dataclass
class ChangeRecord:
    timestamp:      str
    hive:           str
    key_path:       str
    value_name:     str
    change_type:    ChangeType
    old_data:       str | None
    new_data:       str | None
    category:       str
    severity:       str          # From key config
    malware_match:  str | None   # Name of matched pattern, or None
    pattern_severity: str | None # Severity from matched pattern


def _check_malware_patterns(key_path: str, value_name: str, new_data: str | None) -> tuple[str | None, str | None]:
    """
    Check a changed value against MALWARE_PATTERNS.
    Returns (pattern_name, severity) or (None, None).
    """
    for pattern in MALWARE_PATTERNS:
        path_match  = pattern["match_path"]  in key_path
        value_match = (pattern["match_value"] is None) or (pattern["match_value"].lower() == value_name.lower())
        data_match  = (pattern["match_data"]  is None) or (pattern["match_data"] == str(new_data))

        if path_match and value_match and data_match:
            return pattern["name"], pattern["severity"]

    return None, None


def monitor_once(baseline: dict) -> list[dict]:
    """
    Run a single monitoring cycle.
    Compares live registry state against `baseline` and logs / returns all changes.
    """
    changes: list[ChangeRecord] = []
    now = datetime.now().isoformat(timespec="seconds")

    for entry in MONITORED_KEYS:
        full_path = f"{entry['hive']}\\{entry['path']}"
        baseline_key = baseline.get("keys", {}).get(full_path, {})
        baseline_values: dict = baseline_key.get("values", {})

        live_values = read_key(entry["hive"], entry["path"])

        # ── Detect ADDED values ───────────────────────────────────────────────
        for name, live_val in live_values.items():
            if name not in baseline_values:
                match_name, match_sev = _check_malware_patterns(
                    full_path, name, live_val["data"]
                )
                rec = ChangeRecord(
                    timestamp=now,
                    hive=entry["hive"],
                    key_path=entry["path"],
                    value_name=name,
                    change_type="ADDED",
                    old_data=None,
                    new_data=live_val["data"],
                    category=entry["category"],
                    severity=entry["severity"],
                    malware_match=match_name,
                    pattern_severity=match_sev,
                )
                changes.append(rec)
                _emit(rec)

        # ── Detect DELETED values ─────────────────────────────────────────────
        for name, base_val in baseline_values.items():
            if name not in live_values:
                match_name, match_sev = _check_malware_patterns(
                    full_path, name, None
                )
                rec = ChangeRecord(
                    timestamp=now,
                    hive=entry["hive"],
                    key_path=entry["path"],
                    value_name=name,
                    change_type="DELETED",
                    old_data=base_val["data"],
                    new_data=None,
                    category=entry["category"],
                    severity=entry["severity"],
                    malware_match=match_name,
                    pattern_severity=match_sev,
                )
                changes.append(rec)
                _emit(rec)

        # ── Detect MODIFIED values ────────────────────────────────────────────
        for name, live_val in live_values.items():
            if name in baseline_values:
                if live_val["hash"] != baseline_values[name]["hash"]:
                    match_name, match_sev = _check_malware_patterns(
                        full_path, name, live_val["data"]
                    )
                    rec = ChangeRecord(
                        timestamp=now,
                        hive=entry["hive"],
                        key_path=entry["path"],
                        value_name=name,
                        change_type="MODIFIED",
                        old_data=baseline_values[name]["data"],
                        new_data=live_val["data"],
                        category=entry["category"],
                        severity=entry["severity"],
                        malware_match=match_name,
                        pattern_severity=match_sev,
                    )
                    changes.append(rec)
                    _emit(rec)

    if not changes:
        log_info("No changes detected this cycle.")

    return [asdict(c) for c in changes]


def _emit(rec: ChangeRecord):
    """Print a human-readable alert line to the console."""
    effective_sev = rec.pattern_severity or rec.severity
    label = f"[{rec.change_type}]"
    path  = f"{rec.hive}\\{rec.key_path}\\{rec.value_name}"

    if effective_sev == "CRITICAL":
        log_alert(f"CRITICAL  {label:12s} {path}")
        if rec.malware_match:
            log_alert(f"          Pattern : {rec.malware_match}")
        log_alert(f"          Old     : {rec.old_data!r}")
        log_alert(f"          New     : {rec.new_data!r}")

    elif effective_sev == "HIGH":
        log_warn(f"HIGH      {label:12s} {path}")
        log_warn(f"          Old={rec.old_data!r}  New={rec.new_data!r}")

    else:
        log_info(f"INFO      {label:12s} {path}")
        log_info(f"          Old={rec.old_data!r}  New={rec.new_data!r}")
