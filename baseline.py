"""
modules/baseline.py
Capture a registry snapshot and persist it to disk.
Each value is stored alongside a SHA-256 hash so the integrity checker
can detect modifications even if the raw value looks similar.
"""

import json
import hashlib
import os
from datetime import datetime

# winreg is Windows-only; guard for dev/test on non-Windows machines
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

from config import MONITORED_KEYS, BASELINE_FILE
from modules.logger import log_info, log_warn


# ── Hive name → winreg constant ───────────────────────────────────────────────
HIVE_MAP = {
    "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
    "HKLM":               winreg.HKEY_LOCAL_MACHINE if WINREG_AVAILABLE else None,
    "HKEY_CURRENT_USER":  winreg.HKEY_CURRENT_USER  if WINREG_AVAILABLE else None,
    "HKCU":               winreg.HKEY_CURRENT_USER  if WINREG_AVAILABLE else None,
}


def _hash_value(data: str) -> str:
    """Return SHA-256 hex digest of a string value."""
    return hashlib.sha256(str(data).encode("utf-8")).hexdigest()


def read_key(hive: str, path: str) -> dict:
    """
    Read all values under a registry key.
    Returns {value_name: {"data": ..., "type": ..., "hash": ...}}
    Returns {} if the key does not exist or access is denied.
    """
    if not WINREG_AVAILABLE:
        log_warn(f"winreg not available — skipping {hive}\\{path}")
        return {}

    hive_const = HIVE_MAP.get(hive.upper())
    if hive_const is None:
        log_warn(f"Unknown hive: {hive}")
        return {}

    values = {}
    try:
        with winreg.OpenKey(hive_const, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    values[name] = {
                        "data":  str(data),
                        "type":  reg_type,
                        "hash":  _hash_value(data),
                    }
                    i += 1
                except OSError:
                    break   # No more values
    except PermissionError:
        log_warn(f"Access denied: {hive}\\{path}")
    except FileNotFoundError:
        log_warn(f"Key not found: {hive}\\{path}")
    except Exception as e:
        log_warn(f"Error reading {hive}\\{path}: {e}")

    return values


def capture_baseline() -> dict:
    """
    Snapshot all MONITORED_KEYS and write to BASELINE_FILE.
    Returns the baseline dict.
    """
    os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)

    snapshot = {
        "captured_at": datetime.now().isoformat(),
        "keys": {}
    }

    for entry in MONITORED_KEYS:
        full_path = f"{entry['hive']}\\{entry['path']}"
        log_info(f"  Snapping: {full_path}")
        values = read_key(entry["hive"], entry["path"])
        snapshot["keys"][full_path] = {
            "values":      values,
            "category":    entry["category"],
            "severity":    entry["severity"],
            "description": entry["description"],
        }

    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

    log_info(f"Baseline saved → {BASELINE_FILE}")
    return snapshot


def load_baseline() -> dict | None:
    """Load baseline from disk. Returns None if file missing."""
    if not os.path.exists(BASELINE_FILE):
        return None
    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)
