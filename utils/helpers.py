"""
utils/helpers.py
================
Miscellaneous utility functions shared across the toolkit.
"""

import json
import os
import re
from datetime import datetime


def load_json(path: str) -> dict | list | None:
    """Load JSON file, return None if missing or malformed."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, IOError):
        return None


def save_json(path: str, data) -> bool:
    """Save data as pretty-printed JSON. Returns True on success."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return True
    except IOError:
        return False


def now_iso() -> str:
    """Return current timestamp as ISO-8601 string (seconds precision)."""
    return datetime.now().isoformat(timespec="seconds")


def severity_color(severity: str) -> str:
    """Map severity string to an HTML hex color."""
    return {
        "HIGH":   "#E24B4A",
        "MEDIUM": "#EF9F27",
        "LOW":    "#378ADD",
    }.get(severity.upper(), "#888780")


def change_type_badge(change_type: str) -> str:
    """Map change type to a short HTML badge label."""
    return {
        "ADDED":    "&#x2B; Added",
        "DELETED":  "&#x2212; Deleted",
        "MODIFIED": "&#x2260; Modified",
    }.get(change_type.upper(), change_type)


def is_suspicious_path(path: str) -> bool:
    """
    Heuristic check: flag executable paths that look suspicious.
    Checks for temp dirs, AppData, suspicious extensions in unusual locations.
    """
    path_lower = path.lower()
    suspicious_dirs = [
        r"appdata\roaming",
        r"appdata\local\temp",
        r"\temp\\",
        r"\tmp\\",
        r"programdata",
    ]
    suspicious_exts = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"]

    in_suspicious_dir = any(d in path_lower for d in suspicious_dirs)
    has_suspicious_ext = any(path_lower.endswith(ext) for ext in suspicious_exts)

    return in_suspicious_dir and has_suspicious_ext


def parse_log_file(log_path: str) -> list[dict]:
    """
    Parse the change log file into a list of structured dicts.
    Handles lines produced by the monitor logger.
    Format:  YYYY-MM-DD HH:MM:SS  LEVEL     message
    """
    entries = []
    if not os.path.exists(log_path):
        return entries

    pattern = re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
        r"(?P<level>\w+)\s+"
        r"(?P<message>.+)$"
    )

    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = pattern.match(line.strip())
            if m:
                entries.append({
                    "timestamp": m.group("ts"),
                    "level":     m.group("level"),
                    "message":   m.group("message"),
                })

    return entries
