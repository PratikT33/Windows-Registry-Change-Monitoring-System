"""
core/registry_reader.py
=======================
Low-level wrapper around winreg (Windows Registry API).
On non-Windows systems this module provides a stub so the rest of the
codebase can be imported and tested without a Windows environment.
"""

import hashlib
import sys

IS_WINDOWS = sys.platform.startswith("win")

if IS_WINDOWS:
    import winreg

    _HIVE_MAP = {
        "HKEY_LOCAL_MACHINE":  winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER":   winreg.HKEY_CURRENT_USER,
        "HKEY_CLASSES_ROOT":   winreg.HKEY_CLASSES_ROOT,
        "HKEY_USERS":          winreg.HKEY_USERS,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
    }

    def _resolve_hive(hive_str: str):
        h = _HIVE_MAP.get(hive_str.upper())
        if h is None:
            raise ValueError(f"Unknown registry hive: {hive_str!r}")
        return h

    def read_key_values(hive_str: str, subkey: str) -> dict:
        """Return all values under a registry key as {name: str(data)}."""
        results = {}
        try:
            hive = _resolve_hive(hive_str)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                idx = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, idx)
                        results[name] = str(data)
                        idx += 1
                    except OSError:
                        break
        except (FileNotFoundError, PermissionError):
            pass
        return results

    def read_single_value(hive_str: str, subkey: str, value_name: str):
        """Return (data, type) for a single registry value, or (None, None)."""
        try:
            hive = _resolve_hive(hive_str)
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                data, reg_type = winreg.QueryValueEx(key, value_name)
                return str(data), reg_type
        except (FileNotFoundError, PermissionError, OSError):
            return None, None

else:
    def read_key_values(hive_str: str, subkey: str) -> dict:
        """Stub: returns empty dict on non-Windows."""
        return {}

    def read_single_value(hive_str: str, subkey: str, value_name: str):
        """Stub: returns (None, None) on non-Windows."""
        return None, None


def hash_values(values: dict) -> str:
    """SHA-256 fingerprint of a {name: value} dict for integrity checks."""
    stable = sorted(f"{k}={v}" for k, v in values.items())
    content = "\n".join(stable).encode("utf-8")
    return hashlib.sha256(content).hexdigest()
