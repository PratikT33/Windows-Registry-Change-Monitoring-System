"""
config.py — Central configuration for all monitored registry keys and threat patterns.
Edit this file to add/remove keys from monitoring scope.
"""

import sys

# ---------------------------------------------------------------------------
# Monitored registry paths
# ---------------------------------------------------------------------------
# Each entry is a dict with:
#   hive    : winreg constant name (string) — resolved at runtime on Windows
#   subkey  : registry subkey path
#   label   : human-readable name
#   severity: HIGH | MEDIUM | LOW
# ---------------------------------------------------------------------------

MONITORED_KEYS = [
    # ── Autorun / Persistence ───────────────────────────────────────────────
    {
        "hive": "HKEY_CURRENT_USER",
        "subkey": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "label": "HKCU Autorun (Run)",
        "severity": "HIGH",
        "category": "Persistence",
    },
    {
        "hive": "HKEY_CURRENT_USER",
        "subkey": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "label": "HKCU Autorun (RunOnce)",
        "severity": "HIGH",
        "category": "Persistence",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "label": "HKLM Autorun (Run)",
        "severity": "HIGH",
        "category": "Persistence",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "label": "HKLM Autorun (RunOnce)",
        "severity": "HIGH",
        "category": "Persistence",
    },
    # ── Windows Defender ────────────────────────────────────────────────────
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "label": "Windows Defender Policy",
        "severity": "HIGH",
        "category": "Security Tool Tampering",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Microsoft\Windows Defender\Features",
        "label": "Windows Defender Features",
        "severity": "HIGH",
        "category": "Security Tool Tampering",
    },
    # ── UAC / Privilege Escalation ──────────────────────────────────────────
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "label": "UAC / System Policies",
        "severity": "MEDIUM",
        "category": "Privilege Escalation",
    },
    # ── Shell / Winlogon ────────────────────────────────────────────────────
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "label": "Winlogon (Shell/Userinit)",
        "severity": "HIGH",
        "category": "Shell Replacement",
    },
    # ── Firewall ────────────────────────────────────────────────────────────
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "label": "Firewall Standard Profile",
        "severity": "MEDIUM",
        "category": "Firewall Tampering",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "label": "Firewall Domain Profile",
        "severity": "MEDIUM",
        "category": "Firewall Tampering",
    },
    # ── Image File Execution Options (IFEO hijacking) ───────────────────────
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "label": "IFEO (Debugger Hijack)",
        "severity": "HIGH",
        "category": "IFEO Hijacking",
    },
    # ── Services ────────────────────────────────────────────────────────────
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SYSTEM\CurrentControlSet\Services",
        "label": "Windows Services",
        "severity": "LOW",
        "category": "Service Tampering",
    },
]

# ---------------------------------------------------------------------------
# Malware-pattern value checks
# ---------------------------------------------------------------------------
# If a key+value_name matches AND the value contains one of the bad_values,
# an additional MALWARE PATTERN alert is raised.
# ---------------------------------------------------------------------------

MALWARE_PATTERNS = [
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "value_name": "DisableAntiSpyware",
        "bad_values": ["1"],
        "description": "Windows Defender AntiSpyware disabled via policy",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Policies\Microsoft\Windows Defender",
        "value_name": "DisableRealtimeMonitoring",
        "bad_values": ["1"],
        "description": "Windows Defender real-time protection disabled",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "value_name": "EnableLUA",
        "bad_values": ["0"],
        "description": "UAC (User Account Control) disabled",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "value_name": "Shell",
        "bad_values": [],          # any value != "explorer.exe" triggers alert
        "expected_value": "explorer.exe",
        "description": "Default shell replaced — possible shell hijack",
    },
    {
        "hive": "HKEY_LOCAL_MACHINE",
        "subkey": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "value_name": "EnableFirewall",
        "bad_values": ["0"],
        "description": "Windows Firewall (Standard Profile) disabled",
    },
]

# ---------------------------------------------------------------------------
# Known-good autorun executables (whitelist)
# ---------------------------------------------------------------------------
# Entries in Run/RunOnce keys whose values start with any of these paths
# are treated as expected and won't raise alerts.

AUTORUN_WHITELIST = [
    r"C:\Windows\System32",
    r"C:\Program Files\Windows Defender",
    r"C:\Program Files\Microsoft Office",
    r"C:\Program Files\OneDrive",
]

# ---------------------------------------------------------------------------
# Polling / alert settings
# ---------------------------------------------------------------------------

DEFAULT_POLL_INTERVAL = 30      # seconds between registry scans
BASELINE_FILE         = "logs/baseline.json"
CHANGE_LOG_FILE       = "logs/changes.log"
REPORT_OUTPUT         = "reports/registry_report.html"

# ---------------------------------------------------------------------------
# Platform guard — most functionality requires Windows
# ---------------------------------------------------------------------------

IS_WINDOWS = sys.platform.startswith("win")
