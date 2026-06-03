# Windows Registry Change Monitoring System

A Python-based **blue team toolkit** for detecting unauthorized or suspicious
Windows Registry modifications, identifying malware-like persistence mechanisms,
and verifying registry integrity through baseline comparison.

---

## Project structure

```
registry_monitor/
├── main.py                  ← Entry point (CLI)
├── config.py                ← All monitored keys & malware patterns
├── requirements.txt
├── run_tests.py             ← Run all unit tests
│
├── core/
│   ├── registry_reader.py   ← Low-level winreg wrapper + stubs
│   ├── baseline.py          ← Capture & load baseline snapshots
│   ├── integrity.py         ← One-shot integrity checker
│   ├── monitor.py           ← Continuous polling monitor
│   └── malware_detector.py  ← Malware pattern & autorun checks
│
├── utils/
│   ├── logger.py            ← Dual console/file logger (colored)
│   └── helpers.py           ← JSON I/O, path heuristics, log parser
│
├── reports/
│   └── report_generator.py  ← HTML report from change logs
│
├── tests/
│   ├── test_registry_reader.py
│   ├── test_helpers.py
│   └── test_baseline.py
│
├── logs/                    ← Created at runtime
│   ├── baseline.json
│   └── changes.log
│
└── docs/
    └── README.md            ← This file
```

---

## Quick start (Windows, Python 3.10+)

```powershell
# 1. Capture a baseline (run once, as Administrator for full HKLM access)
python main.py --mode baseline

# 2. Start the real-time monitor (polls every 30 s by default)
python main.py --mode monitor

# 3. One-shot integrity check against the baseline
python main.py --mode check

# 4. Generate an HTML report from the change log
python main.py --mode report
```

> **Tip:** Run as Administrator to read HKLM keys that require elevated access.

---

## Monitored registry paths

| Label | Path | Severity | Category |
|---|---|---|---|
| HKCU Autorun (Run) | `HKCU\...\CurrentVersion\Run` | HIGH | Persistence |
| HKLM Autorun (Run) | `HKLM\...\CurrentVersion\Run` | HIGH | Persistence |
| Windows Defender Policy | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` | HIGH | Security Tool Tampering |
| UAC / System Policies | `HKLM\...\Policies\System` | MEDIUM | Privilege Escalation |
| Winlogon (Shell) | `HKLM\...\Windows NT\CurrentVersion\Winlogon` | HIGH | Shell Replacement |
| Firewall Standard Profile | `HKLM\SYSTEM\...\FirewallPolicy\StandardProfile` | MEDIUM | Firewall Tampering |
| IFEO (Debugger Hijack) | `HKLM\...\Image File Execution Options` | HIGH | IFEO Hijacking |

Add custom paths in **`config.py → MONITORED_KEYS`**.

---

## Malware patterns detected

- Windows Defender AntiSpyware disabled (`DisableAntiSpyware = 1`)
- Windows Defender real-time protection disabled
- UAC disabled (`EnableLUA = 0`)
- Default shell replaced (Winlogon Shell ≠ `explorer.exe`)
- Windows Firewall disabled

---

## Sample log output

```
2024-11-15 09:14:02  ERROR     ALERT  [HIGH] ADDED | HKCU Autorun | Value: 'UpdateHelper' | Old: None | New: 'C:\Users\User\AppData\Roaming\malware.exe'
2024-11-15 09:14:02  ERROR     MALWARE PATTERN DETECTED: Windows Defender AntiSpyware disabled via policy
2024-11-15 09:14:10  WARNING   WARN   [HIGH] MODIFIED | Winlogon (Shell) | Value: 'Shell' | Old: 'explorer.exe' | New: 'explorer.exe,malicious.exe'
2024-11-15 09:15:00  INFO      Poll complete — no changes.
```

---

## Running tests

```powershell
python run_tests.py
```

Tests run on **any platform** (winreg calls are stubbed on non-Windows).

---

## Extending the toolkit

| Task | Where |
|---|---|
| Add new registry paths to monitor | `config.py → MONITORED_KEYS` |
| Add new malware value patterns | `config.py → MALWARE_PATTERNS` |
| Whitelist legitimate autorun programs | `config.py → AUTORUN_WHITELIST` |
| Change poll interval | `--interval` CLI flag or `config.DEFAULT_POLL_INTERVAL` |
| Customize the HTML report | `reports/report_generator.py → _HTML_TEMPLATE` |

---

## Technologies used

- **Python 3.10+** (standard library only — no pip install required)
- `winreg` — Windows Registry access
- `hashlib` — SHA-256 integrity fingerprints
- `logging` + `RotatingFileHandler` — Dual console/file logging
- `argparse` — CLI interface
- `signal` — Graceful Ctrl+C shutdown

---

*Blue Team Toolkit — Windows Registry Change Monitoring System*
