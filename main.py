"""
Windows Registry Change Monitoring System
==========================================
Main entry point. Run this script to start the monitor.

Usage:
    python main.py --mode monitor       # Start real-time polling monitor
    python main.py --mode baseline      # Capture a fresh baseline snapshot
    python main.py --mode check         # One-shot integrity check vs baseline
    python main.py --mode report        # Generate HTML report from logs
    python main.py --help
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from core.baseline import BaselineManager
from core.monitor import RegistryMonitor
from core.integrity import IntegrityChecker
from reports.report_generator import ReportGenerator
from utils.logger import setup_logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="Windows Registry Change Monitoring System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mode",
        choices=["monitor", "baseline", "check", "report"],
        default="monitor",
        help="Operating mode (default: monitor)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Polling interval in seconds for monitor mode (default: 30)",
    )
    parser.add_argument(
        "--baseline-file",
        default="logs/baseline.json",
        help="Path to baseline JSON file (default: logs/baseline.json)",
    )
    parser.add_argument(
        "--log-file",
        default="logs/changes.log",
        help="Path to change log file (default: logs/changes.log)",
    )
    parser.add_argument(
        "--report-out",
        default="reports/registry_report.html",
        help="Output path for HTML report (default: reports/registry_report.html)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logger(args.log_file)

    logger.info("=" * 60)
    logger.info("Registry Monitoring System — starting")
    logger.info(f"Mode: {args.mode}")
    logger.info("=" * 60)

    if args.mode == "baseline":
        mgr = BaselineManager(args.baseline_file, logger)
        mgr.capture()

    elif args.mode == "check":
        checker = IntegrityChecker(args.baseline_file, logger)
        checker.run()

    elif args.mode == "monitor":
        monitor = RegistryMonitor(
            baseline_file=args.baseline_file,
            log_file=args.log_file,
            interval=args.interval,
            logger=logger,
        )
        monitor.start()

    elif args.mode == "report":
        gen = ReportGenerator(args.log_file, args.report_out, logger)
        gen.generate()


if __name__ == "__main__":
    main()
