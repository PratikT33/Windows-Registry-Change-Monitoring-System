"""
utils/logger.py
===============
Sets up a dual-output logger: console (colored by level) + rotating file.
"""

import logging
import os
from logging.handlers import RotatingFileHandler

# ANSI color codes for console output
_COLORS = {
    "DEBUG":    "\033[90m",   # dark gray
    "INFO":     "\033[0m",    # default
    "WARNING":  "\033[93m",   # yellow
    "ERROR":    "\033[91m",   # red
    "CRITICAL": "\033[95m",   # magenta
    "RESET":    "\033[0m",
}


class _ColorFormatter(logging.Formatter):
    FMT = "%(asctime)s  %(levelname)-8s  %(message)s"
    DATE = "%Y-%m-%d %H:%M:%S"

    def format(self, record):
        color = _COLORS.get(record.levelname, "")
        reset = _COLORS["RESET"]
        formatter = logging.Formatter(
            f"{color}{self.FMT}{reset}", datefmt=self.DATE
        )
        return formatter.format(record)


def setup_logger(log_file: str, level: int = logging.DEBUG) -> logging.Logger:
    """
    Create and return the application logger.
    Writes DEBUG+ to file, INFO+ to console (with color).
    """
    logger = logging.getLogger("registry_monitor")
    logger.setLevel(level)

    if logger.handlers:
        return logger  # Already configured (e.g. during testing)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(_ColorFormatter())
    logger.addHandler(ch)

    # Rotating file handler (5 MB per file, keep 3 backups)
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    fh = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(fh)

    return logger
