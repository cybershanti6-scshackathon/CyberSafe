"""
Structured Audit Logger — audit trail
======================================
Call log_scan_event() at the start and end of every .scan() call.
This is what makes findings defensible later:
  "what did the tool actually check, and when?"

Usage:
    from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event
    logger = get_audit_logger()
    log_scan_event(logger, "rpp1", "example.com", "started")
    # ... run scan ...
    log_scan_event(logger, "rpp1", "example.com", "completed")
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_audit_logger_instance: Optional[logging.Logger] = None


def get_audit_logger(log_dir: str = "logs") -> logging.Logger:
    """
    Get or create the singleton audit logger.

    Creates ``logs/audit_YYYYMMDD.log`` if it doesn't exist.
    """
    global _audit_logger_instance
    if _audit_logger_instance is not None:
        return _audit_logger_instance

    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("msme_auditor.audit")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handlers on repeated calls
    if not logger.handlers:
        handler = logging.FileHandler(
            f"{log_dir}/audit_{datetime.now(timezone.utc):%Y%m%d}.log",
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter(
                '{"time":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}'
            )
        )
        logger.addHandler(handler)

    _audit_logger_instance = logger
    return logger


def log_scan_event(
    logger: logging.Logger,
    check_id: str,
    target: str,
    status: str,
    run_by: str = "system",
    extra: Optional[dict] = None,
) -> None:
    """
    Log a structured scan event.

    Args:
        logger: The audit logger instance.
        check_id: Scanner ID (e.g. ``"rpp1"``).
        target: What was scanned.
        status: Event status (e.g. ``"started"``, ``"completed"``, ``"failed"``).
        run_by: Who initiated the scan.
        extra: Optional additional fields to include.
    """
    event = {
        "check_id": check_id,
        "target": target,
        "status": status,
        "run_by": run_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        event.update(extra)
    logger.info(json.dumps(event))
