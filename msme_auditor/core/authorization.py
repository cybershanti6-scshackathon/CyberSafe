"""
Authorization Guard — closes the legal gap
===========================================
Refuses to scan anything not explicitly whitelisted for this engagement.

Usage:
    from msme_auditor.core.authorization import check_authorization
    if not check_authorization(target):
        return [make_check("unauthorized", ...)]
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("msme_auditor")


def check_authorization(
    target: str,
    auth_file: Optional[str] = None,
) -> bool:
    """
    Check if a target is authorized for scanning.

    Args:
        target: The hostname, IP, or URL to scan.
        auth_file: Path to the authorized targets JSON file.
                   Defaults to ``config/authorized_targets.json``.

    Returns:
        ``True`` if the target is in the authorized list AND scope_confirmed.
        ``False`` if the auth file is missing, target not found, or scope not confirmed.
    """
    if not auth_file:
        auth_file = str(
            Path(__file__).resolve().parent.parent.parent / "config" / "authorized_targets.json"
        )

    p = Path(auth_file)
    if not p.exists():
        logger.warning("Authorization file not found: %s", auth_file)
        return False

    try:
        authorized: List[Dict] = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read authorization file: %s", exc)
        return False

    return any(
        entry.get("target") == target and entry.get("scope_confirmed", False)
        for entry in authorized
    )
