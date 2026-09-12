"""
Policy Loader — config-driven compliance thresholds
====================================================
Every scanner compares evidence against load_policy() values instead of
magic numbers.  One YAML edit changes the compliance baseline for every
client engagement.

Usage:
    from msme_auditor.core.policy_loader import load_policy, load_policy_for
    policy = load_policy("rpp1")  # loads config/rpp1_policy.yaml
    if min_len < policy["min_length"]: ...
"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"

# Map of scanner_id -> (yaml_key, filename)
_POLICY_MAP = {
    "rpp1": ("rpp1", "rpp1_policy.yaml"),
    "rpp2": ("rpp2", "rpp2_policy.yaml"),
    "rpp3": ("rpp3", "rpp3_policy.yaml"),
    "rpp4": ("rpp4", "rpp4_policy.yaml"),
    "nes1": ("nes1", "nes1_policy.yaml"),
    "nes2": ("nes2", "nes2_policy.yaml"),
    "nes3": ("nes3", "nes3_policy.yaml"),
}


@lru_cache(maxsize=8)
def load_policy_for(scanner_id: str, path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a policy from YAML for a specific scanner.

    Args:
        scanner_id: Scanner ID (e.g. ``"rpp1"``, ``"rpp2"``).
        path: Optional path to a custom policy YAML file.
              Defaults to ``config/{scanner_id}_policy.yaml``.

    Returns:
        The scanner-specific section of the YAML as a dict.

    Raises:
        FileNotFoundError: If the policy file does not exist.
        KeyError: If the expected key is missing from the YAML.
    """
    if scanner_id not in _POLICY_MAP:
        raise ValueError(f"Unknown scanner_id: {scanner_id}. Valid: {list(_POLICY_MAP.keys())}")

    yaml_key, filename = _POLICY_MAP[scanner_id]
    p = Path(path) if path else _CONFIG_DIR / filename
    if not p.exists():
        raise FileNotFoundError(f"Policy config missing: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if yaml_key not in raw:
        raise KeyError(f"Missing '{yaml_key}' key in policy file: {p}")
    return raw[yaml_key]


# Backward-compatible alias for rpp1
load_policy = lambda path=None: load_policy_for("rpp1", path)
