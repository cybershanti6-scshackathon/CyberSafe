"""
Cross-Platform Evidence Normalization
=====================================
Converts vendor/OS-specific evidence into one standard internal JSON schema.
The rule engine downstream never needs to know which OS/platform the
evidence came from.

Standard normalized schema:
{
    "password_policy": {
        "minimum_length": int,
        "uppercase_required": bool,
        "lowercase_required": bool,
        "numbers_required": bool,
        "special_chars_required": bool,
        "expiry_days": int,
        "history_count": int,
        "education_policy_exists": bool,
    },
    "lockout_policy": {
        "enabled": bool,
        "max_failed_attempts": int,
        "lockout_duration_minutes": int,
        "reset_window_minutes": int,
        "admin_unlock_enabled": bool,
        "audit_logging": bool,
    },
    "mfa_policy": {
        "admin_mfa_enabled": bool,
        "remote_mfa_enabled": bool,
        "critical_mfa_enabled": bool,
        "mfa_method": str,
        "policy_exists": bool,
    },
    "password_storage": {
        "encryption_at_rest": bool,
        "hash_algorithm": str,
        "salted": bool,
        "no_plaintext": bool,
    },
    "network_security": {
        "open_ports": list,
        "firewall_active": bool,
        "ssh_open": bool,
        "rdp_open": bool,
        "db_ports_open": bool,
    },
    "email_security": {
        "spf_configured": bool,
        "dmarc_configured": bool,
        "dkim_configured": bool,
    },
    "wifi_security": {
        "encryption_type": str,
        "password_strength": str,
        "wps_disabled": bool,
        "custom_ssid": bool,
        "signal_strength_pct": int,
        "radio_type": str,
    },
}
"""

from typing import Any, Dict, Optional


def normalize_evidence(
    raw_evidence: Dict[str, Any],
    source_os: str,
    scanner_id: str,
) -> Dict[str, Any]:
    """
    Normalize raw evidence from a specific OS/platform into the standard schema.

    Args:
        raw_evidence: Raw key-value pairs from the OS-specific collector.
        source_os: One of "windows", "linux", "web", "manual".
        scanner_id: Scanner ID (e.g. "rpp1", "nes1").

    Returns:
        Normalized evidence dict following the standard schema.
    """
    normalizer = _NORMALIZERS.get(scanner_id, _default_normalize)
    return normalizer(raw_evidence, source_os)


def _default_normalize(raw: Dict, source_os: str) -> Dict:
    """Fallback normalizer — pass through with OS metadata."""
    return {"raw": raw, "source_os": source_os}


# =============================================================================
# RPP.1 — Password Complexity & Expiry
# =============================================================================

def _normalize_rpp1(raw: Dict, source_os: str) -> Dict:
    """Normalize password policy evidence across platforms."""
    result = {"source_os": source_os}

    if source_os == "windows":
        result["password_policy"] = {
            "minimum_length": raw.get("min_len", 0),
            "uppercase_required": raw.get("complexity", False),
            "lowercase_required": raw.get("complexity", False),
            "numbers_required": raw.get("complexity", False),
            "special_chars_required": raw.get("complexity", False),
            "expiry_days": raw.get("max_age", 0),
            "history_count": raw.get("history", 0),
            "education_policy_exists": False,  # Cannot detect from OS
        }
    elif source_os == "linux":
        result["password_policy"] = {
            "minimum_length": raw.get("min_len", 0),
            "uppercase_required": raw.get("ucredit", 0) < 0,
            "lowercase_required": raw.get("lcredit", 0) < 0,
            "numbers_required": raw.get("dcredit", 0) < 0,
            "special_chars_required": raw.get("ocredit", 0) < 0,
            "expiry_days": raw.get("max_age", 0),
            "history_count": raw.get("history", 0),
            "education_policy_exists": False,
        }
    elif source_os == "web":
        # Web target: evidence comes from HTTP probing
        result["password_policy"] = {
            "minimum_length": raw.get("min_length", 0),
            "uppercase_required": raw.get("require_uppercase", False),
            "lowercase_required": raw.get("require_lowercase", False),
            "numbers_required": raw.get("require_numbers", False),
            "special_chars_required": raw.get("require_special_chars", False),
            "expiry_days": raw.get("max_age_days", 0),
            "history_count": raw.get("history_count", 0),
            "education_policy_exists": raw.get("education_policy_exists", False),
        }
    else:
        # Manual/config input
        result["password_policy"] = {
            "minimum_length": raw.get("min_length", raw.get("minimum_length", 0)),
            "uppercase_required": raw.get("require_uppercase", raw.get("uppercase_required", False)),
            "lowercase_required": raw.get("require_lowercase", raw.get("lowercase_required", False)),
            "numbers_required": raw.get("require_numbers", raw.get("numbers_required", False)),
            "special_chars_required": raw.get("require_special_chars", raw.get("special_chars_required", False)),
            "expiry_days": raw.get("max_age_days", raw.get("expiry_days", 0)),
            "history_count": raw.get("history_count", 0),
            "education_policy_exists": raw.get("education_policy_exists", False),
        }

    return result


# =============================================================================
# RPP.2 — Account Lockout Policy
# =============================================================================

def _normalize_rpp2(raw: Dict, source_os: str) -> Dict:
    """Normalize lockout policy evidence across platforms."""
    result = {"source_os": source_os}

    if source_os == "windows":
        result["lockout_policy"] = {
            "enabled": raw.get("threshold", 0) > 0,
            "max_failed_attempts": raw.get("threshold", 0),
            "lockout_duration_minutes": raw.get("duration", 0),
            "reset_window_minutes": raw.get("window", 0),
            "admin_unlock_enabled": raw.get("admin_unlock", True),
            "audit_logging": raw.get("audit_logging", True),
        }
    elif source_os == "linux":
        result["lockout_policy"] = {
            "enabled": raw.get("threshold", 0) > 0,
            "max_failed_attempts": raw.get("threshold", 0),
            "lockout_duration_minutes": raw.get("duration", 0),
            "reset_window_minutes": raw.get("window", 0),
            "admin_unlock_enabled": True,
            "audit_logging": raw.get("audit_logging", False),
        }
    else:
        result["lockout_policy"] = {
            "enabled": raw.get("max_failed_attempts", 0) > 0,
            "max_failed_attempts": raw.get("max_failed_attempts", 0),
            "lockout_duration_minutes": raw.get("lockout_duration_minutes", 0),
            "reset_window_minutes": raw.get("reset_window_minutes", 0),
            "admin_unlock_enabled": raw.get("admin_unlock_enabled", True),
            "audit_logging": raw.get("audit_logging", False),
        }

    return result


# =============================================================================
# RPP.3 — Multi-Factor Authentication
# =============================================================================

def _normalize_rpp3(raw: Dict, source_os: str) -> Dict:
    """Normalize MFA evidence across platforms."""
    result = {"source_os": source_os}

    if source_os == "windows":
        method = "None"
        if raw.get("hello_enabled"):
            method = "Windows Hello"
        if raw.get("smart_card"):
            method = f"{method}, Smart Card" if method != "None" else "Smart Card"
        result["mfa_policy"] = {
            "admin_mfa_enabled": raw.get("hello_enabled", False) or raw.get("smart_card", False),
            "remote_mfa_enabled": raw.get("hello_enabled", False),
            "critical_mfa_enabled": raw.get("cred_guard", False),
            "mfa_method": method,
            "policy_exists": raw.get("cred_guard", False),
        }
    elif source_os == "linux":
        method = raw.get("ssh_mfa_method", "None")
        result["mfa_policy"] = {
            "admin_mfa_enabled": raw.get("ssh_mfa", False),
            "remote_mfa_enabled": raw.get("ssh_mfa", False),
            "critical_mfa_enabled": raw.get("ssh_mfa", False),
            "mfa_method": method or "None",
            "policy_exists": False,
        }
    else:
        result["mfa_policy"] = {
            "admin_mfa_enabled": raw.get("admin_mfa_enabled", False),
            "remote_mfa_enabled": raw.get("remote_mfa_enabled", False),
            "critical_mfa_enabled": raw.get("critical_mfa_enabled", False),
            "mfa_method": raw.get("mfa_method", "None"),
            "policy_exists": raw.get("policy_exists", False),
        }

    return result


# =============================================================================
# RPP.4 — Password Encryption & Hashing
# =============================================================================

def _normalize_rpp4(raw: Dict, source_os: str) -> Dict:
    """Normalize password storage evidence across platforms."""
    result = {"source_os": source_os}
    result["password_storage"] = {
        "encryption_at_rest": raw.get("encryption_at_rest", False),
        "hash_algorithm": raw.get("hash_algorithm", "unknown"),
        "salted": raw.get("salted", False),
        "no_plaintext": raw.get("no_plaintext", True),
    }
    return result


# =============================================================================
# NES.1 — Firewall & Open Ports
# =============================================================================

def _normalize_nes1(raw: Dict, source_os: str) -> Dict:
    """Normalize network security evidence from port scan."""
    open_ports = raw.get("open_ports", [])
    result = {
        "source_os": source_os,
        "network_security": {
            "open_ports": open_ports,
            "firewall_active": len(open_ports) == 0,
            "ssh_open": 22 in open_ports,
            "rdp_open": 3389 in open_ports,
            "db_ports_open": any(p in open_ports for p in [3306, 5432, 1433, 27017]),
        },
    }
    return result


# =============================================================================
# NES.2 — WiFi Security
# =============================================================================

def _normalize_nes2(raw: Dict, source_os: str) -> Dict:
    """Normalize WiFi security evidence."""
    result = {
        "source_os": source_os,
        "wifi_security": {
            "encryption_type": raw.get("auth", "Unknown"),
            "password_strength": raw.get("password_strength", "Unknown"),
            "wps_disabled": raw.get("wps_disabled", True),
            "custom_ssid": raw.get("custom_ssid", False),
            "signal_strength_pct": raw.get("signal_pct", 0),
            "radio_type": raw.get("radio", "Unknown"),
            "ssid": raw.get("ssid", "Unknown"),
        },
    }
    return result


# =============================================================================
# NES.3 — VPN / Remote Access
# =============================================================================

def _normalize_nes3(raw: Dict, source_os: str) -> Dict:
    """Normalize VPN/remote access evidence."""
    open_vpn_ports = raw.get("open_vpn_ports", [])
    result = {
        "source_os": source_os,
        "network_security": {
            "vpn_detected": len(open_vpn_ports) > 0,
            "vpn_ports": open_vpn_ports,
            "vpn_mfa_enabled": raw.get("vpn_mfa_enabled", False),
            "vpn_encryption_enabled": raw.get("vpn_encryption_enabled", True),
        },
    }
    return result


# =============================================================================
# NES.4 — Email SPF & DMARC
# =============================================================================

def _normalize_nes4(raw: Dict, source_os: str) -> Dict:
    """Normalize email security evidence."""
    result = {
        "source_os": source_os,
        "email_security": {
            "spf_configured": raw.get("spf_found", False),
            "dmarc_configured": raw.get("dmarc_found", False),
            "dkim_configured": raw.get("dkim_found", False),
        },
    }
    return result


# =============================================================================
# Registry
# =============================================================================

_NORMALIZERS = {
    "rpp1": _normalize_rpp1,
    "rpp2": _normalize_rpp2,
    "rpp3": _normalize_rpp3,
    "rpp4": _normalize_rpp4,
    "nes1": _normalize_nes1,
    "nes2": _normalize_nes2,
    "nes3": _normalize_nes3,
    "nes4": _normalize_nes4,
}
