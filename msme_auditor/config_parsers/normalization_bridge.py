"""
Normalization → CERT-In Bridge
================================
Maps NormalizedSecurityConfig output to the config dicts that
existing CERT-In scanners (RPP.1–4, NES.1–4, WEB.1) expect.

This bridge ensures that:
1. No scanner code is modified
2. Normalized config feeds directly into existing _scan_config() methods
3. Evidence (original config, line numbers, vendor) is preserved
4. Unknown configurations are flagged and tracked

Usage::

    from msme_auditor.config_parsers.normalization_bridge import build_scanner_configs

    bridge = build_scanner_configs(normalization_result)
    # bridge.rpp1_config  →  config dict for RPP.1 scanner
    # bridge.rpp2_config  →  config dict for RPP.2 scanner
    # bridge.evidence     →  evidence dict with vendor/line/param mapping
"""

from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from msme_auditor.config_parsers.normalization_engine import NormalizationResult
from msme_auditor.config_parsers.base import UnknownConfiguration
from msme_auditor.schemas.config_normalization import (
    NormalizedSecurityConfig,
    AuthenticationConfig,
    NetworkConfig,
    LoggingConfig,
    EncryptionConfig,
    AccessControlConfig,
)


# =============================================================================
# Bridge Result
# =============================================================================

@dataclass
class BridgeResult:
    """
    Output of mapping normalized config to CERT-In scanner inputs.

    Contains:
    - Per-scanner config dicts (ready to pass to scanners)
    - Evidence trail (param → source → line number)
    - Unknown configurations (for human-in-the-loop)
    - Metadata about the mapping
    """
    # Per-scanner config dicts
    rpp1_config: Dict[str, Any] = field(default_factory=dict)
    rpp2_config: Dict[str, Any] = field(default_factory=dict)
    rpp3_config: Dict[str, Any] = field(default_factory=dict)
    rpp4_config: Dict[str, Any] = field(default_factory=dict)
    nes1_config: Dict[str, Any] = field(default_factory=dict)

    # Evidence: maps parameter_name → {source, line_number, original_command}
    evidence: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Unknowns carried through
    unknown_configurations: List[UnknownConfiguration] = field(default_factory=list)

    # Metadata
    vendor: str = "Unknown"
    device_model: str = "Unknown"
    os_version: str = "Unknown"
    parse_confidence: float = 0.0
    coverage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "vendor": self.vendor,
            "device_model": self.device_model,
            "os_version": self.os_version,
            "parse_confidence": self.parse_confidence,
            "coverage": self.coverage,
            "rpp1_config": self.rpp1_config,
            "rpp2_config": self.rpp2_config,
            "rpp3_config": self.rpp3_config,
            "rpp4_config": self.rpp4_config,
            "nes1_config": self.nes1_config,
            "evidence": self.evidence,
            "unknown_count": len(self.unknown_configurations),
            "unknowns": [u.to_dict() for u in self.unknown_configurations],
        }


# =============================================================================
# Bridge Logic
# =============================================================================

def build_scanner_configs(norm_result: NormalizationResult) -> BridgeResult:
    """
    Map a NormalizationResult to per-scanner config dicts.

    This is the core bridge function. It reads the NormalizedSecurityConfig
    and produces config dicts that match what each CERT-In scanner's
    _scan_config() method expects.

    Args:
        norm_result: Output from normalize_config()

    Returns:
        BridgeResult with per-scanner configs and evidence
    """
    config = norm_result.normalized_config
    auth = config.authentication
    net = config.network
    log = config.logging
    enc = config.encryption
    ac = config.access_control

    bridge = BridgeResult(
        vendor=norm_result.vendor,
        device_model=config.device.model,
        os_version=config.device.version,
        parse_confidence=norm_result.parse_confidence,
        coverage=norm_result.coverage,
        unknown_configurations=norm_result.unknown_configurations,
    )

    # ========================================================================
    # RPP.1 — Password Complexity & Expiry
    # Maps: password_min_length, password_complexity, password_expiry_days,
    #        password_history_count
    # ========================================================================
    bridge.rpp1_config = {
        "min_length": auth.password_min_length or 0,
        "require_uppercase": auth.password_complexity_enabled or False,
        "require_lowercase": auth.password_complexity_enabled or False,
        "require_numbers": auth.password_complexity_enabled or False,
        "require_special_chars": auth.password_complexity_enabled or False,
        "max_age_days": auth.password_expiry_days or 0,
        "history_count": auth.password_history_count or 0,
        "education_policy_exists": False,  # Cannot be determined from config alone
    }

    # Build evidence for RPP.1
    _add_evidence(bridge, "password_min_length", auth.password_min_length, config)
    _add_evidence(bridge, "password_complexity_enabled", auth.password_complexity_enabled, config)
    _add_evidence(bridge, "password_expiry_days", auth.password_expiry_days, config)
    _add_evidence(bridge, "password_history_count", auth.password_history_count, config)

    # ========================================================================
    # RPP.2 — Account Lockout Policy
    # Maps: account_lockout_enabled, account_lockout_threshold, session_timeout
    # ========================================================================
    bridge.rpp2_config = {
        "max_failed_attempts": auth.account_lockout_threshold or 0,
        "lockout_duration_minutes": 0,  # Not directly available from config parsing
        "reset_window_minutes": 15,  # Default assumption
        "admin_unlock_enabled": True,  # Cannot be determined from config alone
        "audit_logging": log.logging_enabled or False,
    }

    _add_evidence(bridge, "account_lockout_enabled", auth.account_lockout_enabled, config)
    _add_evidence(bridge, "account_lockout_threshold", auth.account_lockout_threshold, config)
    _add_evidence(bridge, "session_timeout", auth.session_timeout, config)

    # ========================================================================
    # RPP.3 — Multi-Factor Authentication
    # Maps: mfa_enabled
    # ========================================================================
    bridge.rpp3_config = {
        "admin_mfa_enabled": auth.mfa_enabled or False,
        "remote_mfa_enabled": auth.mfa_enabled or False,
        "critical_mfa_enabled": False,  # Cannot be determined from config alone
        "mfa_method": "Unknown",
        "policy_exists": False,  # Cannot be determined from config alone
    }

    _add_evidence(bridge, "mfa_enabled", auth.mfa_enabled, config)

    # ========================================================================
    # RPP.4 — Password Encryption & Hashing
    # Maps: password_encryption_enabled
    # ========================================================================
    bridge.rpp4_config = {
        "sample_hashes": [],  # No hashes from device config
        "encryption_at_rest": auth.password_encryption_enabled or False,
    }

    _add_evidence(bridge, "password_encryption_enabled", auth.password_encryption_enabled, config)

    # ========================================================================
    # NES.1 — Firewall & Open Ports (partial — from config, not live scan)
    # ========================================================================
    bridge.nes1_config = {
        "ssh_open": net.ssh_enabled or False,
        "telnet_open": net.telnet_enabled or False,
        "https_enabled": net.https_enabled or False,
    }

    _add_evidence(bridge, "ssh_enabled", net.ssh_enabled, config)
    _add_evidence(bridge, "telnet_enabled", net.telnet_enabled, config)
    _add_evidence(bridge, "https_enabled", net.https_enabled, config)
    _add_evidence(bridge, "logging_enabled", log.logging_enabled, config)
    _add_evidence(bridge, "remote_syslog_enabled", log.remote_syslog_enabled, config)

    return bridge


def build_all_scanner_configs(norm_result: NormalizationResult) -> Dict[str, Dict[str, Any]]:
    """
    Convenience function: returns a dict of {scanner_id: config_dict}
    that can be passed directly to run_scan() or the orchestrator.

    Args:
        norm_result: Output from normalize_config()

    Returns:
        Dict mapping scanner IDs to their config dicts
    """
    bridge = build_scanner_configs(norm_result)
    return {
        "rpp1": bridge.rpp1_config,
        "rpp2": bridge.rpp2_config,
        "rpp3": bridge.rpp3_config,
        "rpp4": bridge.rpp4_config,
    }


def get_evidence_for_finding(
    bridge: BridgeResult,
    parameter: str,
) -> Dict[str, Any]:
    """
    Get the evidence trail for a specific normalized parameter.

    Returns a dict with:
    - parameter: the normalized parameter name
    - value: the normalized value
    - vendor: detected vendor
    - device: device model
    - original_config_line: (if available)
    - line_number: (if available)

    This is used by the evidence tracking system (Step 14) to provide
    full traceability from CERT-In finding → normalized parameter →
    original configuration.
    """
    evidence = bridge.evidence.get(parameter, {})
    return {
        "parameter": parameter,
        "value": evidence.get("value"),
        "vendor": bridge.vendor,
        "device_model": bridge.device_model,
        "os_version": bridge.os_version,
        "parse_confidence": bridge.parse_confidence,
        "source": evidence.get("source", "normalized_config"),
    }


# =============================================================================
# Internal helpers
# =============================================================================

def _add_evidence(
    bridge: BridgeResult,
    parameter: str,
    value: Any,
    config: NormalizedSecurityConfig,
) -> None:
    """Add an evidence entry for a parameter.

    Uses the evidence_trail from the normalized config if available,
    otherwise creates a basic evidence entry.
    """
    if value is not None:
        # Check if we have detailed evidence from the parser
        trail = config.get_evidence(parameter)
        if trail:
            bridge.evidence[parameter] = {
                "value": value,
                "source": "normalized_config",
                "vendor": config.device.vendor,
                "model": config.device.model,
                "source_line": trail.get("source_line", ""),
                "line_number": trail.get("line_number", 0),
                "confidence": trail.get("confidence", 1.0),
            }
        else:
            bridge.evidence[parameter] = {
                "value": value,
                "source": "normalized_config",
                "vendor": config.device.vendor,
                "model": config.device.model,
            }
