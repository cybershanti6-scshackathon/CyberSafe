"""
Evidence Tracker — Full Traceability for CERT-In Findings
=========================================================

Captures the complete chain from CERT-In compliance finding
back to the original configuration line:

    CERT-In Control (RPP.1)
        ↓
    Normalized Parameter (password_min_length)
        ↓
    Vendor (Cisco)
        ↓
    Original Configuration Line (security passwords min-length 6)
        ↓
    Line Number (147)

NEVER exposes redacted secrets.
Always integrates with the existing reporting structure.

Usage::

    tracker = EvidenceTracker()

    # During parsing, record evidence for each parameter
    tracker.record(
        parameter="ssh_enabled",
        value=True,
        source_line="ip ssh version 2",
        line_number=42,
        vendor="cisco",
        model="IOS",
    )

    # After scanning, get evidence for a finding
    evidence = tracker.get_for_check("min_length")
"""

import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone


# =============================================================================
# Secret Detection (never expose secrets in evidence)
# =============================================================================

_SECRET_PATTERNS = [
    re.compile(r"enable\s+secret\s+\S+", re.IGNORECASE),
    re.compile(r"password\s+\S+", re.IGNORECASE),
    re.compile(r"encrypted-password\s+\S+", re.IGNORECASE),
    re.compile(r"\$\d+\$\S+", re.IGNORECASE),  # Hash patterns ($1$, $5$, $6$)
    re.compile(r"ssh-\S+\s+\S+", re.IGNORECASE),  # SSH keys
    re.compile(r"api[_-]?key\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"community\s+\S+", re.IGNORECASE),  # SNMP community
]

_SECRET_KEYWORDS = [
    "secret", "password", "passwd", "credential", "token",
    "api_key", "apikey", "private-key", "ssh-rsa", "ssh-dsa",
    "ssh-ecdsa", "encrypted-password",
]


def _is_secret_line(line: str) -> bool:
    """Check if a config line likely contains a secret."""
    line_lower = line.lower()
    for kw in _SECRET_KEYWORDS:
        if kw in line_lower:
            return True
    for pattern in _SECRET_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _redact_secrets(line: str) -> str:
    """Redact secrets from a config line for safe display."""
    if not _is_secret_line(line):
        return line

    # Replace hashed passwords
    redacted = re.sub(
        r"(\$\d+\$)\S+",
        r"\1[REDACTED]",
        line,
    )
    # Replace plaintext passwords after keywords
    redacted = re.sub(
        r"(secret|password|passwd)\s+(\S+)",
        r"\1 [REDACTED]",
        redacted,
        flags=re.IGNORECASE,
    )
    # Replace SSH key data
    redacted = re.sub(
        r"(ssh-\S+\s+)\S+",
        r"\1[REDACTED]",
        redacted,
    )
    # Replace API keys
    redacted = re.sub(
        r"(api[_-]?key\s*[=:]\s*)\S+",
        r"\1[REDACTED]",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


# =============================================================================
# Evidence Entry
# =============================================================================

@dataclass
class EvidenceEntry:
    """
    A single evidence entry linking a normalized parameter
    to its source in the original configuration.
    """

    parameter: str               # Normalized parameter name (e.g., "ssh_enabled")
    value: Any                   # Normalized value (e.g., True)
    source_line: str             # Original config line (redacted if secret)
    source_line_raw: str         # Original config line (with secrets redacted)
    line_number: int             # Line number in original config
    vendor: str                  # Detected vendor (e.g., "cisco")
    model: str = "Unknown"       # Device model (e.g., "IOS")
    confidence: float = 1.0      # Confidence in this mapping (0.0-1.0)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict (never includes raw secrets)."""
        return {
            "parameter": self.parameter,
            "value": self.value,
            "source_line": self.source_line,  # Redacted
            "line_number": self.line_number,
            "vendor": self.vendor,
            "model": self.model,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


# =============================================================================
# Evidence Tracker
# =============================================================================

class EvidenceTracker:
    """
    Tracks evidence for all normalized parameters.

    Builds the complete traceability chain:
        CERT-In finding → normalized parameter → vendor → original config line

    Features:
    - Records evidence during parsing
    - Automatically redacts secrets
    - Supports multiple evidence entries per parameter (last wins)
    - Provides lookup by parameter name or check ID
    """

    def __init__(self):
        self._entries: Dict[str, EvidenceEntry] = {}
        self._check_to_param: Dict[str, str] = {}  # check_id → parameter

    def record(
        self,
        parameter: str,
        value: Any,
        source_line: str,
        line_number: int,
        vendor: str,
        model: str = "Unknown",
        confidence: float = 1.0,
    ) -> None:
        """
        Record evidence for a normalized parameter.

        Args:
            parameter: Normalized parameter name (e.g., "ssh_enabled")
            value: The normalized value (e.g., True)
            source_line: Original config line that produced this value
            line_number: Line number in the original config
            vendor: Detected vendor name
            model: Device model
            confidence: Confidence in this mapping (0.0-1.0)
        """
        # Redact secrets for safe storage/display
        safe_line = _redact_secrets(source_line)

        self._entries[parameter] = EvidenceEntry(
            parameter=parameter,
            value=value,
            source_line=safe_line,
            source_line_raw=source_line,  # Keep for internal use only
            line_number=line_number,
            vendor=vendor,
            model=model,
            confidence=confidence,
        )

    def map_check_to_param(self, check_id: str, parameter: str) -> None:
        """
        Map a CERT-In check ID to its source normalized parameter.

        Args:
            check_id: The check ID (e.g., "min_length")
            parameter: The normalized parameter (e.g., "password_min_length")
        """
        self._check_to_param[check_id] = parameter

    def get_for_parameter(self, parameter: str) -> Optional[Dict[str, Any]]:
        """
        Get evidence for a specific normalized parameter.

        Args:
            parameter: Normalized parameter name

        Returns:
            Evidence dict or None
        """
        entry = self._entries.get(parameter)
        if entry:
            return entry.to_dict()
        return None

    def get_for_check(self, check_id: str) -> Dict[str, Any]:
        """
        Get evidence for a CERT-In check.

        Looks up the parameter mapped to this check, then returns
        the evidence for that parameter.

        Args:
            check_id: The check ID (e.g., "min_length")

        Returns:
            Evidence dict with parameter, value, vendor, source_line, line_number
        """
        parameter = self._check_to_param.get(check_id)
        if parameter:
            return self.get_for_parameter(parameter) or {}
        return {}

    def get_full_chain(
        self,
        control_id: str,
        sub_control: str,
        check_id: str,
    ) -> Dict[str, Any]:
        """
        Get the full evidence chain for a CERT-In finding.

        Returns:
        {
            "control_id": "RPP",
            "sub_control": "RPP.1",
            "check_id": "min_length",
            "parameter": "password_min_length",
            "value": 6,
            "vendor": "cisco",
            "device_model": "IOS",
            "source_line": "security passwords min-length 6",
            "line_number": 147,
            "confidence": 1.0,
        }
        """
        evidence = self.get_for_check(check_id)
        return {
            "control_id": control_id,
            "sub_control": sub_control,
            "check_id": check_id,
            "parameter": evidence.get("parameter", "unknown"),
            "value": evidence.get("value"),
            "vendor": evidence.get("vendor", "Unknown"),
            "device_model": evidence.get("model", "Unknown"),
            "source_line": evidence.get("source_line", ""),
            "line_number": evidence.get("line_number", 0),
            "confidence": evidence.get("confidence", 0.0),
        }

    def all_entries(self) -> Dict[str, Dict[str, Any]]:
        """Get all evidence entries as dicts."""
        return {
            param: entry.to_dict()
            for param, entry in self._entries.items()
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full tracker state."""
        return {
            "entries": self.all_entries(),
            "check_mappings": dict(self._check_to_param),
            "total_entries": len(self._entries),
        }

    def clear(self) -> None:
        """Reset the tracker."""
        self._entries.clear()
        self._check_to_param.clear()

    @property
    def entry_count(self) -> int:
        """Number of evidence entries."""
        return len(self._entries)


# =============================================================================
# Check-to-Parameter Mapping (CERT-In RPP.1-4)
# =============================================================================

# Maps CERT-In check IDs to their source normalized parameters.
# This is the key mapping that enables traceability.
CHECK_PARAMETER_MAP = {
    # RPP.1 — Password Complexity & Expiry
    "min_length": "password_min_length",
    "uppercase": "password_complexity_enabled",
    "lowercase": "password_complexity_enabled",
    "numbers": "password_complexity_enabled",
    "special": "password_complexity_enabled",
    "expiry": "password_expiry_days",
    "history": "password_history_count",
    "education": None,  # No config source

    # RPP.2 — Account Lockout
    "lockout_threshold": "account_lockout_enabled",
    "lockout_duration": "account_lockout_threshold",
    "reset_window": "session_timeout",
    "admin_unlock": None,  # No config source
    "audit_logging": "logging_enabled",

    # RPP.3 — MFA
    "admin_mfa": "mfa_enabled",
    "remote_mfa": "mfa_enabled",
    "critical_mfa": None,  # No config source
    "mfa_method": "mfa_enabled",
    "mfa_policy": None,  # No config source

    # RPP.4 — Password Encryption
    "no_plaintext": "password_encryption_enabled",
    "hash_algorithm": "password_encryption_enabled",
    "salting": "password_encryption_enabled",
    "no_weak": "password_encryption_enabled",
    "encryption_at_rest": "password_encryption_enabled",
}


def create_tracker_with_defaults() -> EvidenceTracker:
    """
    Create an EvidenceTracker pre-configured with the standard
    CERT-In check-to-parameter mappings.
    """
    tracker = EvidenceTracker()
    for check_id, parameter in CHECK_PARAMETER_MAP.items():
        if parameter:
            tracker.map_check_to_param(check_id, parameter)
    return tracker
