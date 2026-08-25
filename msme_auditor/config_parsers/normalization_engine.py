"""
Normalization Engine
====================
Orchestrates the full configuration normalization pipeline:

    Raw Config Text
        ↓
    Vendor Detection (deterministic)
        ↓
    Vendor Parser Selection
        ↓
    Parsing + Unknown Tracking
        ↓
    NormalizedSecurityConfig  →  CERT-In Compliance Engine

This is the single entry point for consuming vendor configurations.
It is independent of the compliance engine — it produces a
NormalizedSecurityConfig that any scanner can consume.

Usage::

    from msme_auditor.config_parsers.normalization_engine import normalize_config

    result = normalize_config(raw_config_text)
    print(result.normalized_config.to_flat_dict())
"""

from typing import Optional, Dict, Any, List
from pathlib import Path

from msme_auditor.config_parsers.base import (
    ParseResult,
    VendorDetectionResult,
    UnknownConfiguration,
    parse_config,
    discover_parsers,
)
from msme_auditor.config_parsers.vendor_detector import detect_vendor
from msme_auditor.schemas.config_normalization import (
    NormalizedSecurityConfig,
    DeviceInfo,
)


# =============================================================================
# Ensure parsers are discovered on first use
# =============================================================================

_parsers_discovered = False


def _ensure_parsers():
    """Lazily discover parsers on first use."""
    global _parsers_discovered
    if not _parsers_discovered:
        discover_parsers()
        _parsers_discovered = True


# =============================================================================
# Public API
# =============================================================================

class NormalizationResult:
    """
    Complete result of normalizing a vendor configuration.

    Contains:
    - The normalized security config
    - Vendor detection info
    - Unknown configurations for human-in-the-loop
    - Parse metadata (confidence, coverage, errors)
    """

    def __init__(
        self,
        normalized_config: NormalizedSecurityConfig,
        vendor_detection: VendorDetectionResult,
        unknown_configurations: List[UnknownConfiguration],
        parse_confidence: float = 1.0,
        parse_errors: List[str] = None,
        success: bool = True,
    ):
        self.normalized_config = normalized_config
        self.vendor_detection = vendor_detection
        self.unknown_configurations = unknown_configurations
        self.parse_confidence = parse_confidence
        self.parse_errors = parse_errors or []
        self.success = success

    @property
    def vendor(self) -> str:
        """Detected vendor name."""
        return self.vendor_detection.vendor

    @property
    def device(self) -> DeviceInfo:
        """Device information."""
        return self.normalized_config.device

    @property
    def has_unknowns(self) -> bool:
        """Whether unknown commands were found."""
        return len(self.unknown_configurations) > 0

    @property
    def unknown_count(self) -> int:
        return len(self.unknown_configurations)

    @property
    def flat_config(self) -> Dict[str, Any]:
        """Flat dict suitable for CERT-In scanner consumption."""
        return self.normalized_config.to_flat_dict()

    @property
    def coverage(self) -> float:
        """Percentage of config lines recognized."""
        return self.normalized_config.coverage_percentage()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "vendor": self.vendor,
            "device": {
                "vendor": self.device.vendor,
                "model": self.device.model,
                "version": self.device.version,
                "hostname": self.device.hostname,
            },
            "normalized_config": self.normalized_config.model_dump(),
            "flat_config": self.flat_config,
            "vendor_detection": {
                "vendor": self.vendor_detection.vendor,
                "confidence": self.vendor_detection.confidence,
                "detection_method": self.vendor_detection.detection_method,
                "evidence": self.vendor_detection.evidence,
            },
            "unknown_configurations": [u.to_dict() for u in self.unknown_configurations],
            "parse_confidence": self.parse_confidence,
            "coverage_percentage": self.coverage,
            "unknown_count": self.unknown_count,
            "parse_errors": self.parse_errors,
            "success": self.success,
        }


def normalize_config(
    config_text: str,
    vendor_hint: Optional[str] = None,
) -> NormalizationResult:
    """
    Normalize a raw vendor configuration into the common security schema.

    This is the primary entry point for the normalization pipeline.

    Args:
        config_text: Raw configuration text from a network device
        vendor_hint: Optional vendor name to skip auto-detection
                     (e.g., "cisco", "fortinet", "juniper")

    Returns:
        NormalizationResult with normalized config, vendor info, and unknowns

    Example::

        from msme_auditor.config_parsers.normalization_engine import normalize_config

        cisco_config = '''
        hostname Router1
        service password-encryption
        ip ssh version 2
        line vty 0 4
         exec-timeout 5 0
         transport input ssh
        logging host 192.168.1.100
        '''

        result = normalize_config(cisco_config)
        print(f"Vendor: {result.vendor}")
        print(f"SSH enabled: {result.normalized_config.network.ssh_enabled}")
        print(f"Coverage: {result.coverage}%")
    """
    _ensure_parsers()

    # Step 1: Detect vendor
    if vendor_hint:
        vendor_detection = VendorDetectionResult(
            vendor=vendor_hint.lower(),
            confidence=1.0,
            detection_method="explicit_hint",
            evidence=[f"Vendor specified as {vendor_hint}"],
        )
    else:
        vendor_detection = detect_vendor(config_text)

    # Step 2: Parse with appropriate parser
    try:
        parse_result: ParseResult = parse_config(config_text, vendor_hint=vendor_hint)
    except Exception as e:
        # Parser not available or crashed — return minimal result with unknowns
        lines = [l.strip() for l in config_text.splitlines() if l.strip()]
        unknowns = [
            UnknownConfiguration(
                raw_command=line,
                vendor=vendor_detection.vendor or "unknown",
                line_number=i + 1,
                parser_name="NormalizationEngine",
                confidence=1.0,
                possible_category="unknown",
            )
            for i, line in enumerate(lines)
        ]
        return NormalizationResult(
            normalized_config=NormalizedSecurityConfig(
                device=DeviceInfo(
                    vendor=vendor_detection.vendor.title() if vendor_detection.vendor != "unknown" else "Unknown"
                )
            ),
            vendor_detection=vendor_detection,
            unknown_configurations=unknowns,
            parse_confidence=0.0,
            parse_errors=[str(e)],
            success=False,
        )

    # Step 3: Assemble result
    return NormalizationResult(
        normalized_config=parse_result.normalized_config,
        vendor_detection=vendor_detection,
        unknown_configurations=parse_result.unknown_configurations,
        parse_confidence=parse_result.normalized_config.parse_confidence,
        parse_errors=parse_result.parse_errors,
        success=parse_result.success,
    )


def normalize_config_file(
    file_path: str,
    vendor_hint: Optional[str] = None,
) -> NormalizationResult:
    """
    Normalize a configuration from a file.

    Args:
        file_path: Path to the configuration file
        vendor_hint: Optional vendor name to skip auto-detection

    Returns:
        NormalizationResult
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    config_text = path.read_text(encoding="utf-8", errors="replace")
    return normalize_config(config_text, vendor_hint=vendor_hint)


def get_normalized_scanner_config(
    config_text: str,
    vendor_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Normalize a config and return a flat dict suitable for CERT-In scanner input.

    This is the bridge between the normalization engine and the existing
    CERT-In scanner infrastructure. The returned dict can be passed directly
    to scanner _scan_config() methods.

    Args:
        config_text: Raw vendor configuration
        vendor_hint: Optional vendor name

    Returns:
        Flat dict with normalized security parameters

    Example::

        from msme_auditor.config_parsers.normalization_engine import get_normalized_scanner_config

        scanner_config = get_normalized_scanner_config(cisco_config)
        # scanner_config can now be passed to RPP.1, RPP.2, etc.
    """
    result = normalize_config(config_text, vendor_hint)
    return result.flat_config
