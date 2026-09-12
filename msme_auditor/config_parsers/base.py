"""
Base classes and interfaces for configuration parsers.
=======================================================

All vendor parsers inherit from BaseConfigParser.
ParserRegistry auto-discovers and manages them.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
from pathlib import Path

from msme_auditor.schemas.config_normalization import (
    NormalizedSecurityConfig,
    DeviceInfo,
    AuthenticationConfig,
    NetworkConfig,
    LoggingConfig,
    EncryptionConfig,
    AccessControlConfig,
)
from msme_auditor.config_parsers.evidence_tracker import (
    EvidenceTracker,
    create_tracker_with_defaults,
)


# =============================================================================
# Parse Result & Unknown Configuration
# =============================================================================

@dataclass
class UnknownConfiguration:
    """
    A configuration command/line that the parser could not understand.

    This is CRITICAL — we never silently ignore unknown syntax.
    Every unknown command is tracked for:
    1. Knowledge base learning
    2. Human-in-the-loop review
    3. AI-assisted suggestion (future)
    """
    raw_command: str                    # The exact line from config
    vendor: str                         # Detected vendor (Cisco, Fortinet, Juniper, Unknown)
    line_number: int                    # Line number in original config
    parser_name: str                    # Name of parser that failed to understand it
    confidence: float = 0.0             # 0.0-1.0, how confident parser is that this IS unknown
    possible_category: Optional[str] = None  # e.g., "session_timeout", "logging", "aaa"
    context_lines: List[str] = field(default_factory=list)  # Surrounding lines for context
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_command": self.raw_command,
            "vendor": self.vendor,
            "line_number": self.line_number,
            "parser_name": self.parser_name,
            "confidence": self.confidence,
            "possible_category": self.possible_category,
            "context_lines": self.context_lines,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ParseResult:
    """
    Result of parsing a vendor configuration.

    Contains the normalized config + any unknown commands found.
    """
    normalized_config: NormalizedSecurityConfig
    unknown_configurations: List[UnknownConfiguration] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)
    success: bool = True

    @property
    def has_unknowns(self) -> bool:
        return len(self.unknown_configurations) > 0

    @property
    def unknown_count(self) -> int:
        return len(self.unknown_configurations)


# =============================================================================
# Vendor Detection Result
# =============================================================================

@dataclass
class VendorDetectionResult:
    """Result of deterministic vendor detection."""
    vendor: str                 # "cisco", "fortinet", "juniper", "unknown"
    confidence: float           # 0.0 - 1.0
    detection_method: str       # "banner", "command_syntax", "keyword_matching"
    evidence: List[str] = field(default_factory=list)  # Lines that triggered detection

    @property
    def is_unknown(self) -> bool:
        return self.vendor.lower() == "unknown" or self.confidence < 0.5


# =============================================================================
# Base Config Parser (Abstract)
# =============================================================================

class BaseConfigParser(ABC):
    """
    Abstract base class for all vendor configuration parsers.

    Subclasses must implement:
    - vendor_name: Class attribute (e.g., "cisco", "fortinet", "juniper")
    - supported_os: List of OS/firmware names (e.g., ["IOS", "IOS-XE", "NX-OS"])
    - parse(): Main parsing logic

    The parser registry auto-discovers subclasses via discover_parsers().
    """

    # Class-level metadata (must be overridden)
    vendor_name: str = "unknown"
    supported_os: List[str] = []
    version: str = "1.0.0"

    def __init__(self):
        self._unknown_configs: List[UnknownConfiguration] = []
        self._parse_errors: List[str] = []
        self._evidence_tracker: Optional[EvidenceTracker] = None

    @abstractmethod
    def parse(self, config_text: str, device_info: Optional[DeviceInfo] = None) -> ParseResult:
        """
        Parse raw configuration text into NormalizedSecurityConfig.

        Args:
            config_text: Raw configuration as a string
            device_info: Optional pre-detected device info (vendor, model, version)

        Returns:
            ParseResult with normalized_config and any unknown configurations
        """
        ...

    def _create_unknown(
        self,
        raw_command: str,
        line_number: int,
        confidence: float = 0.0,
        possible_category: Optional[str] = None,
        context_lines: Optional[List[str]] = None,
    ) -> UnknownConfiguration:
        """Helper to create an UnknownConfiguration with this parser's metadata."""
        return UnknownConfiguration(
            raw_command=raw_command,
            vendor=self.vendor_name,
            line_number=line_number,
            parser_name=self.__class__.__name__,
            confidence=confidence,
            possible_category=possible_category,
            context_lines=context_lines or [],
        )

    def _init_normalized_config(self, device_info: Optional[DeviceInfo] = None) -> NormalizedSecurityConfig:
        """Create a fresh NormalizedSecurityConfig with device info."""
        if device_info is None:
            device_info = DeviceInfo(vendor=self.vendor_name.title())
        return NormalizedSecurityConfig(device=device_info)

    def _finalize_result(self, config: NormalizedSecurityConfig, raw_line_count: int) -> ParseResult:
        """Finalize parse result with metadata."""
        config.raw_line_count = raw_line_count
        config.recognized_line_count = raw_line_count - len(self._unknown_configs)
        config.unrecognized_commands = [u.raw_command for u in self._unknown_configs]
        config.parse_confidence = 1.0 - (len(self._unknown_configs) / max(raw_line_count, 1))

        return ParseResult(
            normalized_config=config,
            unknown_configurations=self._unknown_configs.copy(),
            parse_errors=self._parse_errors.copy(),
            success=len(self._parse_errors) == 0,
        )

    def reset(self):
        """Reset parser state for reuse."""
        self._unknown_configs.clear()
        self._parse_errors.clear()
        self._evidence_tracker = None

    def _set_with_evidence(
        self,
        config: NormalizedSecurityConfig,
        section: str,
        parameter: str,
        value: Any,
        source_line: str,
        line_number: int,
        confidence: float = 1.0,
    ) -> None:
        """
        Set a normalized parameter value AND record evidence.

        This is the primary method parsers should use when setting
        parameter values. It both updates the config and records
        the evidence trail for full traceability.

        Args:
            config: The NormalizedSecurityConfig being built
            section: Config section name (e.g., "authentication", "network")
            parameter: Parameter name (e.g., "ssh_enabled")
            value: The value to set
            source_line: Original config line that produced this value
            line_number: Line number in the original config
            confidence: Confidence in this mapping (0.0-1.0)
        """
        # Set the value on the config
        section_obj = getattr(config, section, None)
        if section_obj and hasattr(section_obj, parameter):
            setattr(section_obj, parameter, value)

        # Record evidence
        if self._evidence_tracker is None:
            self._evidence_tracker = EvidenceTracker()
        self._evidence_tracker.record(
            parameter=parameter,
            value=value,
            source_line=source_line,
            line_number=line_number,
            vendor=config.device.vendor,
            model=config.device.model,
            confidence=confidence,
        )
        # Also record in the config's evidence_trail
        config.add_evidence(parameter, source_line, line_number, confidence)

    @property
    def evidence_tracker(self) -> EvidenceTracker:
        """Get the evidence tracker for this parser."""
        if self._evidence_tracker is None:
            self._evidence_tracker = create_tracker_with_defaults()
        return self._evidence_tracker


# =============================================================================
# Parser Registry (Plugin Architecture)
# =============================================================================

_PARSER_REGISTRY: Dict[str, BaseConfigParser] = {}


def register_parser(parser: BaseConfigParser) -> None:
    """Register a parser instance. Called at module level in each parser file."""
    _PARSER_REGISTRY[parser.vendor_name.lower()] = parser


def get_all_parsers() -> Dict[str, BaseConfigParser]:
    """Return all registered parsers."""
    return dict(_PARSER_REGISTRY)


def get_parser(vendor_name: str) -> Optional[BaseConfigParser]:
    """Get a parser by vendor name (case-insensitive)."""
    return _PARSER_REGISTRY.get(vendor_name.lower())


def list_parsers() -> List[Dict[str, Any]]:
    """List all parsers with metadata for API/frontend."""
    return [
        {
            "vendor": p.vendor_name,
            "supported_os": p.supported_os,
            "version": p.version,
            "class_name": p.__class__.__name__,
        }
        for p in _PARSER_REGISTRY.values()
    ]


def discover_parsers() -> None:
    """
    Import all parser modules so their register_parser() calls execute.

    Call once at startup (from server.py).
    """
    parser_modules = [
        "msme_auditor.config_parsers.cisco_parser",
        "msme_auditor.config_parsers.fortinet_parser",
        "msme_auditor.config_parsers.juniper_parser",
    ]

    for mod_name in parser_modules:
        try:
            parts = mod_name.split(".")
            module = __import__(mod_name, fromlist=[parts[-1]])

            # Find BaseConfigParser subclasses
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseConfigParser)
                    and attr is not BaseConfigParser
                    and attr.vendor_name
                ):
                    instance = attr()
                    register_parser(instance)
                    print(f"  ✅ Parser registered: {instance.vendor_name} ({attr.__name__})")

        except Exception as exc:
            print(f"  ⚠️  {mod_name}: {exc}")

    print(f"\n[parser_registry] {len(_PARSER_REGISTRY)} parser(s) registered")
    for vid, parser in _PARSER_REGISTRY.items():
        print(f"  - {vid}: {parser.__class__.__name__} (OS: {parser.supported_os})")


def parse_config(config_text: str, vendor_hint: Optional[str] = None) -> ParseResult:
    """
    High-level parse function: detect vendor → select parser → parse.

    Args:
        config_text: Raw configuration text
        vendor_hint: Optional vendor name to skip detection

    Returns:
        ParseResult with normalized config and unknowns
    """
    from msme_auditor.config_parsers.vendor_detector import detect_vendor

    if vendor_hint:
        parser = get_parser(vendor_hint)
        if not parser:
            raise ValueError(f"No parser registered for vendor: {vendor_hint}")
    else:
        detection = detect_vendor(config_text)
        if detection.is_unknown:
            # Return a minimal result with all lines as unknown
            return _parse_as_unknown(config_text, detection)
        parser = get_parser(detection.vendor)
        if not parser:
            return _parse_as_unknown(config_text, detection)

    return parser.parse(config_text)


def _parse_as_unknown(config_text: str, detection: VendorDetectionResult) -> ParseResult:
    """Fallback: treat entire config as unknown when vendor not supported."""
    lines = config_text.splitlines()
    unknowns = [
        UnknownConfiguration(
            raw_command=line,
            vendor=detection.vendor or "unknown",
            line_number=i + 1,
            parser_name="VendorDetector",
            confidence=1.0 - detection.confidence,
            possible_category="unknown",
        )
        for i, line in enumerate(lines) if line.strip()
    ]

    config = NormalizedSecurityConfig(
        device=DeviceInfo(vendor=detection.vendor.title() if detection.vendor != "unknown" else "Unknown"),
        parse_confidence=detection.confidence,
    )
    config.raw_line_count = len(lines)
    config.unrecognized_commands = [u.raw_command for u in unknowns]

    return ParseResult(
        normalized_config=config,
        unknown_configurations=unknowns,
        success=True,
    )


def run_parser(parser_id: str, config_text: str) -> ParseResult:
    """Run a specific parser by vendor name."""
    parser = get_parser(parser_id)
    if not parser:
        raise ValueError(f"Unknown parser: {parser_id}")
    return parser.parse(config_text)
    