"""
CERT-In Integration — Normalization → Compliance Engine
========================================================

Unified entry point that chains:
    Raw Vendor Config
        ↓
    Normalization (vendor detection + parsing)
        ↓
    Bridge (NormalizedSecurityConfig → scanner config dicts)
        ↓
    Existing CERT-In Scanners (RPP.1–4, NES.1–4, WEB.1)
        ↓
    SubControlResults with enriched evidence

DO NOT create a second compliance engine.
DO NOT modify existing scanner logic.
DO preserve the existing output format.

Usage::

    from msme_auditor.config_parsers.certin_integration import run_certin_from_config

    results = run_certin_from_config(cisco_config_text)
    for result in results:
        print(f"{result.sub_control}: {result.status.value} ({result.score}/100)")
"""

from typing import Any, Dict, List, Optional, Tuple

from msme_auditor.config_parsers.normalization_engine import (
    NormalizationResult,
    normalize_config,
)
from msme_auditor.config_parsers.normalization_bridge import (
    BridgeResult,
    build_scanner_configs,
    get_evidence_for_finding,
)
from msme_auditor.config_parsers.ai_remediation import (
    RemediationSuggestion,
    suggest_remediation,
    suggest_remediation_for_findings,
)
from msme_auditor.scanners.registry import discover_scanners, get_scanner, run_scan, get_all_scanners
from msme_auditor.schemas.results import SubControlResult
from msme_auditor.schemas.enums import ComplianceStatus


# =============================================================================
# Ensure scanners are loaded
# =============================================================================

_scanners_discovered = False


def _ensure_scanners():
    """Lazily discover scanners on first use."""
    global _scanners_discovered
    if not _scanners_discovered:
        discover_scanners()
        _scanners_discovered = True


# =============================================================================
# CERT-In Audit Result
# =============================================================================

class CertInAuditResult:
    """
    Complete result of a CERT-In compliance audit from a vendor configuration.

    Contains:
    - SubControlResults from each applicable scanner
    - Normalization metadata (vendor, device, coverage, unknowns)
    - Evidence trail (parameter → source → line number)
    - Overall score and compliance status
    """

    def __init__(
        self,
        results: List[SubControlResult],
        normalization: NormalizationResult,
        bridge: BridgeResult,
    ):
        self.results = results
        self.normalization = normalization
        self.bridge = bridge

    @property
    def vendor(self) -> str:
        """Detected vendor name."""
        return self.normalization.vendor

    @property
    def device(self):
        """Device information."""
        return self.normalization.device

    @property
    def overall_score(self) -> int:
        """Average score across all sub-controls."""
        if not self.results:
            return 0
        return int(sum(r.score for r in self.results) / len(self.results))

    @property
    def overall_status(self) -> ComplianceStatus:
        """Overall compliance status."""
        score = self.overall_score
        if score >= 90:
            return ComplianceStatus.PASSED
        elif score >= 60:
            return ComplianceStatus.WARNING
        return ComplianceStatus.FAILED

    @property
    def coverage(self) -> float:
        """Percentage of config lines recognized."""
        return self.normalization.coverage

    @property
    def unknown_count(self) -> int:
        """Number of unknown configuration commands."""
        return self.normalization.unknown_count

    @property
    def unknowns(self):
        """List of unknown configurations."""
        return self.normalization.unknown_configurations

    @property
    def has_unknowns(self) -> bool:
        """Whether any unknown commands were found."""
        return self.normalization.has_unknowns

    def get_evidence_for(self, parameter: str) -> Dict[str, Any]:
        """
        Get the evidence trail for a specific normalized parameter.

        Returns a dict with:
        - parameter: the normalized parameter name
        - value: the normalized value
        - vendor: detected vendor
        - device_model: device model
        - os_version: OS version
        - parse_confidence: confidence in parsing
        - source: where the value came from
        """
        return get_evidence_for_finding(self.bridge, parameter)

    def failed_checks(self) -> List[Dict[str, Any]]:
        """
        Get all failed checks across all sub-controls.

        Returns a list of dicts with:
        - control_id, sub_control, check_id, check_name
        - expected_value, actual_value, severity
        - remediation_command
        - evidence (from normalization)
        """
        failed = []
        for result in self.results:
            for check in result.checks:
                if not check.passed:
                    # Try to find evidence for the check's parameter
                    evidence = self.bridge.evidence.get(check.check_id, {})
                    failed.append({
                        "control_id": result.control_id,
                        "sub_control": result.sub_control,
                        "sub_control_name": result.sub_control_name,
                        "check_id": check.check_id,
                        "check_name": check.check_name,
                        "expected_value": check.expected_value,
                        "actual_value": check.actual_value,
                        "severity": check.severity.value,
                        "remediation_command": check.remediation_command,
                        "evidence": {
                            "vendor": self.vendor,
                            "device_model": self.device.model,
                            "normalized_value": evidence.get("value"),
                            "source": evidence.get("source", "normalized_config"),
                        },
                    })
        return failed

    def get_remediations(self) -> List[RemediationSuggestion]:
        """
        Get AI remediation suggestions for all failed checks.

        Uses Gemini when available, falls back to deterministic templates.
        Always clearly labeled as "AI-Suggested Remediation".

        Returns:
            List of RemediationSuggestion objects
        """
        failed = self.failed_checks()
        if not failed:
            return []
        return suggest_remediation_for_findings(
            failed,
            vendor=self.vendor,
            device_model=self.device.model,
        )

    def to_dict(self, include_remediations: bool = True) -> Dict[str, Any]:
        """
        Serialize to a JSON-compatible dict.

        Args:
            include_remediations: Whether to include AI remediation suggestions
        """
        d = {
            "vendor": self.vendor,
            "device": {
                "vendor": self.device.vendor,
                "model": self.device.model,
                "version": self.device.version,
                "hostname": self.device.hostname,
            },
            "overall_score": self.overall_score,
            "overall_status": self.overall_status.value,
            "coverage": self.coverage,
            "parse_confidence": self.normalization.parse_confidence,
            "unknown_count": self.unknown_count,
            "results": [
                r.model_dump() if hasattr(r, "model_dump") else r
                for r in self.results
            ],
            "failed_checks": self.failed_checks(),
            "evidence": self.bridge.evidence,
        }
        if include_remediations:
            d["remediations"] = [
                r.to_dict() for r in self.get_remediations()
            ]
        return d


# =============================================================================
# Unified Entry Point
# =============================================================================

# Scanner IDs to run against normalized config
_DEFAULT_SCANNERS = ["rpp1", "rpp2", "rpp3", "rpp4"]

# Check ID → Normalized Parameter mapping
# Used to build evidence chains from CERT-In findings back to config
_CHECK_TO_PARAM = {
    # RPP.1
    "min_length": "password_min_length",
    "uppercase": "password_complexity_enabled",
    "lowercase": "password_complexity_enabled",
    "numbers": "password_complexity_enabled",
    "special": "password_complexity_enabled",
    "expiry": "password_expiry_days",
    "history": "password_history_count",
    # RPP.2
    "lockout_threshold": "account_lockout_enabled",
    "lockout_duration": "account_lockout_threshold",
    "reset_window": "session_timeout",
    "audit_logging": "logging_enabled",
    # RPP.3
    "admin_mfa": "mfa_enabled",
    "remote_mfa": "mfa_enabled",
    # RPP.4
    "no_plaintext": "password_encryption_enabled",
    "hash_algorithm": "password_encryption_enabled",
    "salting": "password_encryption_enabled",
    "no_weak": "password_encryption_enabled",
    "encryption_at_rest": "password_encryption_enabled",
}


def run_certin_from_config(
    config_text: str,
    vendor_hint: Optional[str] = None,
    scanner_ids: Optional[List[str]] = None,
) -> CertInAuditResult:
    """
    Run CERT-In compliance checks against a raw vendor configuration.

    This is the primary entry point for the integration. It chains:
    1. Vendor detection + normalization
    2. Bridge mapping (NormalizedSecurityConfig → scanner configs)
    3. Existing CERT-In scanner execution
    4. Result enrichment with evidence

    Args:
        config_text: Raw vendor configuration text (Cisco, Fortinet, Juniper)
        vendor_hint: Optional vendor name to skip auto-detection
        scanner_ids: Optional list of scanner IDs to run (default: RPP.1-4)

    Returns:
        CertInAuditResult with SubControlResults, evidence, and metadata

    Example::

        from msme_auditor.config_parsers.certin_integration import run_certin_from_config

        cisco_config = '''
        hostname Router1
        service password-encryption
        ip ssh version 2
        line vty 0 4
         exec-timeout 5 0
         transport input ssh
        logging host 192.168.1.100
        '''

        audit = run_certin_from_config(cisco_config)
        print(f"Vendor: {audit.vendor}")
        print(f"Score: {audit.overall_score}/100")
        print(f"Status: {audit.overall_status.value}")

        for result in audit.results:
            print(f"  {result.sub_control}: {result.status.value}")
    """
    _ensure_scanners()

    # Step 1: Normalize the configuration
    norm_result = normalize_config(config_text, vendor_hint=vendor_hint)

    # Step 2: Build scanner configs via bridge
    bridge = build_scanner_configs(norm_result)

    # Step 3: Determine which scanners to run
    if scanner_ids is None:
        scanner_ids = _DEFAULT_SCANNERS

    # Step 4: Run each scanner with the bridged config
    results: List[SubControlResult] = []
    scanner_configs = {
        "rpp1": bridge.rpp1_config,
        "rpp2": bridge.rpp2_config,
        "rpp3": bridge.rpp3_config,
        "rpp4": bridge.rpp4_config,
    }

    for scanner_id in scanner_ids:
        config = scanner_configs.get(scanner_id, {})
        scanner = get_scanner(scanner_id)
        if scanner is None:
            print(f"  ⚠️  Scanner '{scanner_id}' not registered, skipping")
            continue

        try:
            scan_result = run_scan(scanner_id, config)
            # Enrich evidence with normalization data
            _enrich_evidence(scan_result, bridge, norm_result)
            results.append(scan_result)
            icon = "✅" if scan_result.status == ComplianceStatus.PASSED else (
                "⚠️" if scan_result.status == ComplianceStatus.WARNING else "❌"
            )
            print(f"  {icon} {scanner_id}: {scan_result.status.value} ({scan_result.score}/100)")
        except Exception as exc:
            print(f"  ❌ {scanner_id}: ERROR — {exc}")

    return CertInAuditResult(
        results=results,
        normalization=norm_result,
        bridge=bridge,
    )


def run_certin_from_config_verbose(
    config_text: str,
    vendor_hint: Optional[str] = None,
    scanner_ids: Optional[List[str]] = None,
) -> CertInAuditResult:
    """
    Same as run_certin_from_config but with detailed console output.

    Useful for debugging and demo mode.
    """
    _ensure_scanners()

    print("\n" + "=" * 60)
    print("CERT-In COMPLIANCE AUDIT — From Vendor Configuration")
    print("=" * 60)

    # Step 1: Normalize
    print("\n📋 Step 1: Normalizing configuration...")
    norm_result = normalize_config(config_text, vendor_hint=vendor_hint)
    print(f"  Vendor: {norm_result.vendor}")
    print(f"  Device: {norm_result.device.model} {norm_result.device.version}")
    if norm_result.device.hostname:
        print(f"  Hostname: {norm_result.device.hostname}")
    print(f"  Coverage: {norm_result.coverage:.1f}%")
    print(f"  Parse confidence: {norm_result.parse_confidence:.2f}")
    if norm_result.has_unknowns:
        print(f"  ⚠️  Unknown commands: {norm_result.unknown_count}")
        for u in norm_result.unknown_configurations[:5]:
            print(f"    Line {u.line_number}: {u.raw_command}")

    # Step 2: Bridge
    print("\n🔗 Step 2: Building scanner configs...")
    bridge = build_scanner_configs(norm_result)
    print(f"  Evidence entries: {len(bridge.evidence)}")

    # Step 3: Run scanners
    print("\n🔍 Step 3: Running CERT-In scanners...")
    if scanner_ids is None:
        scanner_ids = _DEFAULT_SCANNERS

    results: List[SubControlResult] = []
    scanner_configs = {
        "rpp1": bridge.rpp1_config,
        "rpp2": bridge.rpp2_config,
        "rpp3": bridge.rpp3_config,
        "rpp4": bridge.rpp4_config,
    }

    for scanner_id in scanner_ids:
        config = scanner_configs.get(scanner_id, {})
        scanner = get_scanner(scanner_id)
        if scanner is None:
            print(f"  ⚠️  Scanner '{scanner_id}' not registered, skipping")
            continue

        try:
            scan_result = run_scan(scanner_id, config)
            _enrich_evidence(scan_result, bridge, norm_result)
            results.append(scan_result)
            icon = "✅" if scan_result.status == ComplianceStatus.PASSED else (
                "⚠️" if scan_result.status == ComplianceStatus.WARNING else "❌"
            )
            print(f"  {icon} {scanner_id}: {scan_result.status.value} ({scan_result.score}/100)")
            for check in scan_result.checks:
                check_icon = "✅" if check.passed else "❌"
                print(f"      {check_icon} {check.check_name}: {check.actual_value}")
        except Exception as exc:
            print(f"  ❌ {scanner_id}: ERROR — {exc}")

    # Step 4: Summary
    audit = CertInAuditResult(
        results=results,
        normalization=norm_result,
        bridge=bridge,
    )

    print("\n" + "=" * 60)
    print(f"📊 OVERALL SCORE: {audit.overall_score}/100 — {audit.overall_status.value}")
    print(f"   Coverage: {audit.coverage:.1f}%")
    if audit.has_unknowns:
        print(f"   Unknown commands: {audit.unknown_count}")
    print("=" * 60 + "\n")

    return audit


# =============================================================================
# Internal Helpers
# =============================================================================

def _enrich_evidence(
    scan_result: SubControlResult,
    bridge: BridgeResult,
    norm_result: NormalizationResult,
) -> None:
    """
    Enrich a SubControlResult's evidence field with normalization data.

    This adds the vendor, device, and normalized parameter information
    to the evidence dict so that findings are fully traceable.

    The evidence format:
    {
        "vendor": "cisco",
        "device_model": "IOS",
        "os_version": "15.7",
        "hostname": "Router1",
        "coverage": 85.0,
        "parse_confidence": 0.95,
        "normalized_parameters": {param: value, ...},
        "unknown_commands": [...],
        "evidence_chain": {check_id: {parameter, source_line, line_number}, ...}
    }
    """
    if scan_result.evidence is None:
        scan_result.evidence = {}

    # Add normalization metadata to evidence
    scan_result.evidence["vendor"] = norm_result.vendor
    scan_result.evidence["device_model"] = norm_result.device.model
    scan_result.evidence["os_version"] = norm_result.device.version
    scan_result.evidence["hostname"] = norm_result.device.hostname
    scan_result.evidence["coverage"] = norm_result.coverage
    scan_result.evidence["parse_confidence"] = norm_result.parse_confidence

    # Add relevant normalized parameters based on the scanner
    flat = norm_result.flat_config
    relevant_params = _get_relevant_params(scan_result.sub_control)
    scan_result.evidence["normalized_parameters"] = {
        k: v for k, v in flat.items() if k in relevant_params and v is not None
    }

    # Build evidence chain: check_id → normalized parameter → source config
    evidence_chain = {}
    config_evidence = norm_result.normalized_config.evidence_trail
    for check in scan_result.checks:
        # Map check_id to normalized parameter
        param = _CHECK_TO_PARAM.get(check.check_id)
        if param and param in config_evidence:
            trail = config_evidence[param]
            evidence_chain[check.check_id] = {
                "parameter": param,
                "value": check.actual_value,
                "source_line": trail.get("source_line", ""),
                "line_number": trail.get("line_number", 0),
                "vendor": norm_result.vendor,
                "model": norm_result.device.model,
                "confidence": trail.get("confidence", 1.0),
            }
            # Also attach evidence directly to the check object
            check_evidence = {
                "parameter": param,
                "vendor": norm_result.vendor,
                "device_model": norm_result.device.model,
                "source_line": trail.get("source_line", ""),
                "line_number": trail.get("line_number", 0),
            }
            # Store in check's remediation_url field as JSON (hack for now)
            # Better: add an evidence field to SecurityCheck in future
    scan_result.evidence["evidence_chain"] = evidence_chain

    # Add unknown commands summary
    if norm_result.has_unknowns:
        scan_result.evidence["unknown_commands"] = [
            {
                "command": u.raw_command,
                "line_number": u.line_number,
                "category": u.possible_category,
            }
            for u in norm_result.unknown_configurations
        ]


def _get_relevant_params(sub_control: str) -> List[str]:
    """
    Get the normalized parameters relevant to a specific sub-control.

    This maps CERT-In sub-controls to the NormalizedSecurityConfig
    fields that feed into them.
    """
    mapping = {
        "RPP.1": [
            "password_min_length", "password_complexity_enabled",
            "password_expiry_days", "password_history_count",
        ],
        "RPP.2": [
            "account_lockout_enabled", "account_lockout_threshold",
            "session_timeout", "logging_enabled",
        ],
        "RPP.3": [
            "mfa_enabled",
        ],
        "RPP.4": [
            "password_encryption_enabled",
        ],
        "NES.1": [
            "ssh_enabled", "telnet_enabled", "https_enabled",
            "http_server_enabled", "snmp_community_default",
        ],
        "NES.2": [
            "ssh_enabled", "ssh_version", "ssh_ciphers_strong",
            "unused_ports_disabled",
        ],
        "NES.3": [
            "logging_enabled", "remote_syslog_enabled",
            "log_timestamps_enabled", "login_logging_enabled",
        ],
        "NES.4": [
            "ntp_configured", "aaa_enabled",
        ],
    }
    return mapping.get(sub_control, [])
