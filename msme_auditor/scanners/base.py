"""
Base scanner class and check-builder utilities.
================================================

All scanners inherit from :class:`BaseScanner` and use :func:`make_check`,
:func:`bool_check`, :func:`threshold_check`, and :func:`range_check` to
build :class:`SecurityCheck` instances.

No UI code lives here.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from msme_auditor.schemas.enums import ComplianceStatus, SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.schemas.results import SubControlResult


# =============================================================================
# Scan configuration
# =============================================================================

@dataclass
class ScanConfig:
    """
    Immutable configuration passed to every scanner's ``_scan()`` method.

    Attributes:
        target_type: One of ``"web"``, ``"windows"``, ``"linux"``,
            ``"azure_ad"``, or ``"manual"``.
        target: Hostname, IP, or URL of the scan target.
        config: Free-form dict of scanner-specific settings.
    """

    target_type: str = "manual"
    target: Optional[str] = None
    config: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Check builders — reduce boilerplate in scanners
# =============================================================================

def make_check(
    check_id: str,
    name: str,
    passed: bool,
    expected: str,
    actual: str,
    severity: SeverityLevel,
    remediation: Optional[str] = None,
) -> SecurityCheck:
    """
    Generic factory for :class:`SecurityCheck`.

    Args:
        check_id: Machine-readable identifier (e.g. ``"min_length"``).
        name: Human-readable label (e.g. ``"Minimum Password Length"``).
        passed: Whether the check passed.
        expected: What the policy requires.
        actual: What was actually observed.
        severity: How critical this check is.
        remediation: Optional remediation command / instructions.

    Returns:
        A fully-populated :class:`SecurityCheck` instance.
    """
    return SecurityCheck(
        check_id=check_id,
        check_name=name,
        passed=passed,
        expected_value=expected,
        actual_value=actual,
        severity=severity,
        remediation_command=remediation,
    )


def bool_check(
    check_id: str,
    name: str,
    enabled: bool,
    expected: str,
    severity: SeverityLevel,
    remediation: str,
) -> SecurityCheck:
    """
    Check for an enabled / disabled boolean setting.

    Args:
        check_id: Machine-readable identifier.
        name: Human-readable label.
        enabled: ``True`` if the setting is correctly enabled.
        expected: What the policy expects (e.g. ``"Enabled"``).
        severity: How critical this check is.
        remediation: Remediation instructions.

    Returns:
        A :class:`SecurityCheck` with ``"Enabled"`` or ``"Disabled"`` as
        the actual value.
    """
    return make_check(
        check_id, name, enabled, expected,
        "Enabled" if enabled else "Disabled",
        severity, remediation,
    )


def threshold_check(
    check_id: str,
    name: str,
    value: int,
    min_val: int,
    expected_fmt: str,
    severity: SeverityLevel,
    remediation: str,
) -> SecurityCheck:
    """
    Check that *value* >= *min_val*.

    Args:
        check_id: Machine-readable identifier.
        name: Human-readable label.
        value: The observed value.
        min_val: The minimum acceptable value.
        expected_fmt: Format string with ``{min}`` placeholder.
        severity: How critical this check is.
        remediation: Remediation instructions.

    Returns:
        A :class:`SecurityCheck`.
    """
    return make_check(
        check_id, name, value >= min_val,
        expected_fmt.format(min=min_val),
        str(value),
        severity, remediation,
    )


def range_check(
    check_id: str,
    name: str,
    value: int,
    min_val: int,
    max_val: int,
    expected_fmt: str,
    severity: SeverityLevel,
    remediation: str,
) -> SecurityCheck:
    """
    Check that *min_val* <= *value* <= *max_val*.

    Args:
        check_id: Machine-readable identifier.
        name: Human-readable label.
        value: The observed value.
        min_val: Minimum acceptable value.
        max_val: Maximum acceptable value.
        expected_fmt: Format string with ``{min}`` and ``{max}`` placeholders.
        severity: How critical this check is.
        remediation: Remediation instructions.

    Returns:
        A :class:`SecurityCheck`.
    """
    passed = min_val <= value <= max_val
    return make_check(
        check_id, name, passed,
        expected_fmt.format(min=min_val, max=max_val),
        str(value),
        severity, remediation,
    )


# =============================================================================
# Result builder
# =============================================================================

def build_result(
    control_id: str,
    sub_control: str,
    sub_control_name: str,
    checks: List[SecurityCheck],
    target: str = "",
    scan_method: str = "manual_input",
    evidence: Optional[Dict] = None,
) -> SubControlResult:
    """
    Turn a list of checks into a :class:`SubControlResult` with score,
    status, summary, business impact, and remediation script.

    Args:
        control_id: Parent control ID (e.g. ``"RPP"``, ``"NES"``).
        sub_control: Sub-control ID (e.g. ``"RPP.1"``, ``"NES.4"``).
        sub_control_name: Human-readable name.
        checks: List of :class:`SecurityCheck` results.
        target: What was scanned.
        scan_method: How the scan was performed.
        evidence: Optional raw data for audit trail.

    Returns:
        A fully-populated :class:`SubControlResult`.
    """
    from msme_auditor.engine.scoring import calculate_score

    score = calculate_score(checks)

    if score >= 90:
        status = ComplianceStatus.PASSED
    elif score >= 60:
        status = ComplianceStatus.WARNING
    else:
        status = ComplianceStatus.FAILED

    failed = [c for c in checks if not c.passed]

    if not failed:
        summary = f"{sub_control_name} meets CERT-In requirements."
        finding = "All checks passed."
    else:
        names = [c.check_name for c in failed[:3]]
        summary = f"{sub_control_name} issues: {', '.join(names)}"
        finding = (
            f"Found {len(failed)} issue(s):\n"
            + "\n".join(
                f"- {c.check_name}: Expected {c.expected_value}, found {c.actual_value}"
                for c in failed
            )
        )

    if score < 60:
        impact = (
            f"CRITICAL RISK: {sub_control_name} gaps create significant "
            "breach risk and regulatory exposure."
        )
    elif score < 90:
        impact = (
            f"HIGH RISK: Partial {sub_control_name.lower()} coverage "
            "leaves vulnerabilities."
        )
    else:
        impact = (
            f"LOW RISK: Strong {sub_control_name.lower()} demonstrates "
            "compliance."
        )

    remediation: Optional[str] = None
    if failed:
        lines = [f"# {sub_control} Remediation Script\n"]
        for c in failed:
            if c.remediation_command:
                lines.append(f"# {c.check_name}\n{c.remediation_command}\n")
        remediation = "\n".join(lines)

    return SubControlResult(
        control_id=control_id,
        sub_control=sub_control,
        sub_control_name=sub_control_name,
        status=status,
        score=score,
        severity=SeverityLevel.CRITICAL if score < 60 else SeverityLevel.HIGH,
        summary=summary,
        finding_details=finding,
        business_impact=impact,
        ai_remediation=f"Fix all failed {sub_control_name.lower()} checks.",
        remediation_script=remediation,
        checks=checks,
        target_system=target,
        scan_method=scan_method,
        evidence=evidence,
    )


# =============================================================================
# Base scanner abstract class
# =============================================================================

class BaseScanner(ABC):
    """
    Abstract base for every scanner plugin.

    Subclasses must set the class-level metadata attributes and implement
    :meth:`_scan`.  The :mod:`registry` auto-discovers subclasses by
    scanning for ``BaseScanner`` subclasses in ``msme_auditor/scanners/``.

    Attributes:
        scanner_id: Unique short ID (e.g. ``"rpp1"``, ``"nes4"``).
        name: Display name (e.g. ``"RPP.1 — Password Complexity & Expiry"``).
        description: One-line description shown in the frontend.
        category: Grouping key (``"RPP"``, ``"NES"``, ``"Web Security"``).
        target_types: Supported target types (e.g. ``["web", "windows"]``).
        input_fields: List of dicts driving the dynamic frontend form.
    """

    scanner_id: str = ""
    name: str = ""
    description: str = ""
    category: str = ""
    target_types: List[str] = []
    input_fields: List[Dict[str, Any]] = []

    @abstractmethod
    def _scan(self, scan_config: ScanConfig) -> List[SecurityCheck]:
        """
        Run the actual scan logic and return a list of checks.

        Args:
            scan_config: The scan configuration (target, type, config dict).

        Returns:
            A list of :class:`SecurityCheck` instances.
        """
        ...

    def run(self, config: Optional[Dict[str, Any]] = None) -> SubControlResult:
        """
        Public entry point — builds a :class:`ScanConfig`, calls
        :meth:`_scan`, and wraps the checks in a :class:`SubControlResult`.

        Args:
            config: Scanner-specific configuration dict.

        Returns:
            A :class:`SubControlResult` with score, status, and findings.
        """
        cfg = config or {}
        scan_config = ScanConfig(
            target_type=cfg.get("target_type", "manual"),
            target=cfg.get("target", ""),
            config=cfg,
        )
        checks = self._scan(scan_config)

        return build_result(
            control_id=self.scanner_id[:3].upper(),
            sub_control=(
                self.scanner_id.upper()
                if "." in self.scanner_id
                else self.scanner_id
            ),
            sub_control_name=(
                self.name.split("—")[-1].strip()
                if "—" in self.name
                else self.name
            ),
            checks=checks,
            target=scan_config.target,
            scan_method=scan_config.target_type,
        )
