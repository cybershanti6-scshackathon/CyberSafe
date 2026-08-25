"""
Scoring and status determination utilities.
============================================
Shared by all scanners and the orchestrator to convert lists of
:class:`SecurityCheck` into numeric scores, compliance statuses,
and risk levels.
"""

from typing import List, Tuple

from msme_auditor.schemas.enums import ComplianceStatus, SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.schemas.results import SubControlResult


# Severity weights for weighted score calculation.
_WEIGHTS = {
    SeverityLevel.CRITICAL: 3,
    SeverityLevel.HIGH: 2,
    SeverityLevel.MEDIUM: 1,
    SeverityLevel.LOW: 0.5,
    SeverityLevel.INFO: 0.1,
}


def calculate_score(checks: List[SecurityCheck]) -> int:
    """
    Compute a weighted compliance score (0–100) from a list of checks.

    Critical checks count 3× more than Medium, etc.

    Args:
        checks: The security checks to score.

    Returns:
        An integer score between 0 and 100.
    """
    if not checks:
        return 0
    total_weight = sum(_WEIGHTS.get(c.severity, 1) for c in checks)
    passed_weight = sum(
        _WEIGHTS.get(c.severity, 1) for c in checks if c.passed
    )
    return int((passed_weight / total_weight) * 100)


def determine_status(score: int) -> ComplianceStatus:
    """
    Map a numeric score to a :class:`ComplianceStatus`.

    Args:
        score: An integer between 0 and 100.

    Returns:
        ``PASSED`` (≥90), ``WARNING`` (≥60), or ``FAILED`` (<60).
    """
    if score >= 90:
        return ComplianceStatus.PASSED
    elif score >= 60:
        return ComplianceStatus.WARNING
    else:
        return ComplianceStatus.FAILED


def count_vulnerabilities(
    results: List[SubControlResult],
) -> Tuple[int, int]:
    """
    Count total and critical failed checks across all sub-control results.

    Args:
        results: A list of :class:`SubControlResult` from individual scanners.

    Returns:
        A tuple ``(total_vulnerabilities, critical_vulnerabilities)``.
    """
    total = 0
    critical = 0
    for r in results:
        for c in r.checks:
            if not c.passed:
                total += 1
                if c.severity == SeverityLevel.CRITICAL:
                    critical += 1
    return total, critical


def determine_risk_level(score: int, critical_count: int) -> str:
    """
    Map score + critical count to a human-readable risk level.

    Args:
        score: Overall compliance score (0–100).
        critical_count: Number of critical-severity failures.

    Returns:
        One of ``"Critical"``, ``"High"``, ``"Medium"``, ``"Low"``.
    """
    if critical_count > 0 or score < 50:
        return "Critical"
    elif score < 70:
        return "High"
    elif score < 85:
        return "Medium"
    else:
        return "Low"
