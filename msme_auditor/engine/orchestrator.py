"""
Audit Orchestrator
==================
Runs any combination of scanners and builds a unified :class:`AuditReport`.

The primary entry point is :func:`run_full_audit`, which accepts a target
domain/IP and keyword arguments for per-scanner config.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from msme_auditor.schemas.enums import ComplianceStatus
from msme_auditor.schemas.reports import AuditReport
from msme_auditor.schemas.results import SubControlResult
from msme_auditor.engine.scoring import determine_status, count_vulnerabilities, determine_risk_level


def run_full_audit(
    *,
    target_domain: str = "",
    target_ip: str = "",
    company_name: str = "Unspecified Organization",
    scanner_ids: Optional[List[str]] = None,
    scanner_configs: Optional[Dict[str, Dict[str, Any]]] = None,
) -> AuditReport:
    """
    High-level pipeline: configure → run all scanners → aggregate → report.

    This is the **single function** consumers should call.  It:

    1. Resolves the target domain/IP into per-scanner config.
    2. Runs every requested scanner (or all registered scanners).
    3. Aggregates results into a unified :class:`AuditReport`.

    Args:
        target_domain: The domain to scan (e.g. ``"example.com"``).
            Scanners that need a domain (NES.4, WEB.1, NES.1) receive this
            automatically.
        target_ip: The IP to scan (e.g. ``"93.184.216.34"``).
            Port scanners (NES.1) use this directly.
        company_name: Organization name for the report header.
        scanner_ids: List of scanner IDs to run.  ``None`` means **all**
            registered scanners.
        scanner_configs: Per-scanner overrides, keyed by scanner ID.
            Example: ``{"rpp1": {"min_length": 10}}``.
            Values are merged with the auto-generated target config.

    Returns:
        A fully-populated :class:`AuditReport`.

    Raises:
        RuntimeError: If no scanners are registered or none produce results.

    Example::

        from msme_auditor.engine.orchestrator import run_full_audit

        report = run_full_audit(
            target_domain="example.com",
            target_ip="93.184.216.34",
            company_name="Acme Corp",
        )
        print(report.overall_score)
    """
    from msme_auditor.scanners.registry import get_all_scanners, run_scan

    all_scanners = get_all_scanners()
    if not all_scanners:
        raise RuntimeError(
            "No scanners registered. Call discover_scanners() first."
        )

    # Determine which scanners to run
    if scanner_ids is None:
        scanner_ids = list(all_scanners.keys())

    # Build base config that every scanner receives
    base_config: Dict[str, Any] = {}
    if target_domain:
        base_config["target"] = target_domain
        base_config["domain"] = target_domain
    if target_ip:
        base_config["ip_address"] = target_ip

    # Merge per-scanner overrides
    scanner_configs = scanner_configs or {}
    results: List[SubControlResult] = []

    for sid in scanner_ids:
        if sid not in all_scanners:
            print(f"  ⚠️  Scanner '{sid}' not found, skipping")
            continue

        merged = {**base_config, **scanner_configs.get(sid, {})}

        # Auto-set target_type from domain/ip if not explicitly overridden
        if "target_type" not in merged:
            scanner = all_scanners[sid]
            if "web" in scanner.target_types and (target_domain or target_ip):
                merged["target_type"] = "web"
            elif "windows" in scanner.target_types:
                merged["target_type"] = "windows"
            else:
                merged["target_type"] = "manual"

        try:
            result = run_scan(sid, merged)
            results.append(result)
            icon = "✅" if result.status == ComplianceStatus.PASSED else (
                "⚠️" if result.status == ComplianceStatus.WARNING else "❌"
            )
            print(f"  {icon} {sid}: {result.status.value} (score: {result.score})")
        except Exception as exc:
            print(f"  ❌ {sid}: ERROR — {exc}")

    if not results:
        raise RuntimeError("No scanner produced results")

    return _build_report(company_name, results)


def run_audit(
    company_name: str = "Unspecified Organization",
    scanner_ids: Optional[List[str]] = None,
    config: Optional[Dict[str, dict]] = None,
) -> AuditReport:
    """
    Lower-level entry point used by the API server and CLI runner.

    Prefer :func:`run_full_audit` for new code.

    Args:
        company_name: Organization name for the report.
        scanner_ids: Scanner IDs to run (``None`` = all).
        config: Per-scanner config dict.

    Returns:
        An :class:`AuditReport`.
    """
    from msme_auditor.scanners.registry import get_all_scanners, run_scan

    all_scanners = get_all_scanners()
    if not all_scanners:
        raise RuntimeError(
            "No scanners registered. Call discover_scanners() first."
        )

    if scanner_ids is None:
        scanner_ids = list(all_scanners.keys())

    config = config or {}
    results: List[SubControlResult] = []

    for sid in scanner_ids:
        if sid not in all_scanners:
            print(f"  ⚠️  Scanner '{sid}' not found, skipping")
            continue
        try:
            result = run_scan(sid, config.get(sid, {}))
            results.append(result)
            icon = "✅" if result.status == ComplianceStatus.PASSED else (
                "⚠️" if result.status == ComplianceStatus.WARNING else "❌"
            )
            print(f"  {icon} {sid}: {result.status.value} (score: {result.score})")
        except Exception as exc:
            print(f"  ❌ {sid}: ERROR — {exc}")

    if not results:
        raise RuntimeError("No scanner produced results")

    return _build_report(company_name, results)


# =============================================================================
# Internal helpers
# =============================================================================

def _build_report(
    company_name: str,
    results: List[SubControlResult],
) -> AuditReport:
    """
    Aggregate a list of :class:`SubControlResult` into a single
    :class:`AuditReport`.

    Args:
        company_name: Organization name for the report header.
        results: Results from individual scanners.

    Returns:
        A fully-populated :class:`AuditReport`.
    """
    overall_score = int(sum(r.score for r in results) / len(results))
    overall_status = determine_status(overall_score)
    total_vulns, critical_vulns = count_vulnerabilities(results)
    risk_level = determine_risk_level(overall_score, critical_vulns)

    # Compliance badge
    if overall_score >= 90:
        badge = "CERT-In Compliant"
    elif overall_score >= 60:
        badge = "Partial Compliance — Action Required"
    else:
        badge = "Non-Compliant — Immediate Action Required"

    # Executive summary
    passed = sum(1 for r in results if r.status == ComplianceStatus.PASSED)
    failed = sum(1 for r in results if r.status == ComplianceStatus.FAILED)
    warned = sum(1 for r in results if r.status == ComplianceStatus.WARNING)

    lines = [
        f"{company_name} has undergone an automated CERT-In compliance audit.",
        "",
        f"SUMMARY: {passed} passed, {warned} warnings, {failed} failures.",
        f"Overall Score: {overall_score}/100",
        "",
        "KEY FINDINGS:",
    ]
    for r in results:
        icon = "PASS" if r.status == ComplianceStatus.PASSED else (
            "WARN" if r.status == ComplianceStatus.WARNING else "FAIL"
        )
        lines.append(f"  [{icon}] {r.sub_control}: {r.summary}")

    if overall_score >= 90:
        lines.append("")
        lines.append(
            "RECOMMENDATION: Continue monitoring. "
            "Schedule next audit in 90 days."
        )
    elif overall_score >= 60:
        lines.append("")
        lines.append("RECOMMENDATION: Address gaps within 30 days.")
    else:
        lines.append("")
        lines.append("RECOMMENDATION: IMMEDIATE ACTION REQUIRED.")

    exec_summary = "\n".join(lines)

    next_audit = (
        datetime.now(timezone.utc) + timedelta(days=90)
    ).strftime("%Y-%m-%d")

    report = AuditReport(
        report_id=(
            f"audit-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
            f"-{uuid.uuid4().hex[:8]}"
        ),
        company_name=company_name,
        overall_score=overall_score,
        overall_status=overall_status,
        compliance_badge=badge,
        results=results,
        executive_summary=exec_summary,
        total_vulnerabilities=total_vulns,
        critical_issues=critical_vulns,
        risk_level=risk_level,
        next_audit_recommended=next_audit,
    )

    print(f"\n{'='*50}")
    print(f"  Overall: {overall_score}/100 — {overall_status.value}")
    print(f"  Badge: {badge}")
    print(f"  Risk: {risk_level}")
    print(f"  Vulnerabilities: {total_vulns} total, {critical_vulns} critical")
    print(f"{'='*50}\n")

    return report
