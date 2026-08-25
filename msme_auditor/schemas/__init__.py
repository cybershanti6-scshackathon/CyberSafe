"""
Unified schemas for all CERT-In controls.

Single source of truth — NES and RPP share identical base models.

All imports are lazy to avoid cascading failures at startup.
"""


def __getattr__(name: str):
    """Lazy-load schema classes on first access."""
    if name == "ComplianceStatus":
        from msme_auditor.schemas.enums import ComplianceStatus
        return ComplianceStatus
    if name == "SeverityLevel":
        from msme_auditor.schemas.enums import SeverityLevel
        return SeverityLevel
    if name == "SecurityCheck":
        from msme_auditor.schemas.checks import SecurityCheck
        return SecurityCheck
    if name == "SubControlResult":
        from msme_auditor.schemas.results import SubControlResult
        return SubControlResult
    if name == "AuditReport":
        from msme_auditor.schemas.reports import AuditReport
        return AuditReport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
