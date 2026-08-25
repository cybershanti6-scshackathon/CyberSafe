"""
AuditReport — the final output model for a complete audit run.

Replaces both NESAuditReport and RPPAuditReport with a single unified model
that handles NES, RPP, WEB, or any combination.
"""

from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone
import uuid

from msme_auditor.schemas.enums import ComplianceStatus
from msme_auditor.schemas.results import SubControlResult


class AuditReport(BaseModel):
    """
    Complete audit report — the unified output for all controls.

    Replaces the old NESAuditReport / RPPAuditReport split.
    """

    # Report identity
    report_id: str = Field(
        default_factory=lambda: f"audit-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}-{uuid.uuid4().hex[:8]}",
    )
    company_name: str = Field(default="Unspecified Organization")
    report_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_version: str = Field(default="2.0.0")

    # Overall scores
    overall_score: int = Field(..., ge=0, le=100)
    overall_status: ComplianceStatus = Field(...)
    compliance_badge: str = Field(...)

    # Per-control results
    results: List[SubControlResult] = Field(default_factory=list)

    # Executive summary
    executive_summary: str = Field(default="")

    # Risk assessment
    total_vulnerabilities: int = Field(default=0)
    critical_issues: int = Field(default=0)
    risk_level: str = Field(default="Unknown")

    # Legal / compliance
    legal_notice: str = Field(
        default="This report demonstrates compliance efforts under CERT-In guidelines "
        "and IT Act Section 43A.",
    )
    next_audit_recommended: str = Field(default="")

    class Config:
        json_schema_extra = {
            "example": {
                "report_id": "audit-2026-08-21-a1b2c3d4",
                "company_name": "Acme Corp Pvt Ltd",
                "overall_score": 85,
                "overall_status": "Warning",
                "compliance_badge": "Partial Compliance — Action Required",
                "risk_level": "Medium",
            }
        }
