"""
SubControlResult — the core output model for a single sub-control scan.

Used by every scanner (RPP.1–4, NES.1–4, WEB.1) and feeds into
dashboard visualization and PDF report generation.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from datetime import datetime, timezone
from msme_auditor.schemas.enums import ComplianceStatus, SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck


class SubControlResult(BaseModel):
    """Result for a single sub-control (e.g. NES.1, RPP.3, WEB.1)."""

    # Identification
    control_id: str = Field(
        ...,
        description="Parent control (NES, RPP, WEB)",
    )
    sub_control: str = Field(
        ...,
        description="Sub-control ID (NES.1, RPP.3, WEB.1)",
    )
    sub_control_name: str = Field(
        ...,
        description="Human-readable name",
    )

    # Compliance
    status: ComplianceStatus = Field(...)
    score: int = Field(..., ge=0, le=100)
    severity: SeverityLevel = Field(...)

    # Findings
    summary: str = Field(..., description="One-line executive summary")
    finding_details: str = Field(..., description="Detailed technical finding")
    business_impact: str = Field(..., description="Business impact statement")

    # Remediation
    ai_remediation: str = Field(..., description="Human-readable remediation steps")
    remediation_script: Optional[str] = Field(None, description="Executable fix script")

    # Checks
    checks: List[SecurityCheck] = Field(default_factory=list)

    # Evidence / audit trail
    evidence: Optional[Dict] = Field(None)

    # Metadata
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_system: Optional[str] = Field(None)
    scan_method: Optional[str] = Field(None)
