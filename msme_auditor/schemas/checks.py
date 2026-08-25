"""
SecurityCheck — a single pass/fail check within a sub-control.

Example: RPP.1 has 8 checks (min_length, uppercase_required, etc.)
         NES.4 has 3 checks (spf_configured, dkim_configured, dmarc_configured)
"""

from pydantic import BaseModel, Field
from typing import Optional
from msme_auditor.schemas.enums import SeverityLevel


class SecurityCheck(BaseModel):
    """A single security check within a sub-control."""

    check_id: str = Field(
        ...,
        description="Unique identifier (e.g. 'min_password_length', 'spf_configured')",
    )
    check_name: str = Field(
        ...,
        description="Human-readable name (e.g. 'Minimum Password Length')",
    )
    passed: bool = Field(
        ...,
        description="True if check passed, False if failed",
    )
    expected_value: str = Field(
        ...,
        description="What the policy requires (e.g. 'At least 8 characters')",
    )
    actual_value: Optional[str] = Field(
        None,
        description="What was found (e.g. '6 characters')",
    )
    severity: SeverityLevel = Field(
        SeverityLevel.HIGH,
        description="How critical this check is",
    )
    remediation_command: Optional[str] = Field(
        None,
        description="Copy-paste command to fix the issue",
    )
    remediation_url: Optional[str] = Field(
        None,
        description="Link to documentation for manual fix",
    )
