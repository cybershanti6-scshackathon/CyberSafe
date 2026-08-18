from pydantic import BaseModel, Field


class PasswordPolicyRequest(BaseModel):
    minimum_length: int = Field(..., ge=1)

    requires_uppercase: bool
    requires_lowercase: bool
    requires_number: bool
    requires_special_character: bool

    password_expiry_days: int = Field(..., ge=0)

    password_history_count: int = Field(..., ge=0)

    prevents_credential_sharing: bool
    user_password_security_training: bool


class ComplianceResult(BaseModel):
    control: str
    status: str
    score: int
    total_checks: int
    passed_checks: int
    findings: list
    recommendations: list