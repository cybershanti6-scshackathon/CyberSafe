"""
AI Remediation — CERT-In Failure → Remediation Suggestions
===========================================================

Uses Gemini to generate remediation ONLY after the deterministic
CERT-In engine identifies a failure.

Flow:
    CERT-In Finding (failed check)
        ↓
    AI Explanation (what's wrong)
        ↓
    Suggested Remediation (how to fix)
        ↓
    Device-specific CLI (Cisco/Fortinet/Juniper commands)

Supports:
- Cisco IOS/IOS-XE/NX-OS
- Fortinet FortiOS
- Juniper Junos

CRITICAL RULES:
- Gemini MUST NOT decide CERT-In PASS/FAIL
- Gemini ONLY generates remediation AFTER deterministic engine identifies failure
- Commands are SUGGESTED, never automatically executed
- Always clearly labeled: "AI-Suggested Remediation"
- Secrets are NEVER sent to Gemini
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

from msme_auditor.config_parsers.secret_redaction import redact_secrets, is_safe_for_ai
from msme_auditor.config_parsers.gemini_advisor import _init_gemini, _GEMINI_AVAILABLE, _model


# =============================================================================
# Remediation Result
# =============================================================================

class RemediationSuggestion:
    """
    A remediation suggestion for a CERT-In failed check.

    Contains:
    - The original finding
    - AI-generated explanation
    - Suggested remediation steps
    - Device-specific CLI commands
    - Source label ("AI-Suggested Remediation")
    """

    def __init__(
        self,
        check_id: str,
        check_name: str,
        control_id: str,
        sub_control: str,
        expected_value: str,
        actual_value: str,
        vendor: str,
        device_model: str = "Unknown",
        explanation: str = "",
        remediation_steps: List[str] = None,
        cli_commands: List[str] = None,
        confidence: float = 0.0,
        source: str = "heuristic",
    ):
        self.check_id = check_id
        self.check_name = check_name
        self.control_id = control_id
        self.sub_control = sub_control
        self.expected_value = expected_value
        self.actual_value = actual_value
        self.vendor = vendor
        self.device_model = device_model
        self.explanation = explanation
        self.remediation_steps = remediation_steps or []
        self.cli_commands = cli_commands or []
        self.confidence = confidence
        self.source = source  # "gemini" or "heuristic"
        self.label = "AI-Suggested Remediation"  # Always clearly labeled

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "control_id": self.control_id,
            "sub_control": self.sub_control,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "vendor": self.vendor,
            "device_model": self.device_model,
            "explanation": self.explanation,
            "remediation_steps": self.remediation_steps,
            "cli_commands": self.cli_commands,
            "confidence": self.confidence,
            "source": self.source,
            "label": self.label,
            "warning": "DO NOT automatically execute these commands. Review before applying.",
        }


# =============================================================================
# Deterministic Remediation Templates
# =============================================================================

# Vendor → check_id → remediation template
_REMEDIATION_TEMPLATES = {
    "cisco": {
        "min_length": {
            "explanation": "Password minimum length is below the CERT-In requirement of 8 characters.",
            "steps": [
                "Set minimum password length to at least 8 characters",
                "Consider 12+ characters for higher security",
            ],
            "cli": [
                "conf t",
                "security passwords min-length 8",
                "end",
            ],
        },
        "uppercase": {
            "explanation": "Password complexity (uppercase requirement) is not enforced.",
            "steps": [
                "Enable password complexity requirements",
                "Require uppercase, lowercase, numbers, and special characters",
            ],
            "cli": [
                "conf t",
                "security passwords complexity",
                "end",
            ],
        },
        "lowercase": {
            "explanation": "Password complexity (lowercase requirement) is not enforced.",
            "steps": ["Enable password complexity requirements"],
            "cli": ["conf t", "security passwords complexity", "end"],
        },
        "numbers": {
            "explanation": "Password complexity (number requirement) is not enforced.",
            "steps": ["Enable password complexity requirements"],
            "cli": ["conf t", "security passwords complexity", "end"],
        },
        "special": {
            "explanation": "Password complexity (special character requirement) is not enforced.",
            "steps": ["Enable password complexity requirements"],
            "cli": ["conf t", "security passwords complexity", "end"],
        },
        "expiry": {
            "explanation": "Password expiry is not configured or exceeds 90 days.",
            "steps": [
                "Set password maximum age to 90 days or less",
                "CERT-In requires regular password rotation",
            ],
            "cli": [
                "conf t",
                "security passwords aging 90",
                "end",
            ],
        },
        "history": {
            "explanation": "Password history is not configured or too low.",
            "steps": [
                "Set password history to at least 5 remembered passwords",
                "Prevents password reuse",
            ],
            "cli": [
                "conf t",
                "security passwords history 5",
                "end",
            ],
        },
        "lockout_threshold": {
            "explanation": "Account lockout threshold is not configured or too high.",
            "steps": [
                "Set lockout threshold to 3-5 failed attempts",
                "Prevents brute-force attacks",
            ],
            "cli": [
                "conf t",
                "security passwords lockout 5",
                "end",
            ],
        },
        "admin_unlock": {
            "explanation": "Admin unlock capability is not configured.",
            "steps": ["Enable admin unlock with audit logging"],
            "cli": ["# Configure via AAA: aaa new-model + TACACS+/RADIUS"],
        },
        "audit_logging": {
            "explanation": "Login event logging is not enabled.",
            "steps": [
                "Enable login success/failure logging",
                "Required for audit trail",
            ],
            "cli": [
                "conf t",
                "login on-success log",
                "login on-failure log",
                "end",
            ],
        },
        "admin_mfa": {
            "explanation": "MFA is not enabled for administrative accounts.",
            "steps": [
                "Enable multi-factor authentication for admin accounts",
                "Use TOTP or hardware keys",
            ],
            "cli": ["# Configure via AAA + TACACS+/RADIUS with MFA"],
        },
        "remote_mfa": {
            "explanation": "MFA is not enabled for remote access.",
            "steps": ["Enable MFA for SSH/RDP/VPN access"],
            "cli": ["# Configure via AAA + RADIUS with MFA support"],
        },
        "critical_mfa": {
            "explanation": "MFA is not enabled for critical systems.",
            "steps": ["Enable MFA for all critical system access"],
            "cli": ["# Configure via SSO + MFA for critical applications"],
        },
        "no_plaintext": {
            "explanation": "Plaintext passwords detected in configuration.",
            "steps": [
                "IMMEDIATE: Hash all plaintext passwords",
                "Use bcrypt, Argon2, or scrypt",
            ],
            "cli": [
                "conf t",
                "service password-encryption",
                "end",
            ],
        },
        "hash_algorithm": {
            "explanation": "Weak hash algorithm detected (MD5/SHA1).",
            "steps": [
                "Migrate to bcrypt, Argon2, or scrypt",
                "MD5/SHA1 are cryptographically broken",
            ],
            "cli": ["# Re-hash passwords with secure algorithm"],
        },
        "salting": {
            "explanation": "Unsalted password hashes detected.",
            "steps": ["Use salted hashes (bcrypt/Argon2 auto-salt)"],
            "cli": ["# Use bcrypt or Argon2 for password storage"],
        },
        "no_weak": {
            "explanation": "Weak hash algorithms detected.",
            "steps": [
                "Replace MD5/SHA1 with bcrypt/Argon2",
                "Critical security risk",
            ],
            "cli": ["# Migrate to bcrypt (cost>=10) or Argon2id"],
        },
        "encryption_at_rest": {
            "explanation": "Database encryption at rest is not enabled.",
            "steps": ["Enable TDE or volume encryption"],
            "cli": ["# Enable TDE: alter database set encryption on"],
        },
    },
    "fortinet": {
        "min_length": {
            "explanation": "Password minimum length is below CERT-In requirement.",
            "steps": ["Set minimum password length to at least 8 characters"],
            "cli": [
                "config system password-policy",
                "set min-length 8",
                "end",
            ],
        },
        "uppercase": {
            "explanation": "Password complexity (uppercase) not enforced.",
            "steps": ["Enable uppercase letter requirement"],
            "cli": [
                "config system password-policy",
                "set min-upper-case-letter 1",
                "end",
            ],
        },
        "lowercase": {
            "explanation": "Password complexity (lowercase) not enforced.",
            "steps": ["Enable lowercase letter requirement"],
            "cli": [
                "config system password-policy",
                "set min-lower-case-letter 1",
                "end",
            ],
        },
        "numbers": {
            "explanation": "Password complexity (numbers) not enforced.",
            "steps": ["Enable digit requirement"],
            "cli": [
                "config system password-policy",
                "set min-digit 1",
                "end",
            ],
        },
        "special": {
            "explanation": "Password complexity (special chars) not enforced.",
            "steps": ["Enable special character requirement"],
            "cli": [
                "config system password-policy",
                "set min-special-char 1",
                "end",
            ],
        },
        "expiry": {
            "explanation": "Password expiry not configured or too long.",
            "steps": ["Set password expiry to 90 days or less"],
            "cli": [
                "config system password-policy",
                "set expire 90",
                "end",
            ],
        },
        "history": {
            "explanation": "Password history not configured.",
            "steps": ["Set password history to at least 5"],
            "cli": [
                "config system password-policy",
                "set reuse-history 5",
                "end",
            ],
        },
        "lockout_threshold": {
            "explanation": "Account lockout not configured.",
            "steps": ["Set lockout threshold to 3-5 attempts"],
            "cli": [
                "config system password-policy",
                "set lockout-threshold 5",
                "end",
            ],
        },
        "audit_logging": {
            "explanation": "Login event logging not enabled.",
            "steps": ["Enable logging for login events"],
            "cli": [
                "config log syslogd",
                "set status enable",
                "end",
            ],
        },
        "admin_mfa": {
            "explanation": "MFA not enabled for admin accounts.",
            "steps": ["Enable MFA for admin access"],
            "cli": ["# Configure via FortiAuthenticator or RADIUS with MFA"],
        },
        "remote_mfa": {
            "explanation": "MFA not enabled for remote access.",
            "steps": ["Enable MFA for VPN/SSL access"],
            "cli": ["# Configure SSL VPN with MFA"],
        },
        "no_plaintext": {
            "explanation": "Plaintext passwords detected.",
            "steps": ["Hash all passwords immediately"],
            "cli": [
                "config system admin",
                "edit admin",
                "set password ENC <hashed_password>",
                "end",
            ],
        },
    },
    "juniper": {
        "min_length": {
            "explanation": "Password minimum length below CERT-In requirement.",
            "steps": ["Configure minimum password length in system login"],
            "cli": [
                "set system login password-minimum-length 8",
            ],
        },
        "uppercase": {
            "explanation": "Password complexity not enforced.",
            "steps": ["Enable password complexity rules"],
            "cli": ["set system login password [complexity-rules]"],
        },
        "expiry": {
            "explanation": "Password expiry not configured.",
            "steps": ["Set password aging to 90 days"],
            "cli": ["set system login password aging 90"],
        },
        "history": {
            "explanation": "Password history not configured.",
            "steps": ["Set password history count"],
            "cli": ["set system login password history-count 5"],
        },
        "lockout_threshold": {
            "explanation": "Account lockout not configured.",
            "steps": ["Configure retry options with lockout"],
            "cli": [
                "set system login retry-options tries-before-disconnect 5",
                "set system login retry-options lockout-period 15",
            ],
        },
        "admin_mfa": {
            "explanation": "MFA not enabled for admin accounts.",
            "steps": ["Configure RADIUS/TACACS+ with MFA"],
            "cli": ["set system authentication-order [radius tacplus]"],
        },
        "no_plaintext": {
            "explanation": "Plaintext passwords detected.",
            "steps": ["Use encrypted passwords"],
            "cli": ["set system root-authentication encrypted-password \"$6$...\""],
        },
    },
}


# =============================================================================
# Gemini Remediation
# =============================================================================

def _gemini_remediate(
    check_id: str,
    check_name: str,
    expected_value: str,
    actual_value: str,
    vendor: str,
    device_model: str,
) -> Optional[RemediationSuggestion]:
    """Call Gemini API for remediation suggestion. Returns None on failure."""
    _init_gemini()

    if not _GEMINI_AVAILABLE or _model is None:
        return None

    prompt = f"""You are a network security configuration expert. A CERT-In compliance
check has failed. Generate a remediation suggestion.

Failed Check:
- Check: {check_name} ({check_id})
- Expected: {expected_value}
- Found: {actual_value}
- Vendor: {vendor}
- Device: {device_model}

Generate a remediation with:
1. A clear explanation of what's wrong
2. Step-by-step remediation instructions
3. Device-specific CLI commands (for {vendor})

Respond in JSON format ONLY:
{{
    "explanation": "What's wrong and why it matters",
    "remediation_steps": ["step1", "step2"],
    "cli_commands": ["command1", "command2"],
    "confidence": 0.0_to_1.0
}}

Only return the JSON object, no other text.
IMPORTANT: These are SUGGESTED commands. The admin must review before executing."""

    try:
        response = _model.generate_content(prompt)
        text = response.text.strip()

        # Extract JSON from response
        json_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if json_match:
            text = json_match.group(1)

        data = json.loads(text)

        return RemediationSuggestion(
            check_id=check_id,
            check_name=check_name,
            control_id="",
            sub_control="",
            expected_value=expected_value,
            actual_value=actual_value,
            vendor=vendor,
            device_model=device_model,
            explanation=data.get("explanation", ""),
            remediation_steps=data.get("remediation_steps", []),
            cli_commands=data.get("cli_commands", []),
            confidence=float(data.get("confidence", 0.6)),
            source="gemini",
        )
    except Exception as e:
        print(f"  ⚠️  Gemini remediation error: {e}")
        return None


# =============================================================================
# Heuristic Remediation
# =============================================================================

def _heuristic_remediate(
    check_id: str,
    check_name: str,
    expected_value: str,
    actual_value: str,
    vendor: str,
    device_model: str,
) -> RemediationSuggestion:
    """Deterministic heuristic remediation when Gemini is unavailable."""
    vendor_lower = vendor.lower()
    template = _REMEDIATION_TEMPLATES.get(vendor_lower, {}).get(check_id, {})

    if not template:
        # Generic fallback
        return RemediationSuggestion(
            check_id=check_id,
            check_name=check_name,
            control_id="",
            sub_control="",
            expected_value=expected_value,
            actual_value=actual_value,
            vendor=vendor,
            device_model=device_model,
            explanation=f"Check '{check_name}' failed. Expected: {expected_value}, Found: {actual_value}",
            remediation_steps=[f"Configure {check_name} to meet CERT-In requirement: {expected_value}"],
            cli_commands=[],
            confidence=0.3,
            source="heuristic",
        )

    return RemediationSuggestion(
        check_id=check_id,
        check_name=check_name,
        control_id="",
        sub_control="",
        expected_value=expected_value,
        actual_value=actual_value,
        vendor=vendor,
        device_model=device_model,
        explanation=template["explanation"],
        remediation_steps=template["steps"],
        cli_commands=template["cli"],
        confidence=0.7,
        source="heuristic",
    )


# =============================================================================
# Public API
# =============================================================================

def suggest_remediation(
    check_id: str,
    check_name: str,
    expected_value: str,
    actual_value: str,
    vendor: str = "unknown",
    device_model: str = "Unknown",
    control_id: str = "",
    sub_control: str = "",
) -> RemediationSuggestion:
    """
    Generate a remediation suggestion for a CERT-In failed check.

    Flow:
    1. Try Gemini API (if available)
    2. Fall back to deterministic heuristic templates

    IMPORTANT: This function NEVER:
    - Decides CERT-In PASS/FAIL
    - Automatically executes commands
    - Sends secrets to external services

    Args:
        check_id: Failed check ID (e.g., "min_length")
        check_name: Human-readable check name
        expected_value: What CERT-In requires
        actual_value: What was found
        vendor: Device vendor (cisco, fortinet, juniper)
        device_model: Device model
        control_id: CERT-In control ID (e.g., "RPP")
        sub_control: Sub-control ID (e.g., "RPP.1")

    Returns:
        RemediationSuggestion with explanation, steps, and CLI commands

    Example::

        from msme_auditor.config_parsers.ai_remediation import suggest_remediation

        suggestion = suggest_remediation(
            check_id="min_length",
            check_name="Minimum Password Length",
            expected_value="At least 8 characters",
            actual_value="6 characters",
            vendor="cisco",
        )
        print(suggestion.label)  # "AI-Suggested Remediation"
        print(suggestion.cli_commands)  # ["conf t", "security passwords min-length 8", "end"]
    """
    # Try Gemini first
    gemini_result = _gemini_remediate(
        check_id=check_id,
        check_name=check_name,
        expected_value=expected_value,
        actual_value=actual_value,
        vendor=vendor,
        device_model=device_model,
    )

    if gemini_result is not None:
        gemini_result.control_id = control_id
        gemini_result.sub_control = sub_control
        return gemini_result

    # Fall back to heuristic
    result = _heuristic_remediate(
        check_id=check_id,
        check_name=check_name,
        expected_value=expected_value,
        actual_value=actual_value,
        vendor=vendor,
        device_model=device_model,
    )
    result.control_id = control_id
    result.sub_control = sub_control
    return result


def suggest_remediation_for_findings(
    findings: List[Dict[str, Any]],
    vendor: str = "unknown",
    device_model: str = "Unknown",
) -> List[RemediationSuggestion]:
    """
    Generate remediation suggestions for multiple CERT-In findings.

    Args:
        findings: List of failed check dicts with check_id, check_name, etc.
        vendor: Device vendor
        device_model: Device model

    Returns:
        List of RemediationSuggestion objects
    """
    suggestions = []
    for finding in findings:
        suggestion = suggest_remediation(
            check_id=finding.get("check_id", "unknown"),
            check_name=finding.get("check_name", "Unknown Check"),
            expected_value=finding.get("expected_value", ""),
            actual_value=finding.get("actual_value", ""),
            vendor=vendor,
            device_model=device_model,
            control_id=finding.get("control_id", ""),
            sub_control=finding.get("sub_control", ""),
        )
        suggestions.append(suggestion)
    return suggestions
