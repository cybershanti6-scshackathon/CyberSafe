"""
Gemini AI Advisor for Unknown Configuration Syntax
====================================================

Uses Google Gemini to suggest security parameters for unknown
configuration commands. Applied ONLY to unknown syntax — never
to compliance decisions.

Flow:
    Unknown Command
        ↓
    Secret Redaction (always)
        ↓
    Gemini API (if available)
        ↓
    Suggested Security Parameter
        ↓
    Confidence Score
        ↓
    Admin Approval (human-in-the-loop)
        ↓
    Knowledge Base

CRITICAL RULES:
- Gemini MUST NOT decide CERT-In PASS/FAIL
- Gemini MUST NOT directly modify compliance results
- Gemini MUST NOT execute commands
- If Gemini is unavailable, deterministic scanning still works
- Secrets are ALWAYS redacted before any external call
"""

import json
import os
import re
from typing import Any, Dict, Optional

from msme_auditor.config_parsers.secret_redaction import (
    redact_secrets,
    is_safe_for_ai,
)


# =============================================================================
# Configuration
# =============================================================================

_GEMINI_AVAILABLE = False
_genai = None
_model = None


def _init_gemini():
    """Lazy-initialize Gemini API client."""
    global _GEMINI_AVAILABLE, _genai, _model

    if _GEMINI_AVAILABLE:
        return

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print("  ⚠️  GEMINI_API_KEY not set — AI suggestions will use deterministic fallback")
        return

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        _model = genai.GenerativeModel("gemini-pro")
        _genai = genai
        _GEMINI_AVAILABLE = True
        print("  ✅ Gemini AI advisor initialized")
    except ImportError:
        print("  ⚠️  google-generativeai not installed — using fallback")
    except Exception as e:
        print(f"  ⚠️  Gemini init failed: {e} — using fallback")


# =============================================================================
# Suggestion Result
# =============================================================================

class AISuggestion:
    """Result of an AI suggestion for an unknown command."""

    def __init__(
        self,
        raw_command: str,
        parameter: Optional[str] = None,
        value: Any = None,
        value_type: str = "string",
        unit: str = "",
        confidence: float = 0.0,
        explanation: str = "",
        source: str = "unknown",
        redacted_for_ai: bool = False,
    ):
        self.raw_command = raw_command
        self.parameter = parameter
        self.value = value
        self.value_type = value_type
        self.unit = unit
        self.confidence = confidence
        self.explanation = explanation
        self.source = source  # "gemini", "heuristic", "fallback"
        self.redacted_for_ai = redacted_for_ai

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_command": self.raw_command,
            "parameter": self.parameter,
            "value": self.value,
            "value_type": self.value_type,
            "unit": self.unit,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "source": self.source,
            "redacted_for_ai": self.redacted_for_ai,
        }


# =============================================================================
# Gemini Suggestion
# =============================================================================

def _gemini_suggest(
    redacted_command: str,
    vendor: str,
    category: Optional[str] = None,
) -> Optional[AISuggestion]:
    """Call Gemini API for a suggestion. Returns None on failure."""
    _init_gemini()

    if not _GEMINI_AVAILABLE or _model is None:
        return None

    prompt = f"""You are a network security configuration expert. Analyze this unknown
configuration command and suggest what security parameter it maps to.

Vendor: {vendor}
Command: {redacted_command}
Possible category: {category or 'unknown'}

Respond in JSON format ONLY:
{{
    "parameter": "normalized_parameter_name",
    "value": "extracted_value_if_any",
    "value_type": "int|float|bool|string",
    "unit": "seconds|characters|days|null",
    "confidence": 0.0_to_1.0,
    "explanation": "brief_explanation"
}}

Only return the JSON object, no other text."""

    try:
        response = _model.generate_content(prompt)
        text = response.text.strip()

        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if json_match:
            text = json_match.group(1)

        data = json.loads(text)

        return AISuggestion(
            raw_command=redacted_command,
            parameter=data.get("parameter"),
            value=data.get("value"),
            value_type=data.get("value_type", "string"),
            unit=data.get("unit", ""),
            confidence=float(data.get("confidence", 0.5)),
            explanation=data.get("explanation", ""),
            source="gemini",
            redacted_for_ai=True,
        )
    except Exception as e:
        print(f"  ⚠️  Gemini API error: {e}")
        return None


# =============================================================================
# Heuristic Fallback
# =============================================================================

# Category → heuristic suggestion mapping
_HEURISTIC_MAP = {
    "session_timeout": {
        "parameter": "session_timeout",
        "value_type": "int",
        "unit": "seconds",
        "confidence": 0.6,
        "explanation": "Command appears to set a session timeout value.",
    },
    "authentication": {
        "parameter": "password_min_length",
        "value_type": "int",
        "unit": "characters",
        "confidence": 0.4,
        "explanation": "Command appears related to authentication/password policy.",
    },
    "network_encryption": {
        "parameter": "ssh_enabled",
        "value_type": "bool",
        "unit": "",
        "confidence": 0.4,
        "explanation": "Command appears related to network encryption settings.",
    },
    "logging": {
        "parameter": "logging_enabled",
        "value_type": "bool",
        "unit": "",
        "confidence": 0.5,
        "explanation": "Command appears related to logging configuration.",
    },
    "firewall": {
        "parameter": "firewall_enabled",
        "value_type": "bool",
        "unit": "",
        "confidence": 0.4,
        "explanation": "Command appears related to firewall configuration.",
    },
    "snmp": {
        "parameter": "snmp_enabled",
        "value_type": "bool",
        "unit": "",
        "confidence": 0.4,
        "explanation": "Command appears related to SNMP configuration.",
    },
    "ntp": {
        "parameter": "ntp_configured",
        "value_type": "bool",
        "unit": "",
        "confidence": 0.5,
        "explanation": "Command appears related to NTP configuration.",
    },
}


def _heuristic_suggest(
    command: str,
    vendor: str,
    category: Optional[str] = None,
) -> AISuggestion:
    """Deterministic heuristic suggestion when Gemini is unavailable."""
    # Try to extract a numeric value from the command
    value_match = re.search(r"\b(\d+)\b", command)
    extracted_value = int(value_match.group(1)) if value_match else None

    base = _HEURISTIC_MAP.get(category, {
        "parameter": "unknown",
        "value_type": "string",
        "unit": "",
        "confidence": 0.2,
        "explanation": "Unable to determine parameter from command syntax.",
    })

    return AISuggestion(
        raw_command=command,
        parameter=base["parameter"],
        value=extracted_value,
        value_type=base["value_type"],
        unit=base["unit"],
        confidence=base["confidence"],
        explanation=base["explanation"],
        source="heuristic",
        redacted_for_ai=False,
    )


# =============================================================================
# Public API
# =============================================================================

def suggest_parameter(
    command: str,
    vendor: str = "unknown",
    category: Optional[str] = None,
) -> AISuggestion:
    """
    Get a suggested security parameter for an unknown configuration command.

    Flow:
    1. Check if command contains secrets → redact if needed
    2. Try Gemini API (if available)
    3. Fall back to deterministic heuristic if Gemini unavailable

    IMPORTANT: This function NEVER:
    - Decides CERT-In PASS/FAIL
    - Modifies compliance results
    - Executes commands

    Args:
        command: The unknown configuration command
        vendor: Detected vendor name
        category: Possible category (from UnknownConfiguration)

    Returns:
        AISuggestion with parameter, value, confidence, explanation

    Example::

        from msme_auditor.config_parsers.gemini_advisor import suggest_parameter

        suggestion = suggest_parameter("set system-timeout 300", vendor="juniper")
        print(suggestion.parameter)  # "session_timeout"
        print(suggestion.confidence)  # 0.6 (heuristic) or 0.9 (Gemini)
    """
    # Step 1: Check for secrets
    redacted_for_ai = False
    redacted_command = command

    if not is_safe_for_ai(command):
        redaction_result = redact_secrets(command)
        redacted_command = redaction_result.redacted_text
        redacted_for_ai = True
        print(f"  🔒 Secrets detected in command — redacted for AI")

    # Step 2: Try Gemini
    gemini_result = _gemini_suggest(redacted_command, vendor, category)
    if gemini_result is not None:
        gemini_result.raw_command = command  # Restore original for display
        gemini_result.redacted_for_ai = redacted_for_ai
        return gemini_result

    # Step 3: Heuristic fallback
    return _heuristic_suggest(command, vendor, category)


def is_gemini_available() -> bool:
    """Check if Gemini API is configured and available."""
    _init_gemini()
    return _GEMINI_AVAILABLE
