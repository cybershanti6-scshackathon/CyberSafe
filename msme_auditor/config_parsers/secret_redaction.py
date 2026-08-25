"""
Secret Redaction Module
========================

Detects and redacts sensitive information from configuration text
before sending to external AI models (Gemini, etc.).

Detects and redacts:
- Passwords (Cisco enable secret, Fortinet set password, etc.)
- API keys and tokens
- Private keys (RSA, DSA, ECDSA)
- SNMP community strings
- Encrypted passwords (MD5, bcrypt, etc.)
- Credentials in any format

NEVER send secrets to external services. This module is the gatekeeper.
"""

import re
from typing import List, Tuple, Optional


# =============================================================================
# Redaction Patterns
# =============================================================================

# Each pattern is (compiled_regex, replacement_template, description)
# Order matters — more specific patterns should come first

REDACTION_PATTERNS: List[Tuple[re.Pattern, str, str]] = [
    # --- Private Keys ---
    (
        re.compile(r"(-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----.*?-----END\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----)", re.DOTALL | re.IGNORECASE),
        "[REDACTED_PRIVATE_KEY]",
        "Private key (RSA/DSA/EC/SSH)",
    ),

    # --- Cisco-specific ---
    # enable secret with hash
    (
        re.compile(r"(enable\s+secret\s+)(?:\d+\s+)?(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_SECRET]",
        "Cisco enable secret",
    ),
    # enable password
    (
        re.compile(r"(enable\s+password\s+)(?:\d+\s+)?(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_PASSWORD]",
        "Cisco enable password",
    ),
    # username with secret/password
    (
        re.compile(r"(username\s+\S+\s+(?:secret|password)\s+)(?:\d+\s+)?(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_PASSWORD]",
        "Cisco username password/secret",
    ),
    # password on line (line vty context)
    (
        re.compile(r"(^password\s+)(?:\d+\s+)?(\S+)", re.MULTILINE | re.IGNORECASE),
        r"\g<1>[REDACTED_PASSWORD]",
        "Cisco line password",
    ),

    # --- Fortinet-specific ---
    # set password ENC
    (
        re.compile(r"(set\s+password\s+ENC\s+)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_FORTINET_ENC]",
        "Fortinet encrypted password",
    ),
    # set password (plain)
    (
        re.compile(r"(set\s+password\s+)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_PASSWORD]",
        "Fortinet set password",
    ),
    # set encpassword
    (
        re.compile(r"(set\s+encpassword\s+)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_PASSWORD]",
        "Fortinet encpassword",
    ),

    # --- Juniper-specific ---
    # encrypted-password in quotes
    (
        re.compile(r'(encrypted-password\s+")(.*?)"', re.IGNORECASE),
        r'encrypted-password "[REDACTED_JUNIPER_HASH]"',
        "Juniper encrypted-password",
    ),
    # plain-text-password block
    (
        re.compile(r"(plain-text-password\s*\{[^}]*?)(plain-text-password|})", re.DOTALL | re.IGNORECASE),
        r"[REDACTED_PLAIN_TEXT_PASSWORD_BLOCK]",
        "Juniper plain-text-password block",
    ),
    # ssh-rsa key in quotes
    (
        re.compile(r'(ssh-(?:rsa|dsa|ecdsa)\s+")(.*?)"', re.IGNORECASE),
        r'ssh-rsa "[REDACTED_SSH_KEY]"',
        "Juniper SSH public key",
    ),

    # --- Generic patterns ---
    # SNMP community strings (common defaults)
    (
        re.compile(r"(snmp-server\s+community\s+|set\s+community\s+)(public|private|cisco|admin|community)", re.IGNORECASE),
        r"\g<1>[REDACTED_SNMP_COMMUNITY]",
        "Default SNMP community string",
    ),
    # Any "password" or "passwd" keyword followed by a value
    (
        re.compile(r"((?:password|passwd|pass|pwd)\s*[=:]\s*)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_PASSWORD]",
        "Generic password assignment",
    ),
    # API key / token patterns
    (
        re.compile(r"((?:api[_-]?key|apikey|token|secret[_-]?key|access[_-]?key)\s*[=:]\s*)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_API_KEY]",
        "API key or token",
    ),
    # Authorization / Bearer tokens
    (
        re.compile(r"((?:Authorization|Bearer)\s*[=:]\s*)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_TOKEN]",
        "Authorization/Bearer token",
    ),
    # Generic credential patterns
    (
        re.compile(r"((?:credential|cred|auth[_-]?token)\s*[=:]\s*)(\S+)", re.IGNORECASE),
        r"\g<1>[REDACTED_CREDENTIAL]",
        "Generic credential",
    ),
]


# =============================================================================
# Public API
# =============================================================================

class RedactionResult:
    """Result of redacting a configuration text."""

    def __init__(
        self,
        redacted_text: str,
        original_text: str,
        redactions: List[dict],
    ):
        self.redacted_text = redacted_text
        self.original_text = original_text
        self.redactions = redactions

    @property
    def redaction_count(self) -> int:
        return len(self.redactions)

    @property
    def has_redactions(self) -> bool:
        return self.redaction_count > 0

    def to_dict(self) -> dict:
        return {
            "redacted_text": self.redacted_text,
            "redaction_count": self.redaction_count,
            "has_redactions": self.has_redactions,
            "redactions": self.redactions,
        }


def redact_secrets(text: str) -> RedactionResult:
    """
    Detect and redact all sensitive information from configuration text.

    This is the PRIMARY entry point. Call this before sending ANY
    configuration text to an external AI model.

    Args:
        text: Raw configuration text (may contain secrets)

    Returns:
        RedactionResult with redacted text and list of what was redacted

    Example::

        from msme_auditor.config_parsers.secret_redaction import redact_secrets

        result = redact_secrets("enable secret 5 $1$mERr$hash")
        print(result.redacted_text)
        # "enable secret 5 [REDACTED_SECRET]"
        print(result.redaction_count)
        # 1
    """
    redacted = text
    redactions = []

    for pattern, replacement, description in REDACTION_PATTERNS:
        matches = list(pattern.finditer(redacted))
        if matches:
            for match in matches:
                # Record what we're redacting
                original_segment = match.group(0)
                redacted_segment = pattern.sub(replacement, original_segment)

                # Don't record if nothing actually changed
                if original_segment != redacted_segment:
                    redactions.append({
                        "original": original_segment,
                        "redacted": redacted_segment,
                        "description": description,
                        "position": match.start(),
                    })

            # Apply all replacements for this pattern
            redacted = pattern.sub(replacement, redacted)

    return RedactionResult(
        redacted_text=redacted,
        original_text=text,
        redactions=redactions,
    )


def is_safe_for_ai(text: str) -> bool:
    """
    Quick check: does this text contain potential secrets?

    Returns True if no secrets detected, False if redaction is needed.
    Use this as a gatekeeper before sending to AI.

    Args:
        text: Configuration text to check

    Returns:
        True if safe (no secrets), False if needs redaction
    """
    result = redact_secrets(text)
    return not result.has_redactions


def redact_config_for_ai(
    config_text: str,
    vendor: str = "unknown",
) -> str:
    """
    High-level function: redact a vendor config and return safe text.

    This is what you call before sending to Gemini or any external AI.

    Args:
        config_text: Raw vendor configuration
        vendor: Vendor name (for logging)

    Returns:
        Redacted configuration text safe for external AI
    """
    result = redact_secrets(config_text)

    if result.has_redactions:
        print(f"  🔒 Secret redaction: {result.redaction_count} secret(s) redacted for {vendor}")
        for r in result.redactions:
            print(f"     - {r['description']}: {r['original'][:40]}... → {r['redacted']}")

    return result.redacted_text
