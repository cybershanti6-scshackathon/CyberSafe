"""
Target Validation
=================
Validates and normalizes scan targets (IPs, URLs, domains).
Rejects malformed input with clear error messages.
"""

import re
from typing import Tuple
from urllib.parse import urlparse


# IPv4 pattern (loose but practical)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv6 pattern (simplified — covers common forms)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

# Domain pattern
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

# Private/reserved IP ranges
_PRIVATE_RANGES = [
    (0, 0xFFFFFFFF),           # 0.0.0.0/8
    (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
    (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8
    (0xA9FE0000, 0xA9FEFFFF),  # 169.254.0.0/16
    (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
]


def _ip_to_int(ip: str) -> int:
    """Convert dotted-quad IPv4 to integer."""
    parts = ip.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def _is_private_ip(ip: str) -> bool:
    """Check if an IPv4 address is in a private/reserved range."""
    try:
        ip_int = _ip_to_int(ip)
        return any(lo <= ip_int <= hi for lo, hi in _PRIVATE_RANGES)
    except (ValueError, IndexError):
        return False


def validate_target(raw: str) -> Tuple[str, str, str]:
    """
    Validate and normalize a scan target.

    Args:
        raw: Raw target string (IP, URL, or domain).

    Returns:
        Tuple of (normalized_target, target_type, error_message).
        If valid, error_message is empty.
        If invalid, normalized_target and target_type are empty.

    Examples:
        >>> validate_target("93.184.216.34")
        ('93.184.216.34', 'ip', '')
        >>> validate_target("https://example.com")
        ('https://example.com', 'url', '')
        >>> validate_target("example.com")
        ('example.com', 'domain', '')
        >>> validate_target("not a target")
        ('', '', 'Invalid target: not a valid IP, domain, or URL')
    """
    if not raw or not raw.strip():
        return ("", "", "Target is required. Provide a valid IP, domain, or URL.")

    target = raw.strip()

    # Try parsing as URL first
    if target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            if not parsed.hostname:
                return ("", "", "Invalid URL: no hostname found")
            hostname = parsed.hostname
            # Validate the hostname portion
            if _IPV4_RE.match(hostname):
                return (target, "url", "")
            if _DOMAIN_RE.match(hostname):
                return (target, "url", "")
            return ("", "", f"Invalid URL hostname: '{hostname}' is not a valid IP or domain")
        except Exception as e:
            return ("", "", f"Invalid URL: {e}")

    # Try as IPv4
    if _IPV4_RE.match(target):
        return (target, "ip", "")

    # Try as IPv6 (simplified validation)
    if ":" in target and _IPV6_RE.match(target):
        return (target, "ip", "")

    # Try as domain
    if _DOMAIN_RE.match(target):
        return (target, "domain", "")

    # Check for common mistakes
    if re.match(r"^\d+\.\d+\.\d+$", target):
        return ("", "", f"Invalid IP address: '{target}' (must be 4 octets, e.g. 192.168.1.1)")
    if " " in target:
        return ("", "", "Invalid target: contains spaces")
    if target.startswith("-"):
        return ("", "", "Invalid target: cannot start with a dash")

    return ("", "", f"Invalid target: '{target}' is not a valid IP, domain, or URL")


def is_localhost(target: str) -> bool:
    """Check if target resolves to localhost/loopback."""
    localhost_names = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    if target in localhost_names:
        return True
    # Strip URL scheme
    cleaned = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    return cleaned in localhost_names
