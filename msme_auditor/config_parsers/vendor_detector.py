"""
Deterministic Vendor Detection
===============================

Detects network device vendor from configuration text using
pattern matching on banners, command syntax, and keywords.

NO AI/LLM used — purely deterministic regex/string matching.
"""

import re
from typing import List, Tuple
from dataclasses import dataclass, field

from msme_auditor.config_parsers.base import VendorDetectionResult


# =============================================================================
# Detection Patterns (Vendor -> List of (pattern, weight, description))
# =============================================================================

VENDOR_PATTERNS = {
    "cisco": [
        # Banner patterns (high confidence)
        (r"^!.*Cisco\s+IOS", 0.95, "Cisco IOS banner"),
        (r"^!.*Cisco\s+NX-OS", 0.95, "Cisco NX-OS banner"),
        (r"^!.*Cisco\s+IOS\s+XE", 0.95, "Cisco IOS-XE banner"),
        (r"^!.*Cisco\s+ASA", 0.95, "Cisco ASA banner"),
        (r"^!.*Cisco\s+IOS\s+XR", 0.95, "Cisco IOS-XR banner"),
        (r"^version\s+\d+\.\d+", 0.80, "Cisco version command"),
        (r"^service\s+timestamps", 0.75, "Cisco service timestamps"),
        (r"^hostname\s+\S+", 0.70, "Cisco hostname"),
        (r"^enable\s+secret", 0.85, "Cisco enable secret"),
        (r"^enable\s+password", 0.80, "Cisco enable password"),
        (r"^aaa\s+new-model", 0.90, "Cisco AAA new-model"),
        (r"^ip\s+domain-name", 0.75, "Cisco ip domain-name"),
        (r"^crypto\s+key\s+generate\s+rsa", 0.90, "Cisco crypto key"),
        (r"^line\s+(console|vty|aux)\s+\d+", 0.85, "Cisco line config"),
        (r"^interface\s+(GigabitEthernet|FastEthernet|Ethernet|Serial|Loopback|Vlan)", 0.85, "Cisco interface"),
        (r"^ip\s+access-list\s+(standard|extended)", 0.80, "Cisco ACL"),
        (r"^access-list\s+\d+", 0.75, "Cisco numbered ACL"),
        (r"^logging\s+(host|trap|buffered|console)", 0.80, "Cisco logging"),
        (r"^snmp-server\s+(community|host|contact|location)", 0.80, "Cisco SNMP"),
        (r"^ntp\s+(server|peer|source)", 0.75, "Cisco NTP"),
        (r"^cdp\s+(run|enable|timer)", 0.70, "Cisco CDP"),
        (r"^spanning-tree\s+(mode|vlan|portfast)", 0.70, "Cisco spanning-tree"),
        (r"^vlan\s+\d+", 0.60, "Cisco VLAN"),
        (r"^switchport\s+(mode|access|trunk)", 0.75, "Cisco switchport"),
        (r"^service\s+password-encryption", 0.85, "Cisco password encryption"),
        (r"^username\s+\S+\s+privilege\s+\d+", 0.85, "Cisco username privilege"),
        (r"^ip\s+ssh\s+(version|timeout|authentication)", 0.85, "Cisco SSH config"),
        (r"^exec-timeout\s+\d+\s+\d+", 0.75, "Cisco exec-timeout"),
        (r"^password\s+\d+\s+\S+", 0.60, "Cisco password line"),
    ],
    "fortinet": [
        (r"^#config-version=", 0.95, "FortiOS config version header"),
        (r"^#conf_file_ver=", 0.95, "FortiOS config file version"),
        (r"^config\s+system\s+global", 0.90, "FortiOS system global"),
        (r"^config\s+system\s+interface", 0.90, "FortiOS interface"),
        (r"^config\s+firewall\s+(policy|address|service)", 0.90, "FortiOS firewall"),
        (r"^config\s+vpn\s+(ssl|ipsec)", 0.85, "FortiOS VPN"),
        (r"^config\s+system\s+(admin|dns|ntp|snmp)", 0.85, "FortiOS system config"),
        (r"^config\s+router\s+(static|bgp|ospf)", 0.80, "FortiOS router"),
        (r"^config\s+log\s+(syslogd|fortianalyzer|memory)", 0.85, "FortiOS logging"),
        (r"^config\s+user\s+(local|radius|ldap|tacacs)", 0.85, "FortiOS user"),
        (r"^set\s+(admin-port|admin-sport|ssh-port|http-port|https-port)", 0.75, "FortiOS set port"),
        (r"^set\s+(hostname|timezone|fgfm-port)", 0.75, "FortiOS set hostname"),
        (r"^set\s+strong-crypto\s+(enable|disable)", 0.80, "FortiOS strong-crypto"),
        (r"^set\s+gui-(lines|theme|date-format)", 0.60, "FortiOS GUI settings"),
        (r"^end\s*$", 0.60, "FortiOS end (common but weak alone)"),
    ],
    "juniper": [
        (r"^##\s+Last\s+commit:", 0.95, "Junos commit header"),
        (r"^version\s+\d+\.\d+R?\d*\.\d+;", 0.90, "Junos version"),
        (r"^system\s+\{", 0.85, "Junos system block"),
        (r"^interfaces\s+\{", 0.85, "Junos interfaces block"),
        (r"^security\s+\{", 0.85, "Junos security block"),
        (r"^routing-options\s+\{", 0.80, "Junos routing-options"),
        (r"^protocols\s+\{", 0.80, "Junos protocols"),
        (r"^policy-options\s+\{", 0.80, "Junos policy-options"),
        (r"^firewall\s+\{", 0.85, "Junos firewall"),
        (r"^set\s+system\s+(host-name|domain-name|time-zone|root-authentication)", 0.90, "Junos set system"),
        (r"^set\s+interfaces\s+\S+\s+unit\s+\d+", 0.85, "Junos set interface unit"),
        (r"^set\s+security\s+(zones|policies|nat|screen)", 0.85, "Junos set security"),
        (r"^set\s+system\s+services\s+(ssh|telnet|web-management|snmp|ntp|syslog)", 0.85, "Junos set services"),
        (r"^set\s+system\s+login\s+(user|class|message|password)", 0.85, "Junos set login"),
        (r"^delete\s+", 0.60, "Junos delete (common but weak)"),
        (r"^\s+\w+\s+\{", 0.50, "Junos brace style (weak alone)"),
    ],
    "arista": [
        (r"^!.*Arista\s+Networks", 0.95, "Arista banner"),
        (r"^!.*EOS\s+version", 0.95, "Arista EOS version"),
        (r"^hostname\s+\S+", 0.60, "Arista hostname"),
        (r"^ip\s+routing", 0.60, "Arista ip routing"),
        (r"^management\s+(api|ssh|console)", 0.75, "Arista management"),
        (r"^daemon\s+TerminAttr", 0.85, "Arista TerminAttr"),
    ],
    "paloalto": [
        (r"^<\?xml\s+version", 0.90, "PAN-OS XML config"),
        (r"<device>", 0.85, "PAN-OS device element"),
        (r"<network>", 0.85, "PAN-OS network element"),
        (r"<vsys>", 0.80, "PAN-OS vsys"),
        (r"<rulebase>", 0.80, "PAN-OS rulebase"),
    ],
    "hp": [
        (r"^!.*HP\s+ProCurve", 0.95, "HP ProCurve banner"),
        (r"^!.*HPE\s+FlexNetwork", 0.95, "HPE FlexNetwork banner"),
        (r"^!.*ArubaOS", 0.95, "ArubaOS banner"),
        (r"^vlan\s+\d+", 0.55, "HP/Aruba vlan (weak)"),
        (r"^interface\s+\d+", 0.55, "HP/Aruba interface (weak)"),
    ],
}


# =============================================================================
# Detection Logic
# =============================================================================

def detect_vendor(config_text: str) -> VendorDetectionResult:
    """
    Detect vendor from configuration text using deterministic pattern matching.

    Returns:
        VendorDetectionResult with vendor name, confidence, method, and evidence
    """
    lines = config_text.splitlines()
    non_empty_lines = [l for l in lines if l.strip()]

    if not non_empty_lines:
        return VendorDetectionResult(
            vendor="unknown",
            confidence=0.0,
            detection_method="empty_config",
            evidence=[],
        )

    scores = {vendor: 0.0 for vendor in VENDOR_PATTERNS}
    evidence_map = {vendor: [] for vendor in VENDOR_PATTERNS}

    # Check each line against all patterns
    for i, line in enumerate(non_empty_lines):
        stripped = line.strip()
        for vendor, patterns in VENDOR_PATTERNS.items():
            for pattern, weight, desc in patterns:
                if re.search(pattern, stripped, re.IGNORECASE):
                    scores[vendor] += weight
                    evidence_map[vendor].append(f"Line {i+1}: {desc} ('{stripped[:80]}')")

    # Find vendor with highest score
    best_vendor = max(scores, key=scores.get)
    best_score = scores[best_vendor]

    # Normalize confidence against the best vendor's max possible score
    vendor_max_possible = sum(w for _, w, _ in VENDOR_PATTERNS.get(best_vendor, []))
    confidence = min(best_score / vendor_max_possible, 1.0) if vendor_max_possible > 0 else 0.0

    # Boost confidence if multiple strong patterns matched
    strong_matches = sum(1 for _, w, _ in VENDOR_PATTERNS.get(best_vendor, []) if w > 0.8 and any(e for e in evidence_map[best_vendor]))
    if strong_matches >= 2:
        confidence = min(confidence + 0.15, 1.0)

    # If confidence is too low, return unknown
    if confidence < 0.35 or best_score < 1.5:
        return VendorDetectionResult(
            vendor="unknown",
            confidence=confidence,
            detection_method="pattern_matching",
            evidence=[f"No strong vendor match (best: {best_vendor}={best_score:.2f})"],
        )

    return VendorDetectionResult(
        vendor=best_vendor,
        confidence=round(confidence, 2),
        detection_method="pattern_matching",
        evidence=evidence_map[best_vendor][:10],  # Limit evidence
    )


def quick_vendor_check(config_text: str) -> str:
    """
    Quick vendor check for simple cases (first few lines only).
    Returns vendor name or "unknown".
    """
    first_lines = "\n".join(config_text.splitlines()[:20])
    result = detect_vendor(first_lines)
    return result.vendor if not result.is_unknown else "unknown"