"""
NES.3 — VPN / Remote Access Security
=====================================
Check for VPN portals on common ports (443, 8443, 1194, 51820).
Flags for MFA verification.

No raw socket code — delegates to :mod:`msme_auditor.utils.network`.
"""

from typing import List

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import resolve_host, scan_ports

# Ports commonly used by VPN services.
_VPN_PORTS = [443, 8443, 1194, 51820]


class NES3Scanner(BaseScanner):
    """VPN and remote-access security scanner."""

    scanner_id: str = "nes3"
    name: str = "NES.3 — VPN / Remote Access"
    description: str = (
        "Check for VPN portals on ports 443/8443. "
        "Flags for MFA verification."
    )
    category: str = "NES"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {
            "name": "target",
            "label": "Target Domain or IP",
            "field_type": "text",
            "required": True,
            "placeholder": "example.com or 93.184.216.34",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Probe VPN ports and check for MFA / encryption."""
        target = sc.config.get("target", sc.target or "")
        if not target:
            return [
                make_check(
                    "no_target", "Target Required", False,
                    "A valid domain or IP", "Not provided",
                    SeverityLevel.CRITICAL,
                )
            ]

        ip = resolve_host(target)
        open_vpn_ports = scan_ports(ip, ports=_VPN_PORTS, timeout=3)
        vpn_detected = len(open_vpn_ports) > 0

        return [
            make_check(
                "vpn_detected", "VPN Service Detected", vpn_detected,
                "VPN portal accessible",
                f"Detected on ports {', '.join(str(p) for p in sorted(open_vpn_ports))}"
                if vpn_detected
                else "Not detected",
                SeverityLevel.INFO,
                (
                    "If VPN is used, ensure it uses strong encryption "
                    "(WireGuard / OpenVPN)"
                ),
            ),
            bool_check(
                "mfa", "VPN MFA Enabled",
                sc.config.get("vpn_mfa_enabled", False),
                "MFA enabled on VPN",
                SeverityLevel.CRITICAL,
                (
                    "Enable MFA on VPN concentrator\n"
                    "Options: TOTP, Hardware Key, Certificate-based"
                ),
            ),
            bool_check(
                "encryption", "VPN Encryption Enabled",
                sc.config.get("vpn_encryption_enabled", True),
                "Strong encryption (AES-256)",
                SeverityLevel.HIGH,
                (
                    "Use WireGuard or OpenVPN with AES-256\n"
                    "Avoid PPTP (broken), L2TP without IPsec"
                ),
            ),
        ]
