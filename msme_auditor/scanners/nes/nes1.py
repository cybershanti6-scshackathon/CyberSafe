"""
NES.1 — Firewall & Open Port Assessment
========================================
TCP-connect scan on sensitive ports (22, 3389, 3306, 5432 …).
Open ports on an internet-facing host = security risk.

No raw socket code here — delegates to :mod:`msme_auditor.utils.network`.
"""

from typing import List

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import resolve_host, scan_ports, SENSITIVE_PORTS


class NES1Scanner(BaseScanner):
    """Firewall and open-port assessment scanner."""

    scanner_id: str = "nes1"
    name: str = "NES.1 — Firewall & Open Ports"
    description: str = "TCP port scan on sensitive ports. Open ports = security risk."
    category: str = "NES"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {
            "name": "target",
            "label": "Target Domain or IP",
            "field_type": "text",
            "required": True,
            "placeholder": "example.com or 93.184.216.34",
            "help_text": "Domain name or IP address to scan",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Run the port scan and return security checks."""
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
        open_ports = scan_ports(ip)

        return [
            make_check(
                "perimeter_firewall", "Perimeter Firewall Deployed",
                len(open_ports) == 0,
                "All sensitive ports closed/filtered",
                (
                    f"{len(open_ports)} open: "
                    f"{', '.join(str(p) for p in sorted(open_ports)[:5])}"
                )
                if open_ports
                else "All closed",
                SeverityLevel.CRITICAL if open_ports else SeverityLevel.INFO,
                (
                    "Deploy firewall with default-deny policy\n"
                    "Close all unnecessary ports\n"
                    "Windows: netsh advfirewall set allprofiles state on\n"
                    "Linux: ufw enable && ufw default deny incoming"
                ),
            ),
            bool_check(
                "ssh_open", "SSH Port (22) Closed",
                22 not in open_ports,
                "Port 22 closed or filtered",
                SeverityLevel.HIGH,
                "Disable SSH if not needed.\nIf needed: change default port + key-only auth",
            ),
            bool_check(
                "rdp_open", "RDP Port (3389) Closed",
                3389 not in open_ports,
                "Port 3389 closed or filtered",
                SeverityLevel.CRITICAL,
                "Disable RDP or tunnel through VPN\n"
                "Windows: Disable Remote Desktop in Settings",
            ),
            bool_check(
                "db_ports", "Database Ports Closed",
                3306 not in open_ports and 5432 not in open_ports,
                "Database ports closed",
                SeverityLevel.CRITICAL,
                "Database ports should NEVER be internet-facing\n"
                "Use SSH tunnel or VPN for remote DB access",
            ),
        ]
