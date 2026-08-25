"""
NES.4 — Email Phishing Protection (SPF + DMARC)
================================================
Check DNS TXT records for SPF, DMARC, and DKIM.
Missing records = domain can be spoofed = phishing risk.

No raw DNS code here — delegates to :mod:`msme_auditor.utils.network`.
"""

from typing import List

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import extract_domain, check_txt_record

# Common DKIM selectors to probe (in priority order).
_DKIM_SELECTORS: List[str] = [
    "default", "google", "selector1", "selector2",
    "k1", "mandrill", "dkim", "mail",
]


class NES4Scanner(BaseScanner):
    """Email SPF, DMARC, and DKIM record scanner."""

    scanner_id: str = "nes4"
    name: str = "NES.4 — Email SPF & DMARC"
    description: str = (
        "Check DNS records for SPF, DMARC, and DKIM. "
        "Missing records = phishing risk."
    )
    category: str = "NES"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {
            "name": "target",
            "label": "Domain",
            "field_type": "text",
            "required": True,
            "placeholder": "example.com",
            "help_text": "Domain to check email security records for",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Query DNS for email-security TXT records and return checks."""
        raw = sc.config.get("target", sc.target or sc.config.get("domain", ""))
        domain = extract_domain(raw)

        if not domain:
            return [
                make_check(
                    "no_domain", "Domain Required", False,
                    "A valid domain", "Not provided",
                    SeverityLevel.CRITICAL,
                )
            ]

        spf_found = check_txt_record(domain, "v=spf1")
        dmarc_found = check_txt_record(f"_dmarc.{domain}", "v=DMARC1")
        dkim_found = self._probe_dkim(domain)

        return [
            make_check(
                "spf", "SPF Record Configured", spf_found,
                "v=spf1 ... record present",
                "Found" if spf_found else "MISSING — domain can be spoofed",
                SeverityLevel.CRITICAL,
                (
                    "Add SPF TXT record:\n"
                    "v=spf1 include:_spf.google.com ~all\n"
                    "For Microsoft 365: v=spf1 include:spf.protection.outlook.com ~all"
                ),
            ),
            make_check(
                "dmarc", "DMARC Record Configured", dmarc_found,
                "v=DMARC1 ... record present",
                "Found" if dmarc_found else "MISSING — no email policy enforcement",
                SeverityLevel.CRITICAL,
                (
                    "Add DMARC TXT record at _dmarc.yourdomain.com:\n"
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\n"
                    "Start with p=none to monitor, then p=quarantine, then p=reject"
                ),
            ),
            make_check(
                "dkim", "DKIM Record Configured", dkim_found,
                "DKIM signature present",
                "Found" if dkim_found else "MISSING — emails can be forged",
                SeverityLevel.HIGH,
                (
                    "Enable DKIM in your email provider settings:\n"
                    "Google: Admin → Apps → Gmail → Authenticate email\n"
                    "Microsoft 365: Enable DKIM signing in portal"
                ),
            ),
        ]

    @staticmethod
    def _probe_dkim(domain: str) -> bool:
        """
        Probe common DKIM selector names for a ``p=`` TXT record.

        Args:
            domain: The domain to query (e.g. ``"example.com"``).

        Returns:
            ``True`` if any common selector returns a DKIM record.
        """
        for selector in _DKIM_SELECTORS:
            if check_txt_record(f"{selector}._domainkey.{domain}", "p="):
                return True
        return False
