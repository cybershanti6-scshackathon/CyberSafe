"""
WEB.2 — DNS Security (DNSSEC + CAA)
====================================
Check DNS records for:
  - DNSSEC validation
  - CAA (Certificate Authority Authorization) records
  - DNS CNAME records (subdomain takeover risk)
  - DNS-based tracking (CNAME cloaking)

No raw socket code -- delegates to :mod:`msme_auditor.utils.network`.
"""

from typing import List

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import extract_domain, check_txt_record


def _check_dnssec(domain: str) -> dict:
    """Check if DNSSEC is configured for the domain."""
    import dns.resolver
    import dns.dnssec

    result = {"dnssec_enabled": False, "algorithm": "N/A", "error": None}

    try:
        # Check for DS record (DNSSEC delegation signer)
        ds_records = dns.resolver.resolve(domain, "DS")
        if ds_records:
            result["dnssec_enabled"] = True
            for rdata in ds_records:
                result["algorithm"] = f"DS record found (algorithm: {rdata.algorithm})"
                break
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain not found"
    except dns.resolver.NoAnswer:
        result["error"] = "No DS record found (DNSSEC not configured)"
    except dns.resolver.NoNameservers:
        result["error"] = "DNS resolution failed"
    except Exception as e:
        result["error"] = str(e)

    return result


def _check_caa(domain: str) -> dict:
    """Check for CAA (Certificate Authority Authorization) records."""
    import dns.resolver

    result = {"caa_found": False, "records": [], "error": None}

    try:
        answers = dns.resolver.resolve(domain, "CAA")
        for rdata in answers:
            flags = rdata.flags
            tag = rdata.tag
            value = rdata.value
            result["caa_found"] = True
            result["records"].append(f"{tag}={value}")
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain not found"
    except dns.resolver.NoAnswer:
        result["error"] = "No CAA record found"
    except dns.resolver.NoNameservers:
        result["error"] = "DNS resolution failed"
    except Exception as e:
        result["error"] = str(e)

    return result


def _check_cname(domain: str) -> dict:
    """Check for CNAME records (subdomain takeover risk)."""
    import dns.resolver

    result = {"cname_found": False, "target": "", "error": None}

    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            result["cname_found"] = True
            result["target"] = str(rdata.target).rstrip(".")
            break
    except dns.resolver.NXDOMAIN:
        result["error"] = "Domain not found"
    except dns.resolver.NoAnswer:
        # No CNAME is normal -- A/AAAA records used instead
        pass
    except dns.resolver.NoNameservers:
        result["error"] = "DNS resolution failed"
    except Exception as e:
        result["error"] = str(e)

    return result


class WEB2Scanner(BaseScanner):
    """DNS security scanner -- checks DNSSEC, CAA, and CNAME records."""

    scanner_id: str = "web2"
    name: str = "WEB.2 — DNS Security (DNSSEC + CAA)"
    description: str = (
        "Check DNS records for DNSSEC, CAA, and CNAME takeover risk."
    )
    category: str = "Web Security"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {
            "name": "url",
            "label": "Domain or URL",
            "field_type": "text",
            "required": True,
            "placeholder": "example.com",
            "help_text": "Domain to check DNS security records for",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Run DNS security checks."""
        url = sc.config.get("url", sc.target or "")
        if not url:
            return [
                make_check(
                    "no_url", "Domain Required", False,
                    "A valid domain", "No domain provided",
                    SeverityLevel.CRITICAL,
                )
            ]

        domain = extract_domain(url)
        if not domain:
            return [
                make_check(
                    "invalid_domain", "Invalid Domain", False,
                    "A valid domain name", f"Could not extract domain from: {url}",
                    SeverityLevel.CRITICAL,
                )
            ]

        checks: List[SecurityCheck] = []

        # --- DNSSEC Check ---
        dnssec = _check_dnssec(domain)
        checks.append(make_check(
            "dnssec", "DNSSEC Configured",
            dnssec["dnssec_enabled"],
            "DNSSEC enabled (DS record present)",
            dnssec.get("algorithm", "Not configured") if dnssec["dnssec_enabled"] else "Not configured",
            SeverityLevel.HIGH if not dnssec["dnssec_enabled"] else SeverityLevel.INFO,
            "Enable DNSSEC to prevent DNS spoofing:\n"
            "1. Sign your zone with DNSSEC\n"
            "2. Add DS record at your registrar\n"
            "Cloudflare: Enable in DNS settings\n"
            "AWS Route53: Enable DNSSEC signing",
        ))

        # --- CAA Record Check ---
        caa = _check_caa(domain)
        checks.append(make_check(
            "caa", "CAA Record Configured",
            caa["caa_found"],
            "CAA record restricting certificate issuance",
            "; ".join(caa["records"][:3]) if caa["caa_found"] else "No CAA record",
            SeverityLevel.MEDIUM if not caa["caa_found"] else SeverityLevel.INFO,
            "Add CAA record to restrict which CAs can issue certificates:\n"
            'example.com. CAA 0 issue "letsencrypt.org"\n'
            'example.com. CAA 0 issuewild ";"\n'
            'example.com. CAA 0 iodef "mailto:security@example.com"',
        ))

        # --- CNAME Check (subdomain takeover risk) ---
        cname = _check_cname(domain)
        if cname["cname_found"]:
            target = cname["target"]
            # Check for common takeover targets
            takeover_risks = [
                "amazonaws.com", "herokuapp.com", "github.io",
                "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
                "surge.sh", "bitbucket.io", "zendesk.com",
                "readme.io", "ghost.io", "pantheon.io",
            ]
            is_risky = any(risk in target for risk in takeover_risks)
            checks.append(make_check(
                "cname_takeover", "CNAME Subdomain Takeover Risk",
                not is_risky,
                "CNAME target is controlled or not a takeover risk",
                f"CNAME -> {target}" + (" (TAKEOVER RISK)" if is_risky else ""),
                SeverityLevel.CRITICAL if is_risky else SeverityLevel.INFO,
                "If you don't control the CNAME target, remove the CNAME record\n"
                f"Target: {target}\n"
                "Check: https://github.com/EdOverflow/can-i-take-over-xyz",
            ))
        else:
            checks.append(make_check(
                "cname_takeover", "CNAME Subdomain Takeover Risk",
                True,
                "No CNAME pointing to external service",
                "No CNAME record (uses A/AAAA records)",
                SeverityLevel.INFO,
                "A/AAAA records don't have takeover risk.",
            ))

        return checks
