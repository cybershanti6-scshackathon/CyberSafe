"""
WEB.1 — Website Security Headers & TLS
=======================================
Checks any public URL for HTTPS enforcement, security headers, TLS
certificate validity, and common misconfigurations.

No raw socket/DNS code — delegates to :mod:`msme_auditor.utils.network`.
"""

from datetime import datetime
from typing import List
from urllib.parse import urlparse

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import tls_connect


class WEB1Scanner(BaseScanner):
    """Website security headers and TLS configuration scanner."""

    scanner_id: str = "web1"
    name: str = "WEB.1 — HTTPS, Headers & TLS"
    description: str = (
        "Scan any website for HTTPS enforcement, security headers, "
        "TLS config, cookies, and misconfigurations."
    )
    category: str = "Web Security"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {
            "name": "url",
            "label": "Website URL",
            "field_type": "text",
            "required": True,
            "placeholder": "https://example.com",
            "help_text": "Full URL of the website to scan (https:// recommended)",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Run HTTPS, header, and TLS checks against the target URL."""
        url = sc.config.get("url", sc.target or "")
        if not url:
            return [
                make_check(
                    "no_url", "URL Required", False,
                    "A valid URL", "No URL provided",
                    SeverityLevel.CRITICAL,
                )
            ]

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        checks: List[SecurityCheck] = []
        checks.extend(self._check_https(url))
        checks.extend(self._check_headers(url))
        checks.extend(self._check_tls(url))
        return checks

    # ------------------------------------------------------------------
    # HTTPS enforcement
    # ------------------------------------------------------------------

    @staticmethod
    def _check_https(url: str) -> List[SecurityCheck]:
        """Check that the site uses HTTPS and redirects HTTP."""
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"
        checks = [
            make_check(
                "https_url", "URL Uses HTTPS", is_https,
                "https://", f"{parsed.scheme}://",
                SeverityLevel.CRITICAL,
                "Use HTTPS for all pages. Get a free cert from Let's Encrypt.",
            ),
        ]

        if is_https:
            try:
                import httpx  # type: ignore[import-untyped]

                http_url = url.replace("https://", "http://", 1)
                r = httpx.get(http_url, timeout=10, follow_redirects=False)
                redirected = r.status_code in (301, 302, 307, 308)
                loc = r.headers.get("location", "")
                location_ok = "https://" in loc
                checks.append(
                    make_check(
                        "http_redirect", "HTTP Redirects to HTTPS",
                        redirected and location_ok,
                        "301/302 redirect to https://",
                        (
                            f"HTTP {r.status_code}"
                            + (f" → {loc}" if redirected else " (no redirect)")
                        ),
                        SeverityLevel.HIGH,
                        "Configure web server to redirect all HTTP to HTTPS.",
                    )
                )
            except ImportError:
                checks.append(make_check(
                    "httpx_missing", "HTTP Client Not Installed",
                    False, "httpx library available",
                    "pip install httpx required for redirect check",
                    SeverityLevel.HIGH, "Run: pip install httpx",
                ))
            except Exception:
                pass

        return checks

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_headers(url: str) -> List[SecurityCheck]:
        """Check for essential security headers."""
        try:
            import httpx  # type: ignore[import-untyped]

            resp = httpx.get(url, timeout=10, follow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except ImportError:
            return [
                make_check(
                    "httpx_missing", "HTTP Client Not Installed",
                    False,
                    "httpx library available",
                    "pip install httpx required for header checks",
                    SeverityLevel.HIGH,
                    "Run: pip install httpx",
                )
            ]
        except Exception as exc:
            return [
                make_check(
                    "header_error", "Header Check", False,
                    "HTTP response", f"Failed: {exc}",
                    SeverityLevel.HIGH,
                )
            ]

        checks: List[SecurityCheck] = []

        # HSTS
        hsts = "strict-transport-security" in headers
        checks.append(
            make_check(
                "hsts", "HSTS Enabled", hsts,
                "Strict-Transport-Security header present",
                headers.get("strict-transport-security", "MISSING"),
                SeverityLevel.HIGH,
                "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            )
        )

        # CSP
        csp = "content-security-policy" in headers
        checks.append(
            make_check(
                "csp", "Content Security Policy", csp,
                "Content-Security-Policy header present",
                (headers.get("content-security-policy", "MISSING")[:80] if csp else "MISSING"),
                SeverityLevel.HIGH,
                "Add Content-Security-Policy header to restrict loaded resources.",
            )
        )

        # X-Content-Type-Options
        xcto = headers.get("x-content-type-options", "").lower() == "nosniff"
        checks.append(
            make_check(
                "x_content_type", "X-Content-Type-Options: nosniff", xcto,
                "nosniff", headers.get("x-content-type-options", "MISSING"),
                SeverityLevel.MEDIUM,
                "Add header: X-Content-Type-Options: nosniff",
            )
        )

        # X-Frame-Options
        xfo = headers.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN")
        checks.append(
            make_check(
                "x_frame_options", "X-Frame-Options (Clickjacking)", xfo,
                "DENY or SAMEORIGIN",
                headers.get("x-frame-options", "MISSING"),
                SeverityLevel.MEDIUM,
                "Add header: X-Frame-Options: DENY",
            )
        )

        # Server info leakage
        leak = "server" in headers or "x-powered-by" in headers
        checks.append(
            make_check(
                "server_leak", "Server Info Leakage", not leak,
                "No server/version headers",
                (
                    f"Server: {headers.get('server', '-')}, "
                    f"X-Powered-By: {headers.get('x-powered-by', '-')}"
                ),
                SeverityLevel.MEDIUM,
                "Remove Server and X-Powered-By headers.",
            )
        )

        return checks

    # ------------------------------------------------------------------
    # TLS certificate
    # ------------------------------------------------------------------

    @staticmethod
    def _check_tls(url: str) -> List[SecurityCheck]:
        """Check TLS certificate validity, expiry, and protocol version."""
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return [
                make_check(
                    "tls_error", "TLS Check", False,
                    "Valid hostname", "No hostname in URL",
                    SeverityLevel.CRITICAL,
                )
            ]

        result = tls_connect(hostname, port, timeout=10)

        if "error" in result:
            return [
                make_check(
                    "tls_error", "TLS Connection", False,
                    "Successful TLS handshake",
                    result["error"][:120],
                    SeverityLevel.HIGH,
                    "Ensure the server supports TLS and is reachable.",
                )
            ]

        cert = result["cert"]
        protocol = result["protocol"]

        # Certificate validity
        try:
            not_after = datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
            )
            days_left = (not_after - datetime.now()).days
        except (KeyError, ValueError):
            days_left = 0
            not_after = None

        checks: List[SecurityCheck] = []

        checks.append(
            make_check(
                "cert_valid", "TLS Certificate Valid", days_left > 0,
                "Valid certificate",
                (
                    f"Expires in {days_left} days ({not_after:%Y-%m-%d})"
                    if not_after
                    else "Unable to parse certificate dates"
                ),
                SeverityLevel.CRITICAL,
                "Renew certificate. Use Let's Encrypt for free auto-renewal.",
            )
        )

        tls_ok = protocol in ("TLSv1.2", "TLSv1.3")
        checks.append(
            make_check(
                "tls_version", f"Modern TLS Version ({protocol})", tls_ok,
                "TLS 1.2 or 1.3", protocol,
                SeverityLevel.CRITICAL if not tls_ok else SeverityLevel.INFO,
                "Disable TLS 1.0/1.1. Only allow TLS 1.2+.",
            )
        )

        return checks
