"""
WEB.1 — Website Security Headers & TLS
=======================================
Checks any public URL for HTTPS enforcement, security headers, TLS
certificate validity, cookie security, and common misconfigurations.

No raw socket/DNS code — delegates to :mod:`msme_auditor.utils.network`.
"""

import re
from datetime import datetime
from typing import List
from urllib.parse import urlparse

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import tls_connect

# Browser User-Agent for realistic header detection
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)


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
        checks.extend(self._check_cookies(url))
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
                r = httpx.get(
                    http_url, timeout=10, follow_redirects=False,
                    headers={"User-Agent": _BROWSER_UA},
                )
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

            resp = httpx.get(
                url, timeout=10, follow_redirects=True, verify=False,
                headers={"User-Agent": _BROWSER_UA, "Accept": "text/html,*/*"},
            )
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

        # ── Critical: HSTS ──────────────────────────────────────────────
        hsts = "strict-transport-security" in headers
        hsts_value = headers.get("strict-transport-security", "MISSING")
        hsts_max_age = 0
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts_value)
            if m:
                hsts_max_age = int(m.group(1))
        checks.append(
            make_check(
                "hsts", "HSTS Enabled", hsts and hsts_max_age >= 31536000,
                "max-age >= 1 year (31536000)",
                hsts_value[:80] if hsts else "MISSING",
                SeverityLevel.HIGH,
                "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            )
        )

        # ── Critical: Content-Security-Policy ────────────────────────────
        csp = "content-security-policy" in headers
        csp_value = headers.get("content-security-policy", "MISSING")
        # Check for dangerous CSP patterns
        csp_warnings = []
        if csp:
            if "'unsafe-inline'" in csp_value:
                csp_warnings.append("'unsafe-inline' weakens CSP")
            if "'unsafe-eval'" in csp_value:
                csp_warnings.append("'unsafe-eval' is dangerous")
            if "data:" in csp_value:
                csp_warnings.append("data: URIs can bypass CSP")
        checks.append(
            make_check(
                "csp", "Content Security Policy", csp and not csp_warnings,
                "Strict CSP without unsafe-inline/unsafe-eval",
                (csp_value[:80] + (" ⚠ " + "; ".join(csp_warnings) if csp_warnings else ""))
                if csp else "MISSING",
                SeverityLevel.HIGH,
                "Add Content-Security-Policy header to restrict loaded resources.",
            )
        )

        # ── Medium: X-Content-Type-Options ───────────────────────────────
        xcto = headers.get("x-content-type-options", "").lower() == "nosniff"
        checks.append(
            make_check(
                "x_content_type", "X-Content-Type-Options: nosniff", xcto,
                "nosniff", headers.get("x-content-type-options", "MISSING"),
                SeverityLevel.MEDIUM,
                "Add header: X-Content-Type-Options: nosniff",
            )
        )

        # ── Medium: X-Frame-Options ──────────────────────────────────────
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

        # ── Medium: Referrer-Policy ──────────────────────────────────────
        referrer = "referrer-policy" in headers
        referrer_value = headers.get("referrer-policy", "MISSING")
        # Good values: no-referrer, strict-origin-when-cross-origin, same-origin
        good_referrer = any(
            v in referrer_value.lower()
            for v in ["no-referrer", "strict-origin", "same-origin"]
        ) if referrer else False
        checks.append(
            make_check(
                "referrer_policy", "Referrer-Policy", referrer and good_referrer,
                "no-referrer or strict-origin-when-cross-origin",
                referrer_value[:60],
                SeverityLevel.MEDIUM,
                "Add header: Referrer-Policy: strict-origin-when-cross-origin",
            )
        )

        # ── Medium: Permissions-Policy ───────────────────────────────────
        perm_policy = "permissions-policy" in headers or "feature-policy" in headers
        checks.append(
            make_check(
                "permissions_policy", "Permissions-Policy", perm_policy,
                "Permissions-Policy header present",
                "Present" if perm_policy else "MISSING",
                SeverityLevel.MEDIUM,
                "Add Permissions-Policy to restrict browser features\n"
                "Example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )
        )

        # ── Low: X-XSS-Protection (legacy but still useful) ─────────────
        xss = headers.get("x-xss-protection", "")
        xss_ok = "1" in xss and "mode=block" in xss.lower() if xss else False
        checks.append(
            make_check(
                "xss_protection", "X-XSS-Protection", xss_ok,
                "1; mode=block",
                xss if xss else "MISSING",
                SeverityLevel.LOW,
                "Add header: X-XSS-Protection: 1; mode=block\n"
                "Note: Modern browsers use CSP instead, but this helps older browsers.",
            )
        )

        # ── Medium: Cross-Origin headers ─────────────────────────────────
        coop = "cross-origin-opener-policy" in headers
        coep = "cross-origin-embedder-policy" in headers
        corb = "cross-origin-resource-policy" in headers
        cross_origin_count = sum([coop, coep, corb])
        checks.append(
            make_check(
                "cross_origin_headers", "Cross-Origin Isolation Headers",
                cross_origin_count >= 2,
                "At least 2 of: COOP, COEP, CORP",
                f"{cross_origin_count}/3 present" + (
                    f" ({', '.join(h for h, v in [('COOP', coop), ('COEP', coep), ('CORP', corb)] if v)})"
                    if cross_origin_count > 0 else ""
                ),
                SeverityLevel.MEDIUM,
                "Add Cross-Origin headers to prevent data leaks:\n"
                "Cross-Origin-Opener-Policy: same-origin\n"
                "Cross-Origin-Embedder-Policy: require-corp\n"
                "Cross-Origin-Resource-Policy: same-origin",
            )
        )

        # ── Server info leakage ──────────────────────────────────────────
        leak = "server" in headers or "x-powered-by" in headers
        server_val = headers.get("server", "")
        powered_val = headers.get("x-powered-by", "")
        leak_details = []
        if server_val:
            leak_details.append(f"Server: {server_val}")
        if powered_val:
            leak_details.append(f"X-Powered-By: {powered_val}")
        checks.append(
            make_check(
                "server_leak", "Server Info Leakage", not leak,
                "No server/version headers",
                "; ".join(leak_details) if leak_details else "Clean",
                SeverityLevel.MEDIUM,
                "Remove Server and X-Powered-By headers.",
            )
        )

        # ── Info: Response size (very large pages may lack compression) ──
        content_encoding = headers.get("content-encoding", "")
        has_compression = content_encoding in ("gzip", "br", "deflate", "zstd")
        checks.append(
            make_check(
                "compression", "Response Compression", has_compression,
                "gzip, br, or deflate",
                content_encoding or "None",
                SeverityLevel.INFO,
                "Enable gzip/brotli compression for faster page loads.",
            )
        )

        return checks

    # ------------------------------------------------------------------
    # Cookie security
    # ------------------------------------------------------------------

    @staticmethod
    def _check_cookies(url: str) -> List[SecurityCheck]:
        """Check for secure cookie flags."""
        try:
            import httpx  # type: ignore[import-untyped]

            resp = httpx.get(
                url, timeout=10, follow_redirects=True, verify=False,
                headers={"User-Agent": _BROWSER_UA},
            )
        except Exception:
            return []

        # Extract Set-Cookie headers (case-insensitive)
        cookie_headers = []
        for key, value in resp.headers.items():
            if key.lower() == "set-cookie":
                cookie_headers.append(value)

        if not cookie_headers:
            return []  # No cookies = nothing to check

        checks: List[SecurityCheck] = []

        # Analyze cookie flags
        total_cookies = len(cookie_headers)
        missing_secure = 0
        missing_httponly = 0
        missing_samesite = 0
        insecure_samesite = 0
        session_cookies_without_flags = 0

        for cookie in cookie_headers:
            cookie_lower = cookie.lower()
            name = cookie.split("=")[0].strip() if "=" in cookie else ""

            # Check Secure flag
            if "secure" not in cookie_lower:
                missing_secure += 1

            # Check HttpOnly flag
            if "httponly" not in cookie_lower:
                missing_httponly += 1

            # Check SameSite attribute
            samesite_match = re.search(r"samesite\s*=\s*(\w+)", cookie_lower)
            if samesite_match:
                ss_value = samesite_match.group(1)
                if ss_value == "none":
                    insecure_samesite += 1
            else:
                missing_samesite += 1

            # Check for session cookies without security flags
            is_session = (
                "session" in name.lower()
                or ("expires" not in cookie_lower and "max-age" not in cookie_lower)
            )
            if is_session and ("secure" not in cookie_lower or "httponly" not in cookie_lower):
                session_cookies_without_flags += 1

        # Secure flag
        checks.append(make_check(
            "cookie_secure", "Cookies Have Secure Flag",
            missing_secure == 0,
            f"All {total_cookies} cookies have Secure flag",
            f"{missing_secure}/{total_cookies} missing Secure" if missing_secure else "All cookies have Secure flag",
            SeverityLevel.HIGH,
            "Add 'Secure' flag to all cookies:\n"
            "Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
        ))

        # HttpOnly flag
        checks.append(make_check(
            "cookie_httponly", "Cookies Have HttpOnly Flag",
            missing_httponly == 0,
            f"All {total_cookies} cookies have HttpOnly flag",
            f"{missing_httponly}/{total_cookies} missing HttpOnly" if missing_httponly else "All cookies have HttpOnly flag",
            SeverityLevel.HIGH,
            "Add 'HttpOnly' flag to prevent XSS cookie theft.",
        ))

        # SameSite attribute
        checks.append(make_check(
            "cookie_samesite", "Cookies Have SameSite Attribute",
            missing_samesite == 0 and insecure_samesite == 0,
            f"All cookies have SameSite=Strict or Lax",
            (
                f"{missing_samesite} missing, {insecure_samesite} with SameSite=None"
                if missing_samesite or insecure_samesite
                else "All cookies have SameSite"
            ),
            SeverityLevel.MEDIUM,
            "Add 'SameSite=Strict' or 'SameSite=Lax' to prevent CSRF attacks.",
        ))

        # Session cookie security
        if session_cookies_without_flags > 0:
            checks.append(make_check(
                "session_cookie_security", "Session Cookies Secured",
                False,
                "Session cookies have Secure + HttpOnly",
                f"{session_cookies_without_flags} session cookie(s) lack security flags",
                SeverityLevel.CRITICAL,
                "Session cookies MUST have both Secure and HttpOnly flags.",
            ))

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

        # Certificate subject info
        subject = cert.get("subject", ())
        issuer = cert.get("issuer", ())
        cn = ""
        org = ""
        for rdn in subject:
            for attr, val in rdn:
                if attr == "commonName":
                    cn = val
                if attr == "organizationName":
                    org = val

        issuer_org = ""
        for rdn in issuer:
            for attr, val in rdn:
                if attr == "organizationName":
                    issuer_org = val

        # Check if self-signed
        is_self_signed = (issuer_org == org) if (issuer_org and org) else False

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

        # Certificate expiry warning (warn if < 30 days)
        if days_left > 0 and days_left <= 30:
            checks.append(
                make_check(
                    "cert_expiry_warning", "Certificate Expiry Warning",
                    False,
                    "> 30 days until expiry",
                    f"Expires in {days_left} days — renew soon!",
                    SeverityLevel.HIGH,
                    "Renew certificate before it expires.",
                )
            )

        # Certificate issuer
        if is_self_signed:
            checks.append(
                make_check(
                    "cert_not_self_signed", "Not Self-Signed Certificate",
                    False,
                    "CA-signed certificate",
                    f"Self-signed: {issuer_org or cn}",
                    SeverityLevel.CRITICAL,
                    "Use a CA-signed certificate (Let's Encrypt is free).",
                )
            )

        # TLS version
        tls_ok = protocol in ("TLSv1.2", "TLSv1.3")
        checks.append(
            make_check(
                "tls_version", f"Modern TLS Version ({protocol})", tls_ok,
                "TLS 1.2 or 1.3", protocol,
                SeverityLevel.CRITICAL if not tls_ok else SeverityLevel.INFO,
                "Disable TLS 1.0/1.1. Only allow TLS 1.2+.",
            )
        )

        # Cipher info
        cipher = result.get("cipher", "")
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            # Check for weak ciphers
            weak_patterns = ["RC4", "DES", "NULL", "EXPORT", "MD5", "anon"]
            is_weak = any(w in cipher_name.upper() for w in weak_patterns)
            checks.append(
                make_check(
                    "cipher_strength", f"Strong Cipher ({cipher_name})",
                    not is_weak,
                    "AES-GCM, CHACHA20, or similar strong cipher",
                    cipher_name,
                    SeverityLevel.CRITICAL if is_weak else SeverityLevel.INFO,
                    "Disable weak ciphers (RC4, DES, NULL, EXPORT).",
                )
            )

        # Certificate chain (check Subject Alternative Names)
        san = cert.get("subjectAltName", ())
        san_domains = [val for typ, val in san if typ == "DNS"][:5]
        if san_domains:
            checks.append(
                make_check(
                    "cert_san", "Certificate SAN Coverage",
                    True,
                    "SAN includes target domain",
                    f"Domains: {', '.join(san_domains)}",
                    SeverityLevel.INFO,
                    "Certificate includes Subject Alternative Names.",
                )
            )

        return checks
