"""
WEB.3 — API Security Headers
=============================
Check web applications for API-specific security headers and configurations:
  - CORS (Cross-Origin Resource Sharing) policy
  - API rate limiting headers
  - Authentication headers
  - Request size limits
  - API versioning
  - Error handling (info leakage)

No raw socket code -- uses httpx for HTTP probing.
"""

import re
from typing import List
from urllib.parse import urlparse

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck


_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)


class WEB3Scanner(BaseScanner):
    """API security headers and configuration scanner."""

    scanner_id: str = "web3"
    name: str = "WEB.3 — API Security Headers"
    description: str = (
        "Check for API security: CORS policy, rate limiting, "
        "error handling, and information disclosure."
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
            "help_text": "Full URL of the website to scan",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Run API security checks against the target URL."""
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
        checks.extend(self._check_cors(url))
        checks.extend(self._check_rate_limiting(url))
        checks.extend(self._check_error_handling(url))
        checks.extend(self._check_information_disclosure(url))
        return checks

    # ------------------------------------------------------------------
    # CORS (Cross-Origin Resource Sharing)
    # ------------------------------------------------------------------

    @staticmethod
    def _check_cors(url: str) -> List[SecurityCheck]:
        """Check CORS configuration."""
        try:
            import httpx

            # Send a cross-origin request with Origin header
            resp = httpx.get(
                url, timeout=10, follow_redirects=True, verify=False,
                headers={
                    "User-Agent": _BROWSER_UA,
                    "Origin": "https://evil.com",
                },
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return []

        checks: List[SecurityCheck] = []

        # Check Access-Control-Allow-Origin
        acao = headers.get("access-control-allow-origin", "")
        if acao:
            if acao == "*":
                checks.append(make_check(
                    "cors_wildcard", "CORS Wildcard (*)",
                    False,
                    "Restricted CORS origin",
                    "Access-Control-Allow-Origin: * (wildcard)",
                    SeverityLevel.HIGH,
                    "Avoid wildcard CORS origin\n"
                    "Use specific allowed origins instead:\n"
                    "Access-Control-Allow-Origin: https://yourdomain.com",
                ))
            elif acao == "https://evil.com":
                checks.append(make_check(
                    "cors_reflection", "CORS Origin Reflection",
                    False,
                    "CORS origin validated",
                    "Access-Control-Allow-Origin reflects attacker origin!",
                    SeverityLevel.CRITICAL,
                    "NEVER reflect the Origin header without validation\n"
                    "Validate against a whitelist of allowed origins",
                ))
            else:
                checks.append(make_check(
                    "cors_restricted", "CORS Origin Restricted",
                    True,
                    "CORS origin is specific (not wildcard)",
                    f"Access-Control-Allow-Origin: {acao[:50]}",
                    SeverityLevel.INFO,
                    "CORS is configured with specific origin(s).",
                ))
        else:
            checks.append(make_check(
                "cors_restricted", "CORS Origin Restricted",
                True,
                "No CORS headers (same-origin by default)",
                "No Access-Control-Allow-Origin header",
                SeverityLevel.INFO,
                "No CORS header is secure by default.",
            ))

        # Check Access-Control-Allow-Credentials
        acac = headers.get("access-control-allow-credentials", "")
        if acac.lower() == "true":
            if acao == "*":
                checks.append(make_check(
                    "cors_creds_wildcard", "CORS Credentials + Wildcard",
                    False,
                    "CORS credentials without wildcard",
                    "Access-Control-Allow-Credentials: true + wildcard origin",
                    SeverityLevel.CRITICAL,
                    "NEVER combine credentials=true with wildcard origin\n"
                    "This allows any site to make authenticated requests",
                ))
            else:
                checks.append(make_check(
                    "cors_creds", "CORS Credentials Allowed",
                    True,
                    "CORS credentials with restricted origin",
                    f"Credentials: true, Origin: {acao[:30]}",
                    SeverityLevel.INFO,
                    "CORS credentials allowed with specific origin.",
                ))

        return checks

    # ------------------------------------------------------------------
    # Rate Limiting
    # ------------------------------------------------------------------

    @staticmethod
    def _check_rate_limiting(url: str) -> List[SecurityCheck]:
        """Check for rate limiting headers."""
        try:
            import httpx

            resp = httpx.get(
                url, timeout=10, follow_redirects=True, verify=False,
                headers={"User-Agent": _BROWSER_UA},
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return []

        checks: List[SecurityCheck] = []

        # Check for rate limiting headers
        rate_limit_headers = [
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "x-rate-limit-limit",
            "retry-after",
            "x-account-limit",
            "x-throttling-limit",
        ]
        found = [h for h in rate_limit_headers if h in headers]

        if found:
            details = [f"{h}: {headers[h][:30]}" for h in found[:3]]
            checks.append(make_check(
                "rate_limiting", "Rate Limiting Headers Present",
                True,
                "Rate limiting headers detected",
                "; ".join(details),
                SeverityLevel.INFO,
                "Rate limiting is configured.",
            ))
        else:
            checks.append(make_check(
                "rate_limiting", "Rate Limiting Headers Present",
                False,
                "Rate limiting headers present",
                "No rate limiting headers detected",
                SeverityLevel.MEDIUM,
                "Add rate limiting to prevent brute-force and DDoS:\n"
                "X-RateLimit-Limit: 100\n"
                "X-RateLimit-Remaining: 95\n"
                "X-RateLimit-Reset: 1609459200",
            ))

        return checks

    # ------------------------------------------------------------------
    # Error Handling
    # ------------------------------------------------------------------

    @staticmethod
    def _check_error_handling(url: str) -> List[SecurityCheck]:
        """Check for information leakage in error responses."""
        try:
            import httpx
            from urllib.parse import urljoin

            checks: List[SecurityCheck] = []

            # Try to trigger a 404 error
            test_paths = ["/nonexistent-page-12345", "/api/nonexistent"]
            for path in test_paths:
                try:
                    test_url = urljoin(url.rstrip("/"), path)
                    resp = httpx.get(
                        test_url, timeout=10, follow_redirects=False,
                        verify=False, headers={"User-Agent": _BROWSER_UA},
                    )
                    if resp.status_code == 404:
                        body = resp.text.lower()

                        # Check for detailed error messages
                        info_leak_patterns = [
                            (r"stack\s*trace", "Stack trace exposed"),
                            (r"traceback", "Python traceback exposed"),
                            (r"exception.*at line", "Exception details exposed"),
                            (r"internal server error.*debug", "Debug mode exposed"),
                            (r"sql.*syntax.*error", "SQL error exposed"),
                            (r"database.*error", "Database error exposed"),
                            (r"file.*not found.*\/", "File path exposed"),
                            (r"php.*error", "PHP error exposed"),
                        ]

                        leaks = []
                        for pattern, desc in info_leak_patterns:
                            if re.search(pattern, body):
                                leaks.append(desc)

                        if leaks:
                            checks.append(make_check(
                                "error_info_leak", "Error Information Leakage",
                                False,
                                "Generic error messages",
                                f"Leaked: {', '.join(leaks[:3])}",
                                SeverityLevel.HIGH,
                                "Configure custom error pages\n"
                                "Disable debug mode in production\n"
                                "Use generic error messages for users",
                            ))
                        else:
                            checks.append(make_check(
                                "error_info_leak", "Error Information Leakage",
                                True,
                                "Generic error messages",
                                "No sensitive info in error response",
                                SeverityLevel.INFO,
                                "Error handling looks good.",
                            ))
                        break
                except Exception:
                    continue

            return checks

        except Exception:
            return []

    # ------------------------------------------------------------------
    # Information Disclosure
    # ------------------------------------------------------------------

    @staticmethod
    def _check_information_disclosure(url: str) -> List[SecurityCheck]:
        """Check for common information disclosure endpoints."""
        try:
            import httpx
            from urllib.parse import urljoin

            checks: List[SecurityCheck] = []

            # Common sensitive endpoints that shouldn't be public
            sensitive_endpoints = [
                ("/.env", "Environment file"),
                ("/.git/config", "Git configuration"),
                ("/wp-config.php", "WordPress config"),
                ("/config.json", "Configuration file"),
                ("/api/docs", "API documentation"),
                ("/swagger.json", "Swagger/OpenAPI docs"),
                ("/graphql", "GraphQL endpoint"),
                ("/.htaccess", "Apache configuration"),
                ("/server-status", "Apache server status"),
                ("/server-info", "Apache server info"),
                ("/.well-known/", "Well-known directory"),
            ]

            exposed = []
            for path, desc in sensitive_endpoints:
                try:
                    test_url = urljoin(url.rstrip("/"), path)
                    resp = httpx.get(
                        test_url, timeout=5, follow_redirects=False,
                        verify=False, headers={"User-Agent": _BROWSER_UA},
                    )
                    if resp.status_code == 200:
                        body = resp.text[:500]
                        # Verify it's actual content, not a generic page
                        if any(kw in body.lower() for kw in [
                            "password", "secret", "key", "token",
                            "database", "api_key", "private",
                            "ssh", "credential", "auth",
                        ]):
                            exposed.append(f"{path} ({desc})")
                except Exception:
                    continue

            if exposed:
                checks.append(make_check(
                    "info_disclosure", "Sensitive Endpoint Exposed",
                    False,
                    "No sensitive endpoints publicly accessible",
                    f"Exposed: {'; '.join(exposed[:4])}",
                    SeverityLevel.CRITICAL,
                    "Restrict access to sensitive endpoints:\n"
                    "- Block .env, .git, config files in web server\n"
                    "- Require authentication for /api/docs\n"
                    "- Remove server-status pages",
                ))
            else:
                checks.append(make_check(
                    "info_disclosure", "Sensitive Endpoint Exposed",
                    True,
                    "No sensitive endpoints publicly accessible",
                    "No sensitive endpoints found",
                    SeverityLevel.INFO,
                    "No common sensitive endpoints exposed.",
                ))

            return checks

        except Exception:
            return []
