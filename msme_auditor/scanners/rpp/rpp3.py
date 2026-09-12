"""
RPP.3 — Multi-Factor Authentication
====================================
CERT-In: Enable MFA for all critical systems, admin accounts, and remote access.

Backend stack:
  - Config-driven policy via config/rpp3_policy.yaml
  - Safe subprocess wrapper (core/command_runner.py)
  - Structured audit logging (core/audit_logger.py)
  - ERROR is distinct from FAIL
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.core.command_runner import run_command
from msme_auditor.core.policy_loader import load_policy_for
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event


class RPP3Scanner(BaseScanner):
    scanner_id = "rpp3"
    name = "RPP.3 — Multi-Factor Authentication"
    description = "Enable MFA for all critical systems, administrative accounts, and remote access tools."
    category = "RPP"
    target_types = ["web", "azure_ad", "linux", "windows"]
    input_fields = [
        {"name": "target_type", "label": "Scan Target", "field_type": "select",
         "options": ["web", "azure_ad", "linux", "windows"], "default": "web"},
        {"name": "target", "label": "Target URL / Host", "field_type": "text",
         "placeholder": "http://localhost:8765"},
        {"name": "admin_mfa_enabled", "label": "Admin MFA Enabled", "field_type": "boolean",
         "default": True, "help_text": "MFA required for admin accounts"},
        {"name": "remote_mfa_enabled", "label": "Remote Access MFA Enabled", "field_type": "boolean",
         "default": True, "help_text": "MFA required for SSH/RDP/VPN"},
        {"name": "critical_mfa_enabled", "label": "Critical Systems MFA Enabled", "field_type": "boolean",
         "default": True, "help_text": "MFA required for databases, payment, customer data"},
        {"name": "mfa_method", "label": "MFA Method", "field_type": "select",
         "options": ["TOTP", "FIDO2", "Hardware Key", "Biometric", "Smart Card", "None"],
         "default": "TOTP", "help_text": "Type of MFA in use (TOTP/Hardware Key recommended)"},
        {"name": "policy_exists", "label": "MFA Policy Documented", "field_type": "boolean",
         "default": True, "help_text": "Written policy mandating MFA"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Dispatch to platform-specific MFA scanner."""
        cfg = sc.config
        tt = sc.target_type

        try:
            policy = load_policy_for("rpp3")
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, sc.target or "localhost", "started")

        try:
            if tt == "windows":
                result = self._scan_windows(policy)
            elif tt == "azure_ad":
                result = self._scan_azure_ad(policy)
            elif tt == "linux":
                result = self._scan_linux_ssh(policy)
            elif tt == "web" and sc.target:
                result = self._scan_web(sc.target, policy)
            else:
                result = self._scan_config(cfg, policy)
        except Exception as exc:
            result = [self._scan_error(str(exc))]
        finally:
            log_scan_event(audit_logger, self.scanner_id, sc.target or "localhost", "completed")

        return result

    # =========================================================================
    # Windows Scanner
    # =========================================================================
    def _scan_windows(self, policy: dict) -> List[SecurityCheck]:
        """Scan Windows for local MFA: Windows Hello, Credential Guard, Smart Card."""
        # Check Windows Hello (PIN / Fingerprint / Face)
        hello_enabled = False
        result = run_command([
            "reg", "query",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\BioNotifications",
            "/v", "OptOut", "/t", "REG_DWORD",
        ])
        if result.success:
            hello_enabled = True
        else:
            # Fallback: check if Windows Hello is available via Credential Manager
            result = run_command([
                "reg", "query",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "/v", "MachineGuid",
            ])
            hello_enabled = result.success

        # Check Credential Guard (VBS-based protection)
        cred_guard = False
        result = run_command([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "/v", "EnableVirtualizationBasedSecurity", "/t", "REG_DWORD",
        ])
        if result.success and "0x1" in result.stdout.lower():
            cred_guard = True

        # Check Smart Card presence
        smart_card = False
        result = run_command(["certutil", "-scinfo"])
        smart_card = result.success and "_card" in result.stdout.lower()

        method = "None"
        if hello_enabled:
            method = "Windows Hello"
        if smart_card:
            method = "Smart Card" if method == "None" else f"{method}, Smart Card"

        return self._build_checks(
            admin=hello_enabled or smart_card,
            remote=hello_enabled,
            critical=cred_guard,
            method=method,
            policy=cred_guard,
            policy_config=policy,
        )

    # =========================================================================
    # Azure AD Scanner
    # =========================================================================
    def _scan_azure_ad(self, policy: dict) -> List[SecurityCheck]:
        """Scan Azure AD for MFA status via ``az`` CLI."""
        result = run_command([
            "az", "ad", "user", "list",
            "--query", "[].{user:userPrincipalName, mfa:strongAuthenticationMethods, roles:assignedRoles}",
            "--out", "json",
        ], timeout=30)

        if not result.success:
            return [self._scan_error(f"Azure CLI not authenticated or unavailable: {result.error or result.stderr}")]

        try:
            users = json.loads(result.stdout)
        except json.JSONDecodeError:
            return [self._scan_error("Failed to parse Azure AD response")]

        admins_mfa = admins_total = 0
        for u in users:
            if u.get("roles"):
                admins_total += 1
                if u.get("mfa"):
                    admins_mfa += 1

        ok = admins_total == 0 or admins_mfa == admins_total
        method = "Azure AD MFA" if ok else "None"

        return self._build_checks(ok, ok, ok, method, True, policy)

    # =========================================================================
    # Linux SSH Scanner
    # =========================================================================
    def _scan_linux_ssh(self, policy: dict) -> List[SecurityCheck]:
        """Scan Linux SSH PAM config for MFA modules."""
        ssh_mfa = False
        method = None

        pam = Path("/etc/pam.d/sshd")
        if pam.exists():
            try:
                txt = pam.read_text(encoding="utf-8", errors="ignore")
                if "pam_google_authenticator" in txt or "pam_totp" in txt:
                    ssh_mfa, method = True, "TOTP"
                elif "pam_yubico" in txt:
                    ssh_mfa, method = True, "Hardware Key"
            except OSError:
                pass

        return self._build_checks(ssh_mfa, ssh_mfa, ssh_mfa, method or "None", False, policy)

    # =========================================================================
    # Web Scanner
    # =========================================================================
    def _scan_web(self, target: str, policy: dict) -> List[SecurityCheck]:
        """Probe web application for MFA evidence."""
        import httpx
        from urllib.parse import urljoin

        TIMEOUT = 5
        HEADERS = {
            "User-Agent": "Mozilla/5.0 (compatible; CyberSure-SecurityScanner/1.0)",
            "Accept": "text/html,application/json",
        }

        evidence: Dict[str, Any] = {}
        source = "none"

        # Step 1: Try structured API endpoints
        api_endpoints = [
            "/api/security/mfa-settings",
            "/api/auth/mfa",
            "/api/auth/config",
            "/api/security/config",
        ]

        for endpoint in api_endpoints:
            try:
                url = urljoin(target.rstrip("/"), endpoint)
                resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=False,
                                 verify=False, headers=HEADERS)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and any(
                            k in str(data).lower() for k in (
                                "mfa", "two_factor", "2fa", "totp",
                                "authenticator", "fido", "webauthn",
                            )
                        ):
                            evidence = data
                            source = f"API endpoint: {endpoint}"
                            break
                    except Exception:
                        continue
            except Exception:
                continue

        # Step 2: Probe login page for MFA-related UI elements
        if not evidence:
            login_paths = ["/login", "/signin"]
            for path in login_paths:
                try:
                    url = urljoin(target.rstrip("/"), path)
                    resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                     verify=False, headers=HEADERS)
                    if resp.status_code == 200:
                        html = resp.text.lower()
                        mfa_patterns = {
                            "FIDO2/WebAuthn": [r"webauthn", r"fido2", r"passkey", r"security.key"],
                            "TOTP": [r"totp", r"time.?based.*one.?time", r"authenticator.*app", r"otp.*code"],
                            "2FA": [r"two.?factor", r"2fa", r"multi.?factor", r"mfa"],
                            "SMS": [r"sms.*code", r"text.*code", r"phone.*verify"],
                        }
                        detected_methods = []
                        for method_name, patterns in mfa_patterns.items():
                            for pattern in patterns:
                                if re.search(pattern, html):
                                    detected_methods.append(method_name)
                                    break
                        if detected_methods:
                            method_priority = ["FIDO2/WebAuthn", "TOTP", "2FA", "SMS"]
                            best_method = next(
                                (m for m in method_priority if m in detected_methods),
                                detected_methods[0],
                            )
                            evidence["mfa_detected"] = True
                            evidence["mfa_method"] = best_method
                            source = f"Login page MFA detection: {path}"
                            break
                except Exception:
                    continue

        # Step 3: Check for MFA-related response headers
        if not evidence:
            try:
                url = urljoin(target.rstrip("/"), "/")
                resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                 verify=False, headers=HEADERS)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                mfa_headers = ["x-mfa-required", "x-two-factor-required", "x-authenticator-required"]
                found = [h for h in mfa_headers if h in resp_headers]
                if found:
                    evidence["mfa_detected"] = True
                    evidence["mfa_method"] = "Unknown (header detected)"
                    source = f"Response headers: {', '.join(found)}"
            except Exception:
                pass

        if not evidence:
            return [make_check(
                "web_probe_failed", "Web MFA Probe",
                False,
                "Accessible MFA configuration or detected MFA on login page",
                (f"Could not determine MFA status from {target}. "
                 "No MFA API found and no MFA elements detected on login pages."),
                SeverityLevel.HIGH,
                ("Option 1: Expose MFA config at /api/security/mfa-settings\n"
                 "Option 2: Ensure login page shows 2FA/TOTP elements\n"
                 "Option 3: Run this scanner in 'linux' or 'windows' mode on the server"),
            )]

        method = evidence.get("mfa_method", "None")
        mfa_detected = evidence.get("mfa_detected", False)

        return self._build_checks(mfa_detected, mfa_detected, mfa_detected, method, False, policy)

    # =========================================================================
    # Config (Manual Input) Scanner
    # =========================================================================
    def _scan_config(self, cfg: dict, policy: dict) -> List[SecurityCheck]:
        """Build checks from manually-supplied MFA configuration."""
        return self._build_checks(
            cfg.get("admin_mfa_enabled", False),
            cfg.get("remote_mfa_enabled", False),
            cfg.get("critical_mfa_enabled", False),
            cfg.get("mfa_method", "None"),
            cfg.get("policy_exists", False),
            policy,
        )

    # =========================================================================
    # Check Builder — unified evaluation
    # =========================================================================
    def _build_checks(
        self, admin: bool, remote: bool, critical: bool,
        method: str, policy_exists: bool, policy_config: dict,
    ) -> List[SecurityCheck]:
        """Build MFA checks from raw values against policy thresholds."""
        approved = [m.lower() for m in policy_config.get("approved_methods", [])]
        method_lower = method.lower() if method else ""
        method_secure = bool(method_lower and any(
            approved_m in method_lower for approved_m in approved
        ))

        return [
            bool_check("admin_mfa", "MFA for Administrative Accounts", admin,
                       "Enabled (TOTP/Hardware Key)", SeverityLevel.CRITICAL,
                       "Azure AD: Enable MFA per-user\nLinux: PAM + Google Authenticator"),
            bool_check("remote_mfa", "MFA for Remote Access", remote,
                       "Enabled for SSH/RDP/VPN", SeverityLevel.CRITICAL,
                       "SSH: libpam-google-authenticator\nRDP: Azure AD MFA"),
            bool_check("critical_mfa", "MFA for Critical Systems", critical,
                       "Enabled for all critical systems", SeverityLevel.CRITICAL,
                       "Implement SSO+MFA for all critical app access"),
            make_check("mfa_method", "MFA Method Security", method_secure,
                       "TOTP, Hardware Key, or FIDO2", method or "Not configured",
                       SeverityLevel.HIGH,
                       "Use TOTP apps or Hardware keys (YubiKey)\nAvoid SMS (SIM-swap risk)"),
            bool_check("mfa_policy", "MFA Enforcement Policy", policy_exists,
                       "Documented policy mandating MFA", SeverityLevel.MEDIUM,
                       "Create MFA policy: who/what requires MFA, approved methods"),
        ]

    # =========================================================================
    # Helpers
    # =========================================================================
    def _scan_error(self, message: str) -> SecurityCheck:
        """Return a scan-error check — never fake pass/fail."""
        return make_check(
            "scan_error", "RPP.3 Scan Error",
            False,
            "Successful scan execution",
            f"Scan failed: {message}",
            SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
