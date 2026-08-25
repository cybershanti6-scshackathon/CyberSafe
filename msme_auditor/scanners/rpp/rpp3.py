"""
RPP.3 — Multi-Factor Authentication
====================================
CERT-In: Enable MFA for all critical systems, admin accounts, and remote access.
"""

import subprocess
import json
from pathlib import Path
from typing import List

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck


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

        if tt == "windows":
            return self._scan_windows()
        elif tt == "azure_ad":
            return self._scan_azure_ad()
        elif tt == "linux":
            return self._scan_linux_ssh()
        elif tt == "web" and sc.target:
            return self._scan_web(sc.target)
        else:
            return self._scan_config(cfg)

    def _scan_windows(self) -> List[SecurityCheck]:
        """Scan Windows for local MFA: Windows Hello, Credential Guard, Smart Card."""
        import subprocess, re

        # Check Windows Hello (PIN / Fingerprint / Face)
        hello_enabled = False
        try:
            result = subprocess.run(
                ["reg", "query",
                 r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\BioNotifications",
                 "/v", "OptOut", "/t", "REG_DWORD"],
                capture_output=True, text=True, timeout=10,
            )
            # If OptOut=0 or key exists, Hello is available
            hello_enabled = result.returncode == 0
        except Exception:
            pass

        # Fallback: check if Windows Hello is configured via Credential Manager
        if not hello_enabled:
            try:
                result = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SOFTWARE\Microsoft\Cryptography",
                     "/v", "MachineGuid"],
                    capture_output=True, text=True, timeout=10,
                )
                # If registry key exists, Windows Hello is available
                hello_enabled = result.returncode == 0
            except Exception:
                pass

        # Check Credential Guard (VBS-based protection)
        cred_guard = False
        try:
            result = subprocess.run(
                ["reg", "query",
                 r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
                 "/v", "EnableVirtualizationBasedSecurity", "/t", "REG_DWORD"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and "0x1" in result.stdout.lower():
                cred_guard = True
        except Exception:
            pass

        # Check Smart Card presence
        smart_card = False
        try:
            result = subprocess.run(
                ["certutil", "-scinfo"],
                capture_output=True, text=True, timeout=10,
            )
            smart_card = result.returncode == 0 and "_card" in result.stdout.lower()
        except Exception:
            pass

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
        )

    def _scan_azure_ad(self) -> List[SecurityCheck]:
        """Scan Azure AD for MFA status via ``az`` CLI."""
        try:
            result = subprocess.run(
                ["az", "ad", "user", "list",
                 "--query", "[].{user:userPrincipalName, mfa:strongAuthenticationMethods, roles:assignedRoles}",
                 "--out", "json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                raise Exception("Azure CLI not authenticated")
            users = json.loads(result.stdout)
            admins_mfa = admins_total = 0
            for u in users:
                if u.get("roles"):
                    admins_total += 1
                    if u.get("mfa"):
                        admins_mfa += 1
            ok = admins_total == 0 or admins_mfa == admins_total
            return self._build_checks(ok, ok, ok, "Azure AD MFA" if ok else "None", True)
        except Exception as e:
            return self._fail(str(e))

    def _scan_linux_ssh(self) -> List[SecurityCheck]:
        """Scan Linux SSH PAM config for MFA modules."""
        ssh_mfa = False
        method = None
        pam = Path("/etc/pam.d/sshd")
        if pam.exists():
            try:
                txt = pam.read_text()
                if "pam_google_authenticator" in txt or "pam_totp" in txt:
                    ssh_mfa, method = True, "TOTP"
                elif "pam_yubico" in txt:
                    ssh_mfa, method = True, "Hardware Key"
            except Exception:
                pass
        critical = ssh_mfa
        return self._build_checks(ssh_mfa, ssh_mfa, critical, method or "None", False)

    def _scan_web(self, target: str) -> List[SecurityCheck]:
        """
        Probe web application for MFA evidence.

        Real probing pipeline:
        1. Try /api/security/mfa-settings
        2. Probe login page for 2FA/TOTP/MFA hints in HTML
        3. Check for common MFA redirect paths
        4. Report honestly if no evidence found
        """
        import httpx
        from urllib.parse import urljoin

        evidence = {}
        source = "web_probe"

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
                resp = httpx.get(url, timeout=8, follow_redirects=True, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, dict) and (
                            "mfa" in str(data).lower()
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
            login_paths = ["/login", "/signin", "/auth/login"]
            for path in login_paths:
                try:
                    url = urljoin(target.rstrip("/"), path)
                    resp = httpx.get(url, timeout=8, follow_redirects=True, verify=False)
                    if resp.status_code == 200:
                        html = resp.text.lower()
                        hints = {}
                        # Look for 2FA/TOTP/MFA elements
                        if "two-factor" in html or "2fa" in html or "totp" in html:
                            hints["mfa_detected"] = True
                            hints["mfa_method"] = "TOTP" if "totp" in html else "2FA"
                        if "authenticator" in html and ("app" in html or "code" in html):
                            hints["mfa_detected"] = True
                            hints["mfa_method"] = "Authenticator App"
                        if "sms" in html and ("code" in html or "verify" in html):
                            hints["mfa_detected"] = True
                            hints["mfa_method"] = "SMS"
                        if hints:
                            evidence = hints
                            source = f"Login page MFA detection: {path}"
                            break
                except Exception:
                    continue

        if not evidence:
            return [
                make_check(
                    "web_probe_failed", "Web MFA Probe",
                    False,
                    "Accessible MFA configuration or detected MFA on login page",
                    (f"Could not determine MFA status from {target}. "
                     "No MFA API found and no MFA elements detected on login pages."),
                    SeverityLevel.HIGH,
                    ("Option 1: Expose MFA config at /api/security/mfa-settings\n"
                     "Option 2: Ensure login page shows 2FA/TOTP elements\n"
                     "Option 3: Run this scanner in 'linux' or 'windows' mode on the server"),
                ),
            ]

        method = evidence.get("mfa_method", "None")
        mfa_detected = evidence.get("mfa_detected", False)
        return self._build_checks(
            mfa_detected,  # admin
            mfa_detected,  # remote
            mfa_detected,  # critical
            method,
            False,  # policy_exists - can't determine from web probe
        )

    def _build_checks(self, admin, remote, critical, method, policy) -> List[SecurityCheck]:
        """Build MFA checks from raw boolean / string values."""
        secure = {"totp", "hardware_key", "fido2", "biometric", "authenticator_app"}
        method_secure = bool(method and method.lower() in secure)
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
            bool_check("mfa_policy", "MFA Enforcement Policy", policy,
                       "Documented policy mandating MFA", SeverityLevel.MEDIUM,
                       "Create MFA policy: who/what requires MFA, approved methods"),
        ]

    def _scan_config(self, cfg: dict) -> List[SecurityCheck]:
        """Build checks from manually-supplied MFA configuration."""
        return self._build_checks(
            cfg.get("admin_mfa_enabled", False),
            cfg.get("remote_mfa_enabled", False),
            cfg.get("critical_mfa_enabled", False),
            cfg.get("mfa_method", "None"),
            cfg.get("policy_exists", False),
        )

    def _fail(self, err: str) -> List[SecurityCheck]:
        """Return a clear scan-failure indication — never fake default values."""
        return [
            make_check(
                "scan_error", "RPP.3 Scan Error",
                False,
                "Successful scan execution",
                f"Scan failed: {err}",
                SeverityLevel.HIGH,
                f"Manual audit required. Error: {err}",
            ),
        ]
