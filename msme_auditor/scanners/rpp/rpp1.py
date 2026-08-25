"""
RPP.1 — Password Complexity & Expiry
=====================================
CERT-In: Enforce strong passwords (8–12+ chars, mixed case, numbers, special chars).
Set expiry intervals and restrict reuse.
"""

import re
import subprocess
import tempfile
from pathlib import Path
from typing import List

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, build_result
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck


class RPP1Scanner(BaseScanner):
    scanner_id = "rpp1"
    name = "RPP.1 — Password Complexity & Expiry"
    description = (
        "Enforce strong, unique passwords: 8–12+ chars, mixed case, numbers, "
        "special chars. Set expiry and restrict reuse."
    )
    category = "RPP"
    target_types = ["web", "windows", "linux"]
    input_fields = [
        {"name": "target_type", "label": "Scan Target", "field_type": "select",
         "options": ["web", "windows", "linux"], "default": "web",
         "help_text": "What system to scan"},
        {"name": "target", "label": "Target URL / Host", "field_type": "text",
         "placeholder": "http://localhost:8765",
         "help_text": "URL for web scans, hostname for OS scans"},
        {"name": "min_length", "label": "Minimum Password Length", "field_type": "number",
         "default": 8, "min_value": 1, "max_value": 128,
         "help_text": "Minimum characters required (CERT-In: 8–12)"},
        {"name": "require_uppercase", "label": "Require Uppercase Letters", "field_type": "boolean",
         "default": True, "help_text": "Must contain A–Z"},
        {"name": "require_lowercase", "label": "Require Lowercase Letters", "field_type": "boolean",
         "default": True, "help_text": "Must contain a–z"},
        {"name": "require_numbers", "label": "Require Numbers", "field_type": "boolean",
         "default": True, "help_text": "Must contain 0–9"},
        {"name": "require_special_chars", "label": "Require Special Characters", "field_type": "boolean",
         "default": True, "help_text": "Must contain !@#$%^&* etc."},
        {"name": "max_age_days", "label": "Max Password Age (days)", "field_type": "number",
         "default": 90, "min_value": 0, "max_value": 365,
         "help_text": "Password expiry in days (0 = never, CERT-In: ≤90)"},
        {"name": "history_count", "label": "Password History Count", "field_type": "number",
         "default": 5, "min_value": 0, "max_value": 24,
         "help_text": "Remember last N passwords (CERT-In: ≥5)"},
        {"name": "education_policy_exists", "label": "User Education Policy Exists", "field_type": "boolean",
         "default": False, "help_text": "Documented policy against credential sharing"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Dispatch to platform-specific scanner based on target type."""
        cfg = sc.config
        target_type = sc.target_type

        if target_type == "windows":
            return self._scan_windows()
        elif target_type == "linux":
            return self._scan_linux()
        elif target_type == "web" and sc.target:
            return self._scan_web(sc.target)
        else:
            return self._scan_config(cfg)

    def _scan_windows(self) -> List[SecurityCheck]:
        """Scan Windows password policy via ``net accounts`` + ``secedit``."""
        try:
            result = subprocess.run(["net", "accounts"], capture_output=True, text=True, timeout=10)
            output = result.stdout
            min_len = max_age = history = 0
            complexity = False

            for line in output.split("\n"):
                if "Minimum password length" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        min_len = int(m.group())
                elif "Maximum password age" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        max_age = int(m.group())
                elif "Password history length" in line:
                    m = re.search(r"\d+", line)
                    if m:
                        history = int(m.group())

            try:
                cfg_path = Path(tempfile.gettempdir()) / "rpp1_secpol.cfg"
                subprocess.run(
                    ["secedit", "/export", "/cfg", str(cfg_path), "/quiet"],
                    capture_output=True, text=True, timeout=15,
                )
                if cfg_path.exists():
                    content = cfg_path.read_text(encoding="utf-16-le", errors="ignore")
                    m = re.search(r"PasswordComplexity\s*=\s*(\d+)", content)
                    if m:
                        complexity = int(m.group(1)) == 1
            except Exception:
                pass

            return [
                make_check("min_length", "Minimum Password Length", min_len >= 8,
                           "At least 8 characters", f"{min_len} characters", SeverityLevel.CRITICAL,
                           "Windows: net accounts /minpwlen:8"),
                make_check("uppercase", "Uppercase Required", complexity, "Required", "Enabled" if complexity else "Disabled",
                           SeverityLevel.HIGH, "Windows: net accounts /minupper:1"),
                make_check("lowercase", "Lowercase Required", complexity, "Required", "Enabled" if complexity else "Disabled",
                           SeverityLevel.HIGH, "Windows: net accounts /minlower:1"),
                make_check("numbers", "Numbers Required", complexity, "Required", "Enabled" if complexity else "Disabled",
                           SeverityLevel.HIGH, "Windows: net accounts /mindigits:1"),
                make_check("special", "Special Chars Required", complexity, "Required", "Enabled" if complexity else "Disabled",
                           SeverityLevel.HIGH, "Windows: net accounts /minspecial:1"),
                make_check("expiry", "Password Expiry", 0 < max_age <= 90,
                           "≤90 days", f"{max_age} days" if max_age else "Disabled",
                           SeverityLevel.HIGH, "Windows: net accounts /maxpwage:90"),
                make_check("history", "Password History", history >= 5,
                           "≥5 previous passwords", f"{history} remembered",
                           SeverityLevel.MEDIUM, "Windows: net accounts /uniquepw:5"),
                make_check("education", "User Education Policy", False,
                           "Documented policy", "Not found", SeverityLevel.MEDIUM,
                           "Create a password policy document and conduct quarterly training."),
            ]
        except Exception as e:
            return self._fail(str(e))

    def _scan_linux(self) -> List[SecurityCheck]:
        """Scan Linux password policy via ``/etc/login.defs`` and ``pwquality.conf``."""
        min_len = max_age = history = 0
        ucredit = lcredit = dcredit = ocredit = 0

        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            try:
                for line in login_defs.read_text().split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        if parts[0] == "PASS_MIN_LEN":
                            min_len = int(parts[1])
                        elif parts[0] == "PASS_MAX_DAYS":
                            max_age = int(parts[1])
            except Exception:
                pass

        pwquality = Path("/etc/security/pwquality.conf")
        if pwquality.exists():
            try:
                for line in pwquality.read_text().split("\n"):
                    line = line.strip()
                    for key in ("minlen", "ucredit", "lcredit", "dcredit", "ocredit"):
                        if line.startswith(key):
                            m = re.search(r"-?\d+", line)
                            if m:
                                val = int(m.group())
                                if key == "minlen":
                                    min_len = val
                                elif key == "ucredit":
                                    ucredit = val
                                elif key == "lcredit":
                                    lcredit = val
                                elif key == "dcredit":
                                    dcredit = val
                                elif key == "ocredit":
                                    ocredit = val
            except Exception:
                pass

        return [
            make_check("min_length", "Minimum Password Length", min_len >= 8,
                       "At least 8 characters", f"{min_len} characters", SeverityLevel.CRITICAL,
                       "Edit /etc/security/pwquality.conf → minlen = 8"),
            make_check("uppercase", "Uppercase Required", ucredit < 0, "Required",
                       "Enabled" if ucredit < 0 else "Disabled", SeverityLevel.HIGH,
                       "Edit /etc/security/pwquality.conf → ucredit = -1"),
            make_check("lowercase", "Lowercase Required", lcredit < 0, "Required",
                       "Enabled" if lcredit < 0 else "Disabled", SeverityLevel.HIGH,
                       "Edit /etc/security/pwquality.conf → lcredit = -1"),
            make_check("numbers", "Numbers Required", dcredit < 0, "Required",
                       "Enabled" if dcredit < 0 else "Disabled", SeverityLevel.HIGH,
                       "Edit /etc/security/pwquality.conf → dcredit = -1"),
            make_check("special", "Special Chars Required", ocredit < 0, "Required",
                       "Enabled" if ocredit < 0 else "Disabled", SeverityLevel.HIGH,
                       "Edit /etc/security/pwquality.conf → ocredit = -1"),
            make_check("expiry", "Password Expiry", 0 < max_age <= 90,
                       "≤90 days", f"{max_age} days" if max_age else "Disabled",
                       SeverityLevel.HIGH, "Edit /etc/login.defs → PASS_MAX_DAYS 90"),
            make_check("history", "Password History", history >= 5,
                       "≥5 previous passwords", f"{history} remembered",
                       SeverityLevel.MEDIUM, "Configure pam_pwhistory in /etc/pam.d/common-password"),
            make_check("education", "User Education Policy", False,
                       "Documented policy", "Not found", SeverityLevel.MEDIUM,
                       "Create a password policy document and conduct quarterly training."),
        ]

    def _scan_web(self, target: str) -> List[SecurityCheck]:
        """Query a web API endpoint for password-policy configuration."""
        try:
            import httpx
            resp = httpx.get(f"{target}/api/security/password-policy", timeout=10)
            policy = resp.json()
            return [
                make_check("min_length", "Minimum Password Length",
                           policy.get("min_length", 0) >= 8,
                           "At least 8 characters", f"{policy.get('min_length', 0)} characters",
                           SeverityLevel.CRITICAL, "Set min_length ≥ 8"),
                make_check("uppercase", "Uppercase Required", policy.get("require_uppercase", False),
                           "Required", "Enabled" if policy.get("require_uppercase") else "Disabled",
                           SeverityLevel.HIGH, "Enable require_uppercase"),
                make_check("lowercase", "Lowercase Required", policy.get("require_lowercase", False),
                           "Required", "Enabled" if policy.get("require_lowercase") else "Disabled",
                           SeverityLevel.HIGH, "Enable require_lowercase"),
                make_check("numbers", "Numbers Required", policy.get("require_numbers", False),
                           "Required", "Enabled" if policy.get("require_numbers") else "Disabled",
                           SeverityLevel.HIGH, "Enable require_numbers"),
                make_check("special", "Special Chars Required", policy.get("require_special_chars", False),
                           "Required", "Enabled" if policy.get("require_special_chars") else "Disabled",
                           SeverityLevel.HIGH, "Enable require_special_chars"),
                make_check("expiry", "Password Expiry", 0 < policy.get("max_age_days", 0) <= 90,
                           "≤90 days", f"{policy.get('max_age_days', 0)} days",
                           SeverityLevel.HIGH, "Set max_age_days ≤ 90"),
                make_check("history", "Password History", policy.get("history_count", 0) >= 5,
                           "≥5 previous passwords", f"{policy.get('history_count', 0)} remembered",
                           SeverityLevel.MEDIUM, "Set history_count ≥ 5"),
                make_check("education", "User Education Policy", policy.get("education_policy_exists", False),
                           "Documented policy", "Enabled" if policy.get("education_policy_exists") else "Not found",
                           SeverityLevel.MEDIUM, "Create a password policy document"),
            ]
        except Exception as e:
            return self._fail(str(e))

    def _scan_config(self, cfg: dict) -> List[SecurityCheck]:
        """Build checks from manually-supplied configuration values."""
        return [
            make_check("min_length", "Minimum Password Length", cfg.get("min_length", 0) >= 8,
                       "At least 8 characters", f"{cfg.get('min_length', 0)} characters",
                       SeverityLevel.CRITICAL, "Set min_length ≥ 8"),
            make_check("uppercase", "Uppercase Required", cfg.get("require_uppercase", False),
                       "Required", "Enabled" if cfg.get("require_uppercase") else "Disabled",
                       SeverityLevel.HIGH, "Enable require_uppercase"),
            make_check("lowercase", "Lowercase Required", cfg.get("require_lowercase", False),
                       "Required", "Enabled" if cfg.get("require_lowercase") else "Disabled",
                       SeverityLevel.HIGH, "Enable require_lowercase"),
            make_check("numbers", "Numbers Required", cfg.get("require_numbers", False),
                       "Required", "Enabled" if cfg.get("require_numbers") else "Disabled",
                       SeverityLevel.HIGH, "Enable require_numbers"),
            make_check("special", "Special Chars Required", cfg.get("require_special_chars", False),
                       "Required", "Enabled" if cfg.get("require_special_chars") else "Disabled",
                       SeverityLevel.HIGH, "Enable require_special_chars"),
            make_check("expiry", "Password Expiry", 0 < cfg.get("max_age_days", 0) <= 90,
                       "≤90 days", f"{cfg.get('max_age_days', 0)} days",
                       SeverityLevel.HIGH, "Set max_age_days ≤ 90"),
            make_check("history", "Password History", cfg.get("history_count", 0) >= 5,
                       "≥5 previous passwords", f"{cfg.get('history_count', 0)} remembered",
                       SeverityLevel.MEDIUM, "Set history_count ≥ 5"),
            make_check("education", "User Education Policy", cfg.get("education_policy_exists", False),
                       "Documented policy", "Enabled" if cfg.get("education_policy_exists") else "Not found",
                       SeverityLevel.MEDIUM, "Create a password policy document"),
        ]

    def _fail(self, err: str) -> List[SecurityCheck]:
        """Return a clear scan-failure indication — never fake default values."""
        return [
            make_check(
                "scan_error", "RPP.1 Scan Error",
                False,
                "Successful scan execution",
                f"Scan failed: {err}",
                SeverityLevel.HIGH,
                f"Manual audit required. Error: {err}",
            ),
        ]
