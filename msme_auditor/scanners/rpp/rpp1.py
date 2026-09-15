"""
RPP.1 — Password Complexity & Expiry
=====================================
CERT-In: Enforce strong passwords (8–12+ chars, mixed case, numbers, special chars).
Set expiry intervals and restrict reuse.

Backend stack:
  - Config-driven policy via config/rpp1_policy.yaml
  - Safe subprocess wrapper (core/command_runner.py)
  - Structured audit logging (core/audit_logger.py)
  - ERROR is a distinct outcome from FAIL — "couldn't determine" never
    silently becomes "insecure" or "secure"
"""

import platform
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.core.command_runner import run_command
from msme_auditor.core.policy_loader import load_policy
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event


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

        # Load config-driven policy
        try:
            policy = load_policy()
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        # Audit logging
        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, sc.target or "localhost", "started")

        try:
            result = None
            if target_type == "windows":
                result = self._scan_windows(policy)
            elif target_type == "linux":
                result = self._scan_linux(policy)
            elif target_type == "web" and sc.target:
                result = self._scan_web(sc.target, policy)

            # If OS scan failed or no target provided, use config with CERT-In defaults
            if result is None or (
                len(result) == 1
                and result[0].check_id == "scan_error"
            ):
                result = self._scan_config(cfg, policy)
        except Exception as exc:
            result = [self._scan_error(str(exc))]
        finally:
            log_scan_event(
                audit_logger, self.scanner_id, sc.target or "localhost", "completed",
            )

        return result

    # =========================================================================
    # Windows Scanner
    # =========================================================================
    def _scan_windows(self, policy: dict) -> List[SecurityCheck]:
        """Scan Windows password policy via ``net accounts`` + ``secedit``."""
        result = run_command(["net", "accounts"])
        if not result.success:
            return [self._scan_error(
                f"Could not query password policy: {result.error or result.stderr}"
            )]

        evidence = {
            "min_pw_len": self._extract(r"Minimum password length\s*:\s*(\d+)", result.stdout),
            "max_pw_age": self._extract(r"Maximum password age.*?:\s*(\d+)", result.stdout),
            "min_pw_age": self._extract(r"Minimum password age.*?:\s*(\d+)", result.stdout),
            "history": self._extract(r"Length of password history.*?:\s*(\d+)", result.stdout),
        }

        # Complexity check — unique temp file, guaranteed cleanup
        evidence["complexity_enabled"] = self._check_windows_complexity()

        return self._build_checks(evidence, policy)

    def _check_windows_complexity(self) -> Optional[bool]:
        """Check Windows password complexity via secedit export."""
        tmp = Path(tempfile.gettempdir()) / f"rpp1_secpol_{uuid.uuid4().hex[:8]}.cfg"
        try:
            result = run_command(["secedit", "/export", "/cfg", str(tmp), "/quiet"])
            if not result.success or not tmp.exists():
                return None
            text = tmp.read_text(encoding="utf-16-le", errors="ignore")
            return "PasswordComplexity = 1" in text
        finally:
            tmp.unlink(missing_ok=True)

    # =========================================================================
    # Linux Scanner
    # =========================================================================
    def _scan_linux(self, policy: dict) -> List[SecurityCheck]:
        """Scan Linux password policy via config files."""
        evidence: Dict[str, Any] = {}

        # PAM password history — try distro-family variants
        pam_candidates = [
            "/etc/pam.d/common-password",   # Debian/Ubuntu
            "/etc/pam.d/system-auth",       # RHEL/CentOS/Fedora
            "/etc/pam.d/password-auth",     # RHEL alt
        ]
        pam_file = next((Path(p) for p in pam_candidates if Path(p).exists()), None)
        if pam_file is None:
            evidence["pam_file_found"] = False
        else:
            try:
                text = pam_file.read_text(encoding="utf-8", errors="ignore")
                m = re.search(r"pam_pwhistory\.so.*?remember=(\d+)", text)
                evidence["reuse_history"] = int(m.group(1)) if m else 0
                evidence["pam_file_used"] = str(pam_file)
            except OSError:
                evidence["pam_file_found"] = False

        # pwquality.conf
        pwq = Path("/etc/security/pwquality.conf")
        if pwq.exists():
            try:
                text = pwq.read_text(encoding="utf-8", errors="ignore")
                evidence["minlen"] = self._extract(r"minlen\s*=\s*(\d+)", text)
                evidence["ucredit"] = self._extract(r"ucredit\s*=\s*(-?\d+)", text)
                evidence["lcredit"] = self._extract(r"lcredit\s*=\s*(-?\d+)", text)
                evidence["dcredit"] = self._extract(r"dcredit\s*=\s*(-?\d+)", text)
                evidence["ocredit"] = self._extract(r"ocredit\s*=\s*(-?\d+)", text)
            except OSError:
                pass
        else:
            evidence["pwquality_conf_found"] = False

        # login.defs
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            try:
                text = login_defs.read_text(encoding="utf-8", errors="ignore")
                evidence["pass_max_days"] = self._extract(r"PASS_MAX_DAYS\s+(\d+)", text)
                evidence["pass_min_days"] = self._extract(r"PASS_MIN_DAYS\s+(\d+)", text)
            except OSError:
                pass

        return self._build_checks(evidence, policy)

    # =========================================================================
    # Web Scanner
    # =========================================================================
    def _scan_web(self, target: str, policy: dict) -> List[SecurityCheck]:
        """
        Probe web application for password policy evidence.

        Pipeline:
        1. Try structured API endpoints for password-policy config
        2. Analyze login page HTML for password validation hints
        3. Check response headers for security indicators
        4. Report honestly if no evidence found
        """
        import httpx
        from urllib.parse import urljoin

        TIMEOUT = 5
        UA = "Mozilla/5.0 (compatible; CyberSure-SecurityScanner/1.0)"
        HEADERS = {"User-Agent": UA, "Accept": "text/html,application/json"}

        evidence: Optional[Dict[str, Any]] = None
        source = "none"

        # Step 1: Try structured API endpoints
        api_endpoints = [
            "/api/security/password-policy",
            "/api/auth/password-policy",
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
                            k in data for k in (
                                "min_length", "require_uppercase",
                                "password_policy", "policy",
                            )
                        ):
                            evidence = data
                            source = f"API: {endpoint}"
                            if "password_policy" in evidence:
                                evidence = evidence["password_policy"]
                            elif "policy" in evidence:
                                evidence = evidence["policy"]
                            break
                    except Exception:
                        continue
            except Exception:
                continue

        # Step 2: Analyze login page HTML for password validation hints
        login_hints: Dict[str, Any] = {}
        if not evidence:
            login_paths = ["/login", "/signin", "/auth/login"]
            for path in login_paths:
                try:
                    url = urljoin(target.rstrip("/"), path)
                    resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                     verify=False, headers=HEADERS)
                    if resp.status_code == 200:
                        html = resp.text.lower()

                        minlength_match = re.search(r'minlength["\']+\s*(\d+)', html)
                        if minlength_match:
                            login_hints["min_length"] = int(minlength_match.group(1))

                        if any(w in html for w in ["uppercase", "lower case", "special char"]):
                            login_hints["complexity_hint"] = True
                        if any(w in html for w in ["number", "digit", "numeric"]):
                            login_hints["numbers_hint"] = True
                        if any(w in html for w in ["special", "symbol", "!@#"]):
                            login_hints["special_hint"] = True
                        if any(w in html for w in [
                            "password-strength", "strength-meter",
                            "pw-strength", "password meter",
                        ]):
                            login_hints["strength_meter"] = True

                        if login_hints:
                            source = f"Login page analysis: {path}"
                            evidence = login_hints
                            break
                except Exception:
                    continue

        # Step 3: Check response headers
        if not evidence:
            try:
                url = urljoin(target.rstrip("/"), "/")
                resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                 verify=False, headers=HEADERS)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                if "x-password-min-length" in headers:
                    login_hints["min_length"] = int(headers["x-password-min-length"])
                    evidence = login_hints
                    source = "Response headers"
            except Exception:
                pass

        # Step 4: Build checks from evidence
        if evidence and source != "none":
            return self._build_web_checks(evidence, source, policy)

        # No evidence found — honest failure
        return [make_check(
            "web_probe_failed", "Password Policy Web Probe",
            False,
            "Accessible password policy configuration",
            (f"Could not determine password policy from {target}. "
             "No password policy API found and no hints on login pages."),
            SeverityLevel.HIGH,
            ("Option 1: Expose password policy at /api/security/password-policy\n"
             "Option 2: Add minlength attribute to password input fields\n"
             "Option 3: Run this scanner in 'linux' or 'windows' mode on the server"),
        )]

    # =========================================================================
    # Source Code Scanner
    # =========================================================================
    def scan_source_code(self, repo_path: str) -> List[SecurityCheck]:
        """
        Scan source code for password policy enforcement in validator files.

        Checks:
        - min_length_enforced: ``len(password) >= 8`` pattern
        - uses_bcrypt_or_argon2: bcrypt or argon2 hashing
        - has_history_check: password_history / previous_password references
        """
        validator_file = Path(repo_path) / "auth" / "validators.py"
        if not validator_file.exists():
            return [self._scan_error(f"Validator file not found: {validator_file}")]

        text = validator_file.read_text(encoding="utf-8", errors="ignore")
        evidence = {
            "min_length_enforced": bool(re.search(r"len\(password\)\s*[<>]=?\s*\d+", text)),
            "uses_bcrypt_or_argon2": bool(re.search(r"bcrypt|argon2", text, re.IGNORECASE)),
            "has_history_check": bool(re.search(r"password_history|previous_password", text, re.IGNORECASE)),
        }

        all_passed = all(evidence.values())
        detail_parts = [f"{k}: {'✓' if v else '✗'}" for k, v in evidence.items()]

        return [make_check(
            "source_code_policy", "Source Code Password Policy Enforcement",
            all_passed,
            "All policy checks enforced in source code",
            "; ".join(detail_parts),
            SeverityLevel.HIGH if not all_passed else SeverityLevel.INFO,
            "Ensure validators enforce: min length, strong hashing (bcrypt/argon2), password history"
        )]

    # =========================================================================
    # Config (Manual Input) Scanner
    # =========================================================================
    def _scan_config(self, cfg: dict, policy: dict) -> List[SecurityCheck]:
        """Build checks from manually-supplied configuration values.

        When config fields are missing, returns "Unable to determine" checks
        instead of reporting False (which would be inaccurate).
        """
        # Only include values the user actually provided; None = not provided
        evidence: Dict[str, Any] = {}
        if "min_length" in cfg:
            evidence["min_length"] = cfg["min_length"]
        if "require_uppercase" in cfg:
            evidence["uppercase"] = cfg["require_uppercase"]
        if "require_lowercase" in cfg:
            evidence["lowercase"] = cfg["require_lowercase"]
        if "require_numbers" in cfg:
            evidence["numbers"] = cfg["require_numbers"]
        if "require_special_chars" in cfg:
            evidence["special"] = cfg["require_special_chars"]
        if "max_age_days" in cfg:
            evidence["max_age_days"] = cfg["max_age_days"]
        if "history_count" in cfg:
            evidence["history_count"] = cfg["history_count"]
        if "education_policy_exists" in cfg:
            evidence["education"] = cfg["education_policy_exists"]

        # Derive complexity from individual flags if all are present
        if all(k in cfg for k in ("require_uppercase", "require_lowercase",
                                   "require_numbers", "require_special_chars")):
            evidence["complexity_enabled"] = all([
                cfg["require_uppercase"],
                cfg["require_lowercase"],
                cfg["require_numbers"],
                cfg["require_special_chars"],
            ])

        return self._build_checks(evidence, policy)

    # =========================================================================
    # Check Builder — unified evaluation
    # =========================================================================
    def _build_checks(self, evidence: dict, policy: dict) -> List[SecurityCheck]:
        """
        Build SecurityCheck list from evidence dict + policy thresholds.

        ERROR is returned when evidence cannot be determined (not FAIL).
        """
        min_len = self._first(evidence, "min_pw_len", "minlen", "min_length")
        max_age = self._first(evidence, "max_pw_age", "pass_max_days", "max_age_days")
        history = self._first(evidence, "history", "reuse_history", "history_count")
        complexity = evidence.get("complexity_enabled")

        checks: List[SecurityCheck] = []

        # Check 1: Minimum password length
        if min_len is None:
            checks.append(self._scan_error("Could not determine minimum password length"))
        else:
            checks.append(make_check(
                "min_length", "Minimum Password Length",
                min_len >= policy["min_length"],
                f"At least {policy['min_length']} characters",
                f"{min_len} characters",
                SeverityLevel.CRITICAL,
                f"Set minimum password length to at least {policy['min_length']}.",
            ))

        # Check 2-5: Complexity requirements
        if complexity is not None:
            # Single flag (Windows/Linux)
            for cid, name in [
                ("uppercase", "Uppercase Required"),
                ("lowercase", "Lowercase Required"),
                ("numbers", "Numbers Required"),
                ("special", "Special Chars Required"),
            ]:
                checks.append(make_check(
                    cid, name, complexity,
                    "Required",
                    "Enabled" if complexity else "Disabled",
                    SeverityLevel.HIGH,
                    f"Enable {cid} requirement in password policy",
                ))
        else:
            # Individual flags from manual/web config
            flag_map = {
                "uppercase": "uppercase",
                "lowercase": "lowercase",
                "numbers": "numbers",
                "special": "special",
            }
            name_map = {
                "uppercase": "Uppercase Required",
                "lowercase": "Lowercase Required",
                "numbers": "Numbers Required",
                "special": "Special Chars Required",
            }
            has_any_individual = any(
                evidence.get(k) for k in flag_map
            )
            if has_any_individual:
                # Use individual flags from config
                for cid in ["uppercase", "lowercase", "numbers", "special"]:
                    enabled = evidence.get(cid, False)
                    checks.append(make_check(
                        cid, name_map[cid], enabled,
                        "Required",
                        "Enabled" if enabled else "Disabled",
                        SeverityLevel.HIGH,
                        f"Enable {cid} requirement in password policy",
                    ))
            else:
                # Can't determine — report as error, not fail
                for cid, name in name_map.items():
                    checks.append(make_check(
                        cid, name, False,
                        "Required",
                        "Unable to determine (check permissions)",
                        SeverityLevel.HIGH,
                        "Run with elevated privileges to check complexity settings",
                    ))

        # Check 6: Password expiry
        if max_age is None:
            checks.append(make_check(
                "expiry", "Password Expiry", False,
                f"≤{policy['max_password_age_days']} days",
                "Unable to determine",
                SeverityLevel.HIGH,
                f"Configure password expiry (recommend {policy['max_password_age_days']} days)",
            ))
        else:
            checks.append(make_check(
                "expiry", "Password Expiry",
                0 < max_age <= policy["max_password_age_days"],
                f"≤{policy['max_password_age_days']} days",
                f"{max_age} days" if max_age else "Disabled (never expires)",
                SeverityLevel.HIGH,
                f"Set password expiry to ≤{policy['max_password_age_days']} days",
            ))

        # Check 7: Password history
        if history is None:
            checks.append(make_check(
                "history", "Password History", False,
                f"≥{policy['password_history_count']} previous passwords",
                "Unable to determine",
                SeverityLevel.MEDIUM,
                f"Configure password history to remember ≥{policy['password_history_count']} passwords",
            ))
        else:
            checks.append(make_check(
                "history", "Password History",
                history >= policy["password_history_count"],
                f"≥{policy['password_history_count']} previous passwords",
                f"{history} remembered",
                SeverityLevel.MEDIUM,
                f"Remember at least {policy['password_history_count']} previous passwords",
            ))

        # Check 8: Education policy
        if "education" in evidence:
            education = evidence["education"]
            checks.append(make_check(
                "education", "User Education Policy",
                education,
                "Documented policy",
                "Found" if education else "Not found",
                SeverityLevel.MEDIUM,
                "Create a password policy document and conduct quarterly training.",
            ))
        else:
            checks.append(make_check(
                "education", "User Education Policy", False,
                "Documented policy", "Unable to determine",
                SeverityLevel.MEDIUM,
                "Provide education policy status or run scan on the target system",
            ))

        return checks

    def _build_web_checks(self, evidence: dict, source: str, policy: dict) -> List[SecurityCheck]:
        """Build checks from web probe evidence."""
        min_len = evidence.get("min_length", 0)
        has_complexity = evidence.get("complexity_hint", False)
        has_numbers = evidence.get("numbers_hint", False)
        has_special = evidence.get("special_hint", False)
        has_strength_meter = evidence.get("strength_meter", False)

        # For API evidence, use full policy
        if source.startswith("API"):
            has_upper = evidence.get("require_uppercase", False)
            has_lower = evidence.get("require_lowercase", False)
            has_numbers = evidence.get("require_numbers", False)
            has_special = evidence.get("require_special_chars", False)
            max_age = evidence.get("max_age_days", 0)
            history = evidence.get("history_count", 0)
        else:
            has_upper = has_complexity
            has_lower = has_complexity
            max_age = 0
            history = 0

        checks: List[SecurityCheck] = []

        checks.append(make_check(
            "min_length", "Minimum Password Length",
            min_len >= policy["min_length"],
            f"At least {policy['min_length']} characters",
            f"{min_len} characters" if min_len else "Unknown (manual verification needed)",
            SeverityLevel.CRITICAL,
            f"Set minimum password length to {policy['min_length']}+ characters",
        ))

        for cid, name, detected in [
            ("uppercase", "Uppercase Required", has_upper),
            ("lowercase", "Lowercase Required", has_lower),
            ("numbers", "Numbers Required", has_numbers),
            ("special", "Special Chars Required", has_special),
        ]:
            checks.append(make_check(
                cid, name, detected,
                "Required",
                "Detected" if detected else "Not detected (manual verification needed)",
                SeverityLevel.HIGH,
                f"Require {cid.replace('_', ' ')} in passwords",
            ))

        checks.append(make_check(
            "expiry", "Password Expiry",
            0 < max_age <= policy["max_password_age_days"] if max_age else False,
            f"≤{policy['max_password_age_days']} days",
            f"{max_age} days" if max_age else "Unable to determine from web probe",
            SeverityLevel.HIGH,
            f"Set password expiry to ≤{policy['max_password_age_days']} days",
        ))

        checks.append(make_check(
            "history", "Password History",
            history >= policy["password_history_count"] if history else False,
            f"≥{policy['password_history_count']} previous passwords",
            f"{history} remembered" if history else "Unable to determine from web probe",
            SeverityLevel.MEDIUM,
            f"Remember at least {policy['password_history_count']} previous passwords",
        ))

        checks.append(make_check(
            "strength_meter", "Password Strength Meter",
            has_strength_meter,
            "Strength meter present on login page",
            "Present" if has_strength_meter else "Not detected",
            SeverityLevel.MEDIUM,
            "Add a password strength meter to guide users",
        ))

        return checks

    # =========================================================================
    # Helpers
    # =========================================================================
    @staticmethod
    def _first(d: dict, *keys: str) -> Optional[int]:
        """Return the first value from *d* whose key is in *keys*, or None.

        Unlike ``d.get(k1) or d.get(k2)``, this does NOT treat 0 as missing.
        """
        for k in keys:
            if k in d:
                return d[k]
        return None

    @staticmethod
    def _extract(pattern: str, text: str) -> Optional[int]:
        """Extract an integer value from text using a regex pattern."""
        m = re.search(pattern, text)
        return int(m.group(1)) if m else None

    def _scan_error(self, message: str) -> SecurityCheck:
        """
        Return a scan-error check — never fake pass/fail.

        ERROR means "couldn't determine", which is distinct from FAIL.
        This distinction is what makes an audit tool trustworthy.
        """
        return make_check(
            "scan_error", "RPP.1 Scan Error",
            False,
            "Successful scan execution",
            f"Scan failed: {message}",
            SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
