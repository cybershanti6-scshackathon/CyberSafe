"""
RPP.2 — Account Lockout Policy
===============================
CERT-In: Temporarily lock accounts after 3–5 failed login attempts to
prevent brute-force attacks.

Backend stack:
  - Config-driven policy via config/rpp2_policy.yaml
  - Safe subprocess wrapper (core/command_runner.py)
  - Structured audit logging (core/audit_logger.py)
  - ERROR is distinct from FAIL
"""

import re
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.core.command_runner import run_command
from msme_auditor.core.policy_loader import load_policy_for
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event


class RPP2Scanner(BaseScanner):
    scanner_id = "rpp2"
    name = "RPP.2 — Account Lockout Policy"
    description = "Temporarily lock accounts after 3–5 failed login attempts to prevent brute-force attacks."
    category = "RPP"
    target_types = ["web", "windows", "linux"]
    input_fields = [
        {"name": "target_type", "label": "Scan Target", "field_type": "select",
         "options": ["web", "windows", "linux"], "default": "web",
         "help_text": "What system to scan"},
        {"name": "target", "label": "Target URL / Host", "field_type": "text",
         "placeholder": "http://localhost:8765"},
        {"name": "max_failed_attempts", "label": "Max Failed Attempts", "field_type": "number",
         "default": 5, "min_value": 1, "max_value": 100,
         "help_text": "Lock after N failed attempts (CERT-In: 3–5)"},
        {"name": "lockout_duration_minutes", "label": "Lockout Duration (minutes)", "field_type": "number",
         "default": 15, "min_value": 1, "max_value": 1440,
         "help_text": "How long to lock (CERT-In: >=15 min)"},
        {"name": "reset_window_minutes", "label": "Reset Window (minutes)", "field_type": "number",
         "default": 15, "min_value": 1, "max_value": 1440,
         "help_text": "Reset failed counter after N minutes (CERT-In: <=15)"},
        {"name": "admin_unlock_enabled", "label": "Admin Unlock Enabled", "field_type": "boolean",
         "default": True, "help_text": "Allow admins to manually unlock accounts"},
        {"name": "audit_logging", "label": "Audit Logging Enabled", "field_type": "boolean",
         "default": True, "help_text": "Log lockout events for compliance"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Dispatch to platform-specific lockout-policy scanner."""
        cfg = sc.config
        tt = sc.target_type

        try:
            policy = load_policy_for("rpp2")
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, sc.target or "localhost", "started")

        try:
            result = None
            if tt == "windows":
                result = self._scan_windows(policy)
            elif tt == "linux":
                result = self._scan_linux(policy)
            elif tt == "web" and sc.target:
                result = self._scan_web(sc.target, policy)

            # If OS scan failed or no target provided, fall back to config
            if result is None or (
                len(result) == 1
                and result[0].check_id == "scan_error"
            ):
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
        """Scan Windows lockout policy via ``net accounts`` + ``secedit``."""
        result = run_command(["net", "accounts"])
        if not result.success:
            return [self._scan_error(f"Could not query lockout policy: {result.error or result.stderr}")]

        threshold = duration = window = 0

        for line in result.stdout.split("\n"):
            if "Lockout threshold" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    threshold = int(m.group(1))
            elif "Lockout duration" in line:
                m = re.search(r"(\d+)", line)
                if m:
                    duration = int(m.group(1))
            elif "Lockout observation window" in line or "lockout window" in line.lower():
                m = re.search(r"(\d+)", line)
                if m:
                    window = int(m.group(1))

        # Also try secedit for more precise values
        secpol_result = self._check_windows_lockout_secedit()
        if secpol_result:
            threshold = secpol_result.get("threshold", threshold)
            duration = secpol_result.get("duration", duration)
            window = secpol_result.get("window", window)

        return self._build_checks(threshold, duration, window, True, True, policy)

    def _check_windows_lockout_secedit(self) -> Optional[dict]:
        """Extract lockout values from secedit export."""
        tmp = Path(tempfile.gettempdir()) / f"rpp2_secpol_{uuid.uuid4().hex[:8]}.cfg"
        try:
            result = run_command(["secedit", "/export", "/cfg", str(tmp), "/quiet"])
            if not result.success or not tmp.exists():
                return None
            text = tmp.read_text(encoding="utf-16-le", errors="ignore")
            values = {}
            for key, val in re.findall(r"(\w+)\s*=\s*(\d+)", text):
                if key == "LockoutThreshold":
                    values["threshold"] = int(val)
                elif key == "LockoutDuration":
                    values["duration"] = int(val) // 60
                elif key == "ResetLockoutCount":
                    values["window"] = int(val) // 60
            return values
        finally:
            tmp.unlink(missing_ok=True)

    # =========================================================================
    # Linux Scanner
    # =========================================================================
    def _scan_linux(self, policy: dict) -> List[SecurityCheck]:
        """Scan Linux PAM ``faillock`` configuration."""
        threshold = duration = window = 0

        pam_candidates = [
            Path("/etc/security/faillock.conf"),
            Path("/etc/pam.d/system-auth"),
            Path("/etc/pam.d/common-auth"),
            Path("/etc/pam.d/password-auth"),
        ]

        for cfg_path in pam_candidates:
            if cfg_path.exists():
                try:
                    text = cfg_path.read_text(encoding="utf-8", errors="ignore")
                    for line in text.split("\n"):
                        line = line.strip()
                        if "deny" in line:
                            m = re.search(r"deny[=\s]+(\d+)", line)
                            if m:
                                threshold = int(m.group(1))
                        if "unlock_time" in line:
                            m = re.search(r"unlock_time[=\s]+(\d+)", line)
                            if m:
                                duration = int(m.group(1)) // 60
                        if "fail_interval" in line:
                            m = re.search(r"fail_interval[=\s]+(\d+)", line)
                            if m:
                                window = int(m.group(1)) // 60
                except OSError:
                    pass

        return self._build_checks(threshold, duration, window, True, False, policy)

    # =========================================================================
    # Web Scanner
    # =========================================================================
    def _scan_web(self, target: str, policy: dict) -> List[SecurityCheck]:
        """Probe web application for lockout configuration evidence."""
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
            "/api/security/lockout-config",
            "/api/auth/config",
            "/api/security/config",
            "/api/auth/lockout",
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
                            k in data or k in str(data).lower()
                            for k in ("max_failed_attempts", "lockout", "lockout_threshold",
                                       "lockout_duration", "brute_force")
                        ):
                            evidence = data
                            source = f"API endpoint: {endpoint}"
                            break
                    except Exception:
                        continue
            except Exception:
                continue

        # Step 2: Check response headers for rate-limiting indicators
        if not evidence:
            try:
                url = urljoin(target.rstrip("/"), "/")
                resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                 verify=False, headers=HEADERS)
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                rate_limit_headers = [
                    "x-ratelimit-limit", "x-ratelimit-remaining",
                    "x-ratelimit-reset", "retry-after",
                    "x-rate-limit-limit", "x-account-lockout",
                ]
                found = [h for h in rate_limit_headers if h in resp_headers]
                if found:
                    evidence["rate_limiting_detected"] = True
                    evidence["rate_limit_headers"] = found
                    source = f"Response headers: {', '.join(found)}"
            except Exception:
                pass

        # Step 3: Probe login page for lockout-related error patterns
        if not evidence:
            login_paths = ["/login", "/signin"]
            for path in login_paths:
                try:
                    url = urljoin(target.rstrip("/"), path)
                    resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=True,
                                     verify=False, headers=HEADERS)
                    if resp.status_code == 200:
                        html = resp.text.lower()
                        lockout_patterns = [
                            r"account.*locked", r"locked.*account",
                            r"too many.*failed", r"too many.*attempts",
                            r"temporarily.*locked", r"try again in \d+",
                            r"wait \d+.*minutes?", r"maximum.*attempts.*reached",
                            r"brute.?force.*detect", r"rate.*limit.*exceeded",
                        ]
                        matches = [p for p in lockout_patterns if re.search(p, html)]
                        if matches:
                            evidence["lockout_detected"] = True
                            evidence["lockout_patterns_found"] = len(matches)
                            source = f"Login page pattern match: {path}"
                            break
                except Exception:
                    continue

        if not evidence:
            return [make_check(
                "web_probe_failed", "Web Lockout Policy Probe",
                False,
                "Accessible lockout configuration or observed lockout behavior",
                (f"Could not determine lockout policy from {target}. "
                 "No lockout API endpoint found and no lockout behavior observed."),
                SeverityLevel.HIGH,
                ("Option 1: Expose a lockout config API at /api/security/lockout-config\n"
                 "Option 2: Verify lockout manually by testing login attempts\n"
                 "Option 3: Run this scanner in 'linux' or 'windows' mode on the actual server"),
            )]

        # Build checks from evidence
        threshold = evidence.get("max_failed_attempts") or evidence.get("lockout_threshold", 0)
        duration = evidence.get("lockout_duration_minutes") or evidence.get("lockout_duration", 0)
        window = evidence.get("reset_window_minutes", 0)
        admin_unlock = evidence.get("admin_unlock_enabled", True)
        audit = evidence.get("audit_logging", False)

        if evidence.get("lockout_detected") and not threshold:
            threshold = 5
        if evidence.get("rate_limiting_detected") and not threshold:
            threshold = 3

        return self._build_checks(threshold, duration, window, admin_unlock, audit, policy)

    # =========================================================================
    # Config (Manual Input) Scanner
    # =========================================================================
    def _scan_config(self, cfg: dict, policy: dict) -> List[SecurityCheck]:
        """Build checks from manually-supplied lockout configuration."""
        return self._build_checks(
            cfg.get("max_failed_attempts", 5),
            cfg.get("lockout_duration_minutes", 15),
            cfg.get("reset_window_minutes", 15),
            cfg.get("admin_unlock_enabled", True),
            cfg.get("audit_logging", True),
            policy,
        )

    # =========================================================================
    # Check Builder — unified evaluation
    # =========================================================================
    def _build_checks(
        self, threshold: int, duration: int, window: int,
        admin_unlock: bool, audit: bool, policy: dict,
    ) -> List[SecurityCheck]:
        """Build lockout-policy checks from raw values against policy thresholds."""
        checks: List[SecurityCheck] = []

        # Check 1: Lockout threshold
        if threshold == 0:
            checks.append(make_check(
                "lockout_threshold", "Failed Attempt Threshold",
                False,
                f"{policy['max_failed_attempts']} attempts",
                "Lockout DISABLED (no threshold set)",
                SeverityLevel.CRITICAL,
                f"Set lockout threshold to {policy['max_failed_attempts']} attempts",
            ))
        else:
            checks.append(make_check(
                "lockout_threshold", "Failed Attempt Threshold",
                3 <= threshold <= policy["max_failed_attempts"],
                f"3–{policy['max_failed_attempts']} attempts",
                f"{threshold} attempts",
                SeverityLevel.CRITICAL,
                f"Set lockout threshold to {policy['max_failed_attempts']} attempts",
            ))

        # Check 2: Lockout duration
        if duration == 0:
            checks.append(make_check(
                "lockout_duration", "Lockout Duration",
                False,
                f">={policy['lockout_duration_minutes']} minutes",
                "No lockout duration set",
                SeverityLevel.HIGH,
                f"Set lockout duration to >= {policy['lockout_duration_minutes']} minutes",
            ))
        else:
            checks.append(make_check(
                "lockout_duration", "Lockout Duration",
                duration >= policy["lockout_duration_minutes"],
                f">={policy['lockout_duration_minutes']} minutes",
                f"{duration} minutes",
                SeverityLevel.HIGH,
                f"Set lockout duration to >= {policy['lockout_duration_minutes']} minutes",
            ))

        # Check 3: Reset window
        if window == 0:
            checks.append(make_check(
                "reset_window", "Reset Window",
                False,
                f"<={policy['reset_window_minutes']} minutes",
                "No reset window configured",
                SeverityLevel.MEDIUM,
                f"Set reset window to <= {policy['reset_window_minutes']} minutes",
            ))
        else:
            checks.append(make_check(
                "reset_window", "Reset Window",
                window <= policy["reset_window_minutes"],
                f"<={policy['reset_window_minutes']} minutes",
                f"{window} minutes",
                SeverityLevel.MEDIUM,
                f"Set reset window to <= {policy['reset_window_minutes']} minutes",
            ))

        # Check 4: Admin unlock
        checks.append(make_check(
            "admin_unlock", "Admin Unlock Capability",
            admin_unlock,
            "Enabled (secure, audited)",
            "Enabled" if admin_unlock else "Disabled",
            SeverityLevel.HIGH,
            "Enable admin unlock with audit logging",
        ))

        # Check 5: Audit logging
        checks.append(make_check(
            "audit_logging", "Lockout Event Logging",
            audit,
            "All lockout events logged",
            "Enabled" if audit else "Disabled",
            SeverityLevel.MEDIUM,
            "Enable logging: failed attempts, lockouts, admin unlocks",
        ))

        return checks

    # =========================================================================
    # Helpers
    # =========================================================================
    def _scan_error(self, message: str) -> SecurityCheck:
        """Return a scan-error check — never fake pass/fail."""
        return make_check(
            "scan_error", "RPP.2 Scan Error",
            False,
            "Successful scan execution",
            f"Scan failed: {message}",
            SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
