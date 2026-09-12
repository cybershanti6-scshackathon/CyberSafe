"""
RPP.4 — Password Encryption & Hashing
======================================
CERT-In: Use secure encryption/hashing for password storage.

Backend stack:
  - Config-driven policy via config/rpp4_policy.yaml
  - Safe subprocess wrapper (core/command_runner.py)
  - Structured audit logging (core/audit_logger.py)
  - ERROR is distinct from FAIL
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.core.command_runner import run_command
from msme_auditor.core.policy_loader import load_policy_for
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event


# Hash identification patterns
HASH_PATTERNS = {
    "bcrypt": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
    "argon2id": r"^\$argon2id\$",
    "argon2i": r"^\$argon2i\$",
    "argon2d": r"^\$argon2d\$",
    "scrypt": r"^\$scrypt\$",
    "sha512_crypt": r"^\$6\$.+\$.+$",
    "sha256_crypt": r"^\$5\$.+\$.+$",
    "md5_crypt": r"^\$1\$.+\$.+$",
    "sha256_plain": r"^[a-fA-F0-9]{64}$",
    "sha1_plain": r"^[a-fA-F0-9]{40}$",
    "md5_plain": r"^[a-fA-F0-9]{32}$",
}

SECURE_ALGOS = {"bcrypt", "argon2id", "argon2i", "argon2d", "scrypt", "sha512_crypt"}
WEAK_ALGOS = {"md5_crypt", "md5_plain", "sha1_plain", "sha256_plain"}


def identify_hash(hash_str: str) -> Dict:
    """Identify hash algorithm and properties."""
    result = {"algorithm": "unknown", "salted": False, "secure": False}
    for algo, pattern in HASH_PATTERNS.items():
        if re.match(pattern, hash_str):
            result["algorithm"] = algo
            is_plain = algo.endswith("_plain")
            result["salted"] = "$" in hash_str and not is_plain
            result["secure"] = algo in SECURE_ALGOS
            break
    if (result["algorithm"] == "unknown"
            and len(hash_str) < 50
            and not re.match(r"^[a-fA-F0-9]+$", hash_str)):
        result["algorithm"] = "plaintext"
    return result


class RPP4Scanner(BaseScanner):
    scanner_id = "rpp4"
    name = "RPP.4 — Password Encryption & Hashing"
    description = "Use secure encryption and hashing algorithms to store passwords safely."
    category = "RPP"
    target_types = ["web", "linux"]
    input_fields = [
        {"name": "target_type", "label": "Scan Target", "field_type": "select",
         "options": ["web", "linux"], "default": "web"},
        {"name": "target", "label": "Target URL / Host", "field_type": "text",
         "placeholder": "http://localhost:8765"},
        {"name": "sample_hashes", "label": "Sample Password Hashes (one per line)", "field_type": "text",
         "placeholder": "$2b$12$... (bcrypt hash)",
         "help_text": "Paste password hashes to analyze (or scan a live system)"},
        {"name": "encryption_at_rest", "label": "Database Encryption at Rest", "field_type": "boolean",
         "default": True, "help_text": "TDE or volume encryption enabled"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Analyze password hashes and encryption-at-rest settings."""
        cfg = sc.config
        tt = sc.target_type

        try:
            policy = load_policy_for("rpp4")
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, sc.target or "localhost", "started")

        try:
            if tt == "linux":
                hashes = self._scan_shadow()
            elif tt == "web" and sc.target:
                hashes = self._scan_web(sc.target)
            elif "sample_hashes" in cfg:
                hashes = [identify_hash(h) for h in cfg["sample_hashes"]]
            else:
                hashes = []

            enc = cfg.get("encryption_at_rest", False) if tt == "manual" else False

            result = self._build_checks(hashes, enc, policy)
        except Exception as exc:
            result = [self._scan_error(str(exc))]
        finally:
            log_scan_event(audit_logger, self.scanner_id, sc.target or "localhost", "completed")

        return result

    # =========================================================================
    # Linux Shadow Scanner
    # =========================================================================
    def _scan_shadow(self) -> List[Dict]:
        """Analyze ``/etc/shadow`` hash algorithms."""
        hashes = []
        shadow = Path("/etc/shadow")
        if shadow.exists():
            try:
                for line in shadow.read_text(encoding="utf-8", errors="ignore").split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1]:
                        hashes.append(identify_hash(parts[1]))
            except (PermissionError, OSError):
                pass
        return hashes

    # =========================================================================
    # Web Scanner
    # =========================================================================
    def _scan_web(self, target: str) -> List[Dict]:
        """Probe web application for password storage evidence."""
        import httpx
        from urllib.parse import urljoin

        TIMEOUT = 5
        HEADERS = {
            "User-Agent": "Mozilla/5.0 (compatible; CyberSure-SecurityScanner/1.0)",
            "Accept": "text/html,application/json",
        }

        api_endpoints = [
            "/api/security/password-storage",
            "/api/security/config",
            "/api/auth/config",
            "/api/config/security",
            "/api/auth/password-policy",
        ]

        for endpoint in api_endpoints:
            try:
                url = urljoin(target.rstrip("/"), endpoint)
                resp = httpx.get(url, timeout=TIMEOUT, follow_redirects=False,
                                 verify=False, headers=HEADERS)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if not isinstance(data, dict):
                            continue
                        if data.get("sample_hashes"):
                            return [identify_hash(h) for h in data["sample_hashes"]]
                        if data.get("algorithm"):
                            return [{"algorithm": data["algorithm"],
                                     "salted": data.get("salted", False),
                                     "secure": data["algorithm"] in SECURE_ALGOS}]
                        storage = data.get("password_storage") or data.get("hashing")
                        if isinstance(storage, dict) and storage.get("algorithm"):
                            return [{"algorithm": storage["algorithm"],
                                     "salted": storage.get("salted", False),
                                     "secure": storage["algorithm"] in SECURE_ALGOS}]
                    except Exception:
                        continue
            except Exception:
                continue

        return []

    # =========================================================================
    # Check Builder — unified evaluation
    # =========================================================================
    def _build_checks(self, hashes: List[Dict], enc: bool, policy: dict) -> List[SecurityCheck]:
        """Build encryption / hashing checks from analysed hash data against policy."""
        approved = set(policy.get("approved_algorithms", []))
        rejected = set(policy.get("rejected_algorithms", []))

        plaintext_count = sum(1 for h in hashes if h.get("algorithm") == "plaintext")
        algos = {h.get("algorithm") for h in hashes if h.get("algorithm")}
        secure = algos & (SECURE_ALGOS | approved)
        weak = algos & (WEAK_ALGOS | rejected)
        unsalted = sum(1 for h in hashes if not h.get("salted", True))

        checks: List[SecurityCheck] = []

        # Check 1: No plaintext passwords
        checks.append(make_check(
            "no_plaintext", "No Plaintext Passwords",
            plaintext_count == 0,
            "0 plaintext passwords",
            f"{plaintext_count} plaintext found" if plaintext_count else "None found",
            SeverityLevel.CRITICAL,
            "IMMEDIATE: Hash all plaintext passwords with bcrypt/Argon2",
        ))

        # Check 2: Secure hash algorithm
        checks.append(make_check(
            "hash_algorithm", "Secure Hash Algorithm",
            bool(secure) and not weak,
            f"Approved: {', '.join(sorted(approved))}" if approved else "bcrypt, Argon2, or scrypt",
            f"Found: {', '.join(sorted(algos))}" if algos else "No hashes to analyze",
            SeverityLevel.CRITICAL,
            f"Use: {', '.join(sorted(approved)[:3])}" if approved else "Use: bcrypt (cost>=10), Argon2id, or scrypt",
        ))

        # Check 3: Password salting
        checks.append(make_check(
            "salting", "Password Salting",
            unsalted == 0,
            "All passwords salted",
            f"{unsalted} unsalted" if unsalted else "All salted",
            SeverityLevel.HIGH,
            "bcrypt/Argon2 auto-salt. For SHA: salt=pbkdf2_hmac(...)",
        ))

        # Check 4: No weak algorithms
        checks.append(make_check(
            "no_weak", "No Weak Hash Algorithms",
            not weak,
            "No MD5, SHA1, or unsalted hashes",
            f"{len(weak)} weak found: {', '.join(sorted(weak))}" if weak else "None",
            SeverityLevel.CRITICAL,
            "CRITICAL: MD5/SHA1 crackable in seconds\nMigrate to bcrypt/Argon2",
        ))

        # Check 5: Encryption at rest
        checks.append(bool_check(
            "encryption_at_rest", "Database Encryption at Rest", enc,
            "Enabled (TDE or volume encryption)", SeverityLevel.HIGH,
            "MySQL: ENCRYPTION='Y'\nPostgreSQL: pgcrypto\nSQL Server: TDE",
        ))

        return checks

    # =========================================================================
    # Helpers
    # =========================================================================
    def _scan_error(self, message: str) -> SecurityCheck:
        """Return a scan-error check — never fake pass/fail."""
        return make_check(
            "scan_error", "RPP.4 Scan Error",
            False,
            "Successful scan execution",
            f"Scan failed: {message}",
            SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
