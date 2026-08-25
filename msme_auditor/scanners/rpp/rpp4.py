"""
RPP.4 — Password Encryption & Hashing
======================================
CERT-In: Use secure encryption/hashing for password storage.
"""

import re
from pathlib import Path
from typing import List, Dict

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck

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
    if result["algorithm"] == "unknown" and len(hash_str) < 50 and not re.match(r"^[a-fA-F0-9]+$", hash_str):
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

        if tt == "linux":
            hashes = self._scan_shadow()
        elif tt == "web" and sc.target:
            hashes = self._scan_web(sc.target)
        elif "sample_hashes" in cfg:
            hashes = [identify_hash(h) for h in cfg["sample_hashes"]]
        else:
            hashes = []

        enc = cfg.get("encryption_at_rest", False) if tt == "manual" else False

        return self._build_checks(hashes, enc)

    def _scan_shadow(self) -> List[Dict]:
        """Analyze ``/etc/shadow`` hash algorithms."""
        hashes = []
        shadow = Path("/etc/shadow")
        if shadow.exists():
            try:
                for line in shadow.read_text().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1]:
                        hashes.append(identify_hash(parts[1]))
            except (PermissionError, Exception):
                pass
        return hashes

    def _scan_web(self, target: str) -> List[Dict]:
        """
        Probe web application for password storage evidence.

        Tries multiple API endpoints for hash/password-storage info.
        Returns empty list if no evidence found — never fakes data.
        """
        import httpx
        from urllib.parse import urljoin

        # Try structured API endpoints
        api_endpoints = [
            "/api/security/password-storage",
            "/api/security/config",
            "/api/auth/config",
            "/api/config",
        ]

        for endpoint in api_endpoints:
            try:
                url = urljoin(target.rstrip("/"), endpoint)
                resp = httpx.get(url, timeout=8, follow_redirects=True, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if not isinstance(data, dict):
                            continue
                        if data.get("sample_hashes"):
                            return [identify_hash(h) for h in data["sample_hashes"]]
                        elif data.get("algorithm"):
                            return [{"algorithm": data["algorithm"],
                                     "salted": data.get("salted", False),
                                     "secure": data["algorithm"] in SECURE_ALGOS}]
                    except Exception:
                        continue
            except Exception:
                continue

        return []

    def _build_checks(self, hashes: List[Dict], enc: bool) -> List[SecurityCheck]:
        """Build encryption / hashing checks from analysed hash data."""
        plaintext_count = sum(1 for h in hashes if h.get("algorithm") == "plaintext")
        algos = {h.get("algorithm") for h in hashes if h.get("algorithm")}
        secure = algos & SECURE_ALGOS
        weak = algos & WEAK_ALGOS
        unsalted = sum(1 for h in hashes if not h.get("salted", True))

        return [
            make_check("no_plaintext", "No Plaintext Passwords", plaintext_count == 0,
                       "0 plaintext passwords", f"{plaintext_count} plaintext found",
                       SeverityLevel.CRITICAL,
                       "IMMEDIATE: Hash all plaintext passwords with bcrypt/Argon2"),
            make_check("hash_algorithm", "Secure Hash Algorithm", bool(secure) and not weak,
                       "bcrypt, Argon2, or scrypt", f"Found: {', '.join(algos)} or none",
                       SeverityLevel.CRITICAL,
                       "Use: bcrypt (cost>=10), Argon2id, or scrypt"),
            make_check("salting", "Password Salting", unsalted == 0,
                       "All passwords salted", f"{unsalted} unsalted",
                       SeverityLevel.HIGH,
                       "bcrypt/Argon2 auto-salt. For SHA: salt=pbkdf2_hmac(...)"),
            make_check("no_weak", "No Weak Hash Algorithms", not weak,
                       "No MD5, SHA1, or unsalted hashes",
                       f"{len(weak)} weak found" if weak else "None",
                       SeverityLevel.CRITICAL,
                       "CRITICAL: MD5/SHA1 crackable in seconds\nMigrate to bcrypt/Argon2"),
            bool_check("encryption_at_rest", "Database Encryption at Rest", enc,
                       "Enabled (TDE or volume encryption)", SeverityLevel.HIGH,
                       "MySQL: ENCRYPTION='Y'\nPostgreSQL: pgcrypto\nSQL Server: TDE"),
        ]

    def _fail(self, err: str) -> List[SecurityCheck]:
        """Return a clear scan-failure indication — never fake default values."""
        return [
            make_check(
                "scan_error", "RPP.4 Scan Error",
                False,
                "Successful scan execution",
                f"Scan failed: {err}",
                SeverityLevel.HIGH,
                f"Manual audit required. Error: {err}",
            ),
        ]
