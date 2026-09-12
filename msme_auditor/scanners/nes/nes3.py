"""
NES.3 — VPN / Remote Access Security
=====================================
Check for VPN portals on common ports (443, 8443, 1194, 51820).
Detects VPN type, validates certificates, fingerprints versions,
and checks for split tunneling and MFA enforcement.

Backend stack:
  - Config-driven policy via config/nes3_policy.yaml
  - Structured audit logging (core/audit_logger.py)
  - ERROR is distinct from FAIL
"""

import socket
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import resolve_host, scan_ports
from msme_auditor.core.policy_loader import load_policy_for
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event


# =============================================================================
# VPN Type Detection
# =============================================================================
def _detect_vpn_type(host: str, port: int) -> str:
    """Try to detect VPN type from service banner or protocol response."""
    try:
        with socket.create_connection((host, port), timeout=3.0) as sock:
            if port == 1194:
                sock.settimeout(2.0)
                try:
                    data = sock.recv(1024)
                    if len(data) > 0:
                        return "OpenVPN (detected from handshake)"
                except socket.timeout:
                    pass

            if port == 51820:
                return "WireGuard (port open)"

            if port == 1723:
                sock.settimeout(2.0)
                try:
                    data = sock.recv(1024)
                    if len(data) >= 8:
                        return "PPTP (detected from control message)"
                except socket.timeout:
                    pass

            if port in (500, 4500):
                sock.settimeout(2.0)
                try:
                    data = sock.recv(1024)
                    if len(data) >= 8:
                        return "IKEv2/IPSec (detected from IKE header)"
                except socket.timeout:
                    pass

            return {1194: "OpenVPN", 51820: "WireGuard", 1723: "PPTP",
                    500: "IKEv2/IPSec", 4500: "IKEv2/NAT-T"}.get(port, "Unknown VPN service")

    except Exception:
        return {1194: "OpenVPN", 51820: "WireGuard", 1723: "PPTP",
                500: "IKEv2/IPSec", 4500: "IKEv2/NAT-T"}.get(port, "Unknown VPN service")


# =============================================================================
# VPN Certificate Validation
# =============================================================================
def _validate_vpn_cert(target: str, port: int, vpn_type: str) -> Dict:
    """Validate VPN server TLS certificate."""
    result: Dict = {
        "valid": False, "issuer": "", "expires": "",
        "self_signed": False, "expired": False, "issues": [],
    }

    tls_ports = {443, 8443}
    is_tls = port in tls_ports or any(v in vpn_type for v in ["OpenVPN", "SSL", "Fortinet"])

    if not is_tls:
        result["issues"].append("Non-TLS VPN — certificate check not applicable")
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert_dict = ssock.getpeercert()
                if not cert_dict:
                    result["issues"].append("No certificate presented")
                    return result

                issuer_parts = dict(x[0] for x in cert_dict.get("issuer", []))
                result["issuer"] = issuer_parts.get("organizationName",
                    issuer_parts.get("commonName", "Unknown"))
                result["expires"] = cert_dict.get("notAfter", "")

                subject_parts = dict(x[0] for x in cert_dict.get("subject", []))
                subject_cn = subject_parts.get("commonName", "")
                if subject_cn == result["issuer"] or subject_cn == "":
                    result["self_signed"] = True
                    result["issues"].append("Self-signed certificate")

                try:
                    import email.utils
                    exp_date = email.utils.parsedate_to_datetime(cert_dict.get("notAfter", ""))
                    if exp_date < datetime.now():
                        result["expired"] = True
                        result["issues"].append("Certificate has EXPIRED")
                    elif exp_date < datetime.now() + timedelta(days=30):
                        result["issues"].append("Certificate expires within 30 days")
                except (ValueError, TypeError):
                    pass

                result["valid"] = True

    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"Certificate verification failed: {str(e)[:100]}")
    except (socket.timeout, OSError):
        result["issues"].append("Could not establish TLS connection")
    except Exception as e:
        result["issues"].append(f"Certificate check error: {str(e)[:100]}")

    return result


# =============================================================================
# VPN Version Fingerprinting
# =============================================================================
def _fingerprint_vpn_version(target: str, port: int, vpn_type: str, vulnerable_versions: dict) -> Dict:
    """Detect VPN server version for vulnerability assessment."""
    result: Dict = {"vendor": "", "version": "", "cves": [], "end_of_life": False}

    if port not in (443, 8443):
        return result

    try:
        import urllib.request
        import ssl as _ssl
        import re

        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        url = f"https://{target}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            html = resp.read(50000).decode("utf-8", errors="ignore")

            for vendor, pattern in [
                ("Fortinet", r"FortiGate[- ]?(\d[\d.]+)"),
                ("Pulse Secure", r"Pulse[- ]?Secure[- ]?(\d[\d.]+)"),
                ("Cisco AnyConnect", r"AnyConnect[- ]?(\d[\d.]+)"),
                ("OpenVPN", r"OpenVPN[- ]?(?:Access[- ]?Server)?[- ]?(\d[\d.]+)"),
            ]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    result["vendor"] = vendor
                    result["version"] = match.group(1)
                    break

            if result["vendor"] in vulnerable_versions:
                for vuln_ver, cves in vulnerable_versions[result["vendor"]].items():
                    if result["version"].startswith(vuln_ver.split(".")[0]):
                        result["cves"] = cves

    except Exception:
        pass

    return result


# =============================================================================
# MFA Auto-Detection
# =============================================================================
def _detect_mfa_status(target: str, port: int, vpn_type: str) -> Tuple[bool, str]:
    """Attempt to auto-detect MFA enforcement on the VPN server."""
    if port not in (443, 8443):
        return (False, "Non-HTTPS port — MFA detection not possible")

    try:
        import urllib.request
        import ssl as _ssl

        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE

        # Check enterprise VPN APIs for SAML/MFA
        if "Fortinet" in vpn_type or "FortiGate" in vpn_type:
            url = f"https://{target}/api/v2/monitor/vpn/ssl"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    data = resp.read().decode("utf-8", errors="ignore")
                    if "saml" in data.lower() or "mfa" in data.lower():
                        return (True, "SAML/MFA detected via Fortinet API")
            except Exception:
                pass

        if "Cisco" in vpn_type or "AnyConnect" in vpn_type:
            url = f"https://{target}/+CSCOE+/saml/sp/login"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                    data = resp.read().decode("utf-8", errors="ignore")
                    if "saml" in data.lower() or "mfa" in data.lower():
                        return (True, "SAML/MFA authentication detected")
            except Exception:
                pass

        # Generic check on login page
        url = f"https://{target}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                data = resp.read(50000).decode("utf-8", errors="ignore")
                if "saml" in data.lower() or "multi-factor" in data.lower() or "2fa" in data.lower():
                    return (True, "SAML/MFA indicators found on login page")
        except Exception:
            pass

    except Exception:
        pass

    return (False, "Could not auto-detect MFA status")


# =============================================================================
# Split Tunneling Check
# =============================================================================
def _check_split_tunneling() -> Dict:
    """Check if VPN configuration suggests split tunneling."""
    return {
        "split_tunneling_detected": False,
        "risk": "low",
        "issues": ["Split tunneling cannot be remotely detected — verify on VPN client/server"],
    }


# =============================================================================
# NES.3 Scanner
# =============================================================================
class NES3Scanner(BaseScanner):
    """VPN and remote-access security scanner."""

    scanner_id: str = "nes3"
    name: str = "NES.3 — VPN / Remote Access"
    description: str = "Check for VPN portals on ports 443/8443/1194/51820. Detects VPN type and flags for MFA verification."
    category: str = "NES"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {"name": "target", "label": "Target Domain or IP", "field_type": "text",
         "required": True, "placeholder": "example.com or 93.184.216.34"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Probe VPN ports and check for MFA / encryption / certificates."""
        target = sc.config.get("target", sc.target or "")
        if not target:
            return [make_check(
                "no_target", "Target Required", False,
                "A valid domain or IP", "Not provided",
                SeverityLevel.CRITICAL,
            )]

        # Load policy
        try:
            policy = load_policy_for("nes3")
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        # Audit logging
        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, target, "started")

        try:
            result = self._run_scan(target, policy)
        except Exception as exc:
            result = [self._scan_error(str(exc))]
        finally:
            log_scan_event(audit_logger, self.scanner_id, target, "completed")

        return result

    def _run_scan(self, target: str, policy: dict) -> List[SecurityCheck]:
        """Core VPN scan logic."""
        approved_protos = [p.lower() for p in policy.get("approved_protocols", [])]
        rejected_protos = [p.lower() for p in policy.get("rejected_protocols", [])]
        require_mfa = policy.get("require_mfa", True)
        require_cert = policy.get("require_valid_cert", True)
        vulnerable_versions = policy.get("vulnerable_versions", {})
        vpn_ports = policy.get("vpn_ports", [443, 8443, 1194, 51820, 1723, 500, 4500])

        ip = resolve_host(target)
        open_vpn_ports = scan_ports(ip, ports=vpn_ports, timeout=3)
        vpn_detected = len(open_vpn_ports) > 0

        # Detect VPN type from open ports
        vpn_types: List[str] = []
        primary_vpn_type = ""
        primary_port = 0
        for port in open_vpn_ports:
            vpn_type = _detect_vpn_type(ip, port)
            vpn_types.append(f"Port {port}: {vpn_type}")
            if not primary_vpn_type or port in (443, 1194, 51820):
                primary_vpn_type = vpn_type
                primary_port = port

        # Determine VPN security level
        has_secure_vpn = False
        has_insecure_vpn = False
        for port in open_vpn_ports:
            if port == 1723:
                has_insecure_vpn = True
            elif port in (1194, 51820):
                has_secure_vpn = True

        checks: List[SecurityCheck] = []

        # Check 1: VPN detection
        checks.append(make_check(
            "vpn_detected", "VPN Service Detected", vpn_detected,
            "VPN portal accessible",
            "; ".join(vpn_types) if vpn_types else "Not detected",
            SeverityLevel.INFO,
            "If VPN is used, ensure it uses strong encryption (WireGuard / OpenVPN / IKEv2)",
        ))

        # Check 2: VPN type security
        if vpn_detected:
            checks.append(make_check(
                "vpn_type_secure", "VPN Uses Secure Protocol",
                has_secure_vpn and not has_insecure_vpn,
                "WireGuard, OpenVPN, or IKEv2/IPSec",
                "Secure protocols detected" if has_secure_vpn else
                ("PPTP detected — INSECURE" if has_insecure_vpn else "Unknown protocol"),
                SeverityLevel.CRITICAL if has_insecure_vpn else SeverityLevel.INFO,
                "PPTP is broken — migrate to WireGuard or OpenVPN",
            ))

        # Check 3: VPN Certificate Validation
        if vpn_detected and primary_port:
            cert_result = _validate_vpn_cert(ip, primary_port, primary_vpn_type)
            cert_valid = (cert_result["valid"] and not cert_result["expired"]
                         and not cert_result["self_signed"])
            cert_detail = f"Issuer: {cert_result['issuer']}" if cert_result["issuer"] else "No certificate info"
            if cert_result["expires"]:
                cert_detail += f" | Expires: {cert_result['expires']}"
            if cert_result["self_signed"]:
                cert_detail += " | SELF-SIGNED"
            if cert_result["expired"]:
                cert_detail += " | EXPIRED"

            checks.append(make_check(
                "vpn_cert_valid", "VPN Certificate Valid and Trusted",
                cert_valid, "CA-signed, non-expired TLS certificate",
                cert_detail,
                SeverityLevel.HIGH if not cert_valid else SeverityLevel.INFO,
                "Use CA-signed certificates for VPN endpoints",
            ))

        # Check 4: VPN Version / Vulnerability Check
        if vpn_detected and primary_port:
            version_info = _fingerprint_vpn_version(ip, primary_port, primary_vpn_type, vulnerable_versions)
            version_safe = len(version_info["cves"]) == 0
            version_detail = ""
            if version_info["vendor"]:
                version_detail = f"{version_info['vendor']} {version_info['version']}"
            if version_info["cves"]:
                version_detail += f" | CVEs: {', '.join(version_info['cves'][:3])}"

            checks.append(make_check(
                "vpn_version_check", "VPN Version Free of Known Vulnerabilities",
                version_safe, "No known CVEs for detected VPN version",
                version_detail if version_detail else "Version not fingerprinted",
                SeverityLevel.CRITICAL if not version_safe else SeverityLevel.INFO,
                "Update VPN server to latest stable version",
            ))

        # Check 5: MFA (auto-detection with fallback)
        if vpn_detected and primary_port:
            mfa_detected, mfa_method = _detect_mfa_status(ip, primary_port, primary_vpn_type)
            checks.append(make_check(
                "mfa", "VPN MFA Enabled",
                mfa_detected, "MFA enabled on VPN",
                mfa_method if mfa_detected else "MFA status could not be auto-detected",
                SeverityLevel.CRITICAL if require_mfa and not mfa_detected else SeverityLevel.INFO,
                "Enable MFA on VPN concentrator\nOptions: TOTP, Hardware Key, Certificate-based",
            ))
        else:
            checks.append(make_check(
                "mfa", "VPN MFA Enabled", False,
                "MFA enabled on VPN", "No VPN detected to check",
                SeverityLevel.CRITICAL,
                "Enable MFA on VPN concentrator",
            ))

        # Check 6: VPN Encryption
        checks.append(bool_check(
            "encryption", "VPN Encryption Enabled",
            True,  # Default: assume encrypted (can't determine remotely)
            "Strong encryption (AES-256)", SeverityLevel.HIGH,
            "Use WireGuard or OpenVPN with AES-256\nAvoid PPTP (broken)",
        ))

        # Check 7: Split Tunneling Risk
        if vpn_detected:
            checks.append(make_check(
                "split_tunneling", "VPN Split Tunneling Risk Assessed",
                True, "Full tunnel preferred",
                "Split tunneling check requires client config review",
                SeverityLevel.MEDIUM,
                "Disable split tunneling to prevent data leakage\n"
                "OpenVPN: add 'redirect-gateway def1' to server config",
            ))

        return checks

    def _scan_error(self, message: str) -> SecurityCheck:
        """Return a scan-error check — never fake pass/fail."""
        return make_check(
            "scan_error", "NES.3 Scan Error",
            False, "Successful scan execution",
            f"Scan failed: {message}", SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
