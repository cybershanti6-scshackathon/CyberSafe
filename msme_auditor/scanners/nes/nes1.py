"""
NES.1 — Firewall & Open Port Assessment
========================================
TCP-connect scan on sensitive ports (22, 3389, 3306, 5432 …).
Open ports on an internet-facing host = security risk.

Backend stack:
  - Config-driven policy via config/nes1_policy.yaml
  - Structured audit logging (core/audit_logger.py)
  - ERROR is distinct from FAIL
"""

import random
import socket
import time
from typing import Dict, List, Optional, Set

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.utils.network import resolve_host, scan_ports, SENSITIVE_PORTS
from msme_auditor.core.policy_loader import load_policy_for
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event

# Extended port list for thorough scanning
_EXTENDED_PORTS = {
    **SENSITIVE_PORTS,
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    1521: "Oracle",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Ports that should NEVER be internet-facing
DANGEROUS_PORTS = {
    21: ("FTP", "FTP transmits credentials in plaintext"),
    23: ("Telnet", "Telnet is unencrypted — use SSH instead"),
    3306: ("MySQL", "Database port should NEVER be public"),
    5432: ("PostgreSQL", "Database port should NEVER be public"),
    1433: ("MSSQL", "Database port should NEVER be public"),
    27017: ("MongoDB", "MongoDB often has no auth by default"),
    6379: ("Redis", "Redis often has no auth by default"),
    11211: ("Memcached", "Memcached amplification attack vector"),
    5900: ("VNC", "VNC often lacks encryption"),
}

# Service banner grab timeout
BANNER_TIMEOUT = 2.0

# Protocol-specific probes for banner grabbing
BANNER_PROBES: Dict[int, bytes] = {
    21: b"QUIT\r\n",
    22: b"SSH-2.0-Scan\r\n",
    25: b"EHLO scanner.local\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    110: b"QUIT\r\n",
    143: b"A001 CAPABILITY\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    3306: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    6379: b"PING\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
}


# =============================================================================
# Rate Limiter — prevents IDS triggering and firewall blocking
# =============================================================================
class _RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, max_per_second: int = 50):
        self.interval = 1.0 / max_per_second
        self._last_time = 0.0

    def wait(self) -> None:
        elapsed = time.time() - self._last_time
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self._last_time = time.time()


_rate_limiter = _RateLimiter(max_per_second=50)


# =============================================================================
# Enhanced Port Scanning — concurrent with rate limiting
# =============================================================================
def _scan_ports_concurrent(
    host: str,
    ports: List[int],
    timeout: float = 2.0,
    max_concurrent: int = 50,
) -> Set[int]:
    """Concurrent port scanning with rate limiting and randomised jitter."""
    import concurrent.futures

    open_ports: Set[int] = set()

    def _check_port(port: int) -> Optional[int]:
        _rate_limiter.wait()
        time.sleep(random.uniform(0, 0.1))
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as pool:
        futures = {pool.submit(_check_port, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.add(result)

    return open_ports


# =============================================================================
# Adaptive Timeout — calibrates based on network responsiveness
# =============================================================================
def _adaptive_scan_ports(
    host: str, ports: List[int], base_timeout: float = 1.0
) -> Set[int]:
    """Probe a small sample of ports first, compute an adaptive timeout."""
    open_ports: Set[int] = set()
    sample_size = min(5, len(ports))
    sample_ports = random.sample(ports, sample_size) if len(ports) > sample_size else ports
    remaining_ports = [p for p in ports if p not in sample_ports]

    response_times: List[float] = []

    for port in sample_ports:
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=base_timeout):
                open_ports.add(port)
                response_times.append(time.time() - start)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    if response_times:
        avg = sum(response_times) / len(response_times)
        adaptive_timeout = min(max(avg * 3, 1.0), 5.0)
    else:
        adaptive_timeout = 3.0

    for port in remaining_ports:
        _rate_limiter.wait()
        try:
            with socket.create_connection((host, port), timeout=adaptive_timeout):
                open_ports.add(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass

    return open_ports


# =============================================================================
# Enhanced Banner Grabbing — protocol-specific probes
# =============================================================================
def _grab_banner(host: str, port: int) -> str:
    """Enhanced banner grabbing with protocol-specific probes."""
    try:
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT) as sock:
            probe_template = BANNER_PROBES.get(port, b"\r\n")
            probe = probe_template.replace(b"{host}", host.encode())
            sock.sendall(probe)
            sock.settimeout(BANNER_TIMEOUT)
            data = b""
            for _ in range(3):
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= 1024:
                        break
                except socket.timeout:
                    break
            return data.decode("utf-8", errors="ignore").strip()[:500]
    except Exception:
        return ""


def _parse_banner(banner: str) -> dict:
    """Extract service info from a banner string."""
    import re

    info = {"service": "unknown", "version": "", "warning": ""}
    banner_lower = banner.lower()

    signatures = {
        "ssh": (r"ssh[-_]open(?:ssl)?[-_]?(\\d[\\d.]*)", "SSH"),
        "ftp": (r"ftp[-_]?(\\d[\\d.]*)", "FTP"),
        "smtp": (r"smtp[-_]?(?:postfix|exim|sendmail)?[-_]?(\\d[\\d.]*)", "SMTP"),
        "http": (r"(?:apache|nginx|iis|gunicorn|uvicorn|tomcat)[/-]?(\\d[\\d.]*)", "HTTP"),
        "mysql": (r"mysql[-_]?(\\d[\\d.]*)", "MySQL"),
        "redis": (r"redis[-_]?(\\d[\\d.]*)", "Redis"),
        "mongo": (r"mongodb[-_]?(\\d[\\d.]*)", "MongoDB"),
    }

    for _key, (pattern, name) in signatures.items():
        m = re.search(pattern, banner_lower)
        if m:
            info["service"] = name
            info["version"] = m.group(1) if m.group(1) else ""
            break

    if any(w in banner_lower for w in ["ssl", "tls", "https"]):
        info["encrypted"] = True
    if any(w in banner_lower for w in ["plain", "clear", "insecure"]):
        info["warning"] = "Plaintext protocol detected"

    return info


# =============================================================================
# NES.1 Scanner
# =============================================================================
class NES1Scanner(BaseScanner):
    """Firewall and open-port assessment scanner."""

    scanner_id: str = "nes1"
    name: str = "NES.1 — Firewall & Open Ports"
    description: str = "TCP port scan on sensitive ports. Open ports = security risk."
    category: str = "NES"
    target_types: List[str] = ["web"]
    input_fields: List[dict] = [
        {
            "name": "target",
            "label": "Target Domain or IP",
            "field_type": "text",
            "required": True,
            "placeholder": "example.com or 93.184.216.34",
            "help_text": "Domain name or IP address to scan",
        },
        {
            "name": "scan_depth",
            "label": "Scan Depth",
            "field_type": "select",
            "options": ["quick", "standard", "thorough"],
            "default": "standard",
            "help_text": "Quick: critical ports only, Standard: common ports, Thorough: extended port list",
        },
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        """Run the port scan and return security checks."""
        target = sc.config.get("target", sc.target or "")
        if not target:
            return [make_check(
                "no_target", "Target Required", False,
                "A valid domain or IP", "Not provided",
                SeverityLevel.CRITICAL,
            )]

        # Load policy
        try:
            policy = load_policy_for("nes1")
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        # Audit logging
        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, target, "started")

        try:
            ip = resolve_host(target)
            scan_depth = sc.config.get("scan_depth", "standard")

            # Select port list based on scan depth
            if scan_depth == "quick":
                ports_to_scan = list(SENSITIVE_PORTS.keys())
            elif scan_depth == "thorough":
                ports_to_scan = list(_EXTENDED_PORTS.keys())
            else:
                ports_to_scan = list(SENSITIVE_PORTS.keys()) + [80, 443, 8080, 8443]

            # Use concurrent scanning for large port lists
            if len(ports_to_scan) > 20:
                open_ports = _scan_ports_concurrent(
                    ip, ports=ports_to_scan,
                    timeout=policy.get("port_timeout", 2.0),
                    max_concurrent=policy.get("max_concurrent", 50),
                )
            else:
                open_ports = _adaptive_scan_ports(ip, ports_to_scan, base_timeout=1.0)

            # Grab banners from open ports
            banners: Dict[int, dict] = {}
            for port in open_ports:
                banner = _grab_banner(ip, port)
                if banner:
                    banners[port] = _parse_banner(banner)

            # Build checks using policy thresholds
            result = self._build_checks(open_ports, banners, policy)
        except Exception as exc:
            result = [self._scan_error(str(exc))]
        finally:
            log_scan_event(audit_logger, self.scanner_id, target, "completed")

        return result

    def _build_checks(
        self, open_ports: Set[int], banners: Dict[int, dict], policy: dict,
    ) -> List[SecurityCheck]:
        """Build security checks from scan results against policy thresholds."""
        dangerous = set(policy.get("dangerous_ports", []))
        high_risk = set(policy.get("high_risk_ports", []))
        max_warning = policy.get("max_open_ports_warning", 3)

        checks: List[SecurityCheck] = []

        # Check 1: Perimeter firewall
        checks.append(make_check(
            "perimeter_firewall", "Perimeter Firewall Deployed",
            len(open_ports) == 0,
            "All sensitive ports closed/filtered",
            (f"{len(open_ports)} open: "
             f"{', '.join(str(p) for p in sorted(open_ports)[:8])}")
            if open_ports else "All closed",
            SeverityLevel.CRITICAL if open_ports else SeverityLevel.INFO,
            ("Deploy firewall with default-deny policy\n"
             "Close all unnecessary ports\n"
             "Windows: netsh advfirewall set allprofiles state on\n"
             "Linux: ufw enable && ufw default deny incoming"),
        ))

        # Check 2: SSH exposure
        checks.append(bool_check(
            "ssh_open", "SSH Port (22) Closed",
            22 not in open_ports,
            "Port 22 closed or filtered",
            SeverityLevel.HIGH,
            "Disable SSH if not needed.\nIf needed: change default port + key-only auth",
        ))

        # Check 3: RDP exposure
        checks.append(bool_check(
            "rdp_open", "RDP Port (3389) Closed",
            3389 not in open_ports,
            "Port 3389 closed or filtered",
            SeverityLevel.CRITICAL,
            "Disable RDP or tunnel through VPN\n"
            "Windows: Disable Remote Desktop in Settings",
        ))

        # Check 4: Database ports
        db_ports = {3306, 5432, 1433, 27017, 6379, 11211}
        open_db = db_ports & open_ports
        checks.append(make_check(
            "db_ports", "Database Ports Closed",
            len(open_db) == 0,
            "All database ports closed",
            f"{len(open_db)} open: {', '.join(str(p) for p in sorted(open_db))}"
            if open_db else "All closed",
            SeverityLevel.CRITICAL if open_db else SeverityLevel.INFO,
            "Database ports should NEVER be internet-facing\n"
            "Use SSH tunnel or VPN for remote DB access",
        ))

        # Check 5: Dangerous protocols (FTP, Telnet)
        dangerous_open = {p for p in (21, 23) if p in open_ports}
        checks.append(make_check(
            "insecure_protocols", "No Insecure Protocols (FTP/Telnet)",
            len(dangerous_open) == 0,
            "FTP (21) and Telnet (23) closed",
            f"Open: {', '.join(DANGEROUS_PORTS[p][0] for p in sorted(dangerous_open))}"
            if dangerous_open else "None detected",
            SeverityLevel.CRITICAL if dangerous_open else SeverityLevel.INFO,
            "FTP: Use SFTP or FTPS instead\n"
            "Telnet: Use SSH instead\n"
            "Both transmit credentials in plaintext",
        ))

        # Check 6: Service banners (informational)
        if banners:
            banner_info = []
            for port, info in sorted(banners.items()):
                svc = info.get("service", "unknown")
                ver = info.get("version", "")
                warn = info.get("warning", "")
                entry = f"{port}/{svc}"
                if ver:
                    entry += f" {ver}"
                if warn:
                    entry += f" ({warn})"
                banner_info.append(entry)

            checks.append(make_check(
                "banner_disclosure", "Service Banner Disclosure",
                False,
                "Service banners hidden or generic",
                "; ".join(banner_info[:6]),
                SeverityLevel.MEDIUM,
                "Suppress service version banners\n"
                "Apache: ServerTokens Prod\n"
                "Nginx: server_tokens off\n"
                "SSH: DebianBanner no",
            ))

        return checks

    def _scan_error(self, message: str) -> SecurityCheck:
        """Return a scan-error check — never fake pass/fail."""
        return make_check(
            "scan_error", "NES.1 Scan Error",
            False,
            "Successful scan execution",
            f"Scan failed: {message}",
            SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
