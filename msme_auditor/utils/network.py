"""
Network utilities — DNS resolution, port scanning, TXT record lookup.

All raw socket and DNS code lives here.  Scanner modules call these
functions instead of touching sockets directly.
"""

import socket
import struct
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# DNS resolution
# =============================================================================

def resolve_host(hostname: str) -> str:
    """
    Resolve a hostname to an IP address.

    Args:
        hostname: Domain name or IP address string.

    Returns:
        The resolved IP address, or the original input if resolution fails.

    Examples:
        >>> resolve_host("example.com")
        '93.184.216.34'
        >>> resolve_host("93.184.216.34")
        '93.184.216.34'
    """
    if not hostname:
        return ""
    # Already an IP?
    try:
        socket.inet_aton(hostname)
        return hostname
    except OSError:
        pass
    # Resolve domain
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, OSError):
        return hostname


def extract_domain(target: str) -> str:
    """
    Extract the bare domain from a URL or host string.

    Strips protocol, path, and port.

    Args:
        target: A URL like ``https://example.com/path`` or a bare domain.

    Returns:
        The domain portion, e.g. ``"example.com"``.
    """
    if not target:
        return ""
    return (
        target.replace("http://", "")
        .replace("https://", "")
        .split("/")[0]
        .split(":")[0]
        .strip()
    )


# =============================================================================
# Port scanning
# =============================================================================

# Ports that should NEVER be internet-facing.
SENSITIVE_PORTS: Dict[int, str] = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    11211: "Memcached",
}


def scan_ports(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
) -> Set[int]:
    """
    TCP-connect scan a list of ports and return the ones that are open.

    Args:
        host: IP address or hostname to scan.
        ports: Port numbers to test.  Defaults to :data:`SENSITIVE_PORTS`.
        timeout: Seconds to wait per connection attempt.

    Returns:
        Set of port numbers that accepted a TCP connection.

    Raises:
        Nothing — all errors are caught and return an empty set.
    """
    if not host:
        return set()
    if ports is None:
        ports = list(SENSITIVE_PORTS.keys())

    open_ports: Set[int] = set()
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.add(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return open_ports


# =============================================================================
# DNS TXT record lookup
# =============================================================================

def check_txt_record(record_name: str, expected_substring: str) -> bool:
    """
    Check whether a DNS TXT *record_name* contains *expected_substring*.

    Tries ``dnspython`` first, then falls back to a raw UDP query
    (no external dependencies required).

    Args:
        record_name: The fully-qualified name to query, e.g.
            ``"_dmarc.example.com"``.
        expected_substring: Case-insensitive substring to look for,
            e.g. ``"v=DMARC1"``.

    Returns:
        ``True`` if the substring was found in any TXT record.
    """
    if not record_name:
        return False

    # --- Try dnspython first (cleaner, handles edge cases) ---
    try:
        import dns.resolver  # type: ignore[import-untyped]
        answers = dns.resolver.resolve(record_name, "TXT")  # type: ignore[union-attr]
        for rdata in answers:
            text = str(rdata).strip('"')
            if expected_substring.lower() in text.lower():
                return True
        return False
    except ImportError:
        pass  # dnspython not installed — fall through to raw DNS
    except Exception:
        return False

    # --- Fallback: raw UDP DNS query ---
    try:
        return _raw_txt_lookup(record_name, expected_substring)
    except Exception:
        return False


def _raw_txt_lookup(record_name: str, expected: str, dns_server: str = "8.8.8.8") -> bool:
    """
    Low-level DNS TXT lookup using a raw UDP socket.

    Args:
        record_name: FQDN to query.
        expected: Substring to search for (case-insensitive).
        dns_server: IP of the recursive resolver to use.

    Returns:
        ``True`` if the substring was found.
    """
    query = _build_dns_query(record_name)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512)

    ancount = struct.unpack("!H", data[6:8])[0]
    offset = 12  # skip 12-byte header

    # Skip question section
    qdcount = struct.unpack("!H", data[4:6])[0]
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            offset += data[offset] + 1
        offset += 5  # null + type(2) + class(2)

    # Parse answer section
    for _ in range(ancount):
        # Name (pointer or labels)
        if offset < len(data) and data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        if offset + 10 > len(data):
            break
        rtype = struct.unpack("!H", data[offset : offset + 2])[0]
        rdlength = struct.unpack("!H", data[offset + 8 : offset + 10])[0]
        rdata = data[offset + 10 : offset + 10 + rdlength]
        offset += 10 + rdlength

        if rtype == 16:  # TXT
            txt = _parse_txt_rdata(rdata)
            if expected.lower() in txt.lower():
                return True

    return False


def _build_dns_query(domain: str) -> bytes:
    """Build a raw DNS query packet for TXT records."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b""
    for part in domain.split("."):
        encoded = part.encode("utf-8")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"  # root label
    question += struct.pack("!HH", 16, 1)  # TXT, IN
    return header + question


# =============================================================================
# TLS certificate inspection
# =============================================================================

def tls_connect(
    hostname: str,
    port: int = 443,
    timeout: float = 10.0,
) -> dict:
    """
    Open a TLS connection and return certificate metadata.

    Args:
        hostname: The server hostname (must match the certificate).
        port: The port to connect to (default 443).
        timeout: Seconds before the connection attempt times out.

    Returns:
        A dict with keys ``cert``, ``protocol``, and ``cipher``.
        If the connection fails, returns ``{"error": "..."}``.
    """
    import ssl

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {
                    "cert": ssock.getpeercert(),
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                }
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"Certificate verification failed: {exc}"}
    except (socket.timeout, OSError) as exc:
        return {"error": f"Connection failed: {exc}"}
    except Exception as exc:
        return {"error": str(exc)}


def _parse_txt_rdata(rdata: bytes) -> str:
    """Parse the text content from a DNS TXT record's RDATA."""
    pos = 0
    text = ""
    while pos < len(rdata):
        segment_len = rdata[pos]
        pos += 1
        text += rdata[pos : pos + segment_len].decode("utf-8", errors="ignore")
        pos += segment_len
    return text


# =============================================================================
# Nmap-based service discovery
# =============================================================================

def nmap_discover(
    host: str,
    ports: str = "1-1024",
    timeout: int = 60,
) -> Dict:
    """
    Run Nmap service/version detection on a host.

    Uses ``nmap -sV -oX -`` to discover open ports, running services,
    and service versions. Falls back to socket scanning if Nmap is
    not installed.

    Args:
        host: IP address or hostname to scan.
        ports: Port range for Nmap (e.g. "1-1024", "22,80,443").
        timeout: Maximum seconds for the Nmap scan.

    Returns:
        A dict with keys:
        - ``nmap_available``: bool
        - ``host``: str
        - ``ports``: list of dicts with ``port``, ``protocol``, ``state``,
          ``service``, ``version``
        - ``os_guess``: str or None
        - ``error``: str or None
    """
    import subprocess
    import shutil
    import xml.etree.ElementTree as ET

    result = {
        "nmap_available": False,
        "host": host,
        "ports": [],
        "os_guess": None,
        "error": None,
    }

    # Check if nmap is available
    if not shutil.which("nmap"):
        result["error"] = "Nmap not installed. Install nmap or use socket-based scanning."
        # Fall back to socket scanning
        result["ports"] = _socket_discover(host)
        return result

    result["nmap_available"] = True

    try:
        cmd = [
            "nmap", "-sV", "-oX", "-",
            "-p", ports,
            "--open",
            "--host-timeout", f"{timeout}s",
            host,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 10,
        )

        if proc.returncode != 0 and not proc.stdout:
            result["error"] = f"Nmap failed: {proc.stderr[:200]}"
            result["ports"] = _socket_discover(host)
            return result

        root = ET.fromstring(proc.stdout)

        for port_elem in root.findall(".//port"):
            port_id = port_elem.get("portid", "")
            protocol = port_elem.get("protocol", "tcp")
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            service_elem = port_elem.find("service")
            service = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            version = ""
            if service_elem is not None:
                parts = []
                for attr in ("product", "version", "extrainfo"):
                    val = service_elem.get(attr, "")
                    if val:
                        parts.append(val)
                version = " ".join(parts)

            result["ports"].append({
                "port": int(port_id) if port_id.isdigit() else port_id,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
            })

        # OS detection (requires root)
        os_elem = root.find(".//os/osmatch")
        if os_elem is not None:
            result["os_guess"] = os_elem.get("name", "")

    except subprocess.TimeoutExpired:
        result["error"] = f"Nmap scan timed out after {timeout}s"
        result["ports"] = _socket_discover(host)
    except ET.ParseError as e:
        result["error"] = f"Failed to parse Nmap output: {e}"
        result["ports"] = _socket_discover(host)
    except Exception as e:
        result["error"] = f"Nmap error: {e}"
        result["ports"] = _socket_discover(host)

    return result


def _socket_discover(
    host: str,
    ports: Optional[List[int]] = None,
    timeout: float = 2.0,
) -> List[Dict]:
    """
    Fallback socket-based port discovery when Nmap is unavailable.

    Tests a predefined list of common ports and returns service guesses.
    """
    if ports is None:
        ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
            6379, 8080, 8443, 27017,
        ]

    SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "mssql", 1521: "oracle", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "http-alt", 8443: "https-alt",
        27017: "mongodb",
    }

    discovered = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                discovered.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": SERVICE_MAP.get(port, "unknown"),
                    "version": "",
                })
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
    return discovered
