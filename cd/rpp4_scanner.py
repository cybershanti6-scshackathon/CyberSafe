import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import bcrypt
import httpx
from pydantic import BaseModel


# ============================================================
# RPP.4 RESULT MODEL
# ============================================================
class RPP4Result(BaseModel):
    control_id: str = "RPP"
    sub_control: str = "RPP.4"
    status: str
    score: int
    finding: str
    ai_remediation: str
    checks: dict


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("Invalid website URL.")
    return parsed.hostname


# ============================================================
# SECURITY CHECKS
# ============================================================
def check_https_and_hsts(url: str) -> dict:
    """Checks for HTTPS accessibility and HSTS headers across all redirects."""
    https_url = normalize_url(url)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        with httpx.Client(
            timeout=10, follow_redirects=True, headers=headers
        ) as client:
            response = client.get(https_url)

        all_responses = response.history + [response]
        hsts_passed = any(
            "strict-transport-security" in r.headers for r in all_responses
        )

        return {
            "https_passed": response.url.scheme == "https",
            "hsts_passed": hsts_passed,
            "status_code": response.status_code,
            "final_url": str(response.url),
        }
    except Exception as e:
        return {"https_passed": False, "hsts_passed": False, "error": str(e)}


def check_ssl_certificate(hostname: str) -> dict:
    """Checks SSL/TLS certificate validity and expiry."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

                not_after = cert.get("notAfter") if cert else None
                if not_after:
                    expiry_date = datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    days_remaining = (
                        expiry_date - datetime.now(timezone.utc)
                    ).days
                else:
                    days_remaining = 0

                return {
                    "passed": days_remaining > 0,
                    "tls_version": tls_version,
                    "days_remaining": days_remaining,
                }
    except Exception as e:
        return {"passed": False, "error": str(e)}


# ============================================================
# PASSWORD HASHING
# ============================================================
def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against a bcrypt hash."""
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )


# ============================================================
# MAIN AUDIT FUNCTION
# ============================================================
def run_rpp4_audit(url: str) -> RPP4Result:
    """Main entry point for the RPP.4 audit."""
    normalized = normalize_url(url)
    hostname = get_hostname(normalized)

    http_data = check_https_and_hsts(normalized)
    ssl_data = check_ssl_certificate(hostname)

    score = 0
    if http_data.get("https_passed"):
        score += 40
    if ssl_data.get("passed"):
        score += 40
    if http_data.get("hsts_passed"):
        score += 20

    if score == 100:
        status = "Passed"
        finding = "All HTTPS, SSL/TLS, and HSTS checks passed securely."
    elif score >= 50:
        status = "Warning"
        finding = (
            "Website uses HTTPS but may be missing strict HSTS or has expiring certs."
        )
    else:
        status = "Failed"
        finding = (
            "Severe security risks detected regarding HTTPS or SSL certificates."
        )

    return RPP4Result(
        status=status,
        score=score,
        finding=finding,
        ai_remediation="Ensure port 80 redirects to 443, enforce TLS 1.2+, and implement HSTS headers.",
        checks={"https": http_data, "ssl_certificate": ssl_data},
    )


# ============================================================
# LOCAL TESTING
# ============================================================
if __name__ == "__main__":
    test_url = input("Enter website URL to audit (e.g., google.com): ")
    result = run_rpp4_audit(test_url)
    print(json.dumps(result.model_dump(), indent=2))

    # ============================================================
# LOCAL TESTING & JSON FILE EXPORT
# ============================================================
if __name__ == "__main__":
    import json

    test_url = input("Enter website URL to audit (e.g., google.com): ")
    result = run_rpp4_audit(test_url)

    # 1. Convert result model to dictionary / JSON string
    json_output = result.model_dump()

    # 2. Save directly to rpp4_result.json file in your project folder
    output_filename = "rpp4_result.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(json_output, f, indent=4)

    print("\n" + "=" * 50)
    print(f"SUCCESS! Audit result saved to '{output_filename}'")
    print("=" * 50)