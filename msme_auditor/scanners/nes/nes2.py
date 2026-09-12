"""
NES.2 — Wi-Fi Security (Fully Automated)
=========================================
Auto-detects REAL Wi-Fi settings on Windows and Linux.

Backend stack:
  - Config-driven policy via config/nes2_policy.yaml
  - Safe subprocess wrapper (core/command_runner.py)
  - Structured audit logging (core/audit_logger.py)
  - ERROR is distinct from FAIL
"""

import os
import platform
import re
import math
from typing import List, Dict, Optional

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck
from msme_auditor.core.command_runner import run_command
from msme_auditor.core.policy_loader import load_policy_for
from msme_auditor.core.audit_logger import get_audit_logger, log_scan_event


# =============================================================================
# COMMON PASSWORD DICTIONARY
# =============================================================================
COMMON_PASSWORDS = {
    "password", "12345678", "123456789", "1234567890", "password123",
    "admin", "letmein", "welcome", "monkey", "dragon", "master",
    "qwerty", "login", "abc123", "trustno1", "iloveyou",
    "password1", "sunshine", "princess", "football", "charlie",
    "shadow", "michael", "qwerty123", "12345678910", "superman",
    "hello", "ninja", "mustang", "jessica", "ashley",
    "love", "george", "thomas", "hunter", "andrew",
    "winter", "hunter2", "ranger", "solo", "freedom",
    "passw0rd", "changeme", "default", "test", "guest",
    "master123", "admin123", "root", "toor", "pass",
    "secret", "internet", "wireless", "wifi", "wifi1234",
    "home", "office", "company", "business", "network",
}


# =============================================================================
# PASSWORD STRENGTH ANALYZER
# =============================================================================
def _analyze_password_strength(password: str) -> Dict:
    """Analyze a WiFi password for strength."""
    if not password:
        return {
            "length": 0, "has_upper": False, "has_lower": False,
            "has_digit": False, "has_special": False,
            "entropy_bits": 0, "strength_label": "No Password",
            "is_common": True,
        }

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    is_common = password.lower().strip() in COMMON_PASSWORDS
    if not is_common:
        if len(set(password)) <= 2 and length >= 4:
            is_common = True
        if re.match(r"^(.)\1+$", password):
            is_common = True

    charset_size = 0
    if has_upper: charset_size += 26
    if has_lower: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 33
    if charset_size == 0: charset_size = 26

    entropy_bits = round(length * math.log2(charset_size), 1) if length > 0 else 0

    if is_common:
        strength_label = "Very Weak (common)"
    elif entropy_bits < 28:
        strength_label = "Weak"
    elif entropy_bits < 50:
        strength_label = "Fair"
    elif entropy_bits < 65:
        strength_label = "Strong"
    else:
        strength_label = "Very Strong"

    return {
        "length": length, "has_upper": has_upper, "has_lower": has_lower,
        "has_digit": has_digit, "has_special": has_special,
        "entropy_bits": entropy_bits, "strength_label": strength_label,
        "is_common": is_common,
    }


# =============================================================================
# WINDOWS WIFI DETECTION
# =============================================================================
def _is_admin_windows() -> bool:
    """Check if running with Administrator privileges on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _extract_password_netsh(ssid: str) -> str:
    """Extract WiFi password via netsh (requires admin)."""
    result = run_command(["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"])
    if result.success:
        for line in result.stdout.split("\n"):
            if "Key Content" in line:
                m = re.search(r"Key Content\s*:\s*(.+)$", line, re.IGNORECASE)
                if m:
                    return m.group(1).strip()
    return ""


def _extract_password_xml(ssid: str) -> str:
    """Extract WiFi password from Windows WLAN profile XML files."""
    try:
        profile_dir = r"C:\ProgramData\Microsoft\Wlansvc\Profiles"
        if not os.path.isdir(profile_dir):
            return ""
        for root, _dirs, files in os.walk(profile_dir):
            for fname in files:
                if fname.endswith(".xml"):
                    filepath = os.path.join(root, fname)
                    try:
                        with open(filepath, "r", encoding="utf-16", errors="ignore") as f:
                            content = f.read()
                            if ssid in content:
                                match = re.search(r"<keyMaterial>(.*?)</keyMaterial>", content)
                                if match:
                                    return match.group(1).strip()
                    except (OSError, UnicodeError):
                        pass
    except (OSError, PermissionError):
        pass
    return ""


def _detect_wifi_windows() -> Optional[Dict]:
    """Extract REAL Wi-Fi info from Windows using netsh."""
    info: Dict[str, str] = {}
    is_admin = _is_admin_windows()

    # Step 1: Get connection info
    result = run_command(["netsh", "wlan", "show", "interfaces"])
    if not result.success:
        return None

    output = result.stdout
    if not output or "not connected" in output.lower():
        return None

    patterns = {
        "ssid": r"^\s*SSID\s*#\s*\d+\s*:\s*(.+)$",
        "auth": r"^\s*Authentication\s*:\s*(.+)$",
        "encryption": r"^\s*Encryption\s*:\s*(.+)$",
        "signal": r"^\s*Signal\s*:\s*(\d+)%",
        "radio": r"^\s*Radio type\s*:\s*(.+)$",
        "channel": r"^\s*Channel\s*:\s*(.+)$",
    }

    for line in output.split("\n"):
        for key, pattern in patterns.items():
            if key not in info:
                m = re.match(pattern, line, re.IGNORECASE)
                if m:
                    info[key] = m.group(1).strip()

    if not info.get("ssid"):
        return None

    if info["ssid"] == "" or info["ssid"].lower() == "hidden":
        info["hidden_ssid"] = True

    # Step 2: Extract password with multiple fallback methods
    ssid = info.get("ssid", "")
    password = ""

    if is_admin:
        password = _extract_password_netsh(ssid)

    if not password:
        password = _extract_password_xml(ssid)

    if not password:
        info["password_extraction_failed"] = True
        info["admin_required"] = not is_admin

    info["password"] = password
    info["platform"] = "Windows"
    info["is_admin"] = is_admin

    # Step 3: WPS detection
    info["wps_enabled"] = _detect_wps_windows(ssid)

    return info


def _detect_wps_windows(ssid: str) -> bool:
    """Accurate WPS detection using multiple methods on Windows."""
    result = run_command(["netsh", "wlan", "show", "profile", f"name={ssid}"])
    if result.success:
        for line in result.stdout.lower().split("\n"):
            if "wps" in line and ("enabled" in line or "active" in line or "on" in line):
                return True

    result = run_command(["netsh", "wlan", "show", "profiles"])
    if result.success:
        output = result.stdout.lower()
        if "wps" in output and ("enabled" in output or "active" in output):
            return True

    return False


# =============================================================================
# LINUX WIFI DETECTION
# =============================================================================
def _detect_wifi_linux() -> Optional[Dict]:
    """Extract REAL Wi-Fi info from Linux using nmcli."""
    info: Dict[str, str] = {}

    result = run_command(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,SIGNAL", "device", "wifi", "list"])
    if not result.success:
        return None

    for line in result.stdout.strip().split("\n"):
        parts = line.split(":")
        if len(parts) >= 4 and parts[0] == "yes":
            info["signal"] = parts[-1].strip()
            info["security_raw"] = parts[-2].strip()
            info["ssid"] = ":".join(parts[1:-2]).strip()
            break

    if not info.get("ssid"):
        return None

    security = info.get("security_raw", "").upper()
    if "SAE" in security or "WPA3" in security:
        info["auth"] = "WPA3-Personal"
        info["encryption"] = "AES"
    elif "WPA2" in security:
        info["auth"] = "WPA2-Personal"
        info["encryption"] = "AES"
    elif "WPA" in security:
        info["auth"] = "WPA"
        info["encryption"] = "TKIP"
    elif "WEP" in security:
        info["auth"] = "WEP"
        info["encryption"] = "WEP"
    elif "NONE" in security or not security.strip():
        info["auth"] = "Open"
        info["encryption"] = "None"
    else:
        info["auth"] = security
        info["encryption"] = "Unknown"

    ssid = info.get("ssid", "")
    password = ""
    conn_result = run_command(["nmcli", "-s", "connection", "show", ssid])
    if conn_result.success:
        for line in conn_result.stdout.split("\n"):
            if "802-11-wireless-security.psk:" in line:
                m = re.search(r"802-11-wireless-security\.psk:\s*(.+)$", line)
                if m:
                    password = m.group(1).strip()
                    break

    info["password"] = password
    info["platform"] = "Linux"
    info["wps_enabled"] = False
    info["hidden_ssid"] = False

    return info


# =============================================================================
# ENTERPRISE WI-FI DETECTION
# =============================================================================
def _detect_enterprise_wifi(ssid: str) -> Dict:
    """Detect enterprise Wi-Fi (WPA2/WPA3-Enterprise)."""
    result: Dict = {
        "is_enterprise": False, "auth_type": "",
        "eap_method": "", "certificate_valid": False,
    }

    system = platform.system()

    if system == "Windows":
        cmd_result = run_command(["netsh", "wlan", "show", "profile", f"name={ssid}"])
        if cmd_result.success:
            output = cmd_result.stdout
            if "WPA2-Enterprise" in output or "WPA3-Enterprise" in output:
                result["is_enterprise"] = True
                result["auth_type"] = "WPA3-Enterprise" if "WPA3" in output else "WPA2-Enterprise"
                if "PEAP" in output: result["eap_method"] = "PEAP"
                elif "EAP-TLS" in output: result["eap_method"] = "EAP-TLS"
                elif "TTLS" in output: result["eap_method"] = "EAP-TTLS"
                if "Validate server certificate" in output:
                    section = output.split("Validate server certificate")[1].split("\n")[0]
                    if "yes" in section.lower():
                        result["certificate_valid"] = True

    elif system == "Linux":
        conn_result = run_command(["nmcli", "-s", "connection", "show", ssid])
        if conn_result.success:
            if "802-1x" in conn_result.stdout.lower():
                result["is_enterprise"] = True
                result["auth_type"] = "WPA2/WPA3-Enterprise (802.1X)"
                eap_match = re.search(r"802-1x\.eap:\s*(.+)", conn_result.stdout)
                if eap_match:
                    result["eap_method"] = eap_match.group(1).strip()

    return result


# =============================================================================
# PMF / DEAUTH VULNERABILITY CHECK
# =============================================================================
def _detect_pmf_status(ssid: str) -> Dict:
    """Check if the connected Wi-Fi uses Protected Management Frames (802.11w)."""
    result: Dict = {
        "pmf_enabled": False, "pmf_required": False,
        "vulnerable_to_deauth": True,
    }

    system = platform.system()

    if system == "Windows":
        profile_result = run_command(["netsh", "wlan", "show", "profile", f"name={ssid}"])
        if profile_result.success:
            output = profile_result.stdout
            if "WPA3" in output or "SAE" in output:
                result["pmf_enabled"] = True
                result["pmf_required"] = True
                result["vulnerable_to_deauth"] = False
            elif "Protected Management Frames" in output:
                section = output.split("Protected Management Frames")[1].split("\n")[0]
                if "Required" in section:
                    result["pmf_enabled"] = True
                    result["pmf_required"] = True
                    result["vulnerable_to_deauth"] = False
                elif "Optional" in section:
                    result["pmf_enabled"] = True
                    result["vulnerable_to_deauth"] = False

    elif system == "Linux":
        conn_result = run_command(["nmcli", "-s", "connection", "show", ssid])
        if conn_result.success:
            if "ieee-80211w" in conn_result.stdout:
                section = conn_result.stdout.split("ieee-80211w")[1].split("\n")[0]
                if "1" in section:
                    result["pmf_enabled"] = True
                    result["pmf_required"] = True
                    result["vulnerable_to_deauth"] = False

    return result


# =============================================================================
# COMBINED DETECTION
# =============================================================================
def _detect_current_wifi() -> Optional[Dict]:
    """Detect Wi-Fi settings based on the current OS."""
    system = platform.system()
    if system == "Windows":
        return _detect_wifi_windows()
    elif system == "Linux":
        return _detect_wifi_linux()
    return None


# =============================================================================
# NES.2 SCANNER
# =============================================================================
class NES2Scanner(BaseScanner):
    scanner_id = "nes2"
    name = "NES.2 — Wi-Fi Security"
    description = "Auto-detects real Wi-Fi: SSID, password, encryption, signal strength."
    category = "NES"
    target_types = ["web"]
    input_fields = [
        {"name": "_auto_scan", "label": "Auto-Scan (no input needed)", "field_type": "text",
         "required": False, "placeholder": "Click 'Run Scan' to auto-detect your Wi-Fi",
         "help_text": "This scanner automatically detects your connected Wi-Fi network"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        # Load policy
        try:
            policy = load_policy_for("nes2")
        except (FileNotFoundError, KeyError) as exc:
            return [self._scan_error(f"Policy config error: {exc}")]

        # Audit logging
        audit_logger = get_audit_logger()
        log_scan_event(audit_logger, self.scanner_id, "local_wifi", "started")

        try:
            detected = _detect_current_wifi()
            if detected:
                result = self._build_checks(detected, policy)
            else:
                result = [make_check(
                    "wifi_detected", "Wi-Fi Connection Detected",
                    False, "Active Wi-Fi connection",
                    "No Wi-Fi connection detected on this device",
                    SeverityLevel.CRITICAL,
                    "Connect to a Wi-Fi network first\n"
                    "Or run: netsh wlan show interfaces (Windows)\n"
                    "Or: nmcli device wifi list (Linux)",
                )]
        except Exception as exc:
            result = [self._scan_error(str(exc))]
        finally:
            log_scan_event(audit_logger, self.scanner_id, "local_wifi", "completed")

        return result

    def _build_checks(self, detected: dict, policy: dict) -> List[SecurityCheck]:
        """Build checks from detected Wi-Fi info against policy thresholds."""
        ssid = detected.get("ssid", "Unknown")
        auth = detected.get("auth", detected.get("security_raw", "Unknown"))
        encryption = detected.get("encryption", "Unknown")
        signal = detected.get("signal", "N/A")
        radio = detected.get("radio", "N/A")
        channel = detected.get("channel", "N/A")
        password = detected.get("password", "")
        hidden = detected.get("hidden_ssid", False)
        wps_enabled = detected.get("wps_enabled", False)
        is_admin = detected.get("is_admin", False)

        approved_enc = [e.upper() for e in policy.get("approved_encryption", [])]
        rejected_enc = [e.upper() for e in policy.get("rejected_encryption", [])]
        modern_stds = [s.upper() for s in policy.get("modern_standards", [])]
        safe_channels = policy.get("safe_channels_2ghz", [1, 6, 11])
        min_signal = policy.get("min_signal_strength", 40)
        max_signal = policy.get("max_signal_strength", 80)
        min_pw_len = policy.get("min_password_length", 16)
        min_entropy = policy.get("min_entropy_bits", 50)
        require_pmf = policy.get("require_pmf", True)

        checks: List[SecurityCheck] = []

        # Check 1: Wi-Fi Encryption
        is_wpa3 = bool(auth and ("WPA3" in auth.upper() or "SAE" in auth.upper()))
        is_wpa2 = bool(auth and "WPA2" in auth.upper())
        is_secure = is_wpa3 or is_wpa2
        is_wep = bool(auth and "WEP" in auth.upper())
        is_open = bool(auth and ("OPEN" in auth.upper() or auth.upper() == "NONE"))

        if is_wpa3:
            enc_detail = f"WPA3-Personal ({encryption}) -- BEST"
        elif is_wpa2:
            enc_detail = f"WPA2-Personal ({encryption}) -- Good"
        elif is_wep:
            enc_detail = f"WEP ({encryption}) -- INSECURE"
        elif is_open:
            enc_detail = f"Open ({encryption}) -- INSECURE"
        else:
            enc_detail = f"{auth} ({encryption})"

        checks.append(make_check(
            "wifi_encryption", "WPA2/WPA3 Encryption Active",
            is_secure,
            "WPA3 (preferred) or WPA2-AES minimum",
            enc_detail,
            SeverityLevel.CRITICAL if (is_wep or is_open) else (SeverityLevel.INFO if is_secure else SeverityLevel.HIGH),
            "Upgrade router firmware to support WPA3\nIf WPA3 unavailable, use WPA2-AES (NOT WPA2-TKIP)\nNever use WEP or Open networks for business use",
        ))

        # Check 2: Password Strength
        if password:
            pw_info = _analyze_password_strength(password)
            is_strong = pw_info["length"] >= min_pw_len and pw_info["entropy_bits"] >= min_entropy and not pw_info["is_common"]
            detail_parts = [
                f"Length: {pw_info['length']} chars",
                f"Entropy: {pw_info['entropy_bits']} bits",
                f"Strength: {pw_info['strength_label']}",
            ]
            if pw_info["has_upper"]: detail_parts.append("Uppercase")
            if pw_info["has_lower"]: detail_parts.append("Lowercase")
            if pw_info["has_digit"]: detail_parts.append("Digits")
            if pw_info["has_special"]: detail_parts.append("Special")
            if pw_info["is_common"]: detail_parts.append("COMMON PASSWORD!")

            checks.append(make_check(
                "wifi_password_strength", "Wi-Fi Password Strength",
                is_strong,
                f"{min_pw_len}+ characters, mixed case, numbers, special chars (>={min_entropy} bits entropy)",
                " | ".join(detail_parts),
                SeverityLevel.CRITICAL if not is_strong else SeverityLevel.INFO,
                f"Current password ({pw_info['length']} chars, {pw_info['strength_label']})\n"
                f"Use {min_pw_len}+ char passphrase with mixed characters",
            ))
        else:
            if not is_admin and detected.get("platform") == "Windows":
                pw_msg = "Password extraction requires Administrator privileges"
                remediation = "Run as Administrator to extract password"
            else:
                pw_msg = "Password could not be extracted from system"
                remediation = "Ensure you have permission to read Wi-Fi credentials"

            checks.append(make_check(
                "wifi_password_strength", "Wi-Fi Password Strength",
                False, f"{min_pw_len}+ characters, mixed case, numbers, special chars",
                pw_msg, SeverityLevel.HIGH, remediation,
            ))

        # Check 3: SSID Name
        default_ssid_patterns = [
            r"^linksys", r"^netgear", r"^dlink", r"^d-link",
            r"^tp-link", r"^tplink", r"^asus", r"^mi[-_]", r"^xiaomi",
            r"^tenda", r"^totolink", r"^h3c", r"^zte", r"^huawei",
            r"^belkin", r"^cisco", r"^arris", r"^technicolor",
        ]
        is_default_ssid = any(re.match(p, ssid, re.IGNORECASE) for p in default_ssid_patterns)
        checks.append(make_check(
            "ssid_custom", "Custom SSID Name (Not Default)",
            not is_default_ssid, "Custom SSID name (not router brand default)",
            f'SSID: "{ssid}"' + (" -- default name" if is_default_ssid else " -- custom name"),
            SeverityLevel.MEDIUM if is_default_ssid else SeverityLevel.INFO,
            "Change SSID from default router name\nAvoid names that identify your business",
        ))

        # Check 4: Signal Strength
        try:
            signal_pct = int(re.search(r"\d+", signal).group()) if signal != "N/A" else 0
        except (AttributeError, ValueError):
            signal_pct = 0

        checks.append(make_check(
            "signal_strength", "Wi-Fi Signal Strength",
            min_signal <= signal_pct <= max_signal,
            f"{min_signal}-{max_signal}% (controlled coverage)",
            f"{signal_pct}%" if signal_pct else "N/A",
            SeverityLevel.LOW,
            "Ensure signal does not extend beyond your premises",
        ))

        # Check 5: Radio Type
        radio_upper = radio.upper() if radio != "N/A" else ""
        is_modern_radio = any(r in radio_upper for r in modern_stds)
        checks.append(make_check(
            "radio_type", "Modern Wi-Fi Standard (Wi-Fi 5/6/7)",
            is_modern_radio, "802.11ac or 802.11ax",
            f"Radio: {radio}" if radio != "N/A" else "Not detected",
            SeverityLevel.MEDIUM if not is_modern_radio else SeverityLevel.INFO,
            "Upgrade to Wi-Fi 6 (802.11ax) or Wi-Fi 5 (802.11ac)",
        ))

        # Check 6: WPS Detection
        checks.append(make_check(
            "wps_disabled", "WPS Disabled",
            not wps_enabled, "WPS disabled on all access points",
            "WPS: ENABLED" if wps_enabled else "WPS: Disabled (or unknown)",
            SeverityLevel.CRITICAL if wps_enabled else SeverityLevel.MEDIUM,
            "Disable WPS on router admin panel\nWPS PIN mode is vulnerable to brute-force",
        ))

        # Check 7: Hidden SSID
        checks.append(make_check(
            "hidden_ssid", "SSID Broadcast Configuration",
            not hidden, "SSID visibility appropriate",
            f"SSID: {ssid}" + (" (HIDDEN)" if hidden else " (broadcasting)"),
            SeverityLevel.INFO,
            "Hidden SSIDs provide minimal security (easily discovered)",
        ))

        # Check 8: Channel Security
        try:
            channel_num = int(re.search(r"\d+", str(channel)).group()) if channel != "N/A" else 0
        except (AttributeError, ValueError):
            channel_num = 0

        if channel_num > 0:
            if channel_num <= 14:
                is_safe_channel = channel_num in safe_channels
                freq_band = "2.4 GHz"
            else:
                is_safe_channel = True
                freq_band = "5 GHz"

            checks.append(make_check(
                "channel_security", f"Wi-Fi Channel ({freq_band})",
                is_safe_channel,
                f"Non-overlapping channel ({'/'.join(str(c) for c in safe_channels)} for 2.4 GHz)" if freq_band == "2.4 GHz" else "5 GHz channel (generally safe)",
                f"Channel {channel_num} ({freq_band})",
                SeverityLevel.LOW if not is_safe_channel else SeverityLevel.INFO,
                f"For 2.4 GHz: Use channels {', '.join(str(c) for c in safe_channels)}",
            ))

        # Check 9: Enterprise Wi-Fi
        enterprise_info = _detect_enterprise_wifi(ssid)
        if enterprise_info["is_enterprise"]:
            checks.append(make_check(
                "enterprise_wifi", "Enterprise Wi-Fi (802.1X) Configured",
                True, "WPA2/WPA3-Enterprise with RADIUS",
                f"Auth: {enterprise_info['auth_type']}, EAP: {enterprise_info['eap_method']}",
                SeverityLevel.INFO,
                "Enterprise Wi-Fi provides centralized authentication",
            ))
            checks.append(make_check(
                "cert_validation", "Server Certificate Validation Enabled",
                enterprise_info["certificate_valid"],
                "Certificate validation enabled on client",
                "Enabled" if enterprise_info["certificate_valid"] else "DISABLED",
                SeverityLevel.HIGH,
                "Enable certificate validation to prevent rogue AP attacks",
            ))

        # Check 10: PMF / Deauth Vulnerability
        pmf_info = _detect_pmf_status(ssid)
        if require_pmf:
            checks.append(make_check(
                "pmf_enabled", "Protected Management Frames (802.11w) Enabled",
                not pmf_info["vulnerable_to_deauth"],
                "PMF enabled (WPA3 mandatory, WPA2 optional)",
                "PMF: Enabled (Required)" if pmf_info["pmf_required"] else
                ("PMF: Enabled (Optional)" if pmf_info["pmf_enabled"] else
                 "PMF: Not detected -- VULNERABLE to deauth attacks"),
                SeverityLevel.HIGH if pmf_info["vulnerable_to_deauth"] else SeverityLevel.INFO,
                "Enable 802.11w to prevent deauth attacks\nWPA3 includes mandatory PMF",
            ))

        return checks

    def _scan_error(self, message: str) -> SecurityCheck:
        """Return a scan-error check — never fake pass/fail."""
        return make_check(
            "scan_error", "NES.2 Scan Error",
            False, "Successful scan execution",
            f"Scan failed: {message}", SeverityLevel.HIGH,
            f"Manual audit required. Error: {message}",
        )
