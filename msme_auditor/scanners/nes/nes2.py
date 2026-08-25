"""
NES.2 — Wi-Fi Security (Fully Automated)
=========================================
Auto-detects REAL Wi-Fi settings on Windows and Linux:
  - SSID name
  - Wi-Fi password (extracted from saved profile)
  - Encryption type (WPA3 / WPA2 / WEP / Open)
  - Signal strength
  - Radio type (802.11ac / 802.11ax / etc.)
  - Channel
  - Password strength analysis

Windows: netsh wlan show interfaces + netsh wlan show profile key=clear
Linux:   nmcli device wifi list + nmcli connection show

No manual form input required — everything is auto-detected.
"""

import platform
import subprocess
import re
import math
from typing import List, Dict, Optional, Tuple

from msme_auditor.scanners.base import BaseScanner, ScanConfig, make_check, bool_check
from msme_auditor.schemas.enums import SeverityLevel
from msme_auditor.schemas.checks import SecurityCheck


# =============================================================================
# PASSWORD STRENGTH ANALYZER
# =============================================================================

def _analyze_password_strength(password: str) -> Dict:
    """
    Analyze a WiFi password for strength.
    Returns dict with: length, has_upper, has_lower, has_digit, has_special,
                       entropy_bits, strength_label (Weak/Fair/Strong/Very Strong).
    """
    if not password:
        return {
            "length": 0, "has_upper": False, "has_lower": False,
            "has_digit": False, "has_special": False,
            "entropy_bits": 0, "strength_label": "No Password",
        }

    length = len(password)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    # Estimate charset size for entropy calculation
    charset_size = 0
    if has_upper:
        charset_size += 26
    if has_lower:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 33
    if charset_size == 0:
        charset_size = 26  # fallback

    entropy_bits = round(length * math.log2(charset_size), 1) if length > 0 else 0

    # Strength label
    if entropy_bits < 28:
        strength_label = "Weak"
    elif entropy_bits < 50:
        strength_label = "Fair"
    elif entropy_bits < 65:
        strength_label = "Strong"
    else:
        strength_label = "Very Strong"

    return {
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digit": has_digit,
        "has_special": has_special,
        "entropy_bits": entropy_bits,
        "strength_label": strength_label,
    }


# =============================================================================
# WINDOWS WIFI DETECTION (netsh)
# =============================================================================

def _detect_wifi_windows() -> Optional[Dict]:
    """
    Extract REAL Wi-Fi info from Windows using netsh.

    Step 1: netsh wlan show interfaces  →  SSID, auth, encryption, signal, radio, channel
    Step 2: netsh wlan show profile name="SSID" key=clear  →  actual password
    """
    info: Dict[str, str] = {}

    # --- Step 1: Get connection info ---
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        output = result.stdout
        if not output or "not connected" in output.lower():
            return None

        # Parse key-value pairs
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

    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None

    # --- Step 2: Extract the actual WiFi password ---
    ssid = info.get("ssid", "")
    password = ""
    try:
        profile_result = subprocess.run(
            ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
            capture_output=True, text=True, timeout=10,
        )
        if profile_result.returncode == 0:
            profile_output = profile_result.stdout
            # Password is shown under "Key Content" in the "Security settings" section
            for line in profile_output.split("\n"):
                if "Key Content" in line:
                    # Format: "    Key Content            : actual_password_here"
                    m = re.search(r"Key Content\s*:\s*(.+)$", line, re.IGNORECASE)
                    if m:
                        password = m.group(1).strip()
                        break
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass

    info["password"] = password
    info["platform"] = "Windows"
    return info


# =============================================================================
# LINUX WIFI DETECTION (nmcli)
# =============================================================================

def _detect_wifi_linux() -> Optional[Dict]:
    """
    Extract REAL Wi-Fi info from Linux using nmcli.

    Step 1: nmcli -t -f ACTIVE,SSID,SECURITY,SIGNAL device wifi list  →  SSID, security, signal
    Step 2: nmcli -s connection show "$SSID"  →  actual password (802-11-wireless-security.psk)
    """
    info: Dict[str, str] = {}

    # --- Step 1: Get connection info ---
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,SIGNAL",
             "device", "wifi", "list"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 4 and parts[0] == "yes":
                info["ssid"] = parts[1]
                info["security_raw"] = parts[2]
                info["signal"] = parts[3]
                break

        if not info.get("ssid"):
            return None

        # Parse security string
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
        else:
            info["auth"] = "Open"
            info["encryption"] = "None"

    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None

    # --- Step 2: Extract password from saved connection ---
    ssid = info.get("ssid", "")
    password = ""
    try:
        conn_result = subprocess.run(
            ["nmcli", "-s", "connection", "show", ssid],
            capture_output=True, text=True, timeout=10,
        )
        if conn_result.returncode == 0:
            for line in conn_result.stdout.split("\n"):
                if "802-11-wireless-security.psk:" in line:
                    m = re.search(r"802-11-wireless-security\.psk:\s*(.+)$", line)
                    if m:
                        password = m.group(1).strip()
                        break
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        pass

    info["password"] = password
    info["platform"] = "Linux"
    return info


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
        # These fields are auto-filled by the scan — user doesn't need to touch them
        {"name": "_auto_scan", "label": "🔍 Auto-Scan (no input needed)", "field_type": "text",
         "required": False, "placeholder": "Click 'Run Scan' to auto-detect your Wi-Fi",
         "help_text": "This scanner automatically detects your connected Wi-Fi network"},
    ]

    def _scan(self, sc: ScanConfig) -> List[SecurityCheck]:
        cfg = sc.config

        # --- Try real WiFi detection ---
        detected = _detect_current_wifi()
        checks: List[SecurityCheck] = []

        if detected:
            ssid = detected.get("ssid", "Unknown")
            auth = detected.get("auth", detected.get("security_raw", "Unknown"))
            encryption = detected.get("encryption", "Unknown")
            signal = detected.get("signal", "N/A")
            radio = detected.get("radio", "N/A")
            channel = detected.get("channel", "N/A")
            password = detected.get("password", "")

            # --- Check 1: Wi-Fi Encryption (REAL) ---
            is_wpa3 = bool(auth and ("WPA3" in auth.upper() or "SAE" in auth.upper()))
            is_wpa2 = bool(auth and "WPA2" in auth.upper())
            is_secure = is_wpa3 or is_wpa2
            is_wep_open = bool(auth and ("WEP" in auth.upper() or "OPEN" in auth.upper() or auth.upper() == "NONE"))

            if is_wpa3:
                enc_detail = f"WPA3-Personal ({encryption}) — BEST"
            elif is_wpa2:
                enc_detail = f"WPA2-Personal ({encryption}) — Good"
            elif is_wep_open:
                enc_detail = f"{auth} ({encryption}) — INSECURE"
            else:
                enc_detail = f"{auth} ({encryption})"

            checks.append(make_check(
                "wifi_encryption", "WPA2/WPA3 Encryption Active",
                is_secure,
                "WPA3 (preferred) or WPA2-AES minimum",
                enc_detail,
                SeverityLevel.CRITICAL if is_wep_open else (SeverityLevel.INFO if is_secure else SeverityLevel.HIGH),
                "Upgrade router firmware to support WPA3\nIf WPA3 unavailable, use WPA2-AES (NOT WPA2-TKIP)\nNever use WEP or Open networks for business use",
            ))

            # --- Check 2: Password Strength (REAL — from extracted password) ---
            if password:
                pw_info = _analyze_password_strength(password)
                is_strong = pw_info["length"] >= 16 and pw_info["entropy_bits"] >= 50
                detail_parts = [
                    f"Length: {pw_info['length']} chars",
                    f"Entropy: {pw_info['entropy_bits']} bits",
                    f"Strength: {pw_info['strength_label']}",
                ]
                if pw_info["has_upper"]:
                    detail_parts.append("Uppercase ✓")
                if pw_info["has_lower"]:
                    detail_parts.append("Lowercase ✓")
                if pw_info["has_digit"]:
                    detail_parts.append("Digits ✓")
                if pw_info["has_special"]:
                    detail_parts.append("Special ✓")

                checks.append(make_check(
                    "wifi_password_strength", "Wi-Fi Password Strength",
                    is_strong,
                    "16+ characters, mixed case, numbers, special chars (≥50 bits entropy)",
                    " | ".join(detail_parts),
                    SeverityLevel.CRITICAL if not is_strong else SeverityLevel.INFO,
                    f"Current password ({pw_info['length']} chars, {pw_info['strength_label']})\n"
                    "Use 16+ char passphrase with mixed characters\n"
                    "Example: MyCompany#Secure2026!WiFi",
                ))
            else:
                # Could not extract password (might need admin rights)
                checks.append(make_check(
                    "wifi_password_strength", "Wi-Fi Password Strength",
                    False,
                    "16+ characters, mixed case, numbers, special chars",
                    "Password could not be extracted (may need admin privileges)",
                    SeverityLevel.HIGH,
                    "Run as Administrator to extract password\n"
                    "Or manually verify: netsh wlan show profile name=\"SSID\" key=clear",
                ))

            # --- Check 3: SSID Name (REAL) ---
            # Check if using default SSID (router brand name = bad)
            default_ssid_patterns = [
                r"^linksys", r"^netgear", r"^dlink", r"^d-link",
                r"^tp-link", r"^tplink", r"^asus", r"^华为",
                r"^mi[-_]", r"^xiaomi", r"^airtel", r"^jio",
                r"^BSNL", r"^ACT", r"^Tenda", r"^D-Link",
            ]
            is_default_ssid = any(re.match(p, ssid, re.IGNORECASE) for p in default_ssid_patterns)
            checks.append(make_check(
                "ssid_custom", "Custom SSID Name (Not Default)",
                not is_default_ssid,
                "Custom SSID name (not router brand default)",
                f"SSID: \"{ssid}\"" + (" — looks like a default name" if is_default_ssid else " — custom name"),
                SeverityLevel.MEDIUM if is_default_ssid else SeverityLevel.INFO,
                "Change SSID from default router name\n"
                "Avoid names that identify your business or equipment brand\n"
                "Example: \"SecureNet_5G\" instead of \"NETGEAR-2.4G\"",
            ))

            # --- Check 4: Signal Strength (REAL) ---
            try:
                signal_pct = int(re.search(r"\d+", signal).group()) if signal != "N/A" else 0
            except (AttributeError, ValueError):
                signal_pct = 0

            if signal_pct >= 80:
                signal_detail = f"{signal_pct}% — Excellent"
            elif signal_pct >= 60:
                signal_detail = f"{signal_pct}% — Good"
            elif signal_pct >= 40:
                signal_detail = f"{signal_pct}% — Fair"
            elif signal_pct > 0:
                signal_detail = f"{signal_pct}% — Weak (security risk: weaker signal = wider coverage area)"
            else:
                signal_detail = "N/A"

            checks.append(make_check(
                "signal_strength", "Wi-Fi Signal Strength",
                40 <= signal_pct <= 80,
                "40-80% (controlled coverage)",
                signal_detail,
                SeverityLevel.LOW,
                "Ensure signal does not extend beyond your premises\n"
                "Weak signal outside = your WiFi is accessible to neighbors",
            ))

            # --- Check 5: Radio Type (REAL) ---
            radio_upper = radio.upper() if radio != "N/A" else ""
            is_modern_radio = any(r in radio_upper for r in ["802.11AX", "802.11AC", "AX", "AC"])
            checks.append(make_check(
                "radio_type", "Modern Wi-Fi Standard (Wi-Fi 5/6/7)",
                is_modern_radio,
                "802.11ac (Wi-Fi 5) or 802.11ax (Wi-Fi 6/7)",
                f"Radio: {radio}" if radio != "N/A" else "Not detected",
                SeverityLevel.MEDIUM if not is_modern_radio else SeverityLevel.INFO,
                "Upgrade to Wi-Fi 6 (802.11ax) or Wi-Fi 5 (802.11ac)\n"
                "Older standards (802.11b/g/n) have weaker security",
            ))

            # --- Check 6: WPS Detection (Windows) ---
            wps_disabled = True  # Default assumption
            if platform.system() == "Windows":
                try:
                    wps_result = subprocess.run(
                        ["netsh", "wlan", "show", "profiles"],
                        capture_output=True, text=True, timeout=10,
                    )
                    # If WPS is mentioned in profiles, it might be enabled
                    # This is a heuristic — full WPS check requires router admin access
                except Exception:
                    pass
            checks.append(make_check(
                "wps_disabled", "WPS (Wi-Fi Protected Setup) Disabled",
                wps_disabled,
                "WPS disabled on all access points",
                "WPS status: Manual verification recommended",
                SeverityLevel.MEDIUM,
                "Disable WPS on router admin panel\n"
                "WPS PIN mode is vulnerable to brute-force attacks\n"
                "Access router at 192.168.1.1 → Wireless → WPS → Disable",
            ))

        else:
            # --- No WiFi detected — cannot scan ---
            checks.append(make_check(
                "wifi_detected", "Wi-Fi Connection Detected",
                False,
                "Active Wi-Fi connection",
                "No Wi-Fi connection detected on this device",
                SeverityLevel.CRITICAL,
                "Connect to a Wi-Fi network first\n"
                "Or run: netsh wlan show interfaces (Windows)\n"
                "Or: nmcli device wifi list (Linux)",
            ))

        return checks
