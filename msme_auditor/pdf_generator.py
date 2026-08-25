"""
MSME Cyber Auditor — PDF Report Generator
==========================================
Uses fpdf2 (PyFPDF) to generate professional CERT-In compliance reports.

Usage:
    from msme_auditor.pdf_generator import generate_pdf
    pdf_bytes = generate_pdf(results, title="Scan Report")
    # write to file or return as HTTP response
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from io import BytesIO

import os
import re

from fpdf import FPDF


# =============================================================================
# Color constants (RGB)
# =============================================================================

class C:
    """
    Color palette optimized for PDF readability.
    Uses dark text on light backgrounds for maximum contrast.
    Section headers use accent colors for visual hierarchy.
    """
    # Backgrounds — light, reliable in all PDF viewers
    BG_PAGE = (255, 255, 255)        # White page background
    SURFACE = (245, 247, 250)        # Light gray card backgrounds
    SURFACE2 = (237, 239, 244)       # Slightly darker surface
    BORDER = (209, 213, 219)         # Subtle borders

    # Accent colors
    PRIMARY = (14, 165, 198)         # CyberSure teal
    PRIMARY_DARK = (11, 132, 158)    # Darker teal for headers
    PRIMARY_LIGHT = (180, 220, 235)  # Light teal for subtle accents
    GREEN = (22, 163, 74)            # Success green
    GREEN_LIGHT = (160, 230, 190)    # Light green for accents
    RED = (220, 38, 38)              # Error red
    RED_LIGHT = (254, 202, 202)      # Light red for accents
    YELLOW = (217, 119, 6)           # Warning amber
    YELLOW_LIGHT = (253, 230, 138)   # Light amber for accents

    # Text — dark, high contrast on white
    TEXT = (15, 39, 64)              # Near-black for headings
    TEXT2 = (55, 65, 81)             # Dark gray for body text
    TEXT3 = (107, 114, 128)          # Medium gray for secondary text
    WHITE = (255, 255, 255)          # White (for text on colored backgrounds)
    HEADER_BG = (15, 39, 64)         # Dark header background
    BG_DARK = (15, 39, 64)           # Alias for dark background (used by pdf_normalization)


# =============================================================================
# PDF Builder
# =============================================================================

# Unicode character mapping for Latin-1 fallback
_UNICODE_MAP = {
    '\u2265': '>=',   # ≥
    '\u2264': '<=',   # ≤
    '\u2260': '!=',   # ≠
    '\u00d7': 'x',    # ×
    '\u00f7': '/',    # ÷
    '\u2013': '-',    # –
    '\u2014': '--',   # —
    '\u2018': "'",    # '
    '\u2019': "'",    # '
    '\u201c': '"',    # "
    '\u201d': '"',    # "
    '\u2022': '*',    # •
    '\u2026': '...',  # …
    '\u2192': '->',   # →
    '\u2190': '<-',   # ←
    '\u2191': '^',    # ↑
    '\u2193': 'v',    # ↓
    '\u2713': '[OK]', # ✓
    '\u2717': '[X]',  # ✗
    '\u2714': '[OK]', # ✔
    '\u2716': '[X]',  # ✖
    '\u25cf': '*',    # ●
    '\u25cb': 'o',    # ○
    '\u25a0': '[ ]',  # ■
    '\u25a1': '[ ]',  # □
}

# Font search paths (common locations for DejaVuSans TTF)
_FONT_SEARCH_PATHS = [
    # Linux
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    '/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf',
    '/usr/share/fonts/dejavu/DejaVuSans.ttf',
    '/usr/share/fonts/TTF/DejaVuSans.ttf',
    # Windows
    'C:/Windows/Fonts/dejavusans.ttf',
    'C:/Windows/Fonts/DejaVuSans.ttf',
    # macOS
    '/Library/Fonts/DejaVuSans.ttf',
    '/System/Library/Fonts/DejaVuSans.ttf',
]


def _sanitize_latin1(text: str) -> str:
    """Replace Unicode characters outside Latin-1 with safe ASCII equivalents."""
    if not isinstance(text, str):
        text = str(text)
    # Apply known Unicode mappings
    for char, replacement in _UNICODE_MAP.items():
        text = text.replace(char, replacement)
    # Replace any remaining non-Latin-1 characters
    result = []
    for ch in text:
        try:
            ch.encode('latin-1')
            result.append(ch)
        except (UnicodeEncodeError, UnicodeDecodeError):
            result.append('?')
    return ''.join(result)


class AuditPDF(FPDF):
    """Custom FPDF subclass for MSME Cyber Auditor reports."""

    def __init__(self, title: str = "Security Audit Report", target: str = "", scan_type: str = ""):
        super().__init__("p", "mm", "A4")
        self.audit_title = title
        self.target = target
        self.scan_type = scan_type
        self.report_id = f"RPT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.set_auto_page_break(auto=True, margin=20)

        # Try to load logo image
        self._logo_path = None
        _logo_candidates = [
            os.path.join(os.path.dirname(__file__), '..', 'Logo.jpeg'),
            os.path.join(os.path.dirname(__file__), '..', 'Logo.jpg'),
            os.path.join(os.path.dirname(__file__), '..', 'Logo.png'),
            'Logo.jpeg', 'Logo.jpg', 'Logo.png',
        ]
        for lp in _logo_candidates:
            if os.path.isfile(lp):
                self._logo_path = lp
                break

        # Try to load a Unicode font (DejaVuSans) for full Unicode support
        self._unicode_font = False
        for font_path in _FONT_SEARCH_PATHS:
            if os.path.isfile(font_path):
                try:
                    self.add_font('DejaVu', '', font_path, uni=True)
                    self.add_font('DejaVu', 'B', font_path.replace('DejaVuSans.ttf', 'DejaVuSans-Bold.ttf'), uni=True)
                    self.add_font('DejaVu', 'I', font_path.replace('DejaVuSans.ttf', 'DejaVuSans-Oblique.ttf'), uni=True)
                    self.add_font('DejaVu', 'BI', font_path.replace('DejaVuSans.ttf', 'DejaVuSans-BoldOblique.ttf'), uni=True)
                    self._unicode_font = True
                    self._font_family = 'DejaVu'
                    break
                except Exception:
                    continue

    def set_font(self, family="", style="", size=0):
        """Override to automatically use Unicode font when available."""
        if family.lower() == "helvetica" and self._unicode_font:
            super().set_font('DejaVu', style, size)
        else:
            super().set_font(family, style, size)

    def cell(self, w, h=0, txt='', **kwargs):
        """Override to sanitize text for Latin-1 font compatibility."""
        if not self._unicode_font:
            txt = _sanitize_latin1(txt)
        super().cell(w, h=h, txt=txt, **kwargs)

    def multi_cell(self, w, h=0, txt='', **kwargs):
        """Override to sanitize text for Latin-1 font compatibility."""
        if not self._unicode_font:
            txt = _sanitize_latin1(txt)
        super().multi_cell(w, h=h, txt=txt, **kwargs)

    # --- Header / Footer ---

    def header(self):
        if self.page_no() == 1:
            return  # cover page has its own header
        # Logo on left (small)
        if self._logo_path:
            try:
                self.image(self._logo_path, 15, 6, 12)
            except Exception:
                pass
        # Header text
        x_start = 29 if self._logo_path else 20
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*C.TEXT)
        self.set_xy(x_start, 7)
        self.cell(0, 5, "CyberSure Security Platform v2.0")
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C.TEXT3)
        self.set_xy(x_start, 12)
        label = self.scan_type or "CERT-In Compliance Scanner"
        self.cell(0, 4, f"{label}  |  Report: {self.report_id}")
        # Confidentiality on right
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*C.RED)
        self.set_xy(150, 7)
        self.cell(40, 4, "CONFIDENTIAL", align="R")
        self.set_draw_color(*C.BORDER)
        self.line(20, self.get_y() + 4, 190, self.get_y() + 4)
        self.set_y(self.get_y() + 8)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*C.TEXT3)
        self.cell(0, 5, f"CyberSure v2.0  |  Report: {self.report_id}  |  Page {self.page_no()}/{{nb}}", align="C")

    # --- Helper drawing primitives ---

    def _set_color(self, rgb):
        self.set_text_color(*rgb)

    def _fill_rect(self, x, y, w, h, rgb):
        self.set_fill_color(*rgb)
        self.rect(x, y, w, h, "F")

    def _draw_rounded_rect(self, x, y, w, h, r, fill_rgb):
        self.set_fill_color(*fill_rgb)
        self.rect(x, y, w, h, "F")

    def _score_color(self, score):
        if score >= 90:
            return C.GREEN
        elif score >= 60:
            return C.YELLOW
        return C.RED

    def _status_label(self, score):
        if score >= 90:
            return "COMPLIANT"
        elif score >= 60:
            return "PARTIAL"
        return "NON-COMPLIANT"

    def _check_page(self, needed_mm=40):
        if self.get_y() + needed_mm > 275:
            self.add_page()


# =============================================================================
# Cover page
# =============================================================================

def _draw_cover(pdf: AuditPDF, results: List[Dict], title: str):
    """Draw the cover page."""
    pdf.add_page()

    # Dark header band — text will be white on this
    pdf._fill_rect(0, 0, 210, 80, C.HEADER_BG)
    # Accent line
    pdf._fill_rect(0, 80, 210, 4, C.PRIMARY)

    # Logo area — use actual logo image if available, otherwise draw shield
    if pdf._logo_path:
        try:
            pdf.image(pdf._logo_path, 18, 14, 30)
        except Exception:
            pdf.set_fill_color(*C.PRIMARY)
            pdf.circle(32, 30, 12, "F")
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*C.WHITE)
            pdf.set_xy(20, 25)
            pdf.cell(24, 6, "CS", align="C")
    else:
        pdf.set_fill_color(*C.PRIMARY)
        pdf.circle(32, 30, 12, "F")
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*C.WHITE)
        pdf.set_xy(20, 25)
        pdf.cell(24, 6, "CS", align="C")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_xy(20, 31)
        pdf.cell(24, 4, "AUDIT", align="C")

    # Title — white on dark header
    x_title = 52
    pdf.set_xy(x_title, 18)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 12, "Security Audit Report")
    pdf.set_xy(x_title, 33)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(180, 190, 205)
    pdf.cell(0, 6, "CERT-In Compliance Assessment")
    pdf.set_xy(x_title, 41)
    pdf.cell(0, 6, "CyberSure Security Platform v2.0")

    # Scan type badge
    scan_type = pdf.scan_type or "Comprehensive"
    pdf.set_fill_color(*C.PRIMARY_DARK)
    pdf.rect(x_title, 49, 60, 8, "F")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*C.WHITE)
    pdf.set_xy(x_title, 49)
    pdf.cell(60, 8, f"Scan Type: {scan_type}", align="C")

    # Score badge on header
    scores = [r.get("score", 0) for r in results]
    avg = round(sum(scores) / len(scores)) if scores else 0
    sc = pdf._score_color(avg)
    pdf.set_fill_color(*sc)
    pdf.circle(180, 35, 14, "F")
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*C.WHITE)
    pdf.set_xy(166, 29)
    pdf.cell(28, 8, str(avg), align="C")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_xy(166, 37)
    pdf.cell(28, 4, "/100", align="C")

    # Report info box — below header
    now = datetime.now()
    date_str = now.strftime("%d %B %Y")
    time_str = now.strftime("%I:%M %p")

    pdf._fill_rect(20, 92, 170, 38, C.SURFACE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(25, 95)
    pdf.cell(0, 4, "REPORT DETAILS")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(25, 102)
    pdf.cell(80, 4, f"Report ID: {pdf.report_id}")
    pdf.set_xy(100, 102)
    pdf.cell(80, 4, f"Date: {date_str}  |  Time: {time_str}")
    pdf.set_xy(25, 108)
    pdf.cell(80, 4, "Tool: CyberSure v2.0")
    pdf.set_xy(100, 108)
    pdf.cell(80, 4, f"Scanners Run: {len(results)}")
    # Target info
    target = pdf.target or "Local System"
    pdf.set_xy(25, 114)
    pdf.cell(80, 4, f"Target: {target}")
    pdf.set_xy(100, 114)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*sc)
    pdf.cell(80, 4, f"Overall Score: {avg}/100  |  {pdf._status_label(avg)}")
    # Confidentiality
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.RED)
    pdf.set_xy(25, 121)
    pdf.cell(80, 4, "CONFIDENTIAL — For authorized recipients only")

    # Bottom summary
    pdf.set_xy(20, 138)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C.TEXT2)
    total_checks = sum(len(r.get("checks", [])) for r in results)
    passed = sum(1 for r in results for c in r.get("checks", []) if c.get("passed"))
    failed = total_checks - passed
    pdf.multi_cell(170, 5,
        f"Overall Score: {avg}/100 ({pdf._status_label(avg)})\n"
        f"Total Checks: {total_checks}  |  Passed: {passed}  |  Failed: {failed}\n"
        f"Risk Level: {'LOW' if avg >= 90 else 'MEDIUM' if avg >= 60 else 'HIGH'}"
    )


# =============================================================================
# Executive Summary
# =============================================================================

def _draw_executive_summary(pdf: AuditPDF, results: List[Dict]):
    """Draw the executive summary page."""
    pdf.add_page()

    # Section header
    pdf._fill_rect(0, 0, 210, 30, C.HEADER_BG)
    pdf._fill_rect(0, 30, 210, 2, C.PRIMARY)
    pdf.set_xy(20, 12)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 8, "Executive Summary")
    pdf.set_xy(20, 22)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(180, 190, 205)
    pdf.cell(0, 4, "What this report means for your business")

    y = 40

    # Score bar
    scores = [r.get("score", 0) for r in results]
    avg = round(sum(scores) / len(scores)) if scores else 0
    sc = pdf._score_color(avg)

    pdf._fill_rect(20, y, 170, 30, C.SURFACE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(25, y + 3)
    pdf.cell(0, 4, "COMPLIANCE SCORE")

    # Score bar background
    bar_y = y + 10
    pdf._fill_rect(25, bar_y, 160, 8, C.SURFACE2)
    # Score bar fill
    bar_w = int(160 * avg / 100)
    pdf._fill_rect(25, bar_y, bar_w, 8, sc)
    # Score text
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C.WHITE)
    pdf.set_xy(25, bar_y)
    pdf.cell(160, 8, f"{avg}%", align="C")

    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(25, bar_y + 10)
    pdf.cell(80, 4, f"Status: {pdf._status_label(avg)}")
    total_checks = sum(len(r.get("checks", [])) for r in results)
    passed = sum(1 for r in results for c in r.get("checks", []) if c.get("passed"))
    pdf.set_xy(100, bar_y + 10)
    pdf.cell(80, 4, f"Checks: {passed} passed, {total_checks - passed} failed out of {total_checks}")

    y += 42

    # --- Summary Table ---
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(20, y)
    pdf.cell(0, 6, "Compliance Summary")
    y += 8

    # Count pass/fail/warn per scanner
    warn_count = 0
    for r in results:
        for c in r.get("checks", []):
            if not c.get("passed") and c.get("severity", "") in ("Medium", "LOW", "Info"):
                warn_count += 1
    fail_count = total_checks - passed - warn_count
    if fail_count < 0:
        fail_count = total_checks - passed
        warn_count = 0

    # Table header
    pdf._fill_rect(20, y, 170, 8, C.SURFACE2)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(25, y + 2)
    pdf.cell(50, 4, "Metric")
    pdf.set_xy(120, y + 2)
    pdf.cell(30, 4, "Count", align="C")
    pdf.set_xy(155, y + 2)
    pdf.cell(30, 4, "Percentage", align="C")
    y += 9

    # Table rows
    table_rows = [
        ("Total Controls Checked", str(total_checks), "100%", C.TEXT),
        ("Passed", str(passed), f"{round(100*passed/total_checks) if total_checks else 0}%", C.GREEN),
        ("Failed", str(fail_count), f"{round(100*fail_count/total_checks) if total_checks else 0}%", C.RED),
        ("Warnings", str(warn_count), f"{round(100*warn_count/total_checks) if total_checks else 0}%", C.YELLOW),
    ]
    for i, (label, count, pct, color) in enumerate(table_rows):
        bg = C.SURFACE if i % 2 == 0 else C.BG_PAGE
        pdf._fill_rect(20, y, 170, 7, bg)
        pdf.set_fill_color(*color)
        pdf.rect(20, y, 3, 7, "F")
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(25, y + 1.5)
        pdf.cell(50, 4, label)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*color)
        pdf.set_xy(120, y + 1.5)
        pdf.cell(30, 4, count, align="C")
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C.TEXT3)
        pdf.set_xy(155, y + 1.5)
        pdf.cell(30, 4, pct, align="C")
        y += 7
    y += 6

    # What Does This Mean?
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(20, y)
    pdf.cell(0, 6, "What Does This Mean?")
    y += 8

    if avg >= 90:
        explanation = ("Your organization has strong security practices that meet CERT-In requirements. "
            "Your passwords are well-protected, accounts are properly locked after failed attempts, "
            "multi-factor authentication is enabled, and password storage uses modern encryption. "
            "You are compliant with Indian cybersecurity regulations.")
    elif avg >= 60:
        explanation = ("Your organization has some security measures in place but has gaps that need attention. "
            "While some areas are protected, there are weaknesses that could be exploited by attackers. "
            "CERT-In requires certain minimum standards - you are partially compliant and should address "
            "the failed checks below to avoid regulatory penalties.")
    else:
        explanation = ("Your organization has significant security gaps that put your data at risk. "
            "Multiple areas do not meet CERT-In requirements. This means your organization could face "
            "regulatory fines under IT Act Section 43A and is vulnerable to data breaches. "
            "Immediate action is required to fix the issues identified below.")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(25, y)
    pdf.multi_cell(160, 4, explanation)
    y = pdf.get_y() + 6

    # Risk level
    risk = "LOW" if avg >= 90 else "MEDIUM" if avg >= 60 else "HIGH"
    risk_color = C.GREEN if risk == "LOW" else C.YELLOW if risk == "MEDIUM" else C.RED

    pdf._fill_rect(20, y, 170, 16, C.SURFACE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(25, y + 4)
    pdf.cell(40, 4, "RISK LEVEL")
    pdf.set_fill_color(*risk_color)
    pdf.rect(65, y + 1, 25, 14, "F")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C.WHITE)
    pdf.set_xy(65, y + 4)
    pdf.cell(25, 8, risk, align="C")

    risk_desc = ("Your security posture is strong." if risk == "LOW"
        else "Moderate risk. Address failed checks within 30 days." if risk == "MEDIUM"
        else "High risk. Immediate action required within 7 days.")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(95, y + 4)
    pdf.cell(90, 4, risk_desc)

    y += 24

    # Per-scanner overview
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(20, y)
    pdf.cell(0, 6, "Scan Results Overview")
    y += 8

    for r in results:
        if y > 260:
            pdf.add_page()
            y = 20
        s = r.get("score", 0)
        st = r.get("status", {})
        status_val = st.get("value", "Unknown") if isinstance(st, dict) else str(st)
        sc = pdf._score_color(s)

        pdf._fill_rect(20, y, 170, 14, C.SURFACE)
        pdf._fill_rect(20, y, 3, 14, sc)

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(26, y + 1)
        pdf.cell(100, 5, f"{r.get('sub_control', '')}  {r.get('sub_control_name', '')}")

        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C.TEXT3)
        pdf.set_xy(26, y + 7)
        pdf.cell(60, 4, status_val)

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*sc)
        pdf.set_xy(160, y + 3)
        pdf.cell(25, 5, f"{s}/100", align="R")

        y += 18


# =============================================================================
# Detailed findings per scanner# =============================================================================
def _build_remediation_suggestions(c: Dict, vendor: str = "") -> List[Dict]:
    """Build 1-3 remediation suggestions for a failed/warn check.

    Structure:
    - Primary fix (from remediation_command)
    - Alternative/compensating control (from NON_TECH_HINTS or generic)
    - Reference to relevant CERT-In/CIS/NIST control
    """
    suggestions = []
    check_name = c.get("check_name", "")
    remediation = c.get("remediation_command", "")

    # --- Suggestion 1: Primary remediation from check data ---
    if remediation:
        suggestions.append({
            "label": "Primary Remediation",
            "description": remediation,
        })
    else:
        hint = _get_hint(check_name)
        if hint.get("tell_your_team"):
            suggestions.append({
                "label": "Primary Remediation",
                "description": hint["tell_your_team"],
            })

    # --- Suggestion 2: Alternative / compensating control ---
    alt = None
    name_lower = check_name.lower()
    if "firewall" in name_lower:
        alt = "Implement application-layer firewall rules as compensating control if network-level firewall cannot be modified."
    elif "password" in name_lower or "min_length" in name_lower:
        alt = "Deploy a password manager with enforced master password policy as an alternative."
    elif "mfa" in name_lower or "multi-factor" in name_lower:
        alt = "Use hardware security keys (FIDO2/WebAuthn) or risk-based conditional access as alternatives."
    elif "lockout" in name_lower:
        alt = "Implement rate-limiting at the reverse proxy or WAF level as a compensating control."
    elif "spf" in name_lower or "dmarc" in name_lower or "dkim" in name_lower:
        alt = "Enable email filtering and anti-phishing solutions (e.g., Proofpoint, Mimecast) as a compensating control."
    elif "ssh" in name_lower or "rdp" in name_lower:
        alt = "Restrict access via VPN-only with MFA, and implement jump hosts / bastion servers."
    elif "encryption" in name_lower:
        alt = "Enable TLS 1.2+ on all endpoints and enforce HSTS as a compensating measure."
    elif "logging" in name_lower:
        alt = "Deploy a centralized SIEM (e.g., ELK Stack, Splunk) as an alternative log aggregation approach."
    elif "backup" in name_lower:
        alt = "Implement 3-2-1 backup strategy: 3 copies, 2 media types, 1 offsite."
    elif "vpn" in name_lower:
        alt = "Enforce zero-trust network access (ZTNA) as a modern alternative to traditional VPN."
    if alt:
        suggestions.append({
            "label": "Alternative / Compensating Control",
            "description": alt,
        })

    # --- Suggestion 3: Compliance reference ---
    control_ref = "CERT-In Guidelines (MeitY)"
    if "password" in name_lower:
        control_ref = "CERT-In RPP.1 / CIS Benchmark 4.1 / NIST SP 800-63B (Digital Identity Guidelines)"
    elif "mfa" in name_lower or "multi-factor" in name_lower:
        control_ref = "CERT-In RPP.3 / CIS Benchmark 4.2 / NIST SP 800-63B Section 6.1"
    elif "lockout" in name_lower:
        control_ref = "CERT-In RPP.2 / CIS Benchmark 5.2 / NIST SP 800-53 AC-7"
    elif "spf" in name_lower or "dmarc" in name_lower or "dkim" in name_lower:
        control_ref = "CERT-In NES.4 / CIS Email Security / NIST SP 800-177 (Email Security)"
    elif "ssh" in name_lower or "rdp" in name_lower:
        control_ref = "CERT-In NES.1 / CIS Benchmark 5.4 / NIST SP 800-53 AC-17"
    elif "encryption" in name_lower:
        control_ref = "CERT-In RPP.4 / CIS Benchmark 4.9 / NIST SP 800-53 SC-8, SC-13"
    elif "logging" in name_lower:
        control_ref = "CERT-In NES.2 / CIS Benchmark 4.1 / NIST SP 800-53 AU-2, AU-3"
    elif "firewall" in name_lower:
        control_ref = "CERT-In NES.1 / CIS Benchmark 3.5 / NIST SP 800-53 SC-7"
    suggestions.append({
        "label": "Compliance Reference",
        "description": control_ref,
    })

    return suggestions


def _draw_detail_page(pdf: AuditPDF, r: Dict):
    """Draw a detailed findings page for one scanner."""
    pdf.add_page()

    s = r.get("score", 0)
    st = r.get("status", {})
    status_val = st.get("value", "Unknown") if isinstance(st, dict) else str(st)
    sc = pdf._score_color(s)

    # Section header
    pdf._fill_rect(0, 0, 210, 30, C.HEADER_BG)
    pdf._fill_rect(0, 30, 210, 2, sc)
    pdf.set_xy(20, 10)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 8, f"{r.get('sub_control', '')} - {r.get('sub_control_name', '')}")
    pdf.set_xy(20, 21)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(180, 190, 205)
    pdf.cell(0, 4, f"Scan Method: {r.get('scan_method', 'N/A')}  |  Target: {r.get('target_system', 'N/A')}")

    y = 38

    # Score box
    pdf._fill_rect(20, y, 170, 18, C.SURFACE)
    pdf.set_fill_color(*sc)
    pdf.circle(30, y + 9, 7, "F")
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C.WHITE)
    pdf.set_xy(23, y + 5)
    pdf.cell(14, 8, str(s), align="C")

    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(42, y + 4)
    pdf.cell(40, 4, "out of 100")
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*sc)
    pdf.set_xy(42, y + 10)
    pdf.cell(40, 4, status_val)

    y += 26

    # Summary
    summary = r.get("summary", "")
    if summary:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(20, y)
        pdf.cell(0, 5, "Summary")
        y += 6
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*C.TEXT2)
        pdf.set_xy(25, y)
        pdf.multi_cell(160, 4, summary)
        y = pdf.get_y() + 4

    # Business impact
    impact = r.get("business_impact", "")
    if impact:
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(20, y)
        pdf.cell(0, 5, "Business Impact")
        y += 6
        pdf.set_font("Helvetica", "", 7)
        pdf.set_text_color(*C.TEXT2)
        pdf.set_xy(25, y)
        pdf.multi_cell(160, 4, impact)
        y = pdf.get_y() + 6

    # --- Checks ---
    checks = r.get("checks", [])
    passed = [c for c in checks if c.get("passed")]
    failed = [c for c in checks if not c.get("passed")]

    if passed:
        pdf._check_page(20)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.GREEN)
        pdf.set_xy(20, y)
        pdf.cell(0, 5, f"PASSED ({len(passed)})")
        y += 6

        for c in passed:
            pdf._check_page(12)
            pdf.set_fill_color(*C.GREEN)
            pdf.circle(24, y - 1, 1.5, "F")
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*C.TEXT)
            pdf.set_xy(28, y - 2)
            pdf.cell(0, 4, c.get("check_name", ""))
            y += 3
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(28, y)
            pdf.cell(0, 3, f"Found: {c.get('actual_value', 'N/A')}")
            y += 6

    if failed:
        pdf._check_page(20)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.RED)
        pdf.set_xy(20, y)
        pdf.cell(0, 5, f"NEEDS ATTENTION ({len(failed)})")
        y += 6

        for c in failed:
            needed = 55
            pdf._check_page(needed)

            # Finding card
            pdf._fill_rect(20, y, 170, 8, C.SURFACE)
            pdf.set_fill_color(*C.RED)
            pdf.rect(20, y, 3, 8, "F")
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*C.RED)
            pdf.set_xy(25, y + 2)
            pdf.cell(0, 4, f"FAIL: {c.get('check_name', '')}")
            y += 10

            # Finding detail
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C.TEXT2)
            pdf.set_xy(25, y)
            pdf.cell(0, 4, f"Finding: Expected {c.get('expected_value', 'N/A')}")
            y += 5

            # Evidence table
            pdf._fill_rect(25, y, 160, 10, C.SURFACE2)
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(28, y + 1)
            pdf.cell(20, 3, "Expected:")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.GREEN)
            pdf.set_xy(50, y + 1)
            pdf.cell(120, 3, c.get('expected_value', 'N/A'))
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(28, y + 5)
            pdf.cell(20, 3, "Found:")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.RED)
            pdf.set_xy(50, y + 5)
            pdf.cell(120, 3, c.get('actual_value', 'N/A'))
            y += 12

            # Why it matters
            hint = _get_hint(c.get("check_name", ""))
            risk_text = hint.get("risk", "This gap could be exploited by attackers or flagged during a CERT-In audit.")
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.TEXT)
            pdf.set_xy(25, y)
            pdf.cell(30, 3, "Why it matters:")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.YELLOW)
            pdf.set_xy(55, y)
            pdf.cell(120, 3, risk_text[:100])
            y += 6

            # Remediation suggestions (2-3 per finding)
            suggestions = _build_remediation_suggestions(c)
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.PRIMARY)
            pdf.set_xy(25, y)
            pdf.cell(40, 3, "Suggested Fixes:")
            y += 5

            for idx, sug in enumerate(suggestions):
                pdf._fill_rect(28, y, 157, 5, C.SURFACE)
                pdf.set_font("Helvetica", "B", 5)
                pdf.set_text_color(*C.PRIMARY_DARK)
                pdf.set_xy(30, y + 0.5)
                pdf.cell(40, 3, f"{idx+1}. {sug['label']}:")
                pdf.set_font("Helvetica", "", 5)
                pdf.set_text_color(*C.TEXT2)
                desc = sug['description']
                lines = [desc[i:i+100] for i in range(0, len(desc), 100)]
                pdf.set_xy(70, y + 0.5)
                pdf.cell(110, 3, lines[0])
                y += 5
                if len(lines) > 1:
                    for extra_line in lines[1:2]:
                        pdf.set_xy(70, y)
                        pdf.cell(110, 3, extra_line)
                        y += 4
            y += 4

    # --- Check Results Summary Table ---
    if checks:
        pdf._check_page(30)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(20, y)
        pdf.cell(0, 5, "Check Results Summary")
        y += 7
        # Table header
        pdf._fill_rect(20, y, 170, 7, C.SURFACE2)
        pdf.set_font("Helvetica", "B", 6)
        pdf.set_text_color(*C.TEXT3)
        pdf.set_xy(22, y + 1.5)
        pdf.cell(60, 4, "Check Name")
        pdf.set_xy(82, y + 1.5)
        pdf.cell(20, 4, "Status", align="C")
        pdf.set_xy(105, y + 1.5)
        pdf.cell(60, 4, "Expected")
        pdf.set_xy(165, y + 1.5)
        pdf.cell(25, 4, "Found", align="L")
        y += 8
        for i, c in enumerate(checks):
            pdf._check_page(6)
            bg = C.SURFACE if i % 2 == 0 else C.BG_PAGE
            pdf._fill_rect(20, y, 170, 6, bg)
            dot_color = C.GREEN if c.get("passed") else C.RED
            pdf.set_fill_color(*dot_color)
            pdf.circle(23, y + 3, 1.2, "F")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT)
            pdf.set_xy(26, y + 1)
            pdf.cell(56, 4, c.get("check_name", "")[:50])
            status_txt = "PASS" if c.get("passed") else "FAIL"
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*dot_color)
            pdf.set_xy(82, y + 1)
            pdf.cell(20, 4, status_txt, align="C")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(105, y + 1)
            pdf.cell(60, 4, c.get("expected_value", "")[:55])
            pdf.set_text_color(*C.TEXT2)
            pdf.set_xy(165, y + 1)
            pdf.cell(25, 4, c.get("actual_value", "")[:22])
            y += 6
        y += 4


# =============================================================================
# Next Steps page
# =============================================================================

def _draw_next_steps(pdf: AuditPDF, results: List[Dict]):
    """Draw the recommended next steps page."""
    pdf.add_page()

    # Section header
    pdf._fill_rect(0, 0, 210, 30, C.HEADER_BG)
    pdf._fill_rect(0, 30, 210, 2, C.PRIMARY)
    pdf.set_xy(20, 12)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 8, "Recommended Next Steps")
    pdf.set_xy(20, 22)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(180, 190, 205)
    pdf.cell(0, 4, "Action items to improve your security posture")

    y = 40

    # Collect all remediation steps from failed checks
    all_remediation = []
    for r in results:
        for c in r.get("checks", []):
            if not c.get("passed") and c.get("remediation_command"):
                all_remediation.append({
                    "check": c.get("check_name", ""),
                    "remediation": c["remediation_command"],
                    "scanner": r.get("sub_control", ""),
                })

    if all_remediation:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(20, y)
        pdf.cell(0, 6, "Priority Actions (from failed checks):")
        y += 8

        for i, item in enumerate(all_remediation):
            pdf._check_page(22)
            pdf._fill_rect(20, y, 170, 18, C.SURFACE)
            pdf._fill_rect(20, y, 3, 18, C.RED)

            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(*C.TEXT)
            pdf.set_xy(26, y + 2)
            pdf.cell(0, 4, f"{i + 1}. {item['check']}")

            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(26, y + 7)
            pdf.cell(0, 3, f"[{item['scanner']}]")

            pdf.set_text_color(*C.TEXT2)
            rem_lines = item["remediation"].split(chr(10))[:2]
            pdf.set_xy(26, y + 11)
            for line in rem_lines:
                pdf.cell(155, 3, line[:90])
                y += 3

            y += 20

    # Legal notice
    y += 5
    pdf._check_page(30)
    pdf._fill_rect(20, y, 170, 22, C.SURFACE)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(25, y + 3)
    pdf.cell(0, 4, "LEGAL & COMPLIANCE NOTE")
    pdf.set_font("Helvetica", "", 6)
    pdf.set_xy(25, y + 9)
    pdf.cell(0, 3, "This report demonstrates compliance efforts under CERT-In guidelines and IT Act Section 43A.")
    pdf.set_xy(25, y + 13)
    pdf.cell(0, 3, "CERT-In mandates 6-hour breach reporting (Section 70B) and 180-day log retention.")
    pdf.set_xy(25, y + 17)
    pdf.cell(0, 3, "Non-compliance may result in penalties up to Rs. 1 Crore under IT Act 2000.")


# =============================================================================
# NON-TECHNICAL REMEDIATION HINTS
# =============================================================================

# Maps check keywords to simple, non-technical explanations
# that a business owner can share with their IT team.
NON_TECH_HINTS = {
    "firewall": {
        "what": "Your computer's firewall (security gate) is either turned off or not configured properly.",
        "risk": "Without a firewall, hackers can easily access your computers from the internet.",
        "tell_your_team": "Please turn on the firewall on all computers and the office router. Block all unnecessary incoming connections.",
        "deadline": "Within 1 week",
    },
    "wifi": {
        "what": "Your office Wi-Fi is using weak encryption or has a weak password.",
        "risk": "Hackers sitting outside your office can intercept your internet traffic and steal passwords.",
        "tell_your_team": "Switch to WPA3 or WPA2 encryption. Set a strong Wi-Fi password (16+ characters). Disable WPS.",
        "deadline": "Within 1 week",
    },
    "vpn": {
        "what": "Your team working from home is not using a secure VPN connection.",
        "risk": "Data sent over public Wi-Fi (cafes, home) can be intercepted. This is a data breach risk.",
        "tell_your_team": "Set up a VPN (WireGuard or OpenVPN) for all remote workers. Require MFA for VPN login.",
        "deadline": "Within 2 weeks",
    },
    "password": {
        "what": "Employee passwords are too short, simple, or never expire.",
        "risk": "Easy passwords can be guessed by hackers in seconds, giving them access to your systems.",
        "tell_your_team": "Enforce minimum 12-character passwords with uppercase, numbers, and symbols. Set passwords to expire every 90 days.",
        "deadline": "Within 1 week",
    },
    "mfa": {
        "what": "Two-factor authentication (2FA) is not enabled on important accounts.",
        "risk": "Even if a hacker steals a password, they can log in without the second verification step.",
        "tell_your_team": "Enable 2FA on all email, banking, and admin accounts. Use Google Authenticator or hardware keys.",
        "deadline": "Within 1 week",
    },
    "lockout": {
        "what": "Accounts are not locked after multiple failed login attempts.",
        "risk": "Hackers can try thousands of passwords (brute force) without any blocking.",
        "tell_your_team": "Lock accounts after 5 failed login attempts. Add a 15-minute cooldown.",
        "deadline": "Within 1 week",
    },
    "spf": {
        "what": "Your email domain is missing SPF record - anyone can send fake emails pretending to be you.",
        "risk": "Hackers can send phishing emails to your customers that look like they come from you.",
        "tell_your_team": "Add an SPF DNS record to your domain. Example: v=spf1 include:_spf.google.com -all",
        "deadline": "Within 3 days",
    },
    "dmarc": {
        "what": "Your email domain is missing DMARC policy - no protection against email spoofing.",
        "risk": "Without DMARC, your brand can be used in phishing attacks and your emails may land in spam.",
        "tell_your_team": "Add a DMARC DNS record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
        "deadline": "Within 3 days",
    },
    "dkim": {
        "what": "Your email is not digitally signed - recipients cannot verify emails are really from you.",
        "risk": "Emails can be forged and your customers cannot distinguish real from fake emails.",
        "tell_your_team": "Enable DKIM signing in your email provider (Google Admin or Microsoft 365 portal).",
        "deadline": "Within 1 week",
    },
    "ssh": {
        "what": "Remote login port (SSH) is open to the internet.",
        "risk": "Hackers can try to break into your server through this open door.",
        "tell_your_team": "Close SSH port (22) on the firewall. If needed, change to a non-standard port and use key-only authentication.",
        "deadline": "Within 3 days",
    },
    "rdp": {
        "what": "Remote Desktop port (RDP) is open to the internet.",
        "risk": "This is the #1 way hackers break into Windows servers. Extremely dangerous.",
        "tell_your_team": "Disable RDP from the internet immediately. Use VPN + RDP instead. Or use a non-standard port.",
        "deadline": "IMMEDIATELY",
    },
    "encryption": {
        "what": "Data is being stored or transmitted without proper encryption.",
        "risk": "If someone steals your data, they can read it immediately like opening a plain letter.",
        "tell_your_team": "Enable encryption (AES-256) for all sensitive data. Use HTTPS for all websites.",
        "deadline": "Within 2 weeks",
    },
    "logging": {
        "what": "System logs are not being kept or are not stored securely.",
        "risk": "If a breach happens, you cannot investigate what happened or prove compliance to CERT-In.",
        "tell_your_team": "Enable logging on all servers and firewalls. Store logs securely for at least 180 days.",
        "deadline": "Within 2 weeks",
    },
    "backup": {
        "what": "No backup system is configured or backups are not tested.",
        "risk": "If ransomware hits, you lose all your data permanently.",
        "tell_your_team": "Set up daily automated backups. Test restoring from backups monthly. Keep one backup offsite.",
        "deadline": "Within 1 week",
    },
    "default": {
        "what": "This security check did not pass the required standard.",
        "risk": "This gap could be exploited by attackers or flagged during a CERT-In audit.",
        "tell_your_team": "Review and fix this security issue as per CERT-In guidelines.",
        "deadline": "Within 2 weeks",
    },
}


def _get_hint(check_name: str) -> Dict:
    """Get non-technical hint for a check name."""
    name_lower = check_name.lower()
    for key, hint in NON_TECH_HINTS.items():
        if key in name_lower:
            return hint
    return NON_TECH_HINTS["default"]


# =============================================================================
# Letter to Technical Team page
# =============================================================================

def _draw_tech_team_letter(pdf: AuditPDF, results: List[Dict], org_name: str = "", auditor_name: str = ""):
    """Draw a one-page letter that a business owner can give to their IT team."""
    pdf.add_page()

    # Section header
    pdf._fill_rect(0, 0, 210, 30, C.HEADER_BG)
    pdf._fill_rect(0, 30, 210, 2, C.YELLOW)
    pdf.set_xy(20, 10)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 8, "Letter to Technical Team")
    pdf.set_xy(20, 21)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(251, 191, 36)
    pdf.cell(0, 4, "Non-technical summary of security issues that need immediate attention")

    y = 40

    # Introduction
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(20, y)
    pdf.multi_cell(170, 5,
        f"Dear Technical Team,\n\n"
        f"We have completed a security audit of our IT systems as required by CERT-In (Indian Computer "
        f"Emergency Response Team). The audit found several security gaps that need your immediate attention. "
        f"Below is a summary of what needs to be fixed, explained in simple terms."
    )
    y = pdf.get_y() + 6

    # Collect all failed checks with hints
    failed_items = []
    for r in results:
        scanner = r.get("sub_control", "")
        scanner_name = r.get("sub_control_name", "")
        for c in r.get("checks", []):
            if not c.get("passed"):
                check_name = c.get("check_name", "Unknown")
                hint = _get_hint(check_name)
                failed_items.append({
                    "scanner": scanner,
                    "scanner_name": scanner_name,
                    "check": check_name,
                    "hint": hint,
                })

    if not failed_items:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*C.GREEN)
        pdf.set_xy(20, y)
        pdf.cell(0, 10, "ALL CHECKS PASSED - No action required!", align="C")
        y += 20
    else:
        # Summary count
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*C.RED)
        pdf.set_xy(20, y)
        pdf.cell(0, 6, f"PRIORITY: {len(failed_items)} security issue(s) found that need fixing:")
        y += 10

        for i, item in enumerate(failed_items):
            hint = item["hint"]
            pdf._check_page(40)

            # Issue card
            pdf._fill_rect(20, y, 170, 32, C.SURFACE)
            pdf._fill_rect(20, y, 3, 32, C.RED)

            # Title
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(*C.RED)
            pdf.set_xy(26, y + 2)
            pdf.cell(140, 4, f"Issue #{i + 1}: {item['check'][:80]}")

            # Deadline badge
            deadline = hint.get("deadline", "Within 2 weeks")
            if "IMMEDIATE" in deadline.upper():
                pdf.set_fill_color(*C.RED)
            elif "3 days" in deadline:
                pdf.set_fill_color(*C.YELLOW)
            else:
                pdf.set_fill_color(*C.SURFACE2)
            pdf.rect(165, y + 1, 22, 6, "F")
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.WHITE)
            pdf.set_xy(165, y + 2)
            pdf.cell(22, 4, deadline, align="C")

            # What it means
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(26, y + 8)
            pdf.cell(20, 3, "WHAT THIS MEANS:")
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C.TEXT2)
            pdf.set_xy(48, y + 8)
            pdf.cell(130, 3, hint.get("what", "")[:100])

            # Risk
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(26, y + 13)
            pdf.cell(20, 3, "WHY IT MATTERS:")
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C.YELLOW)
            pdf.set_xy(48, y + 13)
            pdf.cell(130, 3, hint.get("risk", "")[:100])

            # Tell your team
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.GREEN)
            pdf.set_xy(26, y + 18)
            pdf.cell(40, 3, "TELL YOUR TEAM TO:")
            pdf.set_font("Helvetica", "", 7)
            pdf.set_text_color(*C.TEXT)
            pdf.set_xy(26, y + 22)
            pdf.multi_cell(160, 4, hint.get("tell_your_team", "Fix this issue."))

            # Scanner reference
            pdf.set_font("Helvetica", "", 5)
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(26, y + 28)
            pdf.cell(0, 3, f"[Scanner: {item['scanner']} - {item['scanner_name']}]")

            y += 36

    # Footer note
    y += 5
    pdf._check_page(25)
    pdf._fill_rect(20, y, 170, 20, C.SURFACE)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.YELLOW)
    pdf.set_xy(25, y + 3)
    pdf.cell(0, 4, "IMPORTANT NOTES FOR MANAGEMENT:")
    pdf.set_font("Helvetica", "", 6)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(25, y + 9)
    pdf.cell(0, 3, "1. CERT-In requires these fixes to be completed. Non-compliance may result in penalties up to Rs. 1 Crore.")
    pdf.set_xy(25, y + 13)
    pdf.cell(0, 3, "2. Share this letter with your IT team or IT vendor. They will understand the technical terms.")
    pdf.set_xy(25, y + 17)
    pdf.cell(0, 3, "3. Schedule a follow-up audit within 30 days to verify all fixes are implemented.")


# =============================================================================
# Public API
# =============================================================================

def generate_pdf(
    results: List[Dict],
    title: str = "Security Audit Report",
    org_name: str = "",
    auditor_name: str = "",
    target: str = "",
    scan_type: str = "",
) -> bytes:
    """
    Generate a professional PDF report from scan results.

    Args:
        results: List of scanner result dicts (from SubControlResult.model_dump()).
        title: Report title.
        org_name: Organization name for the report.
        auditor_name: Auditor/assessor name.
        target: Scan target (hostname/IP).
        scan_type: Type of scan (RPP, NES, Web Security, etc.).

    Returns:
        PDF file as bytes.
    """
    # Auto-detect scan type from results if not provided
    if not scan_type and results:
        first_ctrl = results[0].get("control_id", "") or results[0].get("sub_control", "")
        if first_ctrl.upper().startswith("RPP"):
            scan_type = "RPP - Password & Access Policy"
        elif first_ctrl.upper().startswith("NES"):
            scan_type = "NES - Network & Email Security"
        elif first_ctrl.upper().startswith("WEB"):
            scan_type = "Web Security"
        else:
            scan_type = "Comprehensive"

    pdf = AuditPDF(title=title, target=target, scan_type=scan_type)
    pdf.alias_nb_pages()

    # Cover page
    _draw_cover(pdf, results, title)

    # Executive summary
    _draw_executive_summary(pdf, results)

    # Detailed pages per scanner
    for r in results:
        _draw_detail_page(pdf, r)

    # Letter to Technical Team (non-technical summary)
    _draw_tech_team_letter(pdf, results, org_name=org_name, auditor_name=auditor_name)

    # Next steps
    _draw_next_steps(pdf, results)

    # Output as bytes
    output = BytesIO()
    pdf_bytes = pdf.output()
    if isinstance(pdf_bytes, str):
        pdf_bytes = pdf_bytes.encode("latin-1")
    return bytes(pdf_bytes)
