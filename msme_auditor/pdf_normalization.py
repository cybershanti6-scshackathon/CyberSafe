"""
PDF Normalization Sections — Vendor Config → PDF
================================================

Adds normalization-specific sections to the PDF report:
- Vendor/Device Information
- Normalized Security Parameters
- Unknown Commands (with AI suggestions)
- Evidence Trail
- AI Remediation Suggestions

These sections integrate with the existing AuditPDF class.
"""

from typing import Any, Dict, List, Optional
from msme_auditor.pdf_generator import AuditPDF, C


# =============================================================================
# Vendor / Device Information Section
# =============================================================================

def draw_vendor_info(pdf: AuditPDF, audit_data: Dict[str, Any]):
    """
    Draw vendor and device information section.

    Includes:
    - Detected vendor
    - Device model
    - OS version
    - Hostname
    - Parse confidence
    - Coverage percentage
    """
    pdf.add_page()

    # Section header
    pdf._fill_rect(0, 0, 210, 30, C.BG_DARK)
    pdf._fill_rect(0, 30, 210, 2, C.PRIMARY)
    pdf.set_xy(20, 12)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 8, "Vendor Configuration Analysis")
    pdf.set_xy(20, 22)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.cell(0, 4, "Device identification and configuration normalization")

    y = 40

    # Vendor info card
    device = audit_data.get("device", {})
    vendor = audit_data.get("vendor", "Unknown")
    coverage = audit_data.get("coverage", 0)
    parse_conf = audit_data.get("parse_confidence", 0)

    pdf._fill_rect(20, y, 170, 40, C.SURFACE)

    # Vendor badge
    vendor_colors = {
        "cisco": C.PRIMARY,
        "fortinet": C.GREEN,
        "juniper": C.YELLOW,
    }
    vc = vendor_colors.get(vendor.lower(), C.TEXT3)
    pdf.set_fill_color(*vc)
    pdf.rect(20, y, 4, 40, "F")

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(28, y + 4)
    pdf.cell(0, 6, f"Vendor: {vendor.title()}")

    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(28, y + 12)
    pdf.cell(80, 4, f"Model: {device.get('model', 'Unknown')}")
    pdf.set_xy(110, y + 12)
    pdf.cell(80, 4, f"Version: {device.get('version', 'Unknown')}")

    if device.get("hostname"):
        pdf.set_xy(28, y + 18)
        pdf.cell(80, 4, f"Hostname: {device['hostname']}")

    # Coverage bar
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(28, y + 26)
    pdf.cell(40, 4, "Coverage:")

    bar_y = y + 26
    pdf._fill_rect(70, bar_y, 100, 6, C.SURFACE2)
    bar_w = int(100 * coverage / 100) if coverage else 0
    bar_color = C.GREEN if coverage >= 80 else C.YELLOW if coverage >= 50 else C.RED
    pdf._fill_rect(70, bar_y, bar_w, 6, bar_color)
    pdf.set_font("Helvetica", "B", 6)
    pdf.set_text_color(*C.WHITE)
    pdf.set_xy(70, bar_y)
    pdf.cell(100, 6, f"{coverage:.1f}%", align="C")

    # Parse confidence
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(28, y + 34)
    pdf.cell(40, 4, "Parse Confidence:")
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(70, y + 34)
    pdf.cell(40, 4, f"{parse_conf:.1%}")

    y += 50


# =============================================================================
# Normalized Parameters Section
# =============================================================================

def draw_normalized_parameters(pdf: AuditPDF, audit_data: Dict[str, Any]):
    """
    Draw normalized security parameters section.

    Shows all parameters extracted from the vendor configuration.
    """
    flat_config = audit_data.get("flat_config", {})
    if not flat_config:
        return

    pdf._check_page(60)

    # Section header
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C.TEXT)
    pdf.set_xy(20, pdf.get_y())
    pdf.cell(0, 6, "Normalized Security Parameters")
    y = pdf.get_y() + 8

    # Parameters table
    pdf._fill_rect(20, y, 170, 8, C.SURFACE2)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(25, y + 2)
    pdf.cell(60, 4, "Parameter")
    pdf.set_xy(90, y + 2)
    pdf.cell(40, 4, "Value")
    pdf.set_xy(140, y + 2)
    pdf.cell(45, 4, "Status")
    y += 10

    # Group parameters by category
    categories = {
        "Authentication": ["password_min_length", "password_complexity_enabled",
                          "password_expiry_days", "password_history_count",
                          "account_lockout_enabled", "account_lockout_threshold",
                          "session_timeout", "mfa_enabled", "password_encryption_enabled"],
        "Network": ["ssh_enabled", "ssh_version", "telnet_enabled",
                   "http_server_enabled", "https_enabled", "snmp_enabled",
                   "snmp_community_default", "cdp_disabled", "unused_ports_disabled"],
        "Logging": ["logging_enabled", "remote_syslog_enabled",
                   "log_timestamps_enabled", "login_logging_enabled"],
        "Encryption": ["ssh_ciphers_strong", "ntp_configured", "aaa_enabled"],
        "Access Control": ["enable_secret_configured", "exec_timeout_configured",
                          "vty_access_restricted", "banner_configured"],
    }

    for cat_name, params in categories.items():
        cat_params = {k: v for k, v in flat_config.items() if k in params and v is not None}
        if not cat_params:
            continue

        pdf._check_page(15)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*C.PRIMARY)
        pdf.set_xy(25, y)
        pdf.cell(0, 4, cat_name)
        y += 6

        for param, value in cat_params.items():
            pdf._check_page(8)
            # Determine status color
            if isinstance(value, bool):
                status_color = C.GREEN if value else C.RED
                status_text = "Enabled" if value else "Disabled"
            elif isinstance(value, int):
                # Good values for specific params
                good_ranges = {
                    "password_min_length": (8, 999),
                    "ssh_version": (2, 2),
                    "account_lockout_threshold": (1, 10),
                    "session_timeout": (1, 3600),
                }
                if param in good_ranges:
                    min_val, max_val = good_ranges[param]
                    passed = min_val <= value <= max_val
                    status_color = C.GREEN if passed else C.RED
                    status_text = str(value)
                else:
                    status_color = C.TEXT2
                    status_text = str(value)
            else:
                status_color = C.TEXT2
                status_text = str(value)

            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT2)
            pdf.set_xy(28, y)
            pdf.cell(60, 4, param.replace("_", " ").title())

            pdf.set_xy(90, y)
            pdf.cell(40, 4, status_text)

            pdf.set_fill_color(*status_color)
            pdf.circle(145, y + 1.5, 1.5, "F")
            pdf.set_font("Helvetica", "", 5)
            pdf.set_text_color(*status_color)
            pdf.set_xy(150, y)
            pdf.cell(30, 4, "PASS" if status_color == C.GREEN else "FAIL" if status_color == C.RED else "")

            y += 5

        y += 4


# =============================================================================
# Unknown Commands Section
# =============================================================================

def draw_unknown_commands(pdf: AuditPDF, audit_data: Dict[str, Any]):
    """
    Draw unknown commands section.

    Shows commands the parser couldn't understand, with their
    line numbers and possible categories.
    """
    unknowns = audit_data.get("unknowns", [])
    if not unknowns:
        return

    pdf._check_page(40)

    # Section header
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C.YELLOW)
    pdf.set_xy(20, pdf.get_y())
    pdf.cell(0, 6, f"Unknown Commands ({len(unknowns)} found)")
    y = pdf.get_y() + 8

    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(20, y)
    pdf.multi_cell(170, 4,
        "The following commands could not be parsed. They may be vendor-specific "
        "or custom commands. Review and add to the knowledge base if needed.")
    y = pdf.get_y() + 6

    for i, unknown in enumerate(unknowns[:20]):  # Limit to 20
        pdf._check_page(12)
        pdf._fill_rect(20, y, 170, 10, C.SURFACE)
        pdf._fill_rect(20, y, 2, 10, C.YELLOW)

        pdf.set_font("Helvetica", "B", 6)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(24, y + 1)
        pdf.cell(10, 4, f"L{unknown.get('line_number', '?')}:")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*C.TEXT2)
        pdf.set_xy(36, y + 1)
        pdf.cell(120, 4, unknown.get("raw_command", "")[:80])

        category = unknown.get("possible_category", "unknown")
        pdf.set_font("Helvetica", "", 5)
        pdf.set_text_color(*C.YELLOW_LIGHT)
        pdf.set_xy(24, y + 6)
        pdf.cell(0, 3, f"Category: {category}")

        y += 12

    if len(unknowns) > 20:
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*C.TEXT3)
        pdf.set_xy(20, y)
        pdf.cell(0, 4, f"... and {len(unknowns) - 20} more unknown commands")
        y += 6


# =============================================================================
# Evidence Trail Section
# =============================================================================

def draw_evidence_trail(pdf: AuditPDF, audit_data: Dict[str, Any]):
    """
    Draw evidence trail section.

    Shows the traceability from CERT-In findings back to
    original configuration lines.
    """
    evidence = audit_data.get("evidence", {})
    if not evidence:
        return

    pdf._check_page(40)

    # Section header
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*C.PRIMARY)
    pdf.set_xy(20, pdf.get_y())
    pdf.cell(0, 6, "Evidence Trail")
    y = pdf.get_y() + 8

    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.TEXT3)
    pdf.set_xy(20, y)
    pdf.multi_cell(170, 4,
        "Each security parameter is traced back to its source in the "
        "original configuration. This provides full audit trail for CERT-In compliance.")
    y = pdf.get_y() + 6

    # Evidence entries
    count = 0
    for param, ev in evidence.items():
        if count >= 15:  # Limit display
            break
        if not isinstance(ev, dict):
            continue

        pdf._check_page(14)
        pdf._fill_rect(20, y, 170, 12, C.SURFACE)

        pdf.set_font("Helvetica", "B", 6)
        pdf.set_text_color(*C.PRIMARY_LIGHT)
        pdf.set_xy(24, y + 1)
        pdf.cell(50, 4, param.replace("_", " ").title())

        value = ev.get("value", "")
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*C.TEXT2)
        pdf.set_xy(78, y + 1)
        pdf.cell(30, 4, f"= {value}")

        source_line = ev.get("source_line", "")
        if source_line:
            pdf.set_text_color(*C.TEXT3)
            pdf.set_xy(24, y + 6)
            pdf.cell(140, 4, f"Source: {source_line[:70]}")

        line_num = ev.get("line_number", 0)
        if line_num:
            pdf.set_text_color(*C.YELLOW_LIGHT)
            pdf.set_xy(160, y + 6)
            pdf.cell(25, 4, f"Line {line_num}")

        y += 14
        count += 1

    if len(evidence) > 15:
        pdf.set_font("Helvetica", "", 6)
        pdf.set_text_color(*C.TEXT3)
        pdf.set_xy(20, y)
        pdf.cell(0, 4, f"... and {len(evidence) - 15} more evidence entries")
        y += 6


# =============================================================================
# AI Remediation Section
# =============================================================================

def draw_ai_remediation(pdf: AuditPDF, remediations: List[Dict[str, Any]]):
    """
    Draw AI remediation suggestions section.

    Clearly labeled as "AI-Suggested Remediation".
    Includes warning about not auto-executing commands.
    """
    if not remediations:
        return

    pdf.add_page()

    # Section header
    pdf._fill_rect(0, 0, 210, 30, C.BG_DARK)
    pdf._fill_rect(0, 30, 210, 2, C.YELLOW)
    pdf.set_xy(20, 12)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*C.WHITE)
    pdf.cell(0, 8, "AI-Suggested Remediation")
    pdf.set_xy(20, 22)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*C.YELLOW_LIGHT)
    pdf.cell(0, 4, "Generated by AI analysis — Review before applying")

    y = 40

    # Warning box
    pdf._fill_rect(20, y, 170, 16, C.SURFACE)
    pdf._fill_rect(20, y, 3, 16, C.YELLOW)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(*C.YELLOW)
    pdf.set_xy(26, y + 2)
    pdf.cell(0, 4, "WARNING: DO NOT automatically execute these commands.")
    pdf.set_font("Helvetica", "", 6)
    pdf.set_text_color(*C.TEXT2)
    pdf.set_xy(26, y + 8)
    pdf.cell(0, 4, "Review each command with your IT team before applying to production systems.")
    y += 24

    for i, rem in enumerate(remediations):
        if i >= 10:  # Limit
            break

        pdf._check_page(40)

        # Remediation card
        pdf._fill_rect(20, y, 170, 35, C.SURFACE)
        pdf._fill_rect(20, y, 3, 35, C.YELLOW)

        # Title
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*C.TEXT)
        pdf.set_xy(26, y + 2)
        pdf.cell(0, 4, f"{i + 1}. {rem.get('check_name', 'Unknown Check')}")

        # Source badge
        source = rem.get("source", "heuristic")
        badge_color = C.PRIMARY if source == "gemini" else C.TEXT3
        pdf.set_fill_color(*badge_color)
        pdf.rect(155, y + 1, 30, 6, "F")
        pdf.set_font("Helvetica", "B", 5)
        pdf.set_text_color(*C.WHITE)
        pdf.set_xy(155, y + 2)
        pdf.cell(30, 4, f"Source: {source.upper()}", align="C")

        # Explanation
        explanation = rem.get("explanation", "")
        if explanation:
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT2)
            pdf.set_xy(26, y + 9)
            pdf.multi_cell(155, 3, explanation[:150])

        # CLI commands
        cli = rem.get("cli_commands", [])
        if cli:
            pdf.set_font("Helvetica", "B", 6)
            pdf.set_text_color(*C.GREEN_LIGHT)
            pdf.set_xy(26, y + 18)
            pdf.cell(0, 3, "Suggested CLI Commands:")
            pdf.set_font("Helvetica", "", 6)
            pdf.set_text_color(*C.TEXT)
            cmd_y = y + 23
            for cmd in cli[:4]:
                pdf.set_xy(30, cmd_y)
                pdf.cell(140, 3, f"$ {cmd}")
                cmd_y += 3.5

        y += 38


# =============================================================================
# Integration: Generate full audit PDF with normalization
# =============================================================================

def generate_audit_pdf(
    audit_data: Dict[str, Any],
    title: str = "CERT-In Compliance Audit Report",
) -> bytes:
    """
    Generate a complete PDF audit report with normalization data.

    This extends the existing PDF with:
    - Vendor/Device information
    - Normalized parameters
    - Unknown commands
    - Evidence trail
    - AI remediation suggestions

    Args:
        audit_data: Full audit data from CertInAuditResult.to_dict()
        title: Report title

    Returns:
        PDF file as bytes
    """
    from msme_auditor.pdf_generator import AuditPDF, _draw_cover, _draw_executive_summary, _draw_detail_page, _draw_tech_team_letter, _draw_next_steps

    pdf = AuditPDF(title=title)
    pdf.alias_nb_pages()

    results = audit_data.get("results", [])

    # 1. Cover page
    _draw_cover(pdf, results, title)

    # 2. Vendor/Device information
    draw_vendor_info(pdf, audit_data)

    # 3. Normalized parameters
    draw_normalized_parameters(pdf, audit_data)

    # 4. Executive summary
    _draw_executive_summary(pdf, results)

    # 5. Detailed findings per scanner
    for r in results:
        _draw_detail_page(pdf, r)

    # 6. Unknown commands
    draw_unknown_commands(pdf, audit_data)

    # 7. Evidence trail
    draw_evidence_trail(pdf, audit_data)

    # 8. AI Remediation
    remediations = audit_data.get("remediations", [])
    draw_ai_remediation(pdf, remediations)

    # 9. Letter to Technical Team
    _draw_tech_team_letter(pdf, results)

    # 10. Next steps
    _draw_next_steps(pdf, results)

    # Output as bytes
    output = __import__("io").BytesIO()
    pdf_bytes = pdf.output()
    if isinstance(pdf_bytes, str):
        pdf_bytes = pdf_bytes.encode("latin-1")
    return bytes(pdf_bytes)
