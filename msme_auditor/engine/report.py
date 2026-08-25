"""
Report generation — JSON export and PDF audit report.

The PDF is generated with ReportLab.  If ReportLab is not installed the
code falls back to JSON-only output gracefully.
"""

import json
from pathlib import Path
from typing import Union

from msme_auditor.schemas.reports import AuditReport


def save_json(
    report: AuditReport,
    output_path: Union[str, Path] = "audit_report.json",
) -> str:
    """
    Serialise *report* to a JSON file.

    Args:
        report: The audit report to save.
        output_path: Destination file path.

    Returns:
        The absolute path of the written file.
    """
    path = Path(output_path)
    data = report.model_dump(mode="json")
    path.write_text(
        json.dumps(data, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"📄 JSON saved to: {path}")
    return str(path.resolve())


def generate_pdf(
    report: AuditReport,
    output_path: Union[str, Path] = "audit_report.pdf",
) -> str:
    """
    Generate a professional PDF audit report using ReportLab.

    Falls back to JSON if ReportLab is not installed.

    Args:
        report: The audit report to render.
        output_path: Destination PDF file path.

    Returns:
        The absolute path of the written file (PDF or JSON fallback).
    """
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
        from reportlab.lib.units import mm  # type: ignore[import-untyped]
        from reportlab.lib.colors import HexColor  # type: ignore[import-untyped]
        from reportlab.lib.styles import (  # type: ignore[import-untyped]
            getSampleStyleSheet,
            ParagraphStyle,
        )
        from reportlab.platypus import (  # type: ignore[import-untyped]
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
            HRFlowable,
        )
    except ImportError:
        print("⚠️  reportlab not installed.  Run: pip install reportlab")
        print("   Falling back to JSON-only output.")
        return save_json(report, str(output_path).replace(".pdf", ".json"))

    path = Path(output_path)
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title2", parent=styles["Title"],
        fontSize=24, spaceAfter=6 * mm,
        textColor=HexColor("#1a1a2e"),
    )
    h2 = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=14, spaceAfter=4 * mm,
        textColor=HexColor("#2d3436"),
    )
    body = ParagraphStyle(
        "Body2", parent=styles["BodyText"],
        fontSize=10, leading=14, spaceAfter=3 * mm,
    )
    small = ParagraphStyle(
        "Small", parent=styles["BodyText"],
        fontSize=8, textColor=HexColor("#636e72"),
    )

    story = []

    # ── Cover page ──────────────────────────────────────────────────────
    story.append(Spacer(1, 30 * mm))
    story.append(
        Paragraph("🛡️ CERT-In Compliance Audit Report", title_style)
    )
    story.append(
        HRFlowable(width="100%", thickness=1, color=HexColor("#6c5ce7"))
    )
    story.append(Spacer(1, 8 * mm))
    story.append(
        Paragraph(f"<b>Organization:</b> {report.company_name}", body)
    )
    story.append(
        Paragraph(f"<b>Report ID:</b> {report.report_id}", body)
    )
    story.append(
        Paragraph(
            f"<b>Date:</b> "
            f"{report.report_timestamp.strftime('%Y-%m-%d %H:%M UTC')}",
            body,
        )
    )
    story.append(
        Paragraph(f"<b>Tool Version:</b> {report.tool_version}", body)
    )
    story.append(Spacer(1, 6 * mm))

    score_color = (
        "#00b894" if report.overall_score >= 90
        else "#fdcb6e" if report.overall_score >= 60
        else "#e74c3c"
    )
    story.append(
        Paragraph(
            f'<font size="36" color="{score_color}">'
            f"<b>{report.overall_score}</b></font>"
            f'<font size="12" color="#636e72">'
            f" / 100 — {report.overall_status.value}</font>",
            body,
        )
    )
    story.append(
        Paragraph(f"<b>Badge:</b> {report.compliance_badge}", body)
    )
    story.append(
        Paragraph(f"<b>Risk Level:</b> {report.risk_level}", body)
    )
    story.append(
        Paragraph(
            f"<b>Vulnerabilities:</b> {report.total_vulnerabilities} total, "
            f"{report.critical_issues} critical",
            body,
        )
    )
    story.append(PageBreak())

    # ── Executive summary ───────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2))
    for line in report.executive_summary.split("\n"):
        line = line.strip()
        if line:
            story.append(Paragraph(line, body))
    story.append(Spacer(1, 6 * mm))

    # ── Detailed findings ──────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", h2))
    for r in report.results:
        icon = (
            "✅" if r.status.value == "Passed"
            else "⚠️" if r.status.value == "Warning"
            else "❌"
        )
        story.append(
            Paragraph(
                f"<b>{icon} {r.sub_control} — {r.sub_control_name}</b>  "
                f"[{r.score}/100 — {r.status.value}]",
                body,
            )
        )
        story.append(Paragraph(f"<i>{r.summary}</i>", small))
        story.append(
            Paragraph(f"<b>Business Impact:</b> {r.business_impact}", body)
        )

        if r.checks:
            table_data = [["Check", "Status", "Expected", "Found"]]
            for c in r.checks:
                table_data.append([
                    c.check_name,
                    "✅ Pass" if c.passed else "❌ Fail",
                    c.expected_value,
                    c.actual_value or "—",
                ])
            t = Table(
                table_data,
                colWidths=[45 * mm, 20 * mm, 50 * mm, 50 * mm],
            )
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2d3436")),
                ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#dfe6e9")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    HexColor("#ffffff"), HexColor("#f5f6fa"),
                ]),
            ]))
            story.append(t)
            story.append(Spacer(1, 4 * mm))

        if r.remediation_script:
            story.append(
                Paragraph("<b>Remediation Script:</b>", body)
            )
            safe = r.remediation_script.replace("\n", "<br/>")
            story.append(
                Paragraph(
                    f'<font face="Courier" size="8">{safe}</font>',
                    body,
                )
            )
        story.append(
            HRFlowable(
                width="100%", thickness=0.5, color=HexColor("#dfe6e9"),
            )
        )
        story.append(Spacer(1, 3 * mm))

    # ── Legal notice ───────────────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph("⚖️ Legal Notice", h2))
    story.append(Paragraph(report.legal_notice, small))
    story.append(
        Paragraph(
            f"Generated: "
            f"{report.report_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} | "
            f"Tool: MSME Cyber Auditor v{report.tool_version}",
            small,
        )
    )

    doc.build(story)
    print(f"📄 PDF saved to: {path}")
    return str(path.resolve())
