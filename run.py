"""
MSME Cyber Auditor — CLI Runner
================================
Run audits from the command line using the clean :func:`run_full_audit`
pipeline.

Usage::

    python run.py --company "Acme Corp" --domain example.com --all --pdf
    python run.py --company "Acme Corp" --demo --pdf
    python run.py --list
"""

import argparse
import sys
from typing import List, Optional

from msme_auditor.scanners.registry import discover_scanners
from msme_auditor.engine.orchestrator import run_full_audit
from msme_auditor.engine.report import save_json, generate_pdf


def _parse_scanner_ids(raw: Optional[str]) -> Optional[List[str]]:
    """Parse a comma-separated scanner ID string into a list."""
    if not raw:
        return None
    return [s.strip() for s in raw.split(",") if s.strip()]


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="MSME Cyber Auditor — CERT-In Compliance Scanner",
    )
    parser.add_argument(
        "--company", default="Unspecified Organization",
        help="Company name for the report",
    )
    parser.add_argument(
        "--domain", default="",
        help="Target domain to scan (e.g. example.com)",
    )
    parser.add_argument(
        "--ip", default="",
        help="Target IP to scan (e.g. 93.184.216.34)",
    )
    parser.add_argument(
        "--scanners", default=None,
        help="Comma-separated scanner IDs (e.g. rpp1,rpp2,nes4)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Run ALL registered scanners",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available scanners and exit",
    )
    parser.add_argument(
        "--json", default="audit_report.json",
        help="Output JSON path (default: audit_report.json)",
    )
    parser.add_argument(
        "--pdf", action="store_true",
        help="Also generate a PDF report",
    )
    parser.add_argument(
        "--pdf-output", default="audit_report.pdf",
        help="Output PDF path (default: audit_report.pdf)",
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run with demo data for testing",
    )

    args = parser.parse_args()

    # Discover scanners
    print("\n🔍 Discovering scanners...\n")
    discover_scanners()

    # ── List mode ──────────────────────────────────────────────────────
    if args.list:
        from msme_auditor.scanners import get_all_scanners

        scanners = get_all_scanners()
        print(f"\n{'ID':<10} {'Category':<15} {'Name'}")
        print("-" * 60)
        for sid, s in sorted(scanners.items()):
            print(f"{sid:<10} {s.category:<15} {s.name}")
        print(f"\nTotal: {len(scanners)} scanners")
        return

    # ── Demo mode ─────────────────────────────────────────────────────
    if args.demo:
        report = run_full_audit(
            target_domain="example.com",
            target_ip="93.184.216.34",
            company_name=args.company,
            scanner_ids=["rpp1", "rpp2", "rpp3", "rpp4"],
            scanner_configs={
                "rpp1": {
                    "min_length": 8,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_special_chars": False,
                    "max_age_days": 90,
                    "history_count": 5,
                    "education_policy_exists": False,
                },
                "rpp2": {
                    "max_failed_attempts": 5,
                    "lockout_duration_minutes": 15,
                    "reset_window_minutes": 15,
                    "admin_unlock_enabled": True,
                    "audit_logging": True,
                },
                "rpp3": {
                    "admin_mfa_enabled": True,
                    "remote_mfa_enabled": True,
                    "critical_mfa_enabled": False,
                    "mfa_method": "TOTP",
                    "policy_exists": True,
                },
                "rpp4": {
                    "sample_hashes": [
                        "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZRGdjGj/n3.q5pIvZrVTLpKjVkYPu",
                        "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.qO.1BoWBPfGKHe",
                    ],
                    "encryption_at_rest": True,
                },
            },
        )
    else:
        # ── Normal mode ───────────────────────────────────────────────
        scanner_ids = None if args.all else _parse_scanner_ids(args.scanners)
        report = run_full_audit(
            target_domain=args.domain,
            target_ip=args.ip,
            company_name=args.company,
            scanner_ids=scanner_ids,
        )

    # Save outputs
    save_json(report, args.json)
    if args.pdf:
        generate_pdf(report, args.pdf_output)

    print(
        f"\n✅ Audit complete!  "
        f"Overall score: {report.overall_score}/100 "
        f"({report.overall_status.value})"
    )


if __name__ == "__main__":
    main()
