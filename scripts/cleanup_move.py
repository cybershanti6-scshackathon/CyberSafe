"""
CyberSure Cleanup Script
========================
Moves all unused/duplicate files to _cleanup/ folder for safe review.
Nothing is permanently deleted — you can review and restore if needed.

Usage: python cleanup_move.py
"""
import os
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLEANUP = PROJECT_ROOT / "_cleanup"

def move(src_rel: str, dest_subfolder: str):
    """Move a file or directory to _cleanup/<dest_subfolder>/."""
    src = PROJECT_ROOT / src_rel
    dest_dir = CLEANUP / dest_subfolder
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / src.name
    if src.exists():
        if dest.exists():
            # Append suffix if already exists
            dest = dest_dir / f"{src.stem}_dup{src.suffix}"
        shutil.move(str(src), str(dest))
        print(f"  Moved: {src_rel} -> _cleanup/{dest_subfolder}/{src.name}")
    else:
        print(f"  Skipped (not found): {src_rel}")

def main():
    print("\n  CyberSure Cleanup — Moving unused files to _cleanup/\n")
    print("=" * 60)

    # ── 1. Old entry points ──
    print("\n[1/7] Old entry points...")
    move("server.py", "old-entry-points")
    move("start_server.py", "old-entry-points")
    move("scan.py", "old-entry-points")
    move("loader.py", "old-entry-points")
    move("scanner_registry.py", "old-entry-points")
    move("frontend.html", "old-entry-points")

    # ── 2. One-time scripts ──
    print("\n[2/7] One-time scripts...")
    move("consolidate.py", "scripts")
    move("reorganize.py", "scripts")
    move("debug_scoring.py", "scripts")
    move("cleanup-to-recyclebin.ps1", "scripts")

    # ── 3. Demo/test data ──
    print("\n[3/7] Demo and test data...")
    move("demo_sih.py", "demos")
    move("industry_demo.py", "demos")
    move("industry_test_dataset.py", "demos")
    move("mock_rpp_target.py", "demos")
    move("frontend-integration-prompt.md", "demos")

    # ── 4. Live test scripts ──
    print("\n[4/7] Live test scripts...")
    move("_live_rpp1.py", "live-tests")
    move("_live_scanners.py", "live-tests")
    move("run_live_rpp_against_mock.py", "live-tests")
    move("run_industry_tests.py", "live-tests")

    # ── 5. All test files ──
    print("\n[5/7] Test files...")
    test_files = [
        "test_all_parsers.py", "test_cert_in_connection.py",
        "test_cisco_parser.py", "test_cisco_parser_pytest.py",
        "test_common_security_schema.py", "test_existing.py",
        "test_fortinet_juniper_parsers.py", "test_gemini_advisor.py",
        "test_juniper_detect.py", "test_knowledge_base.py",
        "test_normalization_module.py", "test_pdf_unicode.py",
        "test_scanners.py", "test_secret_redaction.py",
        "test_startup.py", "test_step17_comprehensive.py",
        "test_step18_e2e.py", "test_training_api.py",
        "test_unknown_detection.py", "test_validate_fix.py",
        "test_vendor_detection.py",
    ]
    for f in test_files:
        move(f, "tests")

    # ── 6. Orphan files ──
    print("\n[6/7] Orphan files...")
    move("package-lock.json", "scripts")

    # ── 7. Old directories ──
    print("\n[7/7] Old directories...")
    old_dirs = [
        "AI-Driven Multi-Vendor Network Security Compliance Auditor",
        "MSME_Cyber_Auditor",
        "PS 2 NES",
        "WEB.1",
        "WEB.1(3)",
        "Scshackathon-all-mem-main",
        "industry_reports",
        "My",
        ".claude",
        "__pycache__",
    ]
    for d in old_dirs:
        move(d, "old-directories")

    # ── Summary ──
    print("\n" + "=" * 60)
    print("  Cleanup complete!")
    print("")
    print("  All unused files are now in _cleanup/")
    print("  Review the files, then delete _cleanup/ when ready:")
    print("")
    print("    Windows:  rmdir /s /q _cleanup")
    print("    Linux:    rm -rf _cleanup")
    print("")
    print("  If you need to restore any file, copy it back from _cleanup/")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()
