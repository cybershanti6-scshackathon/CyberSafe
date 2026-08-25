"""
CyberSure — Build Windows .exe
===============================
Run this script to create a single standalone .exe file.

Prerequisites:
    pip install pyinstaller

Usage:
    python build_exe.py

Output:
    dist/CyberSure.exe  (single file, ~30-50MB)
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
MSME_DIR = PROJECT_ROOT / "msme_auditor"


def clean():
    """Remove old build artifacts."""
    print("Cleaning old build files...")
    for d in [DIST_DIR, BUILD_DIR]:
        if d.exists():
            shutil.rmtree(d)
    for f in PROJECT_ROOT.glob("*.spec"):
        f.unlink()


def build():
    """Build the .exe using PyInstaller."""
    print("\nBuilding CyberSure.exe ...\n")

    # Collect all frontend files as data
    frontend_files = []
    for f in FRONTEND_DIR.iterdir():
        if f.is_file() and not f.name.startswith("."):
            frontend_files.append((str(FRONTEND_DIR / f.name), "frontend"))

    # Collect msme_auditor package
    msme_files = []
    for f in MSME_DIR.rglob("*.py"):
        if "__pycache__" not in str(f):
            rel = f.relative_to(PROJECT_ROOT)
            dest_dir = str(rel.parent)
            msme_files.append((str(f), dest_dir))

    # Build data args
    data_args = []
    for src, dest in frontend_files + msme_files:
        data_args.append(f"--add-data={src};{dest}")

    # Hidden imports that PyInstaller might miss
    hidden_imports = [
        "uvicorn",
        "uvicorn.logging",
        "uvicorn.loops",
        "uvicorn.loops.auto",
        "uvicorn.protocols",
        "uvicorn.protocols.http",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.websockets",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan",
        "uvicorn.lifespan.on",
        "fastapi",
        "pydantic",
        "httpx",
        "dns",
        "dns.resolver",
        "fpdf",
    ]

    hidden_args = [f"--hidden-import={m}" for m in hidden_imports]

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name=CyberSure",
        "--onefile",
        "--noconsole",
        "--clean",
        f"--distpath={DIST_DIR}",
        f"--workpath={BUILD_DIR}",
        f"--specpath={PROJECT_ROOT}",
        *data_args,
        *hidden_args,
        str(PROJECT_ROOT / "launch.py"),
    ]

    print(f"  Command: pyinstaller --name=CyberSure --onefile launch.py\n")

    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))

    if result.returncode == 0:
        exe_path = DIST_DIR / "CyberSure.exe"
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"\n  ✅ Build successful!")
            print(f"  📦 Output: {exe_path}")
            print(f"  📏 Size:   {size_mb:.1f} MB")
            print(f"\n  Share CyberSure.exe with your friends!")
            print(f"  They just double-click it — no Python needed.\n")
        else:
            print(f"\n  ❌ Build completed but .exe not found at {exe_path}")
    else:
        print(f"\n  ❌ Build failed with exit code {result.returncode}")
        print(f"  Check the output above for errors.\n")


def main():
    print()
    print("  ============================================")
    print("    CyberSure — Windows .exe Builder")
    print("  ============================================")
    print()

    clean()
    build()


if __name__ == "__main__":
    main()
