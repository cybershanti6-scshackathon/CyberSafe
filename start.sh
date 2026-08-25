#!/bin/bash
echo ""
echo "============================================"
echo "  🛡️  MSME Cyber Auditor — One-Click Launcher"
echo "============================================"
echo ""
cd "$(dirname "$0")"
python3 launch.py 2>/dev/null || python launch.py 2>/dev/null || {
    echo "❌ Python not found! Please install Python 3.10+"
    echo "   Ubuntu/Debian:  sudo apt install python3 python3-pip"
    echo "   Mac:            brew install python3"
}
