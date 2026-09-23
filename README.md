# 🛡️ CyberSure — MSME Cyber Security Auditor

Automated CERT-In Cyber Compliance Scanner for MSMEs.

## Features
- **RPP** — Robust Password Policy (RPP.1–RPP.4)
- **NES** — Network & Email Security (NES.1–NES.4)
- **Web Security** — Website Security Headers & TLS
- **AI Assistant** — Gemini-powered security advisor
- **PDF Reports** — Professional audit reports
- **Config Normalization** — Vendor config parsing (Cisco, Juniper, Fortinet)

---

## 🚀 Quick Start (Windows)

### Option 1: Double-click `start.cmd`
Just double-click the `start.cmd` file. It will:
- Find Python automatically
- Install dependencies if missing
- Start the server and open your browser

### Option 2: Manual setup
```bash
# 1. Install Python 3.10+ from https://python.org
#    ✅ Check "Add Python to PATH" during install

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the project
python launch.py
```

---

## 🐧 Quick Start (Linux / Mac)

```bash
# 1. Install Python 3.10+
#    Ubuntu/Debian:  sudo apt install python3 python3-pip
#    Mac:            brew install python3

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
bash start.sh
# or
python3 launch.py
```

---

## 📁 Project Structure

```
├── frontend/              # Web UI (HTML/CSS/JS)
│   ├── index.html         # Landing page
│   ├── dashboard.html     # Dashboard
│   ├── rpp.html           # Password Policy scanner
│   ├── nes.html           # Network & Email Security scanner
│   ├── web-security.html  # Web Security scanner
│   └── scanner.js         # Scanner JS logic
├── msme_auditor/          # Backend (Python)
│   ├── api/server.py      # FastAPI server
│   ├── scanners/          # Scanner modules (RPP, NES, Web)
│   ├── config_parsers/    # Vendor config normalization
│   └── engine/            # Audit orchestration
├── scripts/               # Utility scripts
│   ├── build_exe.py       # Windows .exe builder
│   ├── cleanup_move.py    # Project cleanup utility
│   └── generate_feasibility_pptx.py  # Presentation generator
├── tests/                 # Test files
│   └── test_pdf_gen.py    # PDF generation test
├── docs/                  # Documentation & reference files
│   └── Elemental_Cyber_Defense_Controls_for_MSME.pdf
├── launch.py              # One-click launcher
├── run.py                 # CLI runner
├── start.cmd              # Windows launcher
├── start.sh               # Linux/Mac launcher
└── requirements.txt       # Python dependencies
```

---

## 🌐 Getting Started

⚠️ Note About the Project

The live demo is hosted on Render's free tier. Because of Render's free-tier behavior, the service may go to sleep after a period of inactivity.

If the website doesn't load immediately, please wait a few seconds and refresh the page while the server starts up.

Note: The first visit may take longer than subsequent visits. Once the server is awake, the website should load normally.

---

## ⚠️ Troubleshooting

**"Python not found"**
→ Install Python from https://python.org and check "Add to PATH"

**"ModuleNotFoundError: No module named 'fastapi'"**
→ Run: `pip install -r requirements.txt`

**"Port 8000 already in use"**
→ Close other programs using port 8000, or change the port in `launch.py`

---

## Project URL
**Your live URL:** `https://cybersafe-urpz.onrender.com`

---

## 📄 License

Internal project — CERT-In Compliance Scanner for MSMEs.
# CyberSure-SIH
