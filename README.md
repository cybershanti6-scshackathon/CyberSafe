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
├── launch.py              # One-click launcher
├── start.cmd              # Windows launcher
├── start.sh               # Linux/Mac launcher
└── requirements.txt       # Python dependencies
```

---

## 🌐 After Starting

| Page | URL |
|------|-----|
| Home | http://localhost:8000 |
| Dashboard | http://localhost:8000/dashboard.html |
| API Docs | http://localhost:8000/docs |

---

## ⚠️ Troubleshooting

**"Python not found"**
→ Install Python from https://python.org and check "Add to PATH"

**"ModuleNotFoundError: No module named 'fastapi'"**
→ Run: `pip install -r requirements.txt`

**"Port 8000 already in use"**
→ Close other programs using port 8000, or change the port in `launch.py`

---

## 📄 License

Internal project — CERT-In Compliance Scanner for MSMEs.
