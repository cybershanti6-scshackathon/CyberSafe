# 🛡️ CyberSure — AI-Driven Multi-Vendor Network Security Compliance Auditor

> **Smart India Hackathon | Problem Statement ID: 26155**  
> **Organization:** National Technical Research Organisation (NTRO)  
> **Category:** Software  
> **Theme:** Blockchain & Cybersecurity

CyberSure is an AI-driven multi-vendor network security compliance auditing platform designed to help organizations assess network security configurations, identify security weaknesses, map findings to relevant security controls, and generate actionable reports.

The platform is designed around a simple workflow:

**Configuration/Input → Normalization → Security Scanning → Compliance Analysis → Risk Assessment → AI Explanation → Report**

---

## 🔗 Project Resources

| Resource | Link |
|---|---|
| 🌐 **Live Demo** | `www.youtube.com/watch?v=M1gZCs4Jfbg` |
| 📑 **Technical Presentation** | `YOUR_TECHNICAL_PRESENTATION_URL` |
| 🏗️ **Architecture Document** | [`docs/ARCHITECTURE.pdf`]("C"C:\Users\LENOVO\Documents\CyberSure.pdf") |
| 📸 **Project Screenshots** | [`docs/screenshots/`](docs/screenshots/) |



## 📋 Table of Contents

- [Problem Overview](#-problem-overview)
- [Our Solution](#-our-solution)
- [Key Features](#-key-features)
- [System Workflow](#-system-workflow)
- [System Architecture](#-system-architecture)
- [Multi-Vendor Approach](#-multi-vendor-approach)
- [Security & Compliance Analysis](#-security--compliance-analysis)
- [AI-Assisted Risk Explanation](#-ai-assisted-risk-explanation)
- [Dynamic Reporting](#-dynamic-reporting)
- [Technology Stack](#️-technology-stack)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [How to Use CyberSure](#-how-to-use-cybersure)
- [API Overview](#-api-overview)
- [Documentation](#-documentation)
- [Screenshots](#-screenshots)
- [Demo](#-demo)
- [Limitations](#-limitations)
- [Future Scope](#-future-scope)
- [Team](#-team)

---

# 🔎 Problem Overview

Network security environments often contain devices and configurations from different vendors. Security teams may need to manually inspect configurations, understand vendor-specific settings, compare them against security requirements, and prepare reports.

This creates several practical challenges:

- Vendor-specific configuration formats
- Manual security assessment
- Difficulty maintaining consistent compliance checks
- Time-consuming interpretation of technical findings
- Separate reporting workflows
- Limited security expertise in smaller organizations

The **NTRO Problem Statement 26155** calls for an **AI-Driven Multi-Vendor Network Security Compliance Auditor**, including capabilities such as vendor-specific processing, automated security/compliance assessment, and dynamic reporting.

---

# 💡 Our Solution

**CyberSure** brings these activities into a single workflow.

Instead of manually checking every configuration, the platform accepts security-related inputs/configurations, processes them through modular scanners, evaluates the relevant security conditions, and presents the results through a centralized dashboard.

The platform also uses AI-assisted explanations to make technical findings easier to understand and provides report generation for assessment results.

### Core idea

```text
              USER INPUT
                  │
                  ▼
        ┌───────────────────┐
        │ Configuration /   │
        │ Security Inputs   │
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ Vendor Processing │
        │ & Normalization   │
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ Security Scanners │
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ Compliance & Risk │
        │     Analysis      │
        └─────────┬─────────┘
                  │
          ┌───────┴────────┐
          ▼                ▼
 ┌────────────────┐  ┌───────────────┐
 │ AI Explanation │  │ PDF Reporting │
 └───────┬────────┘  └───────┬───────┘
         │                   │
         └─────────┬─────────┘
                   ▼
             FINAL DASHBOARD
```

---

# 🚀 Key Features

### 1. Multi-Vendor Security Assessment

CyberSure is designed to process security information from different network/security vendors through a common assessment workflow.

The architecture supports vendor-specific processing and normalization so that the assessment logic can work on a consistent internal representation.

### 2. Modular Security Scanners

Security checks are separated into scanner modules instead of putting every check into one large function.

This makes the system easier to:

- Extend
- Test
- Maintain
- Add new controls to
- Add vendor-specific checks

### 3. Compliance-Oriented Analysis

Findings can be mapped against relevant security controls and benchmarks, including references such as:

- CIS Benchmarks
- NIST SP 800-53
- DISA STIGs
- ISO/IEC 27001
- Vendor-specific security guidance

> The prototype provides compliance-oriented assessment and mapping. It should not be interpreted as a formal certification or official compliance certificate.

### 4. Risk-Oriented Results

The dashboard presents security findings in a form that allows users to identify issues requiring attention and understand the associated remediation direction.

### 5. AI-Assisted Explanation

CyberSure uses an AI layer to translate technical security findings into more understandable explanations and recommended remediation guidance.

A deterministic fallback can be used where an AI response is unavailable.

### 6. Dynamic PDF Reporting

The reporting module generates assessment reports from scan results.

The report can include information such as:

- Device/vendor information
- Model and software/version information where available
- Security findings
- Assessment results
- Risk information
- Recommended remediation
- Overall assessment information

### 7. Centralized Dashboard

The web interface brings the major assessment modules together in one place.

Current prototype modules include:

- Dashboard
- Devices & Vendors
- Network/Endpoint Security
- Risk & Policy Protection
- Web Security
- AI Assistant
- Reports

---

# 🔄 System Workflow

CyberSure follows the following high-level workflow:

### Step 1 — Input

The user provides supported security information such as:

- Vendor configuration
- Device details
- Network information
- Domain/security inputs
- Security assessment parameters

### Step 2 — Normalize

Vendor-specific information is converted into a common structure wherever required.

### Step 3 — Scan

Modular security scanners evaluate the relevant inputs.

### Step 4 — Analyze

The results are processed to identify security findings and assessment conditions.

### Step 5 — Compliance Mapping

Applicable findings are associated with relevant security controls/benchmarks.

### Step 6 — Risk Explanation

The platform presents the technical issue and provides AI-assisted explanation/remediation guidance.

### Step 7 — Report

The final assessment can be converted into a structured PDF report.

---

# 🏗️ System Architecture

```text
┌─────────────────────────────────────────────────────┐
│                    CYBERSURE UI                     │
│             Web Dashboard / Frontend                │
└────────────────────────┬────────────────────────────┘
                         │
                         │ REST API
                         ▼
┌─────────────────────────────────────────────────────┐
│                  FASTAPI BACKEND                     │
│                                                     │
│  API Routes │ Validation │ Orchestration │ Results  │
└─────────────┬──────────────┬──────────────┬─────────┘
              │              │              │
              ▼              ▼              ▼
       ┌────────────┐ ┌──────────────┐ ┌─────────────┐
       │  Vendor    │ │   Security   │ │ Compliance  │
       │ Processing │ │   Scanners   │ │   Engine    │
       └─────┬──────┘ └──────┬───────┘ └──────┬──────┘
             │               │                │
             └───────────────┼────────────────┘
                             ▼
                    ┌────────────────┐
                    │ Risk / Findings│
                    └───────┬────────┘
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
          ┌──────────────┐    ┌──────────────┐
          │ AI Assistant │    │   Reporting  │
          │ / Explanation│    │    Engine    │
          └──────┬───────┘    └──────┬───────┘
                 │                   │
                 └─────────┬─────────┘
                           ▼
                  ┌─────────────────┐
                  │ Dashboard / PDF │
                  │     Report      │
                  └─────────────────┘
```

For the detailed two-page architecture document, see:

**[`docs/ARCHITECTURE.pdf`](docs/ARCHITECTURE.pdf)**

---

# 🔌 Multi-Vendor Approach

A key requirement of the problem statement is handling multiple vendors.

CyberSure therefore follows a modular approach:

```text
Vendor A Configuration ──┐
                         │
Vendor B Configuration ──┼──► Normalization ──► Common Assessment Logic
                         │
Vendor C Configuration ──┘
```

Vendor-specific processing is kept separate from the common assessment workflow wherever possible.

This allows the platform to be extended with additional vendors without redesigning the complete application.

---

# 🛡️ Security & Compliance Analysis

CyberSure can organize security checks around recognized security references and vendor guidance.

### Reference categories

| Reference | Purpose |
|---|---|
| **CIS Benchmarks** | Secure configuration guidance |
| **NIST SP 800-53** | Security and privacy control reference |
| **DISA STIGs** | Security configuration guidance |
| **ISO/IEC 27001** | Information security management reference |
| **Vendor-specific guidance** | Vendor/device-specific security checks |

The assessment output focuses on identifying configuration/security issues and providing remediation-oriented information.

---

# 🤖 AI-Assisted Risk Explanation

Security scanner output can be technical and difficult for non-specialist users to interpret.

CyberSure adds an AI-assisted layer to help explain:

```text
Technical Finding
       ↓
Why does this matter?
       ↓
Potential Security Impact
       ↓
Recommended Remediation
```

The AI layer is intended to improve the usability of security findings rather than replace the underlying deterministic security checks.

### Example

```text
Finding:
HTTP service exposure detected

AI-assisted explanation:
The service may expose traffic without transport encryption.

Recommendation:
Review whether HTTPS/TLS should be enabled and whether
unencrypted HTTP access is required.
```

---

# 📄 Dynamic Reporting

Reporting is a core part of the requested solution.

CyberSure generates reports from the **actual assessment output** instead of relying only on a fixed static document.

Conceptually:

```text
Device Information
       +
Software / Version
       +
Scanner Results
       +
Compliance Findings
       +
Risk Information
       +
Remediation
       ↓
Dynamic Report Generation
       ↓
PDF Assessment Report
```

The report-generation component is implemented in Python and can use libraries such as **ReportLab/FPDF** depending on the project configuration.

---

# 🧰 Technology Stack

| Layer | Technology / Approach |
|---|---|
| **Frontend** | HTML, CSS, JavaScript / project frontend components |
| **Backend** | Python, FastAPI |
| **API Communication** | REST APIs |
| **Security Logic** | Modular Python scanners |
| **AI Layer** | Gemini / configured LLM integration |
| **Reporting** | Python PDF generation |
| **Containerization** | Docker-ready architecture |
| **Version Control** | Git & GitHub |

> Update this table if the final submitted repository uses additional frameworks or libraries.

---

# 📂 Project Structure

The exact structure may vary with the final submitted repository. A recommended organization is:

```text
CyberSure/
│
├── frontend/
│   ├── assets/
│   ├── components/
│   └── ...
│
├── backend/
│   ├── main.py
│   ├── routes/
│   ├── scanners/
│   ├── reports/
│   └── ...
│
├── docs/
│   ├── ARCHITECTURE.pdf
│   ├── TECHNICAL_PRESENTATION.pdf
│   └── screenshots/
│
├── tests/
│
├── requirements.txt
├── README.md
└── ...
```

Keep the repository structure consistent with the actual submitted source code.

---

# ⚡ Quick Start

## Prerequisites

Install:

- Python 3.x
- Git
- A modern web browser
- Node.js/npm if required by the final frontend

---

## 1. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd CyberSure
```

---

## 2. Set Up the Backend

```bash
cd backend
```

Create and activate a virtual environment:

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
python -m pip install -r requirements.txt
```

---

## 3. Configure Environment Variables

If the final application uses external AI/API services, create a `.env` file according to the project's configuration.

Example:

```env
GEMINI_API_KEY=YOUR_API_KEY
```

**Never commit real API keys, passwords, tokens, or credentials to GitHub.**

---

## 4. Start the FastAPI Backend

From the backend directory:

```bash
uvicorn main:app --reload
```

The local API will normally be available at:

```text
http://127.0.0.1:8000
```

FastAPI documentation can normally be accessed at:

```text
http://127.0.0.1:8000/docs
```

---

## 5. Start the Frontend

Open a new terminal and move to the frontend directory.

If the final frontend is Node.js based:

```bash
cd frontend
npm install
npm start
```

Use the actual frontend command documented by the final repository if it differs.

---

# 🎮 How to Use CyberSure

A typical prototype flow is:

### 1. Open the Dashboard

Review the available security assessment modules.

### 2. Select Devices & Vendors

Choose the relevant vendor/device workflow.

### 3. Provide Assessment Input

Enter or upload the supported configuration/security information.

### 4. Run the Scanner

Start the appropriate security assessment.

### 5. Review Findings

Inspect detected issues and their assessment information.

### 6. Review AI Explanation

Use the AI assistant to understand technical findings and remediation guidance.

### 7. Generate Report

Generate the assessment report from the current scan results.

### 8. Export / Review PDF

Open the generated report and review the device-specific assessment information.

---

# 🔗 API Overview

CyberSure uses a FastAPI backend to expose application functionality through APIs.

Typical API areas include:

```text
/api/health
/api/rpp1/scan
/api/rpp2/scan
```

The exact endpoints should be verified against the final submitted backend.

### API documentation

When the backend is running:

```text
http://127.0.0.1:8000/docs
```

This provides the interactive FastAPI/OpenAPI documentation for the implemented endpoints.

---

# 📚 Documentation

All SIH-related supporting documents should be kept accessible from this section.

### 🏗️ Architecture Document

**Maximum 2 pages — SIH deliverable**

[`Open Architecture Document`](docs/ARCHITECTURE.pdf)

### 📑 Technical Presentation

**Maximum 5 slides — SIH deliverable**

[`Open Technical Presentation`](docs/TECHNICAL_PRESENTATION.pdf)

### 🎥 Demo Video

**Maximum 2 minutes — SIH deliverable**

[▶️ Watch the CyberSure Demo](YOUR_DEMO_VIDEO_URL)


### 💻 Source Code

[Open the GitHub Repository](YOUR_GITHUB_REPOSITORY_URL)

---

### Dashboard

![CyberSure Dashboard](docs/screenshots/dashboard.png)

### Devices & Vendors

![Devices and Vendors](docs/screenshots/devices-vendors.png)


> Store the screenshots inside `docs/screenshots/` using the filenames shown above, or update the paths to match the actual files.

---

# 🎥 Demo

The complete prototype demonstration is available here:

**[▶️ Watch the 2-Minute CyberSure Demo](www.youtube.com/watch?v=M1gZCs4Jfbg`)**

The demo demonstrates the primary flow:

```text
Open Application
      ↓
Select Security Module
      ↓
Provide Input
      ↓
Run Scan
      ↓
View Findings
      ↓
AI Explanation
      ↓
Generate Report
```

---

# ⚠️ Prototype Scope & Limitations

CyberSure is an **SIH prototype** and should be evaluated according to the functionality implemented in the submitted version.

Important limitations may include:

- Scanner coverage is limited to the checks implemented in the prototype.
- Vendor support depends on the implemented vendor modules.
- AI-generated explanations should be reviewed by a qualified security professional before operational use.
- Compliance mapping in the prototype does not constitute legal certification or formal third-party certification.
- Non-intrusive scanning should be used only on systems for which the user has authorization.
- Production deployment would require additional authentication, authorization, secure secret management, logging, monitoring, testing, and infrastructure hardening.

---

# 🔮 Future Scope

Potential future development includes:

- Additional network/security vendors
- Expanded security control coverage
- Continuous configuration monitoring
- Scheduled compliance assessments
- Role-based access control
- Enterprise authentication
- Centralized audit logs
- Cloud deployment
- SIEM/SOC integrations
- More advanced risk prioritization
- Expanded AI-assisted remediation
- Automated configuration remediation with explicit authorization

---

# 👥 Team

**Project:** CyberSure  
**Problem Statement:** 26155  
**Organization:** National Technical Research Organisation (NTRO)  
**Theme:** Blockchain & Cybersecurity  
**Category:** Software

### Team Members

| Name | 
| `MRUNAL DESHMUKH` | `LEADER` |
| `TEJASWINI TALOKAR` | 
| `CHAITANYA DESHPANDE` | 
| `YASH EKADE` | 
| `WANSH KOHAD` | 
| `OM HATEKAR` | 

## 🛡️ CyberSure

**AI-Driven Multi-Vendor Network Security Compliance Auditor**

**Smart India Hackathon — Problem Statement 26155**

> **Assess. Understand. Secure. Report.**
