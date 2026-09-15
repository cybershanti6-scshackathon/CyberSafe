"""
MSME Cyber Auditor — API Server
================================
FastAPI HTTP layer.  **No business logic here** — scanners and aggregation
live in ``msme_auditor.scanners`` and ``msme_auditor.engine``.

Endpoints
---------
GET  /                       Serve the frontend HTML
GET  /api/health             Health-check + registered scanner count
GET  /api/scanners           List scanners grouped by category
GET  /api/scanners/{id}      Input-field schema for one scanner
POST /api/scanners/{id}/scan Run a single scanner
POST /api/scan-all           Run every registered scanner
POST /api/audit              Full audit → unified AuditReport JSON
"""

import ipaddress
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from msme_auditor.scanners.registry import (
    discover_scanners,
    get_all_scanners,
    get_scanner,
    list_scanners_by_category,
    scanner_to_api_schema,
    run_scan,
)



# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent.parent

app = FastAPI(
    title="MSME Cyber Auditor",
    description="CERT-In Compliance Scanner for MSMEs",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auto-discover scanners on import — never let this crash the server
print("\n🔍 Discovering scanners...")
try:
    discover_scanners()
except Exception as _exc:
    print(f"  ⚠️  Scanner discovery error (non-fatal): {_exc}")
print()


# ---------------------------------------------------------------------------
# Request schemas (HTTP transport only — no business logic)
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """HTTP body for single-scanner and scan-all endpoints."""

    config: Dict[str, Any] = Field(default_factory=dict)
    target_type: Optional[str] = Field(
        default=None,
        description="Override target type (web, windows, linux …)",
    )
    target: Optional[str] = Field(
        default=None,
        description="Override scan target (URL, IP, domain)",
    )
    dry_run: bool = Field(
        default=True,
        description="If True, no live requests are sent (web scans only)",
    )

    @field_validator("target")
    @classmethod
    def block_internal_targets(cls, v: Optional[str], info) -> Optional[str]:
        """Block private/loopback targets for web scans to prevent SSRF."""
        if not v:
            return v
        try:
            parsed = urlparse(v if "://" in v else f"https://{v}")
            host = parsed.hostname
            if host:
                ip = ipaddress.ip_address(host)
                if ip.is_private or ip.is_loopback:
                    raise ValueError(
                        "Private/loopback targets require authorization file entry. "
                        "Add the target to config/authorized_targets.json."
                    )
        except ValueError:
            raise
        except Exception:
            pass  # hostname, not raw IP — fine
        return v


class AuditRequest(BaseModel):
    """HTTP body for the full-audit endpoint."""

    company_name: str = Field(default="Unspecified Organization")
    target_domain: str = Field(
        default="",
        description="Domain to scan (e.g. example.com)",
    )
    target_ip: str = Field(
        default="",
        description="IP to scan (e.g. 93.184.216.34)",
    )
    scanner_ids: Optional[List[str]] = Field(
        default=None,
        description="Subset of scanner IDs, or None for all",
    )
    scanner_configs: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Per-scanner config overrides",
    )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _merge_config(req: ScanRequest) -> Dict[str, Any]:
    """
    Merge the base config with optional target/type overrides.

    This is **transport-level** prep (not business logic): the frontend
    sends ``target_type`` and ``target`` as top-level fields, but scanners
    expect them inside the config dict.
    """
    cfg = dict(req.config)
    if req.target_type:
        cfg["target_type"] = req.target_type
    if req.target:
        cfg["target"] = req.target
    # Frontend may send newline-separated hashes as a single string
    if "sample_hashes" in cfg and isinstance(cfg["sample_hashes"], str):
        cfg["sample_hashes"] = [
            h.strip() for h in cfg["sample_hashes"].split("\n") if h.strip()
        ]
    return cfg


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health() -> Dict[str, Any]:
    """
    Health check — returns scanner count and IDs.

    Returns:
        ``{"status": "ok", "version": "2.0.0", "scanners_registered": N, ...}``
    """
    scanners = get_all_scanners()
    return {
        "status": "ok",
        "version": "2.0.0",
        "scanners_registered": len(scanners),
        "scanner_ids": list(scanners.keys()),
    }


@app.get("/api/system-info")
def system_info() -> Dict[str, str]:
    """Detect the host OS and return recommended target types for scanners."""
    os_name = platform.system()
    if os_name == "Windows":
        recommended = "windows"
    elif os_name == "Linux":
        recommended = "linux"
    else:
        recommended = "web"
    return {
        "os": os_name,
        "recommended_target_type": recommended,
        "hostname": platform.node(),
    }


@app.get("/api/scanners")
def list_scanners() -> Dict[str, Any]:
    """
    List all registered scanners grouped by category.

    Returns:
        ``{"categories": {"RPP": [...], "NES": [...]}, "total": N}``
    """
    by_cat = list_scanners_by_category()
    result: Dict[str, list] = {}
    for cat, scanners in by_cat.items():
        result[cat] = [scanner_to_api_schema(s) for s in scanners]
    return {"categories": result, "total": len(get_all_scanners())}




# ---------------------------------------------------------------------------
# Configuration Converter API
# ---------------------------------------------------------------------------

class ConvertRequest(BaseModel):
    """Request body for configuration conversion."""
    config_text: str = Field(..., description="Raw vendor configuration text")
    source_vendor: str = Field(..., description="Source vendor (cisco, juniper, fortinet)")
    target_vendor: str = Field(..., description="Target vendor (cisco, juniper, fortinet)")


@app.get("/api/converter/pairs")
def api_converter_pairs() -> List[Dict[str, Any]]:
    """Get supported vendor conversion pairs."""
    from msme_auditor.config_parsers.config_converter import get_supported_pairs
    return get_supported_pairs()


@app.post("/api/converter/convert")
def api_convert_config(req: ConvertRequest) -> Dict[str, Any]:
    """
    Convert configuration between vendors.
    
    Tier 1: Fully automated (hostname, SSH, VLANs, interfaces, routes, OSPF, logging, NTP)
    Tier 2: AI-assisted draft + flagged for review (ACLs, NAT)
    Tier 3: Not supported (QoS)
    """
    from msme_auditor.config_parsers.config_converter import convert_config
    
    try:
        result = convert_config(
            source_vendor=req.source_vendor,
            target_vendor=req.target_vendor,
            config_text=req.config_text,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Conversion failed: {str(exc)}")


@app.get("/api/scanners/{scanner_id}")
def get_scanner_schema(scanner_id: str) -> dict:
    """
    Return the input-field schema for a single scanner.

    Raises:
        HTTPException: 404 if *scanner_id* is not registered.
    """
    scanner = get_scanner(scanner_id)
    if not scanner:
        raise HTTPException(
            status_code=404,
            detail=f"Scanner '{scanner_id}' not found",
        )
    return scanner_to_api_schema(scanner)


@app.post("/api/scanners/{scanner_id}/scan")
def execute_scan(scanner_id: str, req: ScanRequest) -> dict:
    """
    Run a single scanner and return its :class:`SubControlResult` as JSON.

    Raises:
        HTTPException: 404 if not found, 422 for invalid target, 500 on scan failure.
    """
    scanner = get_scanner(scanner_id)
    if not scanner:
        raise HTTPException(
            status_code=404,
            detail=f"Scanner '{scanner_id}' not found",
        )
    # Validate target if provided
    if req.target:
        from msme_auditor.utils.target import validate_target
        normalized, target_type, error = validate_target(req.target)
        if error:
            raise HTTPException(status_code=422, detail=f"Invalid target: {error}")
    try:
        result = run_scan(scanner_id, _merge_config(req))
        return result.model_dump() if hasattr(result, "model_dump") else result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/scan-all")
def scan_all(req: ScanRequest) -> Dict[str, dict]:
    """
    Run every registered scanner and return a dict keyed by scanner ID.
    """
    merged = _merge_config(req)
    results: Dict[str, dict] = {}
    for scanner_id in get_all_scanners():
        try:
            result = run_scan(scanner_id, dict(merged))
            results[scanner_id] = (
                result.model_dump() if hasattr(result, "model_dump") else result
            )
        except Exception as exc:
            results[scanner_id] = {"error": str(exc)}
    return results


class ConfigUploadRequest(BaseModel):
    """Request body for config upload and normalization."""
    config_text: str = Field(..., description="Raw vendor configuration text")
    vendor_hint: Optional[str] = Field(
        default=None,
        description="Optional vendor hint (cisco, fortinet, juniper)",
    )


class ConfigAuditRequest(BaseModel):
    """Request body for full CERT-In audit from vendor config."""
    config_text: str = Field(..., description="Raw vendor configuration text")
    vendor_hint: Optional[str] = Field(
        default=None,
        description="Optional vendor hint (cisco, fortinet, juniper)",
    )
    scanner_ids: Optional[List[str]] = Field(
        default=None,
        description="Subset of scanner IDs, or None for RPP.1-4",
    )


class TrainingApproveRequest(BaseModel):
    """Request body for approving a mapping."""
    vendor: str = Field(..., description="Vendor name")
    pattern: str = Field(..., description="Pattern to approve")
    approved_by: str = Field(default="admin", description="Who approved it")


class TrainingEditRequest(BaseModel):
    """Request body for editing a mapping."""
    vendor: str = Field(..., description="Vendor name")
    pattern: str = Field(..., description="Current pattern")
    updates: Dict[str, Any] = Field(..., description="Fields to update")


class TrainingRejectRequest(BaseModel):
    """Request body for rejecting a mapping."""
    vendor: str = Field(..., description="Vendor name")
    pattern: str = Field(..., description="Pattern to reject")


class TrainingSaveRequest(BaseModel):
    """Request body for saving an approved mapping."""
    pattern: str = Field(..., description="Regex pattern")
    vendor: str = Field(..., description="Vendor name")
    normalized_parameter: str = Field(..., description="Target parameter")
    value_type: str = Field(default="string", description="Value type")
    unit: str = Field(default="", description="Unit if applicable")
    confidence: float = Field(default=0.8, description="Confidence 0.0-1.0")
    source_command_example: str = Field(default="", description="Example command")


class PdfExportRequest(BaseModel):
    """Request body for PDF export."""
    results: List[Dict[str, Any]] = Field(default_factory=list)
    title: str = Field(default="Security Audit Report")
    target: str = Field(default="", description="Scan target (hostname/IP)")
    scan_type: str = Field(default="", description="Type of scan (RPP, NES, Web Security, etc.)")
    audit_data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Full audit data from CertInAuditResult.to_dict()",
    )


@app.post("/api/export-pdf")
def export_pdf(req: PdfExportRequest) -> StreamingResponse:
    """
    Generate a professional PDF report from scan results.
    Returns the PDF as a downloadable file.

    If audit_data is provided (from /api/config/audit), includes:
    - Vendor/Device information
    - Normalized parameters
    - Unknown commands
    - Evidence trail
    - AI remediation suggestions
    """
    try:
        # If full audit data is provided, use the enhanced PDF generator
        if req.audit_data:
            from msme_auditor.pdf_normalization import generate_audit_pdf
            pdf_bytes = generate_audit_pdf(req.audit_data, title=req.title)
        else:
            from msme_auditor.pdf_generator import generate_pdf
            pdf_bytes = generate_pdf(req.results, title=req.title, target=req.target, scan_type=req.scan_type)
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={
                "Content-Disposition":
                    f'attachment; filename="audit-report.pdf"',
            },
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/audit")
def run_full_audit(req: AuditRequest) -> dict:
    """
    Run a full audit and return a unified :class:`AuditReport` as JSON.

    Delegates to :func:`msme_auditor.engine.orchestrator.run_full_audit`.
    """
    from msme_auditor.engine.orchestrator import run_full_audit as run_audit

    try:
        report = run_audit(
            target_domain=req.target_domain,
            target_ip=req.target_ip,
            company_name=req.company_name,
            scanner_ids=req.scanner_ids,
            scanner_configs=req.scanner_configs,
        )
        return report.model_dump()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Training API — Configuration Intelligence
# ---------------------------------------------------------------------------

# Lazy-loaded singletons for training workflow
_kb_instance = None


def _get_kb():
    """Get or create the global KnowledgeBase instance."""
    global _kb_instance
    if _kb_instance is None:
        from msme_auditor.config_parsers.knowledge_base import init_knowledge_base
        kb_path = PROJECT_ROOT / "knowledge_base.json"
        _kb_instance = init_knowledge_base(kb_path)
    return _kb_instance


# In-memory store for normalization results (session-scoped)
_normalization_sessions: Dict[str, Dict[str, Any]] = {}


@app.post("/api/config/normalize")
def normalize_config(req: ConfigUploadRequest) -> Dict[str, Any]:
    """
    Upload a vendor configuration and normalize it.

    Returns normalized config, vendor info, unknown commands, and a
    session_id for follow-up operations.
    """
    import uuid
    from msme_auditor.config_parsers.normalization_engine import normalize_config as do_normalize

    try:
        result = do_normalize(req.config_text, vendor_hint=req.vendor_hint)
        session_id = uuid.uuid4().hex[:12]

        # Store session for follow-up operations
        _normalization_sessions[session_id] = {
            "config_text": req.config_text,
            "vendor_hint": req.vendor_hint,
            "result": result,
        }

        return {
            "session_id": session_id,
            "vendor": result.vendor,
            "device": {
                "vendor": result.device.vendor,
                "model": result.device.model,
                "version": result.device.version,
                "hostname": result.device.hostname,
            },
            "parse_confidence": result.parse_confidence,
            "coverage": result.coverage,
            "unknown_count": result.unknown_count,
            "unknowns": [
                {
                    "raw_command": u.raw_command,
                    "line_number": u.line_number,
                    "possible_category": u.possible_category,
                    "vendor": u.vendor,
                }
                for u in result.unknown_configurations
            ],
            "flat_config": result.flat_config,
            "success": result.success,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/config/audit")
def audit_config(req: ConfigAuditRequest) -> Dict[str, Any]:
    """
    Full CERT-In audit from a vendor configuration.

    Chains: normalize → bridge → CERT-In scanners → SubControlResults.
    Returns the same output format as the existing scanner endpoints.
    """
    from msme_auditor.config_parsers.certin_integration import run_certin_from_config

    try:
        audit = run_certin_from_config(
            config_text=req.config_text,
            vendor_hint=req.vendor_hint,
            scanner_ids=req.scanner_ids,
        )
        return audit.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


class RemediateRequest(BaseModel):
    """Request body for AI remediation suggestions."""
    check_id: str = Field(..., description="Failed check ID")
    check_name: str = Field(..., description="Check name")
    expected_value: str = Field(..., description="What CERT-In requires")
    actual_value: str = Field(..., description="What was found")
    vendor: str = Field(default="unknown", description="Device vendor")
    device_model: str = Field(default="Unknown", description="Device model")
    control_id: str = Field(default="", description="CERT-In control ID")
    sub_control: str = Field(default="", description="Sub-control ID")


@app.post("/api/remediate")
def get_remediation(req: RemediateRequest) -> Dict[str, Any]:
    """
    Get AI remediation suggestion for a CERT-In failed check.

    Uses Gemini when available, falls back to deterministic templates.
    Clearly labeled as "AI-Suggested Remediation".
    """
    from msme_auditor.config_parsers.ai_remediation import suggest_remediation

    try:
        suggestion = suggest_remediation(
            check_id=req.check_id,
            check_name=req.check_name,
            expected_value=req.expected_value,
            actual_value=req.actual_value,
            vendor=req.vendor,
            device_model=req.device_model,
            control_id=req.control_id,
            sub_control=req.sub_control,
        )
        return suggestion.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/training/unknowns")
def get_unknowns(session_id: str) -> Dict[str, Any]:
    """
    Get unknown configurations from a normalization session.

    Query params:
        session_id: The session ID from /api/config/normalize
    """
    session = _normalization_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    result = session["result"]
    return {
        "session_id": session_id,
        "vendor": result.vendor,
        "unknowns": [
            {
                "id": f"{session_id}_{i}",
                "raw_command": u.raw_command,
                "line_number": u.line_number,
                "vendor": u.vendor,
                "parser_name": u.parser_name,
                "confidence": u.confidence,
                "possible_category": u.possible_category,
                "context_lines": u.context_lines,
            }
            for i, u in enumerate(result.unknown_configurations)
        ],
        "total": result.unknown_count,
    }


@app.get("/api/training/unknowns/{unknown_id}")
def get_unknown_details(unknown_id: str) -> Dict[str, Any]:
    """
    Get details for a specific unknown configuration.

    Args:
        unknown_id: Format: {session_id}_{index}
    """
    parts = unknown_id.rsplit("_", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail="Invalid unknown_id format")

    session_id, idx_str = parts
    try:
        idx = int(idx_str)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid index in unknown_id")

    session = _normalization_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    result = session["result"]
    if idx >= len(result.unknown_configurations):
        raise HTTPException(status_code=404, detail="Unknown index out of range")

    u = result.unknown_configurations[idx]
    return {
        "id": unknown_id,
        "raw_command": u.raw_command,
        "line_number": u.line_number,
        "vendor": u.vendor,
        "parser_name": u.parser_name,
        "confidence": u.confidence,
        "possible_category": u.possible_category,
        "context_lines": u.context_lines,
        "timestamp": u.timestamp.isoformat() if u.timestamp else None,
    }


@app.post("/api/training/suggest")
def get_ai_suggestion(req: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get an AI suggestion for an unknown command.

    Placeholder — returns a deterministic heuristic suggestion.
    Gemini integration comes in Step 11.
    """
    raw_command = req.get("raw_command", "")
    vendor = req.get("vendor", "unknown")
    category = req.get("possible_category", "unknown")

    # Heuristic suggestions based on category
    suggestions = {
        "session_timeout": {
            "parameter": "session_timeout",
            "value_type": "int",
            "unit": "seconds",
            "confidence": 0.7,
            "explanation": "Command appears to set a session timeout value.",
        },
        "authentication": {
            "parameter": "password_min_length",
            "value_type": "int",
            "unit": "characters",
            "confidence": 0.5,
            "explanation": "Command appears related to authentication/password policy.",
        },
        "network_encryption": {
            "parameter": "ssh_enabled",
            "value_type": "bool",
            "unit": "",
            "confidence": 0.5,
            "explanation": "Command appears related to network encryption settings.",
        },
        "logging": {
            "parameter": "logging_enabled",
            "value_type": "bool",
            "unit": "",
            "confidence": 0.6,
            "explanation": "Command appears related to logging configuration.",
        },
    }

    suggestion = suggestions.get(category, {
        "parameter": "unknown",
        "value_type": "string",
        "unit": "",
        "confidence": 0.3,
        "explanation": "Unable to determine parameter from command syntax.",
    })

    return {
        "raw_command": raw_command,
        "vendor": vendor,
        "suggestion": suggestion,
        "source": "heuristic",
    }


@app.post("/api/training/approve")
def approve_mapping(req: TrainingApproveRequest) -> Dict[str, Any]:
    """Approve a pending mapping in the knowledge base."""
    kb = _get_kb()
    success = kb.approve_mapping(req.vendor, req.pattern, req.approved_by)
    if not success:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return {"status": "approved", "vendor": req.vendor, "pattern": req.pattern}


@app.post("/api/training/edit")
def edit_mapping(req: TrainingEditRequest) -> Dict[str, Any]:
    """Edit an existing mapping in the knowledge base."""
    kb = _get_kb()
    success = kb.edit_mapping(req.vendor, req.pattern, **req.updates)
    if not success:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return {"status": "edited", "vendor": req.vendor, "pattern": req.pattern}


@app.post("/api/training/reject")
def reject_mapping(req: TrainingRejectRequest) -> Dict[str, Any]:
    """Reject (delete) a pending mapping from the knowledge base."""
    kb = _get_kb()
    success = kb.reject_mapping(req.vendor, req.pattern)
    if not success:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return {"status": "rejected", "vendor": req.vendor, "pattern": req.pattern}


@app.post("/api/training/save")
def save_mapping(req: TrainingSaveRequest) -> Dict[str, Any]:
    """Save a new approved mapping to the knowledge base."""
    from msme_auditor.config_parsers.knowledge_base import LearnedMapping

    kb = _get_kb()
    mapping = LearnedMapping(
        pattern=req.pattern,
        vendor=req.vendor,
        normalized_parameter=req.normalized_parameter,
        value_type=req.value_type,
        unit=req.unit,
        confidence=req.confidence,
        approved=True,
        approved_at=datetime.now(timezone.utc).isoformat(),
        approved_by="admin",
        source_command_example=req.source_command_example,
    )
    kb.add_mapping(mapping)
    return {"status": "saved", "vendor": req.vendor, "pattern": req.pattern}


@app.post("/api/training/rerun")
def rerun_normalization(session_id: str) -> Dict[str, Any]:
    """
    Re-run normalization on the original config after knowledge base update.

    The knowledge base's find_mapping() is called for each unknown command.
    If a match is found, the command is no longer unknown.
    """
    import uuid
    from msme_auditor.config_parsers.normalization_engine import normalize_config as do_normalize

    session = _normalization_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Re-normalize
    result = do_normalize(session["config_text"], vendor_hint=session["vendor_hint"])

    # Check unknowns against knowledge base
    kb = _get_kb()
    newly_recognized = []
    still_unknown = []

    for u in result.unknown_configurations:
        mapping = kb.find_mapping(u.vendor, u.raw_command)
        if mapping:
            newly_recognized.append({
                "raw_command": u.raw_command,
                "mapped_to": mapping.normalized_parameter,
                "pattern": mapping.pattern,
            })
        else:
            still_unknown.append({
                "raw_command": u.raw_command,
                "line_number": u.line_number,
                "possible_category": u.possible_category,
            })

    # Update session
    new_session_id = uuid.uuid4().hex[:12]
    _normalization_sessions[new_session_id] = {
        "config_text": session["config_text"],
        "vendor_hint": session["vendor_hint"],
        "result": result,
    }

    return {
        "session_id": new_session_id,
        "vendor": result.vendor,
        "coverage": result.coverage,
        "unknown_count": len(still_unknown),
        "newly_recognized": newly_recognized,
        "still_unknown": still_unknown,
        "flat_config": result.flat_config,
    }


@app.get("/api/training/kb/stats")
def kb_stats() -> Dict[str, Any]:
    """Get knowledge base statistics."""
    kb = _get_kb()
    return kb.stats()


@app.get("/api/training/kb/mappings")
def kb_mappings(vendor: Optional[str] = None) -> Dict[str, Any]:
    """Get all mappings from the knowledge base."""
    kb = _get_kb()
    mappings = kb.export_mappings(vendor=vendor)
    return {"mappings": mappings, "total": len(mappings)}


# ---------------------------------------------------------------------------
# Frontend — serve the new CyberSure multi-page app
# ---------------------------------------------------------------------------

FRONTEND_DIR = PROJECT_ROOT / "frontend"

# Serve static assets (styles.css, app.js, scanner.js, etc.)
if FRONTEND_DIR.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def serve_index():
    """Serve the new CyberSure landing page."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    # Fallback to old single-page frontend
    old_path = PROJECT_ROOT / "frontend.html"
    if old_path.exists():
        return FileResponse(str(old_path))
    return JSONResponse(
        status_code=200,
        content={
            "message": "MSME Cyber Auditor API is running.",
            "hint": "Frontend not found. Use /docs for API documentation.",
        },
    )


@app.get("/{page}.html")
def serve_page(page: str):
    """Serve individual frontend pages: dashboard.html, rpp.html, nes.html, etc."""
    page_path = FRONTEND_DIR / f"{page}.html"
    if page_path.exists():
        return FileResponse(str(page_path))
    # Fallback to old single-file frontend
    old_path = PROJECT_ROOT / "frontend.html"
    if old_path.exists():
        return FileResponse(str(old_path))
    return JSONResponse(status_code=404, content={"message": "Page not found."})


# ---------------------------------------------------------------------------
# AI Assistant Chat API
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    """Request body for AI Assistant chat."""
    message: str = Field(..., description="User message")
    scan_results: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Optional scan results for context",
    )


@app.post("/api/ai/chat")
def ai_chat(req: ChatRequest) -> dict:
    """
    AI Assistant chat endpoint.

    Uses Gemini when available for intelligent responses,
    falls back to a deterministic response system.
    """
    message = req.message.strip().lower()
    scan_results = req.scan_results or []

    # Try Gemini first
    try:
        from msme_auditor.config_parsers.gemini_advisor import _init_gemini, _GEMINI_AVAILABLE, _model
        _init_gemini()

        if _GEMINI_AVAILABLE and _model is not None:
            context = ""
            if scan_results:
                scores = [r.get("score", 0) for r in scan_results]
                avg = round(sum(scores) / len(scores)) if scores else 0
                failed_checks = []
                for r in scan_results:
                    for c in r.get("checks", []):
                        if not c.get("passed"):
                            failed_checks.append(f"{c.get('check_name', 'Unknown')}: {c.get('actual_value', 'N/A')} (expected: {c.get('expected_value', 'N/A')})")
                context = f"\nUser's scan results: Overall score {avg}/100. Failed checks: {'; '.join(failed_checks[:5])}"

            prompt = f"""You are the CyberSure AI Security Assistant. Help the user understand cybersecurity assessment results.
Be concise, clear, and actionable. Use plain language. Focus on what matters most.
{context}

User question: {req.message}"""

            response = _model.generate_content(prompt)
            return {"response": response.text.strip(), "source": "gemini"}
    except Exception:
        pass

    # Deterministic fallback — keyword-based responses
    response_text = _deterministic_chat_response(message, scan_results)
    return {"response": response_text, "source": "deterministic"}


def _deterministic_chat_response(message: str, scan_results: list) -> str:
    """Generate a deterministic response based on keywords and scan context."""
    # Calculate summary stats
    total_score = 0
    total_checks = 0
    passed_checks = 0
    failed_checks = []
    scanner_names = []

    for r in scan_results:
        scanner_names.append(r.get("sub_control", "Unknown"))
        total_score += r.get("score", 0)
        for c in r.get("checks", []):
            total_checks += 1
            if c.get("passed"):
                passed_checks += 1
            else:
                failed_checks.append(c)

    avg_score = round(total_score / len(scan_results)) if scan_results else 0

    # Keyword matching
    if any(w in message for w in ["score", "overall", "summary"]):
        if scan_results:
            status = "COMPLIANT" if avg_score >= 90 else "PARTIAL" if avg_score >= 60 else "NON-COMPLIANT"
            return (
                f"Your overall compliance score is {avg_score}/100 ({status}).\n\n"
                f"Scanners run: {', '.join(scanner_names)}\n"
                f"Checks passed: {passed_checks}/{total_checks}\n"
                f"Failed checks: {total_checks - passed_checks}\n\n"
                f"{'Focus on the critical failures below to improve your score.' if avg_score < 60 else 'Good progress! Address the remaining failures to reach full compliance.'}"
            )
        return "No scan results available yet. Run an assessment first to get your compliance score."

    if any(w in message for w in ["critical", "high", "urgent", "important"]):
        critical = [c for c in failed_checks if c.get("severity") in ["critical", "CRITICAL"]]
        if critical:
            items = "\n".join(f"- {c.get('check_name', 'Unknown')}: Expected {c.get('expected_value', 'N/A')}, found {c.get('actual_value', 'N/A')}" for c in critical[:5])
            return f"You have {len(critical)} critical findings that need immediate attention:\n\n{items}\n\nPrioritize these — they represent the highest security risk."
        return "No critical findings detected. Your most important items are the high-severity failures."

    if any(w in message for w in ["rpp", "password", "lockout"]):
        rpp_results = [r for r in scan_results if r.get("sub_control", "").startswith("RPP")]
        if rpp_results:
            scores = [f"{r.get('sub_control')}: {r.get('score', 0)}/100" for r in rpp_results]
            return f"RPP (Password Policy) results:\n" + "\n".join(f"  - {s}" for s in scores) + "\n\nFocus on the lowest-scoring areas first."
        return "No RPP scan results available. Run the RPP assessment to check your password policy compliance."

    if any(w in message for w in ["nes", "network", "wifi", "email"]):
        nes_results = [r for r in scan_results if r.get("sub_control", "").startswith("NES")]
        if nes_results:
            scores = [f"{r.get('sub_control')}: {r.get('score', 0)}/100" for r in nes_results]
            return f"NES (Network & Email Security) results:\n" + "\n".join(f"  - {s}" for s in scores) + "\n\nReview each area for specific improvements."
        return "No NES scan results available. Run the NES assessment to check your network and email security."

    if any(w in message for w in ["recommend", "fix", "improve", "next"]):
        if failed_checks:
            top_fixes = []
            for c in failed_checks[:3]:
                rem = c.get("remediation_command", "Review and fix this setting.")
                top_fixes.append(f"1. {c.get('check_name', 'Unknown')}\n   {rem}")
            return "Top recommendations to improve your score:\n\n" + "\n\n".join(top_fixes)
        return "All checks are passing! No immediate fixes needed. Continue monitoring."

    if any(w in message for w in ["explain", "what", "how", "why"]):
        return (
            "CyberSure scans your systems against CERT-In compliance requirements. "
            "Each scanner checks specific security controls (password policy, network ports, "
            "email authentication, etc.) and reports whether they meet the required standards. "
            "Ask me about specific areas like 'RPP results', 'critical findings', or 'how to improve'."
        )

    return (
        "I can help you understand your cybersecurity assessment. Try asking:\n"
        "  - What is my overall score?\n"
        "  - What are my critical findings?\n"
        "  - Summarize my RPP results\n"
        "  - What should I fix first?\n"
        "  - Explain how CyberSure works"
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the server with uvicorn (called by ``launch.py``)."""
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    print("🛡️  MSME Cyber Auditor — Scanner API Server")
    print(f"   Registered scanners: {list(get_all_scanners().keys())}")
    print(f"   Frontend: http://localhost:{port}")
    print(f"   API docs: http://localhost:{port}/docs\n")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
