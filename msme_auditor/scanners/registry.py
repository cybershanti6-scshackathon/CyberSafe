"""
Scanner Plugin Registry
=======================
Auto-discovers BaseScanner subclasses and provides a unified API
for listing, running, and querying scanners.

Adding a new scanner = create a module with a BaseScanner subclass.
No other files need changes.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path


# =============================================================================
# Registry singleton
# =============================================================================

_REGISTRY: Dict[str, Any] = {}  # scanner_id -> BaseScanner instance


def register_scanner(scanner_instance: Any) -> None:
    """Register a scanner instance."""
    if scanner_instance.scanner_id:
        _REGISTRY[scanner_instance.scanner_id] = scanner_instance


def get_all_scanners() -> Dict[str, Any]:
    """Return all registered scanners."""
    return dict(_REGISTRY)


def get_scanner(scanner_id: str) -> Any:
    """Get a single scanner by ID."""
    return _REGISTRY.get(scanner_id)


def list_scanners_by_category() -> Dict[str, List[Any]]:
    """Group scanners by category."""
    groups: Dict[str, List[Any]] = {}
    for scanner in _REGISTRY.values():
        groups.setdefault(scanner.category, []).append(scanner)
    return groups


def scanner_to_api_schema(scanner: Any) -> dict:
    """Convert a scanner to a JSON-serializable API schema for the frontend."""
    return {
        "id": scanner.scanner_id,
        "name": scanner.name,
        "description": scanner.description,
        "category": scanner.category,
        "target_types": scanner.target_types,
        "input_fields": scanner.input_fields,
    }


def run_scan(scanner_id: str, config: Optional[dict] = None) -> Any:
    """Run a scan by ID with the given config."""
    scanner = _REGISTRY.get(scanner_id)
    if not scanner:
        raise ValueError(f"Unknown scanner: {scanner_id}")
    return scanner.run(config=config or {})


# =============================================================================
# Auto-discovery: import scanner modules and register BaseScanner subclasses
# =============================================================================

def discover_scanners() -> None:
    """
    Import all scanner modules so their BaseScanner subclasses get registered.

    Call once at startup (from server.py).
    """
    from msme_auditor.scanners.base import BaseScanner

    # Import each scanner module — the class definition triggers registration
    _scanner_modules = [
        "msme_auditor.scanners.rpp.rpp1",
        "msme_auditor.scanners.rpp.rpp2",
        "msme_auditor.scanners.rpp.rpp3",
        "msme_auditor.scanners.rpp.rpp4",
        "msme_auditor.scanners.nes.nes1",
        "msme_auditor.scanners.nes.nes2",
        "msme_auditor.scanners.nes.nes3",
        "msme_auditor.scanners.nes.nes4",
        "msme_auditor.scanners.web.web1",
    ]

    for mod_name in _scanner_modules:
        try:
            # Use __import__ to handle the dotted module path
            parts = mod_name.split(".")
            module = __import__(mod_name, fromlist=[parts[-1]])

            # Find BaseScanner subclasses in the loaded module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, BaseScanner)
                    and attr is not BaseScanner
                    and attr.scanner_id
                ):
                    instance = attr()
                    register_scanner(instance)
                    print(f"  ✅ {instance.scanner_id}: {instance.name}")

        except Exception as exc:
            print(f"  ⚠️  {mod_name}: {exc}")

    print(f"\n[registry] {len(_REGISTRY)} scanner(s) registered")
