"""
Scanner plugin system with auto-discovery.

All imports are lazy to avoid cascading failures at startup.
"""


def __getattr__(name: str):
    """Lazy-load scanner utilities on first access."""
    if name in ("BaseScanner", "ScanConfig", "make_check", "bool_check",
                "threshold_check", "range_check", "build_result"):
        from msme_auditor.scanners import base
        return getattr(base, name)
    if name in ("discover_scanners", "get_all_scanners", "get_scanner",
                "list_scanners_by_category", "run_scan", "scanner_to_api_schema"):
        from msme_auditor.scanners import registry
        return getattr(registry, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
