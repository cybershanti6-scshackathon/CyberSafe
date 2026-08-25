"""
Adaptive Knowledge Base
=======================

Stores learned mappings from unknown configuration commands
to normalized security parameters. Supports pattern-based
matching (not just exact string matching).

File format: JSON (prototype), can be migrated to SQLite/DB later.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from threading import Lock


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class LearnedMapping:
    """
    A learned pattern mapping from vendor syntax to normalized parameter.

    Example:
        pattern: "set system-timeout <seconds>"
        vendor: "juniper"
        normalized_parameter: "session_timeout"
        value_type: "int"
        unit: "seconds"
        confidence: 0.95
        approved: true
    """
    pattern: str                      # Regex pattern with named groups for values
    vendor: str                       # Vendor name
    normalized_parameter: str         # Target field in NormalizedSecurityConfig
    value_type: str                   # "int", "float", "bool", "string"
    unit: str = ""                    # Unit if applicable (seconds, chars, days)
    confidence: float = 0.8           # 0.0 - 1.0
    approved: bool = False            # Human-approved
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    source_command_example: str = ""  # Example command that triggered this
    times_matched: int = 0            # How many times this pattern matched

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearnedMapping":
        return cls(**data)


# =============================================================================
# Knowledge Base Class
# =============================================================================

class KnowledgeBase:
    """
    Thread-safe knowledge base for learned configuration mappings.

    Features:
    - Pattern-based matching (regex with named capture groups)
    - Vendor-scoped mappings
    - Approval workflow (pending → approved/rejected)
    - Usage tracking (times_matched)
    - Persistence to JSON
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self._mappings: Dict[str, List[LearnedMapping]] = {}  # vendor -> [mappings]
        self._storage_path = storage_path or Path("knowledge_base.json")
        self._lock = Lock()
        self._load()

    def _load(self) -> None:
        """Load mappings from JSON file."""
        if not self._storage_path.exists():
            return
        try:
            with open(self._storage_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for vendor, mappings in data.items():
                self._mappings[vendor] = [LearnedMapping.from_dict(m) for m in mappings]
        except Exception as e:
            print(f"[knowledge_base] Warning: could not load {self._storage_path}: {e}")

    def _save(self) -> None:
        """Save mappings to JSON file."""
        try:
            data = {
                vendor: [m.to_dict() for m in mappings]
                for vendor, mappings in self._mappings.items()
            }
            with open(self._storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[knowledge_base] Warning: could not save {self._storage_path}: {e}")

    # -------------------------------------------------------------------------
    # Query Methods
    # -------------------------------------------------------------------------

    def find_mapping(self, vendor: str, command: str) -> Optional[LearnedMapping]:
        """
        Find a matching mapping for a vendor command.

        Args:
            vendor: Vendor name (cisco, fortinet, juniper, etc.)
            command: Raw configuration command

        Returns:
            LearnedMapping if match found, None otherwise
        """
        vendor = vendor.lower()
        with self._lock:
            mappings = self._mappings.get(vendor, [])
            for mapping in mappings:
                if not mapping.approved:
                    continue
                try:
                    if re.search(mapping.pattern, command.strip(), re.IGNORECASE):
                        mapping.times_matched += 1
                        self._save()
                        return mapping
                except re.error:
                    continue
        return None

    def get_pending_mappings(self, vendor: Optional[str] = None) -> List[LearnedMapping]:
        """Get all pending (unapproved) mappings, optionally filtered by vendor."""
        with self._lock:
            if vendor:
                return [m for m in self._mappings.get(vendor.lower(), []) if not m.approved]
            result = []
            for mappings in self._mappings.values():
                result.extend([m for m in mappings if not m.approved])
            return result

    def get_approved_mappings(self, vendor: Optional[str] = None) -> List[LearnedMapping]:
        """Get all approved mappings, optionally filtered by vendor."""
        with self._lock:
            if vendor:
                return [m for m in self._mappings.get(vendor.lower(), []) if m.approved]
            result = []
            for mappings in self._mappings.values():
                result.extend([m for m in mappings if m.approved])
            return result

    def get_mapping_by_id(self, vendor: str, pattern: str) -> Optional[LearnedMapping]:
        """Get a specific mapping by vendor and pattern."""
        with self._lock:
            for m in self._mappings.get(vendor.lower(), []):
                if m.pattern == pattern:
                    return m
        return None

    # -------------------------------------------------------------------------
    # Mutation Methods
    # -------------------------------------------------------------------------

    def add_mapping(self, mapping: LearnedMapping) -> None:
        """Add or update a mapping."""
        vendor = mapping.vendor.lower()
        with self._lock:
            if vendor not in self._mappings:
                self._mappings[vendor] = []
            # Check if pattern already exists
            for i, existing in enumerate(self._mappings[vendor]):
                if existing.pattern == mapping.pattern:
                    self._mappings[vendor][i] = mapping
                    self._save()
                    return
            self._mappings[vendor].append(mapping)
            self._save()

    def approve_mapping(self, vendor: str, pattern: str, approved_by: str = "admin") -> bool:
        """Approve a pending mapping."""
        with self._lock:
            for m in self._mappings.get(vendor.lower(), []):
                if m.pattern == pattern:
                    m.approved = True
                    m.approved_at = datetime.now(timezone.utc).isoformat()
                    m.approved_by = approved_by
                    m.updated_at = datetime.now(timezone.utc).isoformat()
                    self._save()
                    return True
        return False

    def reject_mapping(self, vendor: str, pattern: str) -> bool:
        """Reject (delete) a pending mapping."""
        with self._lock:
            mappings = self._mappings.get(vendor.lower(), [])
            for i, m in enumerate(mappings):
                if m.pattern == pattern:
                    del mappings[i]
                    self._save()
                    return True
        return False

    def edit_mapping(self, vendor: str, pattern: str, **updates) -> bool:
        """Edit an existing mapping (pattern, parameter, value_type, etc.)."""
        with self._lock:
            for m in self._mappings.get(vendor.lower(), []):
                if m.pattern == pattern:
                    for key, value in updates.items():
                        if hasattr(m, key):
                            setattr(m, key, value)
                    m.updated_at = datetime.now(timezone.utc).isoformat()
                    self._save()
                    return True
        return False

    # -------------------------------------------------------------------------
    # Stats & Export
    # -------------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics."""
        with self._lock:
            total = sum(len(m) for m in self._mappings.values())
            approved = sum(1 for m in self._mappings.values() for mm in m if mm.approved)
            pending = total - approved
            by_vendor = {v: len(m) for v, m in self._mappings.items()}
            return {
                "total_mappings": total,
                "approved": approved,
                "pending": pending,
                "by_vendor": by_vendor,
                "storage_path": str(self._storage_path),
            }

    def export_mappings(self, vendor: Optional[str] = None) -> List[Dict[str, Any]]:
        """Export mappings as list of dicts."""
        with self._lock:
            if vendor:
                return [m.to_dict() for m in self._mappings.get(vendor.lower(), [])]
            result = []
            for mappings in self._mappings.values():
                result.extend([m.to_dict() for m in mappings])
            return result


# Global instance (initialized on first import)
_knowledge_base: Optional[KnowledgeBase] = None


def get_knowledge_base(storage_path: Optional[Path] = None) -> KnowledgeBase:
    """Get or create the global knowledge base instance."""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase(storage_path)
    return _knowledge_base


def init_knowledge_base(storage_path: Optional[Path] = None) -> KnowledgeBase:
    """Initialize the global knowledge base (call at startup)."""
    global _knowledge_base
    _knowledge_base = KnowledgeBase(storage_path)
    return _knowledge_base