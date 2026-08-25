"""
Standardized enums shared across NES, RPP, and WEB controls.
"""

from enum import Enum


class ComplianceStatus(str, Enum):
    """Overall compliance status for a sub-control."""
    PASSED = "Passed"
    FAILED = "Failed"
    WARNING = "Warning"
    ERROR = "Error"


class SeverityLevel(str, Enum):
    """How critical a finding is."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
