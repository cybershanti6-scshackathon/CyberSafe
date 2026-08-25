"""
Configuration Parser Module
============================
Vendor-agnostic configuration parsing for network devices.
Parses vendor-specific configs (Cisco, Fortinet, Juniper, etc.) into
the common NormalizedSecurityConfig schema for CERT-In compliance evaluation.

Architecture:
    Raw Config
        ↓
Vendor Detection (deterministic)
        ↓
Vendor Parser (Cisco/Fortinet/Juniper/...)
        ↓
Normalization Engine
        ↓
NormalizedSecurityConfig  →  CERT-In Compliance Engine
        ↓
Unknown Syntax?  →  Knowledge Base  →  Human-in-the-Loop  →  AI Suggestion
"""