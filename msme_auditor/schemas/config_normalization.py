"""
Common Security Schema — Normalized Security Model
===================================================
All vendor-specific configurations are parsed into this schema before
being evaluated by the CERT-In compliance engine.

DO NOT duplicate compliance logic here — this is purely a data model.
"""

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class DeviceInfo(BaseModel):
    """Device identification extracted from vendor config."""
    vendor: str = Field(default="Unknown", description="Vendor name (Cisco, Fortinet, Juniper, Unknown)")
    model: str = Field(default="Unknown", description="Device model or OS family")
    version: str = Field(default="Unknown", description="OS/firmware version if detectable")
    hostname: Optional[str] = Field(None, description="Device hostname if present")
    source: str = Field(default="config_file", description="Source of the configuration (config_file, live_scan, api, manual)")
    evidence: List[str] = Field(default_factory=list, description="Raw config lines that identified this device")
    confidence: float = Field(default=1.0, description="Vendor/device detection confidence (0.0-1.0)")


class AuthenticationConfig(BaseModel):
    """Normalized authentication security parameters."""
    password_min_length: Optional[int] = Field(None, description="Minimum password length (characters)")
    password_complexity_enabled: Optional[bool] = Field(None, description="Whether password complexity rules are enforced")
    mfa_enabled: Optional[bool] = Field(None, description="Multi-factor authentication enabled")
    account_lockout_enabled: Optional[bool] = Field(None, description="Account lockout after failed attempts")
    account_lockout_threshold: Optional[int] = Field(None, description="Failed attempts before lockout")
    session_timeout: Optional[int] = Field(None, description="Idle session timeout (seconds)")
    password_expiry_days: Optional[int] = Field(None, description="Password expiry in days")
    password_history_count: Optional[int] = Field(None, description="Number of remembered passwords")
    password_encryption_enabled: Optional[bool] = Field(None, description="Passwords stored encrypted in config")


class NetworkConfig(BaseModel):
    """Normalized network security parameters."""
    telnet_enabled: Optional[bool] = Field(None, description="Telnet service enabled (should be False)")
    ssh_enabled: Optional[bool] = Field(None, description="SSH service enabled")
    ssh_version: Optional[int] = Field(None, description="SSH protocol version (should be 2)")
    unused_ports_disabled: Optional[bool] = Field(None, description="Unused ports are shutdown/disabled")
    http_server_enabled: Optional[bool] = Field(None, description="HTTP server on device enabled")
    https_enabled: Optional[bool] = Field(None, description="HTTPS management enabled")
    snmp_community_default: Optional[bool] = Field(None, description="Default SNMP community string in use")
    snmp_enabled: Optional[bool] = Field(None, description="SNMP agent enabled")
    cdp_disabled: Optional[bool] = Field(None, description="CDP/LLDP disabled on external interfaces")
    source_routing_disabled: Optional[bool] = Field(None, description="IP source routing disabled")
    proxy_arp_disabled: Optional[bool] = Field(None, description="Proxy ARP disabled")
    firewall_enabled: Optional[bool] = Field(None, description="Firewall/security policy enabled")
    firewall_rules_count: Optional[int] = Field(None, description="Number of firewall rules configured")


class LoggingConfig(BaseModel):
    """Normalized logging/security audit parameters."""
    logging_enabled: Optional[bool] = Field(None, description="System logging enabled")
    remote_syslog_enabled: Optional[bool] = Field(None, description="Remote syslog server configured")
    log_timestamps_enabled: Optional[bool] = Field(None, description="Timestamps included in log entries")
    login_logging_enabled: Optional[bool] = Field(None, description="Login attempts are logged")
    config_change_logging: Optional[bool] = Field(None, description="Configuration changes are logged")


class EncryptionConfig(BaseModel):
    """Normalized encryption parameters."""
    ssh_ciphers_strong: Optional[bool] = Field(None, description="Only strong SSH ciphers allowed")
    tls_version_min: Optional[str] = Field(None, description="Minimum TLS version (e.g., 1.2)")
    tls_enabled: Optional[bool] = Field(None, description="TLS/SSL encryption enabled for management")
    ntp_configured: Optional[bool] = Field(None, description="NTP configured for time sync")
    aaa_enabled: Optional[bool] = Field(None, description="AAA (Authentication, Authorization, Accounting) enabled")


class AccessControlConfig(BaseModel):
    """Normalized access control parameters."""
    enable_secret_configured: Optional[bool] = Field(None, description="Enable secret/password configured")
    exec_timeout_configured: Optional[bool] = Field(None, description="Console/VTY exec timeout configured")
    vty_access_restricted: Optional[bool] = Field(None, description="VTY lines access restricted (ACL)")
    banner_configured: Optional[bool] = Field(None, description="Login banner configured")


class NormalizedSecurityConfig(BaseModel):
    """
    Complete normalized security configuration.

    This is the common schema that ALL vendor parsers produce and
    that the CERT-In compliance engine consumes.
    """
    device: DeviceInfo = Field(default_factory=DeviceInfo)
    authentication: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)
    access_control: AccessControlConfig = Field(default_factory=AccessControlConfig)

    # Metadata
    parse_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_line_count: int = Field(default=0, description="Number of lines in original config")
    recognized_line_count: int = Field(default=0, description="Lines successfully parsed")
    unrecognized_commands: List[str] = Field(default_factory=list, description="Commands the parser could not understand")
    parse_confidence: float = Field(default=1.0, description="Overall parse confidence (0.0-1.0)")
    evidence_trail: Dict[str, Any] = Field(default_factory=dict, description="Per-parameter evidence: {param: {source_line, line_number, confidence}}")

    def coverage_percentage(self) -> float:
        """Percentage of config lines that were successfully recognized."""
        if self.raw_line_count == 0:
            return 0.0
        return round(self.recognized_line_count / self.raw_line_count * 100, 1)

    def to_flat_dict(self) -> Dict[str, Any]:
        """Flatten all nested configs into a single dict for the compliance engine."""
        flat: Dict[str, Any] = {}

        # Flatten each section
        for section_name in ("authentication", "network", "logging", "encryption", "access_control"):
            section = getattr(self, section_name)
            for field_name, field_value in section.model_dump().items():
                if field_value is not None:
                    flat[field_name] = field_value

        return flat

    def add_evidence(self, parameter: str, source_line: str, line_number: int = 0, confidence: float = 1.0) -> None:
        """Record the evidence trail for a specific normalized parameter.

        This enables full traceability:
            CERT-In finding → normalized parameter → original config line

        Args:
            parameter: The normalized parameter name (e.g., 'ssh_enabled')
            source_line: The original config line that produced this value
            line_number: Line number in the original config
            confidence: Confidence that this mapping is correct (0.0-1.0)
        """
        self.evidence_trail[parameter] = {
            "source_line": source_line,
            "line_number": line_number,
            "confidence": confidence,
            "vendor": self.device.vendor,
            "model": self.device.model,
        }

    def get_evidence(self, parameter: str) -> Optional[Dict[str, Any]]:
        """Get the evidence trail for a specific parameter.

        Args:
            parameter: The normalized parameter name

        Returns:
            Evidence dict with source_line, line_number, confidence, or None
        """
        return self.evidence_trail.get(parameter)

    def all_parameters(self) -> Dict[str, Any]:
        """Return all non-None normalized parameters as a flat dict.

        Includes device info and metadata.
        """
        result = self.to_flat_dict()
        result["vendor"] = self.device.vendor
        result["device_model"] = self.device.model
        result["os_version"] = self.device.version
        result["hostname"] = self.device.hostname
        result["parse_confidence"] = self.parse_confidence
        result["coverage"] = self.coverage_percentage()
        return result
