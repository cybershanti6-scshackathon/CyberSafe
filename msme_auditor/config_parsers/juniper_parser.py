"""
Juniper Junos Configuration Parser
===================================

Parses Juniper Junos configurations into the NormalizedSecurityConfig schema.
"""

import re
from typing import List, Optional

from msme_auditor.config_parsers.base import (
    BaseConfigParser,
    ParseResult,
    DeviceInfo,
    AuthenticationConfig,
    NetworkConfig,
    LoggingConfig,
    EncryptionConfig,
    AccessControlConfig,
    NormalizedSecurityConfig,
)


class JuniperParser(BaseConfigParser):
    """Parser for Juniper Junos configurations."""

    vendor_name = "juniper"
    supported_os = ["Junos", "JUNOS"]
    version = "1.0.0"

    PATTERNS = {
        # Version / commit header
        "version": re.compile(r"^version\s+([\d\.R\d+\.]+);"),
        "last_commit": re.compile(r"^##\s+Last\s+commit:\s+(.+)"),

        # System block
        "system_block": re.compile(r"^system\s+\{"),
        "host_name": re.compile(r"^host-name\s+(\S+);"),
        "domain_name": re.compile(r"^domain-name\s+(\S+);"),
        "time_zone": re.compile(r"^time-zone\s+(\S+);"),
        "root_auth": re.compile(r"^root-authentication\s+\{"),
        "encrypted_password": re.compile(r"^encrypted-password\s+\"\$(\d+)\$([^\"]+)\";"),
        "plain_password": re.compile(r"^plain-text-password\s+\{"),

        # Login
        "login_block": re.compile(r"^login\s+\{"),
        "login_message": re.compile(r"^message\s+\"([^\"]+)\";"),
        "login_announcement": re.compile(r"^announcement\s+\"([^\"]+)\";"),
        "login_retry": re.compile(r"^retry-options\s+\{"),
        "tries_before_disconnect": re.compile(r"^tries-before-disconnect\s+(\d+);"),
        "lockout_period": re.compile(r"^lockout-period\s+(\d+);"),

        # User
        "user_block": re.compile(r"^user\s+(\S+)\s+\{"),
        "user_class": re.compile(r"^class\s+(\S+);"),
        "user_auth": re.compile(r"^authentication\s+\{"),
        "user_ssh_key": re.compile(r"^ssh-(rsa|dsa|ecdsa)\s+\"([^\"]+)\";"),
        "user_password": re.compile(r"^encrypted-password\s+\"\$(\d+)\$([^\"]+)\";"),

        # Services (SSH, Telnet, etc.)
        "services_block": re.compile(r"^services\s+\{"),
        "ssh_block": re.compile(r"^ssh\s+\{"),
        "ssh_root_login": re.compile(r"^root-login\s+(allow|deny);"),
        "ssh_protocol_version": re.compile(r"^protocol-version\s+v(\d+);"),
        "ssh_ciphers": re.compile(r"^ciphers\s+([^;]+);"),
        "ssh_macs": re.compile(r"^macs\s+([^;]+);"),
        "telnet_block": re.compile(r"^telnet\s+\{"),
        "web_mgmt_block": re.compile(r"^web-management\s+\{"),
        "http_block": re.compile(r"^http\s+\{"),
        "https_block": re.compile(r"^https\s+\{"),
        "snmp_block": re.compile(r"^snmp\s+\{"),
        "ntp_block": re.compile(r"^ntp\s+\{"),
        "syslog_block": re.compile(r"^syslog\s+\{"),
        "dhcp_block": re.compile(r"^dhcp\s+\{"),

        # SSH settings
        "ssh_disable": re.compile(r"^disable;"),
        "ssh_idle_timeout": re.compile(r"^idle-timeout\s+(\d+);"),
        "ssh_max_sessions": re.compile(r"^max-sessions-per-connection\s+(\d+);"),

        # Telnet
        "telnet_disable": re.compile(r"^disable;"),

        # Web management
        "web_http": re.compile(r"^http\s+\{"),
        "web_https": re.compile(r"^https\s+\{"),
        "web_interface": re.compile(r"^interface\s+(\S+);"),
        "web_port": re.compile(r"^port\s+(\d+);"),

        # SNMP
        "snmp_community": re.compile(r"^community\s+(\S+)\s+\{"),
        "snmp_community_auth": re.compile(r"^authorization\s+(read-only|read-write);"),
        "snmp_community_clients": re.compile(r"^clients\s+\{"),
        "snmp_trap_group": re.compile(r"^trap-group\s+(\S+)\s+\{"),
        "snmp_target": re.compile(r"^targets\s+\{"),
        "snmp_location": re.compile(r"^location\s+\"([^\"]+)\";"),
        "snmp_contact": re.compile(r"^contact\s+\"([^\"]+)\";"),

        # NTP
        "ntp_server": re.compile(r"^server\s+(\S+)\s+\{"),
        "ntp_boot_server": re.compile(r"^boot-server\s+(\S+);"),

        # Syslog
        "syslog_host": re.compile(r"^host\s+(\S+)\s+\{"),
        "syslog_any": re.compile(r"^any\s+(\S+);"),
        "syslog_archive": re.compile(r"^archive\s+\{"),
        "syslog_console": re.compile(r"^console\s+\{"),
        "syslog_time_format": re.compile(r"^time-format\s+(year|millisecond|none);"),

        # Authentication order
        "auth_order": re.compile(r"^authentication-order\s+\[([^\]]+)\];"),

        # Radius / TACACS / LDAP
        "radius_server": re.compile(r"^radius-server\s+(\S+)\s+\{"),
        "tacplus_server": re.compile(r"^tacplus-server\s+(\S+)\s+\{"),
        "ldap_server": re.compile(r"^ldap-server\s+(\S+)\s+\{"),

        # Interfaces
        "interfaces_block": re.compile(r"^interfaces\s+\{"),
        "interface_name": re.compile(r"^(\S+)\s+\{"),
        "interface_unit": re.compile(r"^unit\s+(\d+)\s+\{"),
        "interface_disable": re.compile(r"^disable;"),
        "interface_shutdown": re.compile(r"^shutdown;"),
        "interface_description": re.compile(r"^description\s+\"([^\"]+)\";"),

        # Security (for SRX)
        "security_block": re.compile(r"^security\s+\{"),
        "security_zones": re.compile(r"^zones\s+\{"),
        "security_policies": re.compile(r"^policies\s+\{"),
        "security_screen": re.compile(r"^screen\s+\{"),

        # Firewall
        "firewall_block": re.compile(r"^firewall\s+\{"),
        "firewall_family": re.compile(r"^family\s+(\S+)\s+\{"),
        "firewall_filter": re.compile(r"^filter\s+(\S+)\s+\{"),
        "firewall_term": re.compile(r"^term\s+(\S+)\s+\{"),
        "firewall_then": re.compile(r"^then\s+\{"),
        "firewall_accept": re.compile(r"^accept;"),
        "firewall_discard": re.compile(r"^discard;"),
        "firewall_reject": re.compile(r"^reject\s+(\S+);"),

        # Chassis
        "chassis_block": re.compile(r"^chassis\s+\{"),
    }

    def __init__(self):
        super().__init__()
        self._current_section = "global"
        self._in_system = False
        self._in_login = False
        self._in_user = False
        self._in_services = False
        self._in_ssh = False
        self._in_telnet = False
        self._in_web = False
        self._in_https = False
        self._in_snmp = False
        self._in_ntp = False
        self._in_syslog = False
        self._in_interfaces = False
        self._in_security = False
        self._in_firewall = False
        self._current_interface = None
        self._current_unit = None
        self._brace_depth = 0

    def parse(self, config_text: str, device_info: Optional[DeviceInfo] = None) -> ParseResult:
        self.reset()
        lines = config_text.splitlines()

        config = self._init_normalized_config(device_info)
        if config.device.vendor == "Unknown":
            config.device.vendor = "Juniper"
        config.device.model = "Junos"

        for i, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line or line.startswith("##"):
                if line.startswith("## Last commit:"):
                    m = self.PATTERNS["last_commit"].search(line)
                    if m:
                        # Commit timestamp
                        pass
                continue

            # Track brace depth for nested blocks
            self._update_brace_depth(line)

            # Track section
            self._update_section(line)

            matched = self._try_patterns(line, i + 1, config, lines, i)

            if not matched and line and not line.startswith("##") and line not in ("{", "}", "};") and not line.endswith("{"):
                self._unknown_configs.append(self._create_unknown(
                    raw_command=raw_line.strip(),
                    line_number=i + 1,
                    confidence=0.1,
                    possible_category=self._guess_category(line),
                    context_lines=self._get_context(lines, i),
                ))

        self._post_process(config)
        return self._finalize_result(config, len(lines))

    def _update_brace_depth(self, line: str):
        """Track brace nesting level."""
        open_braces = line.count("{")
        close_braces = line.count("}")
        self._brace_depth += open_braces - close_braces

    def _update_section(self, line: str):
        """Track current configuration section."""
        stripped = line.strip()

        # Opening blocks
        if self.PATTERNS["system_block"].search(stripped):
            self._in_system = True
        elif self.PATTERNS["login_block"].search(stripped):
            self._in_login = True
        elif self.PATTERNS["user_block"].search(stripped):
            self._in_user = True
        elif self.PATTERNS["services_block"].search(stripped):
            self._in_services = True
        elif self.PATTERNS["ssh_block"].search(stripped):
            self._in_ssh = True
        elif self.PATTERNS["telnet_block"].search(stripped):
            self._in_telnet = True
        elif self.PATTERNS["web_mgmt_block"].search(stripped):
            self._in_web = True
        elif self.PATTERNS["https_block"].search(stripped):
            self._in_https = True
        elif self.PATTERNS["snmp_block"].search(stripped):
            self._in_snmp = True
        elif self.PATTERNS["ntp_block"].search(stripped):
            self._in_ntp = True
        elif self.PATTERNS["syslog_block"].search(stripped):
            self._in_syslog = True
        elif self.PATTERNS["interfaces_block"].search(stripped):
            self._in_interfaces = True
        elif self.PATTERNS["security_block"].search(stripped):
            self._in_security = True
        elif self.PATTERNS["firewall_block"].search(stripped):
            self._in_firewall = True

        # Closing blocks (brace depth == 0 means we exited a top-level block)
        if self._brace_depth == 0:
            self._in_system = False
            self._in_login = False
            self._in_user = False
            self._in_services = False
            self._in_ssh = False
            self._in_telnet = False
            self._in_web = False
            self._in_https = False
            self._in_snmp = False
            self._in_ntp = False
            self._in_syslog = False
            self._in_interfaces = False
            self._in_security = False
            self._in_firewall = False
            self._current_interface = None
            self._current_unit = None

    def _try_patterns(self, line: str, line_num: int, config: NormalizedSecurityConfig,
                      all_lines: List[str], line_idx: int) -> bool:
        matched = False
        raw_line = line

        # Version
        if m := self.PATTERNS["version"].search(line):
            config.device.version = m.group(1)
            matched = True

        # System
        if self._in_system:
            if m := self.PATTERNS["host_name"].search(line):
                config.device.hostname = m.group(1)
                matched = True
            if self.PATTERNS["root_auth"].search(line):
                config.access_control.enable_secret_configured = True
                matched = True
            if self.PATTERNS["encrypted_password"].search(line):
                config.access_control.enable_secret_configured = True
                matched = True
            if self.PATTERNS["auth_order"].search(line):
                config.encryption.aaa_enabled = True
                matched = True

        # Login (banner, retry options)
        if self._in_login:
            if self.PATTERNS["login_message"].search(line) or self.PATTERNS["login_announcement"].search(line):
                self._set_with_evidence(config, "access_control", "banner_configured", True, raw_line, line_num)
                matched = True
            if m := self.PATTERNS["tries_before_disconnect"].search(line):
                self._set_with_evidence(config, "authentication", "account_lockout_enabled", True, raw_line, line_num)
                self._set_with_evidence(config, "authentication", "account_lockout_threshold", int(m.group(1)), raw_line, line_num)
                matched = True
            if m := self.PATTERNS["lockout_period"].search(line):
                # Lockout period in minutes
                matched = True

        # User
        if self._in_user:
            if self.PATTERNS["user_ssh_key"].search(line):
                config.network.ssh_enabled = True
                matched = True
            if self.PATTERNS["user_password"].search(line):
                config.access_control.enable_secret_configured = True
                matched = True

        # Services
        if self._in_ssh:
            self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
            self._set_with_evidence(config, "network", "ssh_version", 2, raw_line, line_num)
            if self.PATTERNS["ssh_disable"].search(line):
                self._set_with_evidence(config, "network", "ssh_enabled", False, raw_line, line_num)
            if m := self.PATTERNS["ssh_protocol_version"].search(line):
                self._set_with_evidence(config, "network", "ssh_version", int(m.group(1)), raw_line, line_num)
            if self.PATTERNS["ssh_ciphers"].search(line) or self.PATTERNS["ssh_macs"].search(line):
                self._set_with_evidence(config, "encryption", "ssh_ciphers_strong", True, raw_line, line_num)
            if m := self.PATTERNS["ssh_idle_timeout"].search(line):
                self._set_with_evidence(config, "authentication", "session_timeout", int(m.group(1)), raw_line, line_num)
                self._set_with_evidence(config, "access_control", "exec_timeout_configured", True, raw_line, line_num)
            matched = True

        if self._in_telnet:
            self._set_with_evidence(config, "network", "telnet_enabled", True, raw_line, line_num)
            if self.PATTERNS["telnet_disable"].search(line):
                self._set_with_evidence(config, "network", "telnet_enabled", False, raw_line, line_num)
            matched = True

        if self._in_web or self._in_https:
            if self._in_https:
                self._set_with_evidence(config, "network", "https_enabled", True, raw_line, line_num)
            else:
                self._set_with_evidence(config, "network", "http_server_enabled", True, raw_line, line_num)
            matched = True

        # SNMP
        if self._in_snmp:
            if m := self.PATTERNS["snmp_community"].search(line):
                config.network.snmp_enabled = True
                community = m.group(1).lower()
                if community in ("public", "private", "juniper"):
                    config.network.snmp_community_default = True
            if self.PATTERNS["snmp_location"].search(line) or self.PATTERNS["snmp_contact"].search(line):
                config.network.snmp_enabled = True
            matched = True

        # NTP
        if self._in_ntp:
            if self.PATTERNS["ntp_server"].search(line) or self.PATTERNS["ntp_boot_server"].search(line):
                self._set_with_evidence(config, "encryption", "ntp_configured", True, raw_line, line_num)
            matched = True

        # Syslog
        if self._in_syslog:
            if self.PATTERNS["syslog_host"].search(line) or self.PATTERNS["syslog_any"].search(line):
                self._set_with_evidence(config, "logging", "remote_syslog_enabled", True, raw_line, line_num)
                self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            if self.PATTERNS["syslog_archive"].search(line) or self.PATTERNS["syslog_console"].search(line):
                self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            if self.PATTERNS["syslog_time_format"].search(line):
                self._set_with_evidence(config, "logging", "log_timestamps_enabled", True, raw_line, line_num)
            matched = True

        # Interfaces
        if self._in_interfaces:
            if m := self.PATTERNS["interface_name"].search(line):
                self._current_interface = m.group(1)
            if self.PATTERNS["interface_disable"].search(line) or self.PATTERNS["interface_shutdown"].search(line):
                # Interface is disabled/shutdown
                matched = True

        # Recognize common block open/close (don't mark as unknown)
        if stripped in ("{", "}", "};") or stripped.endswith(" {") or stripped.endswith(" {"):
            matched = True
        if any(kw in stripped for kw in ["block", "group", "profile", "policy", "rule", "term", "then", "from", "to"]):
            # These are structural keywords
            matched = True

        return matched

    def _guess_category(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["timeout", "idle-timeout", "session"]):
            return "session_timeout"
        if any(kw in line_lower for kw in ["password", "authentication", "login", "user", "root-auth", "retry", "lockout"]):
            return "authentication"
        if any(kw in line_lower for kw in ["ssh", "telnet", "web-management", "https", "http", "ciphers", "macs", "protocol"]):
            return "network_encryption"
        if any(kw in line_lower for kw in ["syslog", "log", "archive", "time-format", "console"]):
            return "logging"
        if any(kw in line_lower for kw in ["snmp", "community", "trap"]):
            return "snmp"
        if any(kw in line_lower for kw in ["ntp", "time", "clock", "boot-server"]):
            return "ntp"
        if any(kw in line_lower for kw in ["interface", "unit", "disable", "shutdown", "description", "vlan"]):
            return "network_interface"
        if any(kw in line_lower for kw in ["security", "zone", "policy", "screen", "firewall", "filter", "accept", "discard", "reject"]):
            return "firewall"
        if any(kw in line_lower for kw in ["radius", "tacplus", "ldap", "authentication-order"]):
            return "aaa"
        if any(kw in line_lower for kw in ["host-name", "domain-name", "time-zone", "domain-search"]):
            return "system"
        return "unknown"

    def _get_context(self, lines: List[str], idx: int, window: int = 2) -> List[str]:
        start = max(0, idx - window)
        end = min(len(lines), idx + window + 1)
        return [lines[i].strip() for i in range(start, end) if lines[i].strip()]

    def _post_process(self, config: NormalizedSecurityConfig):
        # Defaults
        if config.network.ssh_enabled is None:
            config.network.ssh_enabled = True
            config.network.ssh_version = 2
        if config.network.telnet_enabled is None:
            config.network.telnet_enabled = False
        if config.network.http_server_enabled is None:
            config.network.http_server_enabled = False
        if config.network.https_enabled is None:
            config.network.https_enabled = False
        if config.logging.logging_enabled is None:
            config.logging.logging_enabled = True
        if config.encryption.ntp_configured is None:
            config.encryption.ntp_configured = True
        if config.authentication.session_timeout is None:
            config.authentication.session_timeout = 0  # No default timeout in Junos unless configured


# Register the parser
from msme_auditor.config_parsers.base import register_parser
register_parser(JuniperParser())