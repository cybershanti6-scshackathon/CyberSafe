"""
Fortinet FortiOS Configuration Parser
======================================

Parses Fortinet FortiOS configurations into the NormalizedSecurityConfig schema.
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


class FortinetParser(BaseConfigParser):
    """Parser for Fortinet FortiOS configurations."""

    vendor_name = "fortinet"
    supported_os = ["FortiOS", "FortiGate"]
    version = "1.0.0"

    PATTERNS = {
        # Config version header
        "config_version": re.compile(r"^#config-version=(\S+)"),
        "conf_file_ver": re.compile(r"^#conf_file_ver=(\S+)"),
        "build_no": re.compile(r"^#buildno=(\d+)"),

        # System global
        "config_system_global": re.compile(r"^config\s+system\s+global"),
        "end": re.compile(r"^end\s*$"),
        "next": re.compile(r"^next\s*$"),

        # Hostname
        "hostname": re.compile(r"^set\s+hostname\s+(\S+)"),

        # Admin port settings
        "admin_port": re.compile(r"^set\s+admin-port\s+(\d+)"),
        "admin_sport": re.compile(r"^set\s+admin-sport\s+(\d+)"),
        "ssh_port": re.compile(r"^set\s+ssh-port\s+(\d+)"),
        "http_port": re.compile(r"^set\s+http-port\s+(\d+)"),
        "https_port": re.compile(r"^set\s+https-port\s+(\d+)"),

        # Strong crypto
        "strong_crypto": re.compile(r"^set\s+strong-crypto\s+(enable|disable)"),

        # Admin timeout (session timeout)
        "admin_timeout": re.compile(r"^set\s+admintimeout\s+(\d+)"),

        # Password policy
        "password_policy": re.compile(r"^config\s+system\s+password-policy"),
        "min_length": re.compile(r"^set\s+min-length\s+(\d+)"),
        "must_change": re.compile(r"^set\s+must-change\s+(enable|disable)"),
        "expire_days": re.compile(r"^set\s+expire\s+(\d+)"),
        "reuse_history": re.compile(r"^set\s+reuse-history\s+(\d+)"),
        "min_upper": re.compile(r"^set\s+min-upper-case-letter\s+(\d+)"),
        "min_lower": re.compile(r"^set\s+min-lower-case-letter\s+(\d+)"),
        "min_digit": re.compile(r"^set\s+min-digit\s+(\d+)"),
        "min_special": re.compile(r"^set\s+min-special-char\s+(\d+)"),
        "lockout_duration": re.compile(r"^set\s+lockout-duration\s+(\d+)"),
        "lockout_threshold": re.compile(r"^set\s+lockout-threshold\s+(\d+)"),

        # Admin user / SSH key
        "config_admin": re.compile(r"^config\s+system\s+admin"),
        "ssh_public_key": re.compile(r"^set\s+ssh-public-key\d*\s+"),

        # Trusted hosts (VTY access restriction)
        "trusted_hosts": re.compile(r"^set\s+trusthost\d+\s+(\S+)"),

        # Interface
        "config_interface": re.compile(r"^config\s+system\s+interface"),
        "interface_name": re.compile(r"^edit\s+(\S+)"),
        "interface_status": re.compile(r"^set\s+status\s+(up|down)"),
        "interface_ip": re.compile(r"^set\s+ip\s+(\S+)"),

        # Firewall policy
        "config_firewall_policy": re.compile(r"^config\s+firewall\s+policy"),

        # VPN SSL
        "config_vpn_ssl": re.compile(r"^config\s+vpn\s+ssl"),
        "ssl_enable": re.compile(r"^set\s+ssl\s+(enable|disable)"),

        # VPN IPsec
        "config_vpn_ipsec": re.compile(r"^config\s+vpn\s+ipsec"),

        # System DNS
        "config_dns": re.compile(r"^config\s+system\s+dns"),
        "dns_primary": re.compile(r"^set\s+primary\s+(\S+)"),
        "dns_secondary": re.compile(r"^set\s+secondary\s+(\S+)"),

        # System NTP
        "config_ntp": re.compile(r"^config\s+system\s+ntp"),
        "ntp_server": re.compile(r"^set\s+server\s+(\S+)"),
        "ntp_sync_interval": re.compile(r"^set\s+sync-interval\s+(\d+)"),

        # System SNMP
        "config_snmp": re.compile(r"^config\s+system\s+snmp"),
        "snmp_sysinfo": re.compile(r"^set\s+sysinfo\s+(enable|disable)"),
        "snmp_community": re.compile(r"^set\s+community\s+(\S+)"),
        "snmp_version": re.compile(r"^set\s+version\s+(v1|v2c|v3)"),

        # System SNMP community
        "config_snmp_community": re.compile(r"^config\s+system\s+snmp\s+community"),
        "community_name": re.compile(r"^edit\s+(\S+)"),
        "community_events": re.compile(r"^set\s+events\s+(\S+)"),
        "community_query_v1": re.compile(r"^set\s+query-v1-(enable|disable)"),
        "community_query_v2c": re.compile(r"^set\s+query-v2c-(enable|disable)"),
        "community_trap_v1": re.compile(r"^set\s+trap-v1-(enable|disable)"),
        "community_trap_v2c": re.compile(r"^set\s+trap-v2c-(enable|disable)"),

        # System SNMP sysinfo
        "config_snmp_sysinfo": re.compile(r"^config\s+system\s+snmp\s+sysinfo"),
        "snmp_contact": re.compile(r"^set\s+contact\s+(\S+)"),
        "snmp_location": re.compile(r"^set\s+location\s+(\S+)"),

        # System SNMP user (v3)
        "config_snmp_user": re.compile(r"^config\s+system\s+snmp\s+user"),

        # Log syslogd
        "config_log_syslogd": re.compile(r"^config\s+log\s+syslogd"),
        "log_syslogd_enable": re.compile(r"^set\s+status\s+(enable|disable)"),
        "log_syslogd_server": re.compile(r"^set\s+server\s+(\S+)"),
        "log_syslogd_port": re.compile(r"^set\s+port\s+(\d+)"),
        "log_syslogd_facility": re.compile(r"^set\s+facility\s+(\S+)"),

        # Log syslogd2/3/4
        "config_log_syslogd2": re.compile(r"^config\s+log\s+syslogd2"),
        "config_log_syslogd3": re.compile(r"^config\s+log\s+syslogd3"),
        "config_log_syslogd4": re.compile(r"^config\s+log\s+syslogd4"),

        # Log fortianalyzer
        "config_log_fortianalyzer": re.compile(r"^config\s+log\s+fortianalyzer"),

        # Log memory
        "config_log_memory": re.compile(r"^config\s+log\s+memory"),
        "log_memory_enable": re.compile(r"^set\s+status\s+(enable|disable)"),

        # Log disk
        "config_log_disk": re.compile(r"^config\s+log\s+disk"),

        # User local
        "config_user_local": re.compile(r"^config\s+user\s+local"),
        "user_password": re.compile(r"^set\s+password\s+(\S+)"),
        "user_ssh_key": re.compile(r"^set\s+ssh-public-key\s+"),

        # User radius
        "config_user_radius": re.compile(r"^config\s+user\s+radius"),

        # User ldap
        "config_user_ldap": re.compile(r"^config\s+user\s+ldap"),

        # User tacacs+
        "config_user_tacacs": re.compile(r"^config\s+user\s+tacacs\+"),

        # System accprofile (admin profiles)
        "config_accprofile": re.compile(r"^config\s+system\s+accprofile"),

        # System auto-update
        "config_autoupdate": re.compile(r"^config\s+system\s+auto-update"),

        # System central-management
        "config_central_mgmt": re.compile(r"^config\s+system\s+central-management"),

        # System fortiguard
        "config_fortiguard": re.compile(r"^config\s+system\s+fortiguard"),

        # Wireless controller
        "config_wireless": re.compile(r"^config\s+wireless-controller"),
    }

    def __init__(self):
        super().__init__()
        self._current_section = "global"
        self._in_password_policy = False
        self._in_admin = False
        self._in_interface = False
        self._in_syslogd = False
        self._in_snmp_community = False
        self._current_interface = None

    def parse(self, config_text: str, device_info: Optional[DeviceInfo] = None) -> ParseResult:
        self.reset()
        lines = config_text.splitlines()

        config = self._init_normalized_config(device_info)
        if config.device.vendor == "Unknown":
            config.device.vendor = "Fortinet"
        config.device.model = "FortiOS"

        # State tracking
        in_config_block = False
        current_config = None

        for i, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                if line.startswith("#config-version="):
                    m = self.PATTERNS["config_version"].search(line)
                    if m:
                        config.device.version = m.group(1)
                elif line.startswith("#conf_file_ver="):
                    pass  # Already captured by version
                elif line.startswith("#buildno="):
                    m = self.PATTERNS["build_no"].search(line)
                    if m:
                        config.device.version += f" build {m.group(1)}"
                continue

            # Track config blocks
            matched = self._try_patterns(line, i + 1, config, lines, i)

            # Track section context
            self._update_section(line)

            if not matched and line and not line.startswith("#"):
                self._unknown_configs.append(self._create_unknown(
                    raw_command=raw_line.strip(),
                    line_number=i + 1,
                    confidence=0.1,
                    possible_category=self._guess_category(line),
                    context_lines=self._get_context(lines, i),
                ))

        self._post_process(config)
        return self._finalize_result(config, len(lines))

    def _update_section(self, line: str):
        """Track current configuration section."""
        if line.startswith("config "):
            self._current_section = line
            if "password-policy" in line:
                self._in_password_policy = True
            elif "system admin" == line.split("config ")[-1]:
                self._in_admin = True
            elif "system interface" in line:
                self._in_interface = True
            elif "log syslogd" in line and "syslogd2" not in line and "syslogd3" not in line and "syslogd4" not in line:
                self._in_syslogd = True
            elif "snmp community" in line:
                self._in_snmp_community = True
        elif line == "end":
            self._in_password_policy = False
            self._in_admin = False
            self._in_interface = False
            self._in_syslogd = False
            self._in_snmp_community = False
            self._current_section = "global"
        elif line == "next":
            if self._in_interface:
                self._current_interface = None

    def _try_patterns(self, line: str, line_num: int, config: NormalizedSecurityConfig,
                      all_lines: List[str], line_idx: int) -> bool:
        matched = False
        raw_line = line

        # Version already handled in main loop

        # Hostname
        if m := self.PATTERNS["hostname"].search(line):
            config.device.hostname = m.group(1)
            matched = True

        # Admin ports (indicate services enabled)
        if self.PATTERNS["admin_sport"].search(line):
            self._set_with_evidence(config, "network", "https_enabled", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["ssh_port"].search(line):
            self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
            self._set_with_evidence(config, "network", "ssh_version", 2, raw_line, line_num)
            matched = True
        if self.PATTERNS["http_port"].search(line):
            self._set_with_evidence(config, "network", "http_server_enabled", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["https_port"].search(line):
            self._set_with_evidence(config, "network", "https_enabled", True, raw_line, line_num)
            matched = True

        # Strong crypto
        if m := self.PATTERNS["strong_crypto"].search(line):
            self._set_with_evidence(config, "encryption", "ssh_ciphers_strong", (m.group(1).lower() == "enable"), raw_line, line_num)
            matched = True

        # Admin timeout (session timeout)
        if m := self.PATTERNS["admin_timeout"].search(line):
            self._set_with_evidence(config, "authentication", "session_timeout", int(m.group(1)), raw_line, line_num)
            self._set_with_evidence(config, "access_control", "exec_timeout_configured", True, raw_line, line_num)
            matched = True

        # Password policy
        if self._in_password_policy:
            if m := self.PATTERNS["min_length"].search(line):
                self._set_with_evidence(config, "authentication", "password_min_length", int(m.group(1)), raw_line, line_num)
                matched = True
            if m := self.PATTERNS["expire_days"].search(line):
                self._set_with_evidence(config, "authentication", "password_expiry_days", int(m.group(1)), raw_line, line_num)
                matched = True
            if m := self.PATTERNS["reuse_history"].search(line):
                self._set_with_evidence(config, "authentication", "password_history_count", int(m.group(1)), raw_line, line_num)
                matched = True
            if m := self.PATTERNS["min_upper"].search(line):
                if int(m.group(1)) > 0:
                    self._set_with_evidence(config, "authentication", "password_complexity_enabled", True, raw_line, line_num)
                matched = True
            if m := self.PATTERNS["min_lower"].search(line):
                if int(m.group(1)) > 0:
                    self._set_with_evidence(config, "authentication", "password_complexity_enabled", True, raw_line, line_num)
                matched = True
            if m := self.PATTERNS["min_digit"].search(line):
                if int(m.group(1)) > 0:
                    self._set_with_evidence(config, "authentication", "password_complexity_enabled", True, raw_line, line_num)
                matched = True
            if m := self.PATTERNS["min_special"].search(line):
                if int(m.group(1)) > 0:
                    self._set_with_evidence(config, "authentication", "password_complexity_enabled", True, raw_line, line_num)
                matched = True
            if m := self.PATTERNS["lockout_threshold"].search(line):
                self._set_with_evidence(config, "authentication", "account_lockout_enabled", True, raw_line, line_num)
                self._set_with_evidence(config, "authentication", "account_lockout_threshold", int(m.group(1)), raw_line, line_num)
                matched = True
            if m := self.PATTERNS["lockout_duration"].search(line):
                # Lockout duration in seconds
                matched = True

        # Admin user - SSH public key indicates SSH key auth
        if self._in_admin:
            if self.PATTERNS["ssh_public_key"].search(line):
                config.network.ssh_enabled = True
                matched = True
            if m := self.PATTERNS["trusted_hosts"].search(line):
                config.access_control.vty_access_restricted = True
                matched = True

        # Interface status (for unused ports)
        if self._in_interface:
            if m := self.PATTERNS["interface_name"].search(line):
                self._current_interface = m.group(1)
                matched = True
            elif m := self.PATTERNS["interface_status"].search(line):
                if m.group(1).lower() == "down" and self._current_interface:
                    # Track shutdown interfaces
                    matched = True

        # NTP
        if m := self.PATTERNS["ntp_server"].search(line):
            self._set_with_evidence(config, "encryption", "ntp_configured", True, raw_line, line_num)
            matched = True

        # SNMP
        if self._in_snmp_community:
            if m := self.PATTERNS["community_name"].search(line):
                community = m.group(1).lower()
                config.network.snmp_enabled = True
                if community in ("public", "private", "fortinet"):
                    config.network.snmp_community_default = True
                matched = True

        # Syslog
        if self._in_syslogd:
            if m := self.PATTERNS["log_syslogd_enable"].search(line):
                if m.group(1).lower() == "enable":
                    self._set_with_evidence(config, "logging", "remote_syslog_enabled", True, raw_line, line_num)
                    self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
                matched = True
            if self.PATTERNS["log_syslogd_server"].search(line):
                self._set_with_evidence(config, "logging", "remote_syslog_enabled", True, raw_line, line_num)
                self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
                matched = True

        # User local (password set)
        if "config user local" in self._current_section:
            if self.PATTERNS["user_password"].search(line):
                config.access_control.enable_secret_configured = True
                matched = True
            if self.PATTERNS["user_ssh_key"].search(line):
                config.network.ssh_enabled = True
                matched = True

        # Recognize common section headers (don't mark as unknown)
        if line.startswith("config ") or line == "end" or line == "next" or line.startswith("edit "):
            matched = True

        return matched

    def _guess_category(self, line: str) -> Optional[str]:
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["timeout", "admintimeout"]):
            return "session_timeout"
        if any(kw in line_lower for kw in ["password", "passwd", "auth", "user", "admin"]):
            return "authentication"
        if any(kw in line_lower for kw in ["ssh", "ssl", "cert", "crypto", "key"]):
            return "network_encryption"
        if any(kw in line_lower for kw in ["log", "syslog", "fortianalyzer"]):
            return "logging"
        if any(kw in line_lower for kw in ["snmp", "community"]):
            return "snmp"
        if any(kw in line_lower for kw in ["ntp", "time", "dns"]):
            return "ntp"
        if any(kw in line_lower for kw in ["interface", "port", "vlan", "ip"]):
            return "network_interface"
        if any(kw in line_lower for kw in ["firewall", "policy", "address", "service"]):
            return "firewall"
        if any(kw in line_lower for kw in ["vpn", "ipsec", "ssl"]):
            return "vpn"
        if any(kw in line_lower for kw in ["wireless", "wifi", "ap", "ssid"]):
            return "wireless"
        return "unknown"

    def _get_context(self, lines: List[str], idx: int, window: int = 2) -> List[str]:
        start = max(0, idx - window)
        end = min(len(lines), idx + window + 1)
        return [lines[i].strip() for i in range(start, end) if lines[i].strip()]

    def _post_process(self, config: NormalizedSecurityConfig):
        # Defaults
        if config.network.ssh_enabled is None:
            config.network.ssh_enabled = True  # FortiOS typically has SSH enabled
            config.network.ssh_version = 2
        if config.network.telnet_enabled is None:
            config.network.telnet_enabled = False  # Telnet disabled by default in modern FortiOS
        if config.network.http_server_enabled is None:
            config.network.http_server_enabled = True
        if config.network.https_enabled is None:
            config.network.https_enabled = True
        if config.logging.logging_enabled is None:
            config.logging.logging_enabled = True
        if config.encryption.ntp_configured is None:
            config.encryption.ntp_configured = True
        if config.authentication.session_timeout is None:
            config.authentication.session_timeout = 300  # 5 min default


# Register the parser
from msme_auditor.config_parsers.base import register_parser
register_parser(FortinetParser())