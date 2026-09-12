"""
Cisco IOS Configuration Parser
===============================

Parses Cisco IOS, IOS-XE, NX-OS, and ASA configurations
into the NormalizedSecurityConfig schema.

Uses regex-based parsing (no external dependencies).
Supports:
- SSH / Telnet
- Password encryption
- Password policy (length, complexity)
- Session timeout (exec-timeout)
- Logging (syslog, timestamps, login logging)
- AAA, SNMP, NTP, CDP, etc.
"""

import re
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from msme_auditor.config_parsers.base import (
    BaseConfigParser,
    ParseResult,
    UnknownConfiguration,
    DeviceInfo,
    AuthenticationConfig,
    NetworkConfig,
    LoggingConfig,
    EncryptionConfig,
    AccessControlConfig,
    NormalizedSecurityConfig,
)


class CiscoParser(BaseConfigParser):
    """Parser for Cisco IOS/IOS-XE/NX-OS/ASA configurations."""

    vendor_name = "cisco"
    supported_os = ["IOS", "IOS-XE", "NX-OS", "ASA", "IOS-XR"]
    version = "1.0.0"

    # =========================================================================
    # Regex Patterns
    # =========================================================================

    PATTERNS = {
        # Device identification
        "version": re.compile(r"^version\s+([\d\.\(\)\w]+)", re.IGNORECASE),
        "hostname": re.compile(r"^hostname\s+(\S+)", re.IGNORECASE),
        "banner_motd": re.compile(r"^banner\s+motd\s+", re.IGNORECASE),
        "banner_login": re.compile(r"^banner\s+login\s+", re.IGNORECASE),

        # Authentication / Password
        "enable_secret": re.compile(r"^enable\s+secret\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),
        "enable_password": re.compile(r"^enable\s+password\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),
        "service_password_encryption": re.compile(r"^service\s+password-encryption", re.IGNORECASE),
        "username": re.compile(r"^username\s+(\S+)\s+privilege\s+(\d+)", re.IGNORECASE),
        "username_secret": re.compile(r"^username\s+\S+\s+secret\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),
        "username_password": re.compile(r"^username\s+\S+\s+password\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),
        "aaa_new_model": re.compile(r"^aaa\s+new-model", re.IGNORECASE),
        "aaa_authentication_login": re.compile(r"^aaa\s+authentication\s+login\s+", re.IGNORECASE),
        "aaa_authentication_enable": re.compile(r"^aaa\s+authentication\s+enable\s+", re.IGNORECASE),
        "aaa_authorization": re.compile(r"^aaa\s+authorization\s+", re.IGNORECASE),
        "aaa_accounting": re.compile(r"^aaa\s+accounting\s+", re.IGNORECASE),

        # Password policy (IOS-XE / newer)
        "security_passwords_min_length": re.compile(r"^security\s+passwords\s+min-length\s+(\d+)", re.IGNORECASE),
        "security_passwords_complexity": re.compile(r"^security\s+passwords\s+complexity", re.IGNORECASE),
        "security_passwords_history": re.compile(r"^security\s+passwords\s+history\s+(\d+)", re.IGNORECASE),
        "security_passwords_aging": re.compile(r"^security\s+passwords\s+aging\s+(\d+)", re.IGNORECASE),
        "security_passwords_lockout": re.compile(r"^security\s+passwords\s+lockout\s+(\d+)", re.IGNORECASE),

        # TACACS+ / RADIUS
        "tacacs_server": re.compile(r"^tacacs-server\s+host\s+(\S+)", re.IGNORECASE),
        "tacacs_key": re.compile(r"^tacacs-server\s+key\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),
        "radius_server": re.compile(r"^radius-server\s+host\s+(\S+)", re.IGNORECASE),
        "radius_key": re.compile(r"^radius-server\s+key\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),

        # ACL / Access Control
        "ip_access_list_standard": re.compile(r"^ip\s+access-list\s+standard\s+(\S+)", re.IGNORECASE),
        "ip_access_list_extended": re.compile(r"^ip\s+access-list\s+extended\s+(\S+)", re.IGNORECASE),
        "access_list_deny": re.compile(r"^\s*(deny|permit)\s+", re.IGNORECASE),

        # Switchport Security (IOS)
        "switchport_mode_access": re.compile(r"^switchport\s+mode\s+access", re.IGNORECASE),
        "switchport_portsecurity": re.compile(r"^switchport\s+port-security", re.IGNORECASE),
        "switchport_portsecurity_max": re.compile(r"^switchport\s+port-security\s+maximum\s+(\d+)", re.IGNORECASE),
        "switchport_portsecurity_violation": re.compile(r"^switchport\s+port-security\s+violation\s+(\S+)", re.IGNORECASE),
        "switchport_portsecurity_mac": re.compile(r"^switchport\s+port-security\s+mac-address\s+(\S+)", re.IGNORECASE),

        # VLAN Security
        "vlan_name": re.compile(r"^vlan\s+(\d+)", re.IGNORECASE),
        "native_vlan": re.compile(r"^switchport\s+trunk\s+native\s+vlan\s+(\d+)", re.IGNORECASE),
        "allowed_vlan": re.compile(r"^switchport\s+trunk\s+allowed\s+vlan\s+(\S+)", re.IGNORECASE),

        # IPSEC / VPN
        "crypto_isakmp": re.compile(r"^crypto\s+isakmp\s+", re.IGNORECASE),
        "crypto_ipsec": re.compile(r"^crypto\s+ipsec\s+", re.IGNORECASE),
        "crypto_map": re.compile(r"^crypto\s+map\s+", re.IGNORECASE),

        # NTP Authentication
        "ntp_authentication": re.compile(r"^ntp\s+authentication-key\s+", re.IGNORECASE),
        "ntp_trusted_key": re.compile(r"^ntp\s+trusted-key\s+", re.IGNORECASE),

        # SNMPv3
        "snmpv3_user": re.compile(r"^snmp-server\s+group\s+", re.IGNORECASE),
        "snmpv3_auth": re.compile(r"^snmp-server\s+user\s+", re.IGNORECASE),

        # Line configuration (console, vty, aux)
        "line_console": re.compile(r"^line\s+console\s+(\d+)", re.IGNORECASE),
        "line_vty": re.compile(r"^line\s+vty\s+(\d+)\s+(\d+)", re.IGNORECASE),
        "line_aux": re.compile(r"^line\s+aux\s+(\d+)", re.IGNORECASE),
        "exec_timeout": re.compile(r"^exec-timeout\s+(\d+)\s+(\d+)", re.IGNORECASE),
        "login": re.compile(r"^login\s+(local|tacacs|radius)?", re.IGNORECASE),
        "transport_input": re.compile(r"^transport\s+input\s+(\S+)", re.IGNORECASE),
        "transport_output": re.compile(r"^transport\s+output\s+(\S+)", re.IGNORECASE),
        "password_line": re.compile(r"^password\s+(?:[\d]+\s+)?(\S+)", re.IGNORECASE),

        # SSH
        "ip_ssh_version": re.compile(r"^ip\s+ssh\s+version\s+(\d+)", re.IGNORECASE),
        "ip_ssh_timeout": re.compile(r"^ip\s+ssh\s+timeout\s+(\d+)", re.IGNORECASE),
        "ip_ssh_auth_retries": re.compile(r"^ip\s+ssh\s+authentication-retries\s+(\d+)", re.IGNORECASE),
        "ip_ssh_rsa_keypair": re.compile(r"^ip\s+ssh\s+rsa\s+keypair-name\s+(\S+)", re.IGNORECASE),
        "ip_ssh_pubkey_chain": re.compile(r"^ip\s+ssh\s+pubkey-chain", re.IGNORECASE),
        "crypto_key_generate_rsa": re.compile(r"^crypto\s+key\s+generate\s+rsa", re.IGNORECASE),

        # Telnet (disable check)
        "no_ip_telnet": re.compile(r"^no\s+ip\s+telnet\s+server", re.IGNORECASE),
        "ip_telnet_server": re.compile(r"^ip\s+telnet\s+server", re.IGNORECASE),

        # Logging
        "logging_on": re.compile(r"^logging\s+on", re.IGNORECASE),
        "logging_host": re.compile(r"^logging\s+host\s+(\S+)", re.IGNORECASE),
        "logging_trap": re.compile(r"^logging\s+trap\s+(\w+)", re.IGNORECASE),
        "logging_buffered": re.compile(r"^logging\s+buffered\s+(\d+)?", re.IGNORECASE),
        "logging_console": re.compile(r"^logging\s+console\s+(\w+)?", re.IGNORECASE),
        "logging_timestamp": re.compile(r"^service\s+timestamps\s+(log|debug)\s+datetime", re.IGNORECASE),
        "logging_source_interface": re.compile(r"^logging\s+source-interface\s+(\S+)", re.IGNORECASE),
        "logging_facility": re.compile(r"^logging\s+facility\s+(\w+)", re.IGNORECASE),

        # Login logging
        "login_on_success": re.compile(r"^login\s+on-success\s+log", re.IGNORECASE),
        "login_on_failure": re.compile(r"^login\s+on-failure\s+log", re.IGNORECASE),

        # NTP
        "ntp_server": re.compile(r"^ntp\s+server\s+(\S+)", re.IGNORECASE),
        "ntp_peer": re.compile(r"^ntp\s+peer\s+(\S+)", re.IGNORECASE),
        "ntp_master": re.compile(r"^ntp\s+master\s+(\d+)?", re.IGNORECASE),
        "ntp_source": re.compile(r"^ntp\s+source\s+(\S+)", re.IGNORECASE),

        # SNMP
        "snmp_server_community": re.compile(r"^snmp-server\s+community\s+(\S+)\s+(RO|RW)", re.IGNORECASE),
        "snmp_server_host": re.compile(r"^snmp-server\s+host\s+(\S+)", re.IGNORECASE),
        "snmp_server_contact": re.compile(r"^snmp-server\s+contact\s+(\S+)", re.IGNORECASE),
        "snmp_server_location": re.compile(r"^snmp-server\s+location\s+(\S+)", re.IGNORECASE),
        "snmp_server_enable_traps": re.compile(r"^snmp-server\s+enable\s+traps", re.IGNORECASE),

        # CDP / LLDP
        "cdp_run": re.compile(r"^cdp\s+run", re.IGNORECASE),
        "no_cdp_run": re.compile(r"^no\s+cdp\s+run", re.IGNORECASE),
        "lldp_run": re.compile(r"^lldp\s+run", re.IGNORECASE),

        # HTTP/HTTPS server
        "ip_http_server": re.compile(r"^ip\s+http\s+server", re.IGNORECASE),
        "ip_http_secure_server": re.compile(r"^ip\s+http\s+secure-server", re.IGNORECASE),
        "ip_http_authentication": re.compile(r"^ip\s+http\s+authentication\s+(\w+)", re.IGNORECASE),

        # Source routing / Proxy ARP
        "no_ip_source_route": re.compile(r"^no\s+ip\s+source-route", re.IGNORECASE),
        "no_ip_proxy_arp": re.compile(r"^no\s+ip\s+proxy-arp", re.IGNORECASE),

        # Banner
        "banner_login_present": re.compile(r"^banner\s+login", re.IGNORECASE),
        "banner_motd_present": re.compile(r"^banner\s+motd", re.IGNORECASE),

        # Interface config (for unused ports detection)
        "interface": re.compile(r"^interface\s+(\S+)", re.IGNORECASE),
        "shutdown": re.compile(r"^shutdown", re.IGNORECASE),
        "no_shutdown": re.compile(r"^no\s+shutdown", re.IGNORECASE),

        # VTY access restriction (ACL)
        "access_class": re.compile(r"^access-class\s+(\S+)\s+(in|out)", re.IGNORECASE),
        "ip_access_group": re.compile(r"^ip\s+access-group\s+(\S+)\s+(in|out)", re.IGNORECASE),

        # Domain name / Crypto
        "ip_domain_name": re.compile(r"^ip\s+domain-name\s+(\S+)", re.IGNORECASE),
        "crypto_key": re.compile(r"^crypto\s+key\s+generate\s+rsa", re.IGNORECASE),
    }

    def __init__(self):
        super().__init__()
        self._current_section = "global"
        self._current_interface = None
        self._in_line_config = False
        self._line_type = None  # console, vty, aux

    def parse(self, config_text: str, device_info: Optional[DeviceInfo] = None) -> ParseResult:
        """Parse Cisco configuration text."""
        self.reset()
        lines = config_text.splitlines()

        # Initialize normalized config
        config = self._init_normalized_config(device_info)
        if config.device.vendor == "Unknown":
            config.device.vendor = "Cisco"
        config.device.model = "IOS"  # Default, updated if detected

        # Parse line by line
        for i, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line or line.startswith("!") or line.startswith("#"):
                # Track comments/banners but don't parse
                if line.startswith("!") and "version" in line.lower():
                    m = self.PATTERNS["version"].search(line)
                    if m:
                        config.device.version = m.group(1)
                continue

            # Detect section context
            self._detect_section(line)

            # Try each pattern
            matched = self._try_patterns(line, i + 1, config, lines, i)

            if not matched and line:
                # Track as unknown
                self._unknown_configs.append(self._create_unknown(
                    raw_command=raw_line.strip(),
                    line_number=i + 1,
                    confidence=0.1,
                    possible_category=self._guess_category(line),
                    context_lines=self._get_context(lines, i),
                ))

        # Post-process: infer implicit settings
        self._post_process(config)

        return self._finalize_result(config, len(lines))

    def _detect_section(self, line: str):
        """Track current configuration section."""
        if line.startswith("line "):
            self._in_line_config = True
            if "console" in line:
                self._line_type = "console"
            elif "vty" in line:
                self._line_type = "vty"
            elif "aux" in line:
                self._line_type = "aux"
        elif line.startswith("interface "):
            self._current_section = "interface"
            self._in_line_config = False
        elif line == "exit" or line == "end":
            if self._in_line_config:
                self._in_line_config = False
                self._line_type = None
            elif self._current_section == "interface":
                self._current_section = "global"
        elif line.startswith("banner "):
            self._current_section = "banner"

    def _try_patterns(self, line: str, line_num: int, config: NormalizedSecurityConfig,
                      all_lines: List[str], line_idx: int) -> bool:
        """Try all regex patterns against a line. Returns True if matched."""
        matched = False
        raw_line = line  # Keep original for evidence

        # Device info
        if m := self.PATTERNS["version"].search(line):
            config.device.version = m.group(1)
            # Detect OS from version string
            ver = m.group(1).lower()
            if "nx-os" in ver or "nxos" in ver:
                config.device.model = "NX-OS"
            elif "asa" in ver:
                config.device.model = "ASA"
            elif "xr" in ver:
                config.device.model = "IOS-XR"
            elif "xe" in ver or "ios-xe" in ver:
                config.device.model = "IOS-XE"
            else:
                config.device.model = "IOS"
            matched = True

        if m := self.PATTERNS["hostname"].search(line):
            config.device.hostname = m.group(1)
            matched = True

        # Username commands (various formats)
        if self.PATTERNS["username"].search(line):
            matched = True
        if self.PATTERNS["username_secret"].search(line):
            matched = True
        if self.PATTERNS["username_password"].search(line):
            matched = True

        # AAA authentication / authorization / accounting
        if self.PATTERNS["aaa_authentication_login"].search(line):
            matched = True
        if self.PATTERNS["aaa_authentication_enable"].search(line):
            matched = True

        # TACACS+ / RADIUS (already handled in main pattern block)

        # ACL commands
        if self.PATTERNS["ip_access_list_standard"].search(line) or self.PATTERNS["ip_access_list_extended"].search(line):
            matched = True

        # Switchport commands
        if self.PATTERNS["switchport_mode_access"].search(line):
            matched = True
        if self.PATTERNS["switchport_portsecurity"].search(line):
            matched = True
        if self.PATTERNS["switchport_portsecurity_max"].search(line):
            matched = True
        if self.PATTERNS["switchport_portsecurity_violation"].search(line):
            matched = True
        if self.PATTERNS["switchport_portsecurity_mac"].search(line):
            matched = True

        # VLAN commands
        if self.PATTERNS["vlan_name"].search(line):
            matched = True
        if self.PATTERNS["native_vlan"].search(line):
            matched = True
        if self.PATTERNS["allowed_vlan"].search(line):
            matched = True

        # Crypto / VPN
        if self.PATTERNS["crypto_isakmp"].search(line):
            matched = True
        if self.PATTERNS["crypto_ipsec"].search(line):
            matched = True
        if self.PATTERNS["crypto_map"].search(line):
            matched = True

        # NTP authentication
        if self.PATTERNS["ntp_authentication"].search(line):
            matched = True
        if self.PATTERNS["ntp_trusted_key"].search(line):
            matched = True

        # SNMPv3
        if self.PATTERNS["snmpv3_user"].search(line):
            matched = True
        if self.PATTERNS["snmpv3_auth"].search(line):
            matched = True

        # Password encryption
        if self.PATTERNS["service_password_encryption"].search(line):
            self._set_with_evidence(config, "authentication", "password_encryption_enabled", True, raw_line, line_num)
            matched = True

        # Enable secret/password
        if self.PATTERNS["enable_secret"].search(line):
            self._set_with_evidence(config, "access_control", "enable_secret_configured", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["enable_password"].search(line) and not config.access_control.enable_secret_configured:
            self._set_with_evidence(config, "access_control", "enable_secret_configured", True, raw_line, line_num)
            matched = True

        # AAA
        if self.PATTERNS["aaa_new_model"].search(line):
            config.encryption.aaa_enabled = True
            matched = True

        # Password policy (modern IOS-XE)
        if m := self.PATTERNS["security_passwords_min_length"].search(line):
            self._set_with_evidence(config, "authentication", "password_min_length", int(m.group(1)), raw_line, line_num)
            matched = True

        if self.PATTERNS["security_passwords_complexity"].search(line):
            self._set_with_evidence(config, "authentication", "password_complexity_enabled", True, raw_line, line_num)
            matched = True

        if m := self.PATTERNS["security_passwords_history"].search(line):
            self._set_with_evidence(config, "authentication", "password_history_count", int(m.group(1)), raw_line, line_num)
            matched = True

        if m := self.PATTERNS["security_passwords_aging"].search(line):
            self._set_with_evidence(config, "authentication", "password_expiry_days", int(m.group(1)), raw_line, line_num)
            matched = True

        if m := self.PATTERNS["security_passwords_lockout"].search(line):
            self._set_with_evidence(config, "authentication", "account_lockout_enabled", True, raw_line, line_num)
            self._set_with_evidence(config, "authentication", "account_lockout_threshold", int(m.group(1)), raw_line, line_num)
            matched = True

        # SSH
        if m := self.PATTERNS["ip_ssh_version"].search(line):
            self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
            self._set_with_evidence(config, "network", "ssh_version", int(m.group(1)), raw_line, line_num)
            matched = True

        if self.PATTERNS["ip_ssh_timeout"].search(line) or self.PATTERNS["ip_ssh_auth_retries"].search(line):
            self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["crypto_key_generate_rsa"].search(line) or self.PATTERNS["ip_ssh_rsa_keypair"].search(line):
            self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
            matched = True

        # Telnet
        if self.PATTERNS["no_ip_telnet"].search(line):
            self._set_with_evidence(config, "network", "telnet_enabled", False, raw_line, line_num)
            matched = True
        elif self.PATTERNS["ip_telnet_server"].search(line):
            self._set_with_evidence(config, "network", "telnet_enabled", True, raw_line, line_num)
            matched = True

        # Line config (console/vty/aux) - session timeout, transport
        if self._in_line_config:
            if m := self.PATTERNS["exec_timeout"].search(line):
                minutes = int(m.group(1))
                seconds = int(m.group(2))
                total_seconds = minutes * 60 + seconds
                self._set_with_evidence(config, "authentication", "session_timeout", total_seconds, raw_line, line_num)
                self._set_with_evidence(config, "access_control", "exec_timeout_configured", True, raw_line, line_num)
                matched = True

            if m := self.PATTERNS["transport_input"].search(line):
                transports = m.group(1).lower()
                if "ssh" in transports:
                    self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
                if "telnet" in transports:
                    self._set_with_evidence(config, "network", "telnet_enabled", True, raw_line, line_num)
                if "none" in transports:
                    self._set_with_evidence(config, "network", "telnet_enabled", False, raw_line, line_num)
                    self._set_with_evidence(config, "network", "ssh_enabled", False, raw_line, line_num)
                matched = True

            if self.PATTERNS["login"].search(line):
                # Login required on this line
                matched = True

            if self.PATTERNS["access_class"].search(line) or self.PATTERNS["ip_access_group"].search(line):
                config.access_control.vty_access_restricted = True
                matched = True

        # Explicitly recognize section headers (don't mark as unknown)
        if line.startswith("line ") or line.startswith("interface ") or line == "end" or line.startswith("banner "):
            matched = True

        # Additional common commands that should be recognized
        if line.startswith("description "):
            matched = True
        if line.startswith("ip address ") or line.startswith("no ip address"):
            matched = True
        if line.startswith("ip route "):
            matched = True
        if line.startswith("router "):
            matched = True
        if line.startswith("network "):
            matched = True
        if line.startswith("passive-interface "):
            matched = True
        if line.startswith("redistribute "):
            matched = True
        if line.startswith("default-information "):
            matched = True
        if line.startswith("neighbor "):
            matched = True
        if line.startswith("address-family "):
            matched = True
        if line.startswith("vlan "):
            matched = True
        if line.startswith("name-server "):
            matched = True
        if line.startswith("ip name-server "):
            matched = True
        if line.startswith("domain lookup"):
            matched = True
        if line.startswith("no ip domain-lookup"):
            matched = True
        if line.startswith("ip domain lookup"):
            matched = True
        if line.startswith("clock "):
            matched = True
        if line.startswith("alias "):
            matched = True
        if line.startswith("macro "):
            matched = True
        if line.startswith("spanning-tree "):
            matched = True
        if line.startswith("dot1x "):
            matched = True
        if line.startswith("authentication "):
            matched = True
        if line.startswith("ip arp "):
            matched = True
        if line.startswith("icmp "):
            matched = True
        if line.startswith("track "):
            matched = True
        if line.startswith("event "):
            matched = True
        if line.startswith("timer "):
            matched = True
        # SSH timeout
        if line.startswith("ip ssh time-out "):
            self._set_with_evidence(config, "network", "ssh_enabled", True, raw_line, line_num)
            matched = True
        # Logging trap level
        if line.startswith("logging trap "):
            self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            matched = True
        # Logging source-interface
        if line.startswith("logging source-interface "):
            self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            matched = True
        # SNMP contact/location/traps
        if line.startswith("snmp-server contact ") or line.startswith("snmp-server location "):
            self._set_with_evidence(config, "network", "snmp_enabled", True, raw_line, line_num)
            matched = True
        if line.startswith("snmp-server enable traps"):
            self._set_with_evidence(config, "network", "snmp_enabled", True, raw_line, line_num)
            matched = True
        # HTTP authentication
        if line.startswith("ip http authentication "):
            matched = True
        # Interface commands
        if line == "shutdown" or line == "no shutdown":
            matched = True
        if line == "no ip address":
            matched = True
        # ACL permit/deny rules
        if line.startswith("permit ") or line.startswith("deny "):
            matched = True
        # Banner content lines (between delimiters)
        if line.startswith("^") and len(line) <= 3:
            matched = True
        # Interface description and other interface commands
        if self._current_section == "interface" or (line_idx > 0 and any(all_lines[j].strip().startswith("interface ") for j in range(max(0, line_idx-5), line_idx))):
            if line.startswith("ip address ") or line.startswith("no ip address"):
                matched = True
            if line == "shutdown" or line == "no shutdown":
                matched = True
            if line.startswith("description "):
                matched = True

        # Logging
        if self.PATTERNS["logging_on"].search(line):
            self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            matched = True

        if m := self.PATTERNS["logging_host"].search(line):
            self._set_with_evidence(config, "logging", "remote_syslog_enabled", True, raw_line, line_num)
            self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["logging_buffered"].search(line):
            self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["logging_timestamp"].search(line):
            self._set_with_evidence(config, "logging", "log_timestamps_enabled", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["login_on_success"].search(line) or self.PATTERNS["login_on_failure"].search(line):
            self._set_with_evidence(config, "logging", "login_logging_enabled", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["logging_console"].search(line):
            self._set_with_evidence(config, "logging", "logging_enabled", True, raw_line, line_num)
            matched = True

        # NTP
        if self.PATTERNS["ntp_server"].search(line) or self.PATTERNS["ntp_peer"].search(line) or self.PATTERNS["ntp_master"].search(line):
            self._set_with_evidence(config, "encryption", "ntp_configured", True, raw_line, line_num)
            matched = True

        # SNMP
        if m := self.PATTERNS["snmp_server_community"].search(line):
            self._set_with_evidence(config, "network", "snmp_enabled", True, raw_line, line_num)
            community = m.group(1).lower()
            if community in ("public", "private", "cisco"):
                self._set_with_evidence(config, "network", "snmp_community_default", True, raw_line, line_num)
            matched = True

        if self.PATTERNS["snmp_server_host"].search(line):
            self._set_with_evidence(config, "network", "snmp_enabled", True, raw_line, line_num)
            matched = True

        # CDP
        if self.PATTERNS["no_cdp_run"].search(line):
            config.network.cdp_disabled = True
            matched = True
        elif self.PATTERNS["cdp_run"].search(line):
            config.network.cdp_disabled = False
            matched = True

        if self.PATTERNS["lldp_run"].search(line):
            # LLDP is similar to CDP
            matched = True

        # HTTP/HTTPS
        if self.PATTERNS["ip_http_server"].search(line):
            self._set_with_evidence(config, "network", "http_server_enabled", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["ip_http_secure_server"].search(line):
            self._set_with_evidence(config, "network", "https_enabled", True, raw_line, line_num)
            matched = True

        # Source routing / Proxy ARP
        if self.PATTERNS["no_ip_source_route"].search(line):
            self._set_with_evidence(config, "network", "source_routing_disabled", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["no_ip_proxy_arp"].search(line):
            self._set_with_evidence(config, "network", "proxy_arp_disabled", True, raw_line, line_num)
            matched = True

        # Banner
        if self.PATTERNS["banner_login_present"].search(line) or self.PATTERNS["banner_motd_present"].search(line):
            self._set_with_evidence(config, "access_control", "banner_configured", True, raw_line, line_num)
            matched = True

        # TACACS+ / RADIUS
        if self.PATTERNS["tacacs_server"].search(line) or self.PATTERNS["tacacs_key"].search(line):
            self._set_with_evidence(config, "network", "tacacs_configured", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["radius_server"].search(line) or self.PATTERNS["radius_key"].search(line):
            self._set_with_evidence(config, "network", "radius_configured", True, raw_line, line_num)
            matched = True

        # AAA Authorization / Accounting
        if self.PATTERNS["aaa_authorization"].search(line):
            self._set_with_evidence(config, "network", "aaa_authorization_enabled", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["aaa_accounting"].search(line):
            self._set_with_evidence(config, "logging", "aaa_accounting_enabled", True, raw_line, line_num)
            matched = True

        # ACLs
        if self.PATTERNS["ip_access_list_standard"].search(line) or self.PATTERNS["ip_access_list_extended"].search(line):
            self._set_with_evidence(config, "network", "acl_configured", True, raw_line, line_num)
            matched = True

        # Switchport Security
        if self.PATTERNS["switchport_mode_access"].search(line):
            self._set_with_evidence(config, "network", "switchport_access_mode", True, raw_line, line_num)
            matched = True
        if self.PATTERNS["switchport_portsecurity"].search(line):
            self._set_with_evidence(config, "network", "port_security_enabled", True, raw_line, line_num)
            matched = True
        if m := self.PATTERNS["switchport_portsecurity_max"].search(line):
            self._set_with_evidence(config, "network", "port_security_max_mac", int(m.group(1)), raw_line, line_num)
            matched = True
        if m := self.PATTERNS["switchport_portsecurity_violation"].search(line):
            violation = m.group(1).lower()
            self._set_with_evidence(config, "network", "port_security_violation", violation, raw_line, line_num)
            matched = True

        # VLAN Security
        if m := self.PATTERNS["native_vlan"].search(line):
            vlan = int(m.group(1))
            is_default = vlan == 1
            self._set_with_evidence(config, "network", "native_vlan", vlan, raw_line, line_num)
            self._set_with_evidence(config, "network", "native_vlan_default", is_default, raw_line, line_num)
            matched = True

        # IPSEC / VPN
        if self.PATTERNS["crypto_isakmp"].search(line) or self.PATTERNS["crypto_ipsec"].search(line):
            self._set_with_evidence(config, "network", "ipsec_configured", True, raw_line, line_num)
            matched = True

        # NTP Authentication
        if self.PATTERNS["ntp_authentication"].search(line) or self.PATTERNS["ntp_trusted_key"].search(line):
            self._set_with_evidence(config, "encryption", "ntp_auth_enabled", True, raw_line, line_num)
            matched = True

        # SNMPv3 (more secure than community strings)
        if self.PATTERNS["snmpv3_user"].search(line) or self.PATTERNS["snmpv3_auth"].search(line):
            self._set_with_evidence(config, "network", "snmpv3_configured", True, raw_line, line_num)
            matched = True

        # Unused ports (interface shutdown)
        # We track interfaces in _post_process

        return matched

    def _guess_category(self, line: str) -> Optional[str]:
        """Guess the category of an unknown command."""
        line_lower = line.lower()
        if any(kw in line_lower for kw in ["timeout", "session", "idle"]):
            return "session_timeout"
        if any(kw in line_lower for kw in ["password", "secret", "auth", "login", "username", "aaa"]):
            return "authentication"
        if any(kw in line_lower for kw in ["ssh", "telnet", "transport", "crypto", "key"]):
            return "network_encryption"
        if any(kw in line_lower for kw in ["logging", "syslog", "log", "trap"]):
            return "logging"
        if any(kw in line_lower for kw in ["snmp", "community"]):
            return "snmp"
        if any(kw in line_lower for kw in ["ntp", "time", "clock"]):
            return "ntp"
        if any(kw in line_lower for kw in ["interface", "vlan", "switchport", "port"]):
            return "network_interface"
        if any(kw in line_lower for kw in ["access-list", "access-group", "acl", "policy"]):
            return "access_control"
        if any(kw in line_lower for kw in ["banner", "motd"]):
            return "banner"
        if any(kw in line_lower for kw in ["cdp", "lldp"]):
            return "discovery_protocol"
        if any(kw in line_lower for kw in ["http", "https", "web"]):
            return "management"
        if any(kw in line_lower for kw in ["source-route", "proxy-arp", "directed-broadcast"]):
            return "network_security"
        return "unknown"

    def _get_context(self, lines: List[str], idx: int, window: int = 2) -> List[str]:
        """Get surrounding lines for context."""
        start = max(0, idx - window)
        end = min(len(lines), idx + window + 1)
        return [lines[i].strip() for i in range(start, end) if lines[i].strip()]

    def _post_process(self, config: NormalizedSecurityConfig):
        """Infer implicit settings after parsing all lines."""
        # If SSH version not explicitly set but SSH commands present, assume v2
        if config.network.ssh_enabled and not config.network.ssh_version:
            config.network.ssh_version = 2

        # If no explicit telnet config but transport input on vty includes telnet, it's enabled
        # (handled in transport_input pattern)

        # If no exec-timeout set but line config exists, check default (10 min)
        # Cisco default is 10 minutes 0 seconds
        if not config.access_control.exec_timeout_configured and config.authentication.session_timeout is None:
            # Default Cisco exec-timeout is 10 min
            config.authentication.session_timeout = 600

        # If enable_secret not set but enable_password is, it's still "configured" but weak
        # (handled in patterns)

        # Default: CDP runs unless explicitly disabled
        if config.network.cdp_disabled is None:
            config.network.cdp_disabled = False

        # Default: source routing enabled unless disabled
        if config.network.source_routing_disabled is None:
            config.network.source_routing_disabled = False

        # Default: proxy ARP enabled unless disabled
        if config.network.proxy_arp_disabled is None:
            config.network.proxy_arp_disabled = False

        # HTTP server default is off
        if config.network.http_server_enabled is None:
            config.network.http_server_enabled = False
        if config.network.https_enabled is None:
            config.network.https_enabled = False

        # Login logging default off
        if config.logging.login_logging_enabled is None:
            config.logging.login_logging_enabled = False

        # Timestamps default off
        if config.logging.log_timestamps_enabled is None:
            config.logging.log_timestamps_enabled = False


# Register the parser
from msme_auditor.config_parsers.base import register_parser
register_parser(CiscoParser())