"""
Vendor-neutral network config converter.

Parses Cisco IOS XE / Juniper Junos / FortiOS configuration text into a
shared normalized structure, then re-emits it in the target vendor's syntax.

FULL CONVERSION SUPPORT:
- Interface mapping (physical, VLAN SVIs → irb, switchport configs)
- Routing (static routes, OSPF)
- ACLs → Junos firewall filters
- NAT → Junos security nat
- QoS → Junos class-of-service
- System-level config (SSH, NTP, syslog, TACACS/AAA)
- Pre-output validation/lint pass
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Normalized model
# --------------------------------------------------------------------------

@dataclass
class NormInterface:
    """Normalized interface representation."""
    index: str
    description: Optional[str] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    enabled: bool = False
    is_vlan_svi: bool = False  # True for interface VlanX
    vlan_id: Optional[int] = None  # For VLAN SVIs
    switchport_mode: Optional[str] = None  # 'access', 'trunk', or None
    access_vlan: Optional[int] = None
    trunk_allowed_vlans: Optional[str] = None
    trunk_native_vlan: Optional[int] = None
    nat_inside: bool = False
    nat_outside: bool = False
    acl_in: Optional[str] = None
    acl_out: Optional[str] = None
    qos_policy_out: Optional[str] = None


@dataclass
class NormVlan:
    """Normalized VLAN representation."""
    id: str
    name: Optional[str] = None
    l3_interface: Optional[str] = None  # irb.X for Junos


@dataclass
class NormStaticRoute:
    """Normalized static route."""
    prefix: str
    mask: str
    next_hop: str
    interface: Optional[str] = None


@dataclass
class NormOspfNetwork:
    """Normalized OSPF network statement."""
    network: str
    wildcard: str
    area: str


@dataclass
class NormOspfConfig:
    """Normalized OSPF configuration."""
    process_id: str
    router_id: Optional[str] = None
    networks: list = field(default_factory=list)


@dataclass
class NormAclRule:
    """Normalized ACL rule."""
    action: str  # permit, deny
    protocol: str
    source: str
    dest: str
    source_wildcard: Optional[str] = None
    dest_wildcard: Optional[str] = None
    dest_port: Optional[str] = None
    log: bool = False


@dataclass
class NormAcl:
    """Normalized ACL."""
    name: str
    type: str  # 'standard' or 'extended'
    rules: list = field(default_factory=list)


@dataclass
class NormNatPool:
    """Normalized NAT pool."""
    name: str
    start_ip: str
    end_ip: str
    netmask: str


@dataclass
class NormNatRule:
    """Normalized NAT rule."""
    acl_name: str
    pool_name: Optional[str] = None
    interface: Optional[str] = None
    overload: bool = False


@dataclass
class NormQosClassMap:
    """Normalized QoS class-map."""
    name: str
    match_type: str  # 'match-all', 'match-any'
    match_criteria: list = field(default_factory=list)  # list of (type, value)


@dataclass
class NormQosPolicyMap:
    """Normalized QoS policy-map."""
    name: str
    classes: list = field(default_factory=list)  # list of (class_name, actions)


@dataclass
class NormSysConfig:
    """Normalized system configuration."""
    ssh_enabled: bool = False
    ssh_version: int = 2
    ssh_timeout: Optional[int] = None
    ssh_retries: Optional[int] = None
    telnet_enabled: bool = False
    ntp_servers: list = field(default_factory=list)
    syslog_hosts: list = field(default_factory=list)
    syslog_level: Optional[str] = None
    syslog_buffered_size: Optional[int] = None
    syslog_source_interface: Optional[str] = None
    tacacs_servers: list = field(default_factory=list)
    tacacs_key: Optional[str] = None
    aaa_auth_login: Optional[str] = None
    aaa_auth_exec: Optional[str] = None
    domain_name: Optional[str] = None
    hostname: Optional[str] = None


@dataclass
class NormConfig:
    """Fully normalized configuration."""
    hostname: Optional[str] = None
    interfaces: list = field(default_factory=list)
    vlans: list = field(default_factory=list)
    static_routes: list = field(default_factory=list)
    ospf_config: Optional[NormOspfConfig] = None
    acls: list = field(default_factory=list)
    nat_pools: list = field(default_factory=list)
    nat_rules: list = field(default_factory=list)
    qos_class_maps: list = field(default_factory=list)
    qos_policy_maps: list = field(default_factory=list)
    sys_config: NormSysConfig = field(default_factory=NormSysConfig)
    flagged: list = field(default_factory=list)
    # Lines from the input that did not match any parser rule (dropped/unrecognized)
    skipped_lines: list = field(default_factory=list)
    # Parser-generated review notes (security warnings, semantic issues)
    review_notes: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Utility mappings
# --------------------------------------------------------------------------

CIDR_TO_MASK = {
    "8": "255.0.0.0", "16": "255.255.0.0", "24": "255.255.255.0",
    "25": "255.255.255.128", "26": "255.255.255.192", "27": "255.255.255.224",
    "28": "255.255.255.240", "30": "255.255.255.252", "32": "255.255.255.255",
}
MASK_TO_CIDR = {v: k for k, v in CIDR_TO_MASK.items()}

# Cisco interface name → Junos base mapping
CISCO_TO_JUNOS_IFACE_PREFIX = {
    "GigabitEthernet": "ge",
    "FastEthernet": "fe",
    "TenGigabitEthernet": "xe",
    "FortyGigabitEthernet": "et",
    "HundredGigabitEthernet": "et",
    "Serial": "se",
    "Loopback": "lo",
    "Tunnel": "ip-",
    "Port-channel": "ae",
}

# Junos interface prefix → Cisco interface prefix (reverse mapping)
JUNOS_TO_CISCO_IFACE_PREFIX = {
    "ge": "GigabitEthernet",
    "fe": "FastEthernet",
    "xe": "TenGigabitEthernet",
    "et": "FortyGigabitEthernet",
    "se": "Serial",
    "lo": "Loopback",
    "ae": "Port-channel",
    "irb": "Vlan",
}


# --------------------------------------------------------------------------
# Pre-output validation / lint
# --------------------------------------------------------------------------

def validate_junos_config(lines: list[str]) -> list[str]:
    """
    Validate generated Junos config for common errors.
    Returns list of warning/error messages.
    """
    warnings = []
    seen_lines = set()

    # Track interfaces that get disabled
    disabled_interfaces = set()

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Check for duplicate lines
        if stripped in seen_lines and not stripped.startswith('#'):
            # Allow duplicate 'set vlans' for different VLANs, but catch exact dupes
            if stripped.startswith('set interfaces') or stripped.startswith('set protocols'):
                warnings.append(f"Line {i+1}: Duplicate directive: {stripped}")
        seen_lines.add(stripped)

        # Track disabled interfaces
        if stripped.startswith('set interfaces') and 'disable' in stripped:
            match = re.match(r'^set interfaces\s+(\S+)\s+disable', stripped)
            if match:
                disabled_interfaces.add(match.group(1))

        # Check for WAN uplink being disabled (potential error)
        if 'ge-0/0/0' in stripped and 'disable' in stripped:
            # Check context - if this is the WAN uplink, warn
            for j in range(max(0, i-3), i):
                if 'UPLINK' in lines[j].upper() or 'WAN' in lines[j].upper():
                    warnings.append(f"Line {i+1}: WARNING - WAN uplink interface (ge-0/0/0) is disabled")

    return warnings


def validate_no_contradictions(junos_lines: list[str]) -> list[str]:
    """Check for contradictory directives in generated config."""
    errors = []

    # Group by interface
    iface_configs = {}
    for line in junos_lines:
        m = re.match(r'^set interfaces\s+(\S+)\s+(.+)', line.strip())
        if m:
            iface = m.group(1)
            config = m.group(2)
            if iface not in iface_configs:
                iface_configs[iface] = []
            iface_configs[iface].append(config)

    # Check for contradictions
    for iface, configs in iface_configs.items():
        has_disable = any('disable' in c for c in configs)
        has_unit0_inet = any('unit 0 family inet' in c for c in configs)

        # Interface has IP config but is disabled - potential issue
        if has_disable and has_unit0_inet:
            # Check if it's a management interface (might be intentional)
            desc_configs = [c for c in configs if 'description' in c]
            if desc_configs:
                desc = desc_configs[0]
                if 'MANAGEMENT' in desc.upper() or 'OOB' in desc.upper():
                    continue  # Likely intentional
            # For WAN interfaces, this is usually an error
            if 'UPLINK' in str(configs).upper() or 'WAN' in str(configs).upper():
                errors.append(f"Interface {iface} has IP configured but is disabled (WAN/uplink)")

    return errors


# --------------------------------------------------------------------------
# Validation & Boilerplate Helpers
# --------------------------------------------------------------------------

def _is_valid_ipv4(ip_str: str) -> bool:
    """Return True if ip_str is a valid standard IPv4 decimal dotted quad."""
    try:
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False


def _cidr_to_mask(cidr_str: str) -> str:
    """Convert CIDR prefix length (0-32) to dotted decimal netmask."""
    try:
        n = int(str(cidr_str).strip())
        if 0 <= n <= 32:
            mask_int = (0xffffffff << (32 - n)) & 0xffffffff if n > 0 else 0
            return f"{(mask_int >> 24) & 0xff}.{(mask_int >> 16) & 0xff}.{(mask_int >> 8) & 0xff}.{mask_int & 0xff}"
    except Exception:
        pass
    return CIDR_TO_MASK.get(str(cidr_str).strip(), "255.255.255.0")


def _mask_to_wildcard(mask_str: str) -> str:
    """Convert dotted netmask (e.g. 255.255.255.0) to wildcard mask (0.0.0.255)."""
    try:
        parts = [int(p) for p in mask_str.strip().split('.')]
        if len(parts) == 4:
            return f"{255 - parts[0]}.{255 - parts[1]}.{255 - parts[2]}.{255 - parts[3]}"
    except Exception:
        pass
    return "0.0.0.255"


def _parse_ip_mask(ip_str: str) -> tuple[Optional[str], Optional[str]]:
    """Parse 'IP MASK', 'IP/MASK', or 'IP/CIDR' into (ip, mask)."""
    if not ip_str:
        return None, None
    ip_str = ip_str.strip().strip('"')
    if ' ' in ip_str:
        parts = ip_str.split()
        if len(parts) >= 2:
            ip, m = parts[0], parts[1]
            if _is_valid_ipv4(ip):
                if _is_valid_ipv4(m):
                    return ip, m
                elif m.isdigit() and 0 <= int(m) <= 32:
                    return ip, _cidr_to_mask(m)
    if '/' in ip_str:
        parts = ip_str.split('/', 1)
        ip, m = parts[0], parts[1]
        if _is_valid_ipv4(ip):
            if _is_valid_ipv4(m):
                return ip, m
            elif m.isdigit() and 0 <= int(m) <= 32:
                return ip, _cidr_to_mask(m)
    if _is_valid_ipv4(ip_str):
        return ip_str, "255.255.255.255"
    return None, None


_CISCO_BOILERPLATE = re.compile(
    r'^(?:!|#|end|exit|version\s+\S+|service\s+.*|no\s+service\s+.*|'
    r'boot-start-marker|boot-end-marker|no\s+aaa\s+new-model|'
    r'spanning-tree\s+.*|redundancy|ip\s+classless|ip\s+subnet-zero|'
    r'ip\s+routing|no\s+ip\s+routing|ip\s+forward-protocol\s+.*|'
    r'ip\s+http\s+.*|no\s+ip\s+http\s+.*|line\s+(?:con|aux|vty)\s+.*|'
    r'transport\s+(?:input|output)\s+.*|login\s*.*|exec-timeout\s+.*|'
    r'privilege\s+.*|password\s+.*|username\s+.*|enable\s+(?:secret|password)\s+.*|'
    r'banner\s+.*|alias\s+.*|control-plane|duplex\s+.*|speed\s+.*|'
    r'negotiation\s+auto|no\s+negotiation\s+auto|cdp\s+enable|no\s+cdp\s+enable|'
    r'mtu\s+\d+|channel-group\s+\d+.*|standby\s+.*|ip\s+helper-address\s+.*|'
    r'media-type\s+.*|load-interval\s+.*|no\s+ip\s+address|'
    r'passive-interface\s+.*|default-information\s+.*|redistribute\s+.*|'
    r'auto-cost\s+.*|log-adjacency-changes.*|state\s+(?:active|suspend)|'
    r'switchport\s+nonegotiate|switchport\s+voice\s+vlan\s+\d+|'
    r'storm-control\s+.*|keepalive\s+.*|no\s+keepalive|ip\s+directed-broadcast|'
    r'remark\s+.*)',
    re.I
)


# --------------------------------------------------------------------------
# Cisco IOS XE Parser (Enhanced)
# --------------------------------------------------------------------------

def parse_cisco_iosxe(text: str) -> NormConfig:
    """Parse Cisco IOS XE configuration into normalized model."""
    cfg = NormConfig()
    cur_iface: Optional[NormInterface] = None
    cur_vlan: Optional[NormVlan] = None
    cur_acl: Optional[NormAcl] = None
    cur_class_map: Optional[NormQosClassMap] = None
    cur_policy_map: Optional[NormQosPolicyMap] = None
    cur_policy_class: Optional[str] = None

    in_router_ospf = False
    in_class_map = False
    in_policy_map = False
    in_policy_class_block = False

    def _flush_blocks():
        nonlocal cur_iface, cur_vlan, cur_acl, cur_class_map, cur_policy_map
        if cur_iface:
            existing_idx = -1
            for i, existing in enumerate(cfg.interfaces):
                if existing.index == cur_iface.index:
                    existing_idx = i
                    break
            if existing_idx >= 0:
                cfg.interfaces[existing_idx] = cur_iface
            else:
                cfg.interfaces.append(cur_iface)
            cur_iface = None
        if cur_vlan:
            cfg.vlans.append(cur_vlan)
            cur_vlan = None
        if cur_acl:
            cfg.acls.append(cur_acl)
            cur_acl = None
        if cur_class_map:
            cfg.qos_class_maps.append(cur_class_map)
            cur_class_map = None
        if cur_policy_map:
            cfg.qos_policy_maps.append(cur_policy_map)
            cur_policy_map = None

    lines = text.split('\n')

    for raw in lines:
        line = raw.rstrip('\r')
        trimmed = line.strip()
        if not trimmed:
            continue

        # Comment or section delimiter
        if trimmed.startswith('!') or trimmed.startswith('#') or trimmed in ('exit', 'end'):
            _flush_blocks()
            in_router_ospf = False
            in_class_map = False
            in_policy_map = False
            in_policy_class_block = False
            continue

        # Top-level: OSPF router section
        m = re.match(r'^router\s+ospf\s+(\d+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.ospf_config = NormOspfConfig(process_id=m.group(1))
            in_router_ospf = True
            continue

        if in_router_ospf:
            if re.match(r'^(?:interface|router|vlan|hostname|ip\s+|ntp|logging|tacacs|aaa|line)\s+', trimmed, re.I):
                in_router_ospf = False
            else:
                if cfg.ospf_config:
                    m = re.match(r'^router-id\s+(\S+)', trimmed, re.I)
                    if m:
                        cfg.ospf_config.router_id = m.group(1)
                        continue
                    m = re.match(r'^network\s+(\S+)\s+(\S+)\s+area\s+(\S+)', trimmed, re.I)
                    if m:
                        cfg.ospf_config.networks.append(NormOspfNetwork(
                            network=m.group(1),
                            wildcard=m.group(2),
                            area=m.group(3)
                        ))
                        continue
                if _CISCO_BOILERPLATE.match(trimmed):
                    continue
                cfg.skipped_lines.append(trimmed)
                continue

        # Top-level: class-map section
        m = re.match(r'^class-map\s+(match-all|match-any)\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cur_class_map = NormQosClassMap(name=m.group(2), match_type=m.group(1))
            in_class_map = True
            continue

        if in_class_map:
            if re.match(r'^(?:class-map|policy-map|interface|router|vlan|hostname|ip\s+|line)\s+', trimmed, re.I):
                _flush_blocks()
                in_class_map = False
            else:
                m = re.match(r'^match\s+(?:dscp\s+)?(\S+)', trimmed, re.I)
                if m and cur_class_map:
                    cur_class_map.match_criteria.append(('dscp', m.group(1)))
                    continue
                if _CISCO_BOILERPLATE.match(trimmed):
                    continue
                cfg.skipped_lines.append(trimmed)
                continue

        # Top-level: policy-map section
        m = re.match(r'^policy-map\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cur_policy_map = NormQosPolicyMap(name=m.group(1))
            in_policy_map = True
            continue

        if in_policy_map:
            if re.match(r'^(?:policy-map|class-map|interface|router|vlan|hostname|ip\s+|line)\s+', trimmed, re.I):
                _flush_blocks()
                in_policy_map = False
                in_policy_class_block = False
            else:
                m = re.match(r'^class\s+(\S+)', trimmed, re.I)
                if m:
                    cur_policy_class = m.group(1)
                    in_policy_class_block = True
                    continue
                if in_policy_class_block and cur_policy_map and cur_policy_class:
                    actions = []
                    if re.match(r'^priority\s+', trimmed, re.I):
                        m = re.match(r'^priority\s+(?:percent\s+)?(\d+)', trimmed, re.I)
                        if m:
                            actions.append(('priority', m.group(1)))
                    elif re.match(r'^bandwidth\s+', trimmed, re.I):
                        m = re.match(r'^bandwidth\s+(?:percent\s+)?(\d+)', trimmed, re.I)
                        if m:
                            actions.append(('bandwidth', m.group(1)))
                    elif re.match(r'^fair-queue', trimmed, re.I):
                        actions.append(('fair-queue', 'true'))
                    if actions:
                        cur_policy_map.classes.append((cur_policy_class, actions))
                        continue
                if _CISCO_BOILERPLATE.match(trimmed):
                    continue
                cfg.skipped_lines.append(trimmed)
                continue

        # Top-level: Hostname
        m = re.match(r'^hostname\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.hostname = m.group(1)
            cfg.sys_config.hostname = m.group(1)
            continue

        # Top-level: Domain name
        m = re.match(r'^ip\s+domain-name\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.domain_name = m.group(1)
            continue

        # Top-level: SSH configuration
        m = re.match(r'^ip\s+ssh\s+version\s+(\d+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.ssh_enabled = True
            cfg.sys_config.ssh_version = int(m.group(1))
            continue

        m = re.match(r'^ip\s+ssh\s+time-out\s+(\d+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.ssh_timeout = int(m.group(1))
            cfg.sys_config.ssh_enabled = True
            continue

        m = re.match(r'^ip\s+ssh\s+authentication-retries\s+(\d+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.ssh_retries = int(m.group(1))
            cfg.sys_config.ssh_enabled = True
            continue

        if re.match(r'^crypto\s+key\s+generate\s+rsa', trimmed, re.I):
            _flush_blocks()
            cfg.sys_config.ssh_enabled = True
            continue

        # Top-level: NTP servers
        m = re.match(r'^ntp\s+server\s+(\S+)(?:\s+prefer)?', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.ntp_servers.append(m.group(1))
            continue

        # Top-level: Syslog configuration
        m = re.match(r'^logging\s+host\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.syslog_hosts.append(m.group(1))
            continue

        m = re.match(r'^logging\s+trap\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.syslog_level = m.group(1)
            continue

        m = re.match(r'^logging\s+buffered\s+(\d+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.syslog_buffered_size = int(m.group(1))
            continue

        m = re.match(r'^logging\s+source-interface\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.syslog_source_interface = m.group(1)
            continue

        # Top-level: TACACS configuration
        m = re.match(r'^tacacs-server\s+host\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.tacacs_servers.append(m.group(1))
            continue

        m = re.match(r'^tacacs-server\s+key\s+(?:\d+\s+)?(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.tacacs_key = m.group(1)
            continue

        # Top-level: AAA configuration
        m = re.match(r'^aaa\s+authentication\s+login\s+\S+\s+(.+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.aaa_auth_login = m.group(1)
            continue

        m = re.match(r'^aaa\s+authorization\s+exec\s+\S+\s+(.+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.sys_config.aaa_auth_exec = m.group(1)
            continue

        # Top-level: Static routes
        m = re.match(r'^ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.static_routes.append(NormStaticRoute(
                prefix=m.group(1),
                mask=m.group(2),
                next_hop=m.group(3)
            ))
            continue

        # Top-level: VLANs
        m = re.match(r'^vlan\s+(\d+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cur_vlan = NormVlan(id=m.group(1))
            continue

        if cur_vlan:
            m = re.match(r'^name\s+(\S+)', trimmed, re.I)
            if m:
                cur_vlan.name = m.group(1)
                continue

        # Top-level: Interfaces
        m = re.match(r'^interface\s+(\S+)\s*$', trimmed, re.I)
        if m:
            _flush_blocks()
            iface_name = m.group(1)
            is_vlan_svi = iface_name.lower().startswith('vlan')
            vlan_id = None
            if is_vlan_svi:
                vlan_id_match = re.match(r'vlan(\d+)', iface_name, re.I)
                if vlan_id_match:
                    vlan_id = int(vlan_id_match.group(1))

            existing_iface = None
            for existing in cfg.interfaces:
                if existing.index == iface_name:
                    existing_iface = existing
                    break

            if existing_iface:
                cur_iface = existing_iface
            else:
                cur_iface = NormInterface(
                    index=iface_name,
                    enabled=False,
                    is_vlan_svi=is_vlan_svi,
                    vlan_id=vlan_id
                )
            continue

        # Sub-commands inside an interface
        if cur_iface:
            m = re.match(r'^description\s+(.+)$', trimmed, re.I)
            if m:
                cur_iface.description = m.group(1)
                continue

            m = re.match(r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', trimmed, re.I)
            if m:
                ip_val = m.group(1)
                mask_val = m.group(2)
                if not _is_valid_ipv4(ip_val) or not _is_valid_ipv4(mask_val):
                    cfg.skipped_lines.append(f"{trimmed} (Invalid IPv4 address or subnet mask)")
                    continue
                cur_iface.ip = ip_val
                cur_iface.mask = mask_val
                continue

            if re.match(r'^no\s+shutdown', trimmed, re.I):
                cur_iface.enabled = True
                continue
            if re.match(r'^shutdown$', trimmed, re.I):
                cur_iface.enabled = False
                continue

            m = re.match(r'^switchport\s+mode\s+(access|trunk)', trimmed, re.I)
            if m:
                cur_iface.switchport_mode = m.group(1).lower()
                continue

            m = re.match(r'^switchport\s+access\s+vlan\s+(\d+)', trimmed, re.I)
            if m:
                cur_iface.access_vlan = int(m.group(1))
                continue

            m = re.match(r'^switchport\s+trunk\s+allowed\s+vlan\s+(.+)$', trimmed, re.I)
            if m:
                cur_iface.trunk_allowed_vlans = m.group(1)
                continue

            m = re.match(r'^switchport\s+trunk\s+native\s+vlan\s+(\d+)', trimmed, re.I)
            if m:
                cur_iface.trunk_native_vlan = int(m.group(1))
                continue

            if re.match(r'^ip\s+nat\s+inside', trimmed, re.I):
                cur_iface.nat_inside = True
                continue
            if re.match(r'^ip\s+nat\s+outside', trimmed, re.I):
                cur_iface.nat_outside = True
                continue

            m = re.match(r'^ip\s+access-group\s+(\S+)\s+(in|out)', trimmed, re.I)
            if m:
                if m.group(2).lower() == 'in':
                    cur_iface.acl_in = m.group(1)
                else:
                    cur_iface.acl_out = m.group(1)
                continue

            m = re.match(r'^service-policy\s+output\s+(\S+)', trimmed, re.I)
            if m:
                cur_iface.qos_policy_out = m.group(1)
                continue

            if _CISCO_BOILERPLATE.match(trimmed):
                continue

            # Unrecognized command under interface
            cfg.skipped_lines.append(trimmed)
            continue

        # Top-level: ACLs - extended
        m = re.match(r'^ip\s+access-list\s+extended\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cur_acl = NormAcl(name=m.group(1), type='extended')
            continue

        # Top-level: ACLs - standard
        m = re.match(r'^ip\s+access-list\s+standard\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cur_acl = NormAcl(name=m.group(1), type='standard')
            continue

        # ACL rules (inside ACL block)
        if cur_acl:
            m = re.match(r'^(permit|deny)\s+(ip|tcp|udp|icmp)\s+(.+)$', trimmed, re.I)
            if m:
                action = m.group(1).lower()
                protocol = m.group(2).lower()
                rest = m.group(3).strip()
                parts = rest.split()
                source = parts[0] if parts else 'any'
                source_wildcard = None
                dest = 'any'
                dest_wildcard = None
                dest_port = None
                log = 'log' in trimmed.lower()

                idx = 1
                if idx < len(parts) and not parts[idx] in ('any', 'host') and re.match(r'^\d+\.', parts[idx]):
                    source_wildcard = parts[idx]
                    idx += 1
                if idx < len(parts) and parts[idx] == 'host':
                    idx += 1
                if idx < len(parts):
                    dest = parts[idx]
                    idx += 1
                if idx < len(parts) and re.match(r'^\d+\.', parts[idx]):
                    dest_wildcard = parts[idx]
                    idx += 1
                if idx < len(parts):
                    if parts[idx] == 'eq' and idx + 1 < len(parts):
                        dest_port = parts[idx + 1]

                rule = NormAclRule(
                    action=action,
                    protocol=protocol,
                    source=source,
                    source_wildcard=source_wildcard,
                    dest=dest,
                    dest_wildcard=dest_wildcard,
                    dest_port=dest_port,
                    log=log
                )
                cur_acl.rules.append(rule)
                continue

            m = re.match(r'^(permit|deny)\s+(\S+)(?:\s+(\S+))?', trimmed, re.I)
            if m and cur_acl.type == 'standard':
                rule = NormAclRule(
                    action=m.group(1).lower(),
                    protocol='ip',
                    source=m.group(2),
                    source_wildcard=m.group(3),
                    dest='any',
                    dest_wildcard=None
                )
                cur_acl.rules.append(rule)
                continue

            if _CISCO_BOILERPLATE.match(trimmed):
                continue
            cfg.skipped_lines.append(trimmed)
            continue

        # Top-level: NAT pools
        m = re.match(r'^ip\s+nat\s+pool\s+(\S+)\s+(\S+)\s+(\S+)\s+netmask\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.nat_pools.append(NormNatPool(
                name=m.group(1),
                start_ip=m.group(2),
                end_ip=m.group(3),
                netmask=m.group(4)
            ))
            continue

        # Top-level: NAT rules
        m = re.match(r'^ip\s+nat\s+inside\s+source\s+list\s+(\S+)\s+interface\s+(\S+)\s+overload', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.nat_rules.append(NormNatRule(
                acl_name=m.group(1),
                interface=m.group(2),
                overload=True
            ))
            continue

        m = re.match(r'^ip\s+nat\s+inside\s+source\s+list\s+(\S+)\s+pool\s+(\S+)', trimmed, re.I)
        if m:
            _flush_blocks()
            cfg.nat_rules.append(NormNatRule(
                acl_name=m.group(1),
                pool_name=m.group(2)
            ))
            continue

        # Check boilerplate; if not boilerplate, it's unrecognized/error
        if not _CISCO_BOILERPLATE.match(trimmed):
            cfg.skipped_lines.append(trimmed)

    _flush_blocks()
    return cfg


# --------------------------------------------------------------------------
# Junos Parser
# --------------------------------------------------------------------------

def _junos_hierarchical_to_set(text: str) -> list[str]:
    """
    Convert Juniper hierarchical config format (curly-brace style) to flat 'set' commands.

    Example input:
        system {
            host-name ROUTER1;
            ntp { server 1.2.3.4; }
        }
    Example output:
        ['set system host-name ROUTER1', 'set system ntp server 1.2.3.4']
    """
    set_lines: list[str] = []
    path_stack: list[str] = []
    # current multi-word token buffer when a brace follows on the next line
    pending_tokens: list[str] = []

    for raw in text.split('\n'):
        line = raw.strip().rstrip(';')
        if not line:
            continue
        # Comments / version boilerplate
        if line.startswith('#') or line.startswith('/*') or line.endswith('*/'):
            continue
        if re.match(r'^(?:version\s+\S+|##)', line, re.I):
            continue

        # A line may have inline braces, e.g.:  "ntp { server 1.2.3.4; }"
        # Expand inline { ... } to individual lines first
        # Collapse the whole thing: push/pop in a single pass
        tokens = line.split()
        i = 0
        while i < len(tokens):
            tok = tokens[i].rstrip(';')
            if tok == '{':
                # push accumulated pending tokens
                if pending_tokens:
                    path_stack.append(' '.join(pending_tokens))
                    pending_tokens = []
                i += 1
            elif tok == '}':
                if path_stack:
                    path_stack.pop()
                if pending_tokens:
                    pending_tokens = []
                i += 1
            elif tok == 'inactive:' or tok == 'apply-groups':
                # skip to end of this token group
                break
            else:
                # Regular token — accumulate until { or } or end-of-line
                pending_tokens.append(tok.rstrip(';'))
                # peek ahead: if next is '{', this token-group IS a path segment
                if i + 1 < len(tokens) and tokens[i + 1].lstrip() == '{':
                    path_stack.append(' '.join(pending_tokens))
                    pending_tokens = []
                    i += 2  # skip past '{'
                    continue
                i += 1

        # If we have accumulated tokens and no open brace follows, emit a set command
        if pending_tokens:
            full_path = ' '.join(path_stack + pending_tokens)
            set_lines.append('set ' + full_path)
            pending_tokens = []

    return set_lines


def parse_junos(text: str) -> NormConfig:
    """Parse Juniper Junos configuration into normalized model.

    Accepts both:
    - Flat 'set' format:  set system host-name ROUTER
    - Hierarchical format: system { host-name ROUTER; }
    """
    cfg = NormConfig()
    iface_map: dict[str, NormInterface] = {}
    vlan_map: dict[str, NormVlan] = {}

    # Auto-detect format: if the text has 'set ' lines, treat as flat.
    # If it has curly braces but no 'set ', convert hierarchical → flat.
    raw_lines = [l.strip() for l in text.split('\n') if l.strip()]
    has_set_cmds = any(l.lower().startswith('set ') for l in raw_lines)
    has_braces = any('{' in l or '}' in l for l in raw_lines)

    if has_braces and not has_set_cmds:
        # Pure hierarchical format — convert to set style first
        flat_lines = _junos_hierarchical_to_set(text)
    elif has_braces and has_set_cmds:
        # Mixed — process set lines as-is, skip brace-only lines
        flat_lines = [l for l in raw_lines if l.lower().startswith('set ')]
    else:
        # Already flat set-style
        flat_lines = raw_lines

    for line in flat_lines:
        line = line.strip()
        if not line:
            continue
        # Strip trailing semicolons left over from hierarchical conversion
        line = line.rstrip(';').strip()
        if not line:
            continue
        # Comments and structural braces
        if line.startswith('#') or line.startswith('/*') or line.endswith('*/'):
            continue
        if re.match(r'^(?:version\s+\S+|##\s+Last\s+commit:)', line, re.I):
            continue

        # Hostname
        m = re.match(r'^set\s+system\s+host-name\s+(\S+)', line, re.I)
        if m:
            cfg.hostname = m.group(1).rstrip(';')
            cfg.sys_config.hostname = cfg.hostname
            continue

        # SSH
        if re.match(r'^set\s+system\s+services\s+ssh', line, re.I):
            cfg.sys_config.ssh_enabled = True
            continue

        # NTP
        m = re.match(r'^set\s+system\s+ntp\s+server\s+(\S+)', line, re.I)
        if m:
            cfg.sys_config.ntp_servers.append(m.group(1).rstrip(';'))
            continue

        # Syslog
        m = re.match(r'^set\s+system\s+syslog\s+host\s+(\S+)', line, re.I)
        if m:
            cfg.sys_config.syslog_hosts.append(m.group(1).rstrip(';'))
            continue

        # TACACS+
        m = re.match(r'^set\s+system\s+tacplus-server\s+(\S+)', line, re.I)
        if m:
            cfg.sys_config.tacacs_servers.append(m.group(1).rstrip(';'))
            continue

        # Static route
        m = re.match(r'^set\s+routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)', line, re.I)
        if m:
            route_dest = m.group(1).rstrip(';')
            next_hop = m.group(2).rstrip(';')
            if '/' in route_dest:
                pfx, pfx_len = route_dest.split('/', 1)
                pfx_len = pfx_len.rstrip(';')
                mask = CIDR_TO_MASK.get(pfx_len, '255.255.255.0')
            else:
                pfx, mask = route_dest, '255.255.255.255'
            cfg.static_routes.append(NormStaticRoute(prefix=pfx, mask=mask, next_hop=next_hop))
            continue

        # OSPF router-id
        m = re.match(r'^set\s+protocols\s+ospf\s+area\s+(\S+)\s+interface\s+(\S+)', line, re.I)
        if m:
            if not cfg.ospf_config:
                cfg.ospf_config = NormOspfConfig(process_id="1")
            # Interface in OSPF area — just note it, not full parsing
            continue

        # Interface description  (handles both "ge-0/0/0" and "ge-0/0/0 unit 0" paths)
        m = re.match(r'^set\s+interfaces\s+(\S+?)(?:\s+unit\s+\d+)?\s+description\s+"?([^";]+)"?', line, re.I)
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.description = m.group(2).strip().rstrip('"')
            continue

        # Interface IP — unit style: set interfaces ge-0/0/0 unit 0 family inet address X.X.X.X/N
        m = re.match(
            r'^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)',
            line, re.I
        )
        if m:
            ip_val, cidr_val = m.group(2), m.group(3)
            if not _is_valid_ipv4(ip_val) or not (0 <= int(cidr_val) <= 32):
                cfg.skipped_lines.append(f"{line} (Invalid IPv4 address or CIDR mask)")
                continue
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.ip = ip_val
            it.mask = CIDR_TO_MASK.get(cidr_val, "255.255.255.0")
            continue

        # Interface IP — hierarchical-flattened style: set interfaces ge-0/0/0 address X.X.X.X/N
        m = re.match(
            r'^set\s+interfaces\s+(\S+)\s+address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)',
            line, re.I
        )
        if m:
            ip_val, cidr_val = m.group(2), m.group(3)
            if not _is_valid_ipv4(ip_val) or not (0 <= int(cidr_val) <= 32):
                cfg.skipped_lines.append(f"{line} (Invalid IPv4 address or CIDR mask)")
                continue
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.ip = ip_val
            it.mask = CIDR_TO_MASK.get(cidr_val, "255.255.255.0")
            continue

        # Interface inet address (hierarchical: set interfaces ge-0/0/0 family inet address X/N)
        m = re.match(
            r'^set\s+interfaces\s+(\S+)\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)',
            line, re.I
        )
        if m:
            ip_val, cidr_val = m.group(2), m.group(3)
            if not _is_valid_ipv4(ip_val) or not (0 <= int(cidr_val) <= 32):
                cfg.skipped_lines.append(f"{line} (Invalid IPv4 address or CIDR mask)")
                continue
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.ip = ip_val
            it.mask = CIDR_TO_MASK.get(cidr_val, "255.255.255.0")
            continue

        # Interface disable
        m = re.match(r'^set\s+interfaces\s+(\S+)(?:\s+unit\s+\d+)?\s+disable', line, re.I)
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.enabled = False
            continue

        # VLANs
        m = re.match(r'^set\s+vlans\s+(\S+)\s+vlan-id\s+(\d+)', line, re.I)
        if m:
            vlan_map[m.group(2)] = NormVlan(id=m.group(2), name=m.group(1))
            continue

        # Known benign Junos boilerplate — skip silently
        if re.match(
            r'^set\s+(?:'
            r'system\s+(?:root-authentication|login|time-zone|domain-name|name-server|archival|scripts|commit)|'
            r'protocols\s+(?:lldp|rstp|mstp|ospf|bgp|isis|mpls|rsvp|ldp)|'
            r'snmp|chassis|forwarding-options|routing-options\s+router-id|'
            r'class-of-service|policy-options|routing-instances'
            r')',
            line, re.I
        ):
            continue

        # Flagged firewall/security in Junos
        if re.match(r'^set\s+(?:firewall|security)', line, re.I):
            cfg.flagged.append(line)
            continue

        # Anything else is unrecognized
        if line.lower().startswith('set '):
            cfg.skipped_lines.append(line)

    cfg.interfaces = list(iface_map.values())
    cfg.vlans = list(vlan_map.values())
    return cfg

# --------------------------------------------------------------------------
# FortiOS Parser
# --------------------------------------------------------------------------


def parse_fortios(text: str) -> NormConfig:
    """Parse FortiOS configuration into normalized model."""
    cfg = NormConfig()
    context_stack: list[str] = []
    cur_iface: Optional[NormInterface] = None
    cur_vlan: Optional[NormVlan] = None
    cur_static_route: Optional[dict] = None
    cur_ospf_net: Optional[dict] = None
    port_counter = 0
    port_index_of: dict[str, str] = {}   # forti_name -> numeric index string
    port_origname: dict[str, str] = {}   # numeric index string -> original forti port name

    for raw in text.split('\n'):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue

        # Check block entry: config <name>
        m_cfg = re.match(r'^config\s+(.+)$', line, re.I)
        if m_cfg:
            block_type = m_cfg.group(1).strip().lower()
            context_stack.append(block_type)
            # If firewall or unsupported config, flag it
            if any(block_type.startswith(p) for p in ["firewall", "vpn", "endpoint-control", "user"]):
                cfg.flagged.append(line)
            continue

        # Check block exit: end
        if re.match(r'^end$', line, re.I):
            if cur_iface:
                cfg.interfaces.append(cur_iface)
                cur_iface = None
            if cur_vlan:
                cfg.vlans.append(cur_vlan)
                cur_vlan = None
            if cur_static_route:
                pfx, mask = _parse_ip_mask(cur_static_route.get("dst", "0.0.0.0/0"))
                gw = cur_static_route.get("gateway")
                if pfx and mask and gw:
                    cfg.static_routes.append(NormStaticRoute(prefix=pfx, mask=mask, next_hop=gw))
                cur_static_route = None
            if cur_ospf_net:
                pfx, mask = _parse_ip_mask(cur_ospf_net.get("prefix", ""))
                area = cur_ospf_net.get("area", "0.0.0.0")
                if pfx and mask:
                    wild = _mask_to_wildcard(mask)
                    if not cfg.ospf_config:
                        cfg.ospf_config = NormOspfConfig(process_id="1")
                    cfg.ospf_config.networks.append(NormOspfNetwork(network=pfx, wildcard=wild, area=area))
                cur_ospf_net = None
            if context_stack:
                context_stack.pop()
            continue

        current_ctx = context_stack[-1] if context_stack else ""
        parent_ctx = context_stack[-2] if len(context_stack) >= 2 else ""

        # Flagged contexts (firewall policy, address objects, etc.)
        if any(ctx.startswith("firewall") or ctx.startswith("vpn") for ctx in context_stack):
            cfg.flagged.append(line)
            continue

        # Global system settings
        if current_ctx == "system global":
            m = re.match(r'^set\s+hostname\s+"?([^"]+)"?', line, re.I)
            if m:
                cfg.hostname = m.group(1)
                cfg.sys_config.hostname = m.group(1)
                continue
            m = re.match(r'^set\s+domain\s+"?([^"]+)"?', line, re.I)
            if m:
                cfg.sys_config.domain_name = m.group(1)
                continue
            if re.match(r'^set\s+(?:timezone|admin-sport|admin-ssh-port|language|admin-scp|ssh-server-keygen|ssh-enc-algo|ssh-mac-hmac|sshd-curve25519|ssh-cbc-cipher)\s+', line, re.I):
                continue
            cfg.skipped_lines.append(line)
            continue

        # SSH settings
        if current_ctx == "system ssh":
            if re.match(r'^set\s+status\s+enable', line, re.I):
                cfg.sys_config.ssh_enabled = True
                continue
            m = re.match(r'^set\s+untrusted-hosts-auth-timeout\s+(\d+)', line, re.I)
            if m:
                cfg.sys_config.ssh_timeout = int(m.group(1))
                continue
            m = re.match(r'^set\s+max-retry\s+(\d+)', line, re.I)
            if m:
                cfg.sys_config.ssh_retries = int(m.group(1))
                continue
            continue

        # Interface configuration
        if current_ctx == "system interface":
            m = re.match(r'^edit\s+"?([^"]+)"?', line, re.I)
            if m:
                if cur_iface:
                    cfg.interfaces.append(cur_iface)
                port_name = m.group(1)
                if port_name not in port_index_of:
                    port_counter += 1
                    idx_str = str(port_counter)
                    port_index_of[port_name] = idx_str
                    port_origname[idx_str] = port_name
                cur_iface = NormInterface(
                    index=port_index_of[port_name],
                    enabled=True,
                    description=port_name
                )
                continue
            if re.match(r'^next$', line, re.I):
                if cur_iface:
                    cfg.interfaces.append(cur_iface)
                cur_iface = None
                continue
            if cur_iface:
                m = re.match(r'^set\s+alias\s+"?([^"]+)"?', line, re.I)
                if m:
                    cur_iface.description = m.group(1)
                    continue
                m = re.match(r'^set\s+ip\s+(\S+(?:\s+\S+)?)', line, re.I)
                if m:
                    ip_val, mask_val = _parse_ip_mask(m.group(1))
                    if ip_val and mask_val:
                        cur_iface.ip = ip_val
                        cur_iface.mask = mask_val
                    else:
                        cfg.skipped_lines.append(f"{line} (Invalid IPv4 address or netmask)")
                    continue
                m = re.match(r'^set\s+status\s+(up|down)', line, re.I)
                if m:
                    cur_iface.enabled = m.group(1).lower() == "up"
                    continue
                m = re.match(r'^set\s+vlanid\s+(\d+)', line, re.I)
                if m:
                    cfg.vlans.append(NormVlan(id=m.group(1), name=cur_iface.description or f"VLAN{m.group(1)}"))
                    continue
                if re.match(r'^set\s+(?:vdom|mode|type|allowaccess|snmp-index|mtu-override|broadcast-forward|role|device-identification)\s+', line, re.I):
                    continue
                cfg.skipped_lines.append(line)
                continue

        # VLAN configuration
        if current_ctx in ("system vlan", "vlan"):
            m = re.match(r'^edit\s+"?([^"]+)"?', line, re.I)
            if m:
                if cur_vlan:
                    cfg.vlans.append(cur_vlan)
                vname = m.group(1)
                vid = re.search(r'\d+', vname)
                cur_vlan = NormVlan(id=vid.group(0) if vid else vname, name=vname)
                continue
            if re.match(r'^next$', line, re.I):
                if cur_vlan:
                    cfg.vlans.append(cur_vlan)
                cur_vlan = None
                continue
            if cur_vlan:
                m = re.match(r'^set\s+vlanid\s+(\d+)', line, re.I)
                if m:
                    cur_vlan.id = m.group(1)
                    continue
                if re.match(r'^set\s+(?:interface|description|ip)\s+', line, re.I):
                    continue
                cfg.skipped_lines.append(line)
                continue

        # Static Route configuration
        if current_ctx == "router static":
            if re.match(r'^edit\s+', line, re.I):
                if cur_static_route:
                    pfx, mask = _parse_ip_mask(cur_static_route.get("dst", "0.0.0.0/0"))
                    gw = cur_static_route.get("gateway")
                    if pfx and mask and gw:
                        cfg.static_routes.append(NormStaticRoute(prefix=pfx, mask=mask, next_hop=gw))
                cur_static_route = {}
                continue
            if re.match(r'^next$', line, re.I):
                if cur_static_route:
                    pfx, mask = _parse_ip_mask(cur_static_route.get("dst", "0.0.0.0/0"))
                    gw = cur_static_route.get("gateway")
                    if pfx and mask and gw:
                        cfg.static_routes.append(NormStaticRoute(prefix=pfx, mask=mask, next_hop=gw))
                cur_static_route = None
                continue
            if cur_static_route is not None:
                m = re.match(r'^set\s+dst\s+(\S+(?:\s+\S+)?)', line, re.I)
                if m:
                    cur_static_route["dst"] = m.group(1)
                    continue
                m = re.match(r'^set\s+gateway\s+(\S+)', line, re.I)
                if m:
                    cur_static_route["gateway"] = m.group(1)
                    continue
                continue

        # OSPF configuration
        if current_ctx == "router ospf" or parent_ctx == "router ospf":
            m = re.match(r'^set\s+router-id\s+(\S+)', line, re.I)
            if m:
                if not cfg.ospf_config:
                    cfg.ospf_config = NormOspfConfig(process_id="1")
                cfg.ospf_config.router_id = m.group(1)
                continue
            if current_ctx == "network":
                if re.match(r'^edit\s+', line, re.I):
                    if cur_ospf_net:
                        pfx, mask = _parse_ip_mask(cur_ospf_net.get("prefix", ""))
                        area = cur_ospf_net.get("area", "0.0.0.0")
                        if pfx and mask:
                            wild = _mask_to_wildcard(mask)
                            if not cfg.ospf_config:
                                cfg.ospf_config = NormOspfConfig(process_id="1")
                            cfg.ospf_config.networks.append(NormOspfNetwork(network=pfx, wildcard=wild, area=area))
                    cur_ospf_net = {}
                    continue
                if re.match(r'^next$', line, re.I):
                    if cur_ospf_net:
                        pfx, mask = _parse_ip_mask(cur_ospf_net.get("prefix", ""))
                        area = cur_ospf_net.get("area", "0.0.0.0")
                        if pfx and mask:
                            wild = _mask_to_wildcard(mask)
                            if not cfg.ospf_config:
                                cfg.ospf_config = NormOspfConfig(process_id="1")
                            cfg.ospf_config.networks.append(NormOspfNetwork(network=pfx, wildcard=wild, area=area))
                    cur_ospf_net = None
                    continue
                if cur_ospf_net is not None:
                    m = re.match(r'^set\s+prefix\s+(\S+(?:\s+\S+)?)', line, re.I)
                    if m:
                        cur_ospf_net["prefix"] = m.group(1)
                        continue
                    m = re.match(r'^set\s+area\s+(\S+)', line, re.I)
                    if m:
                        cur_ospf_net["area"] = m.group(1)
                        continue
                continue
            continue

        # NTP server configuration
        if "ntp" in current_ctx or "ntp" in parent_ctx:
            m = re.match(r'^set\s+server\s+"?([^"]+)"?', line, re.I)
            if m:
                srv = m.group(1).strip()
                if srv and srv not in cfg.sys_config.ntp_servers:
                    cfg.sys_config.ntp_servers.append(srv)
                continue
            continue

        # Syslog server configuration
        if any(k in current_ctx or k in parent_ctx for k in ["syslog", "log syslogd"]):
            m = re.match(r'^set\s+server\s+"?([^"]+)"?', line, re.I)
            if m:
                srv = m.group(1).strip()
                if srv and srv not in cfg.sys_config.syslog_hosts:
                    cfg.sys_config.syslog_hosts.append(srv)
                continue
            continue

        cfg.skipped_lines.append(line)

    if cur_iface:
        cfg.interfaces.append(cur_iface)
    if cur_vlan:
        cfg.vlans.append(cur_vlan)
    return cfg


# --------------------------------------------------------------------------
# Cisco IOS XE Generator
# --------------------------------------------------------------------------

def _junos_iface_to_cisco(junos_iface: str) -> str:
    """
    Convert a Junos interface name to Cisco IOS XE format.
    e.g. ge-0/0/0 -> GigabitEthernet0/0/0, irb.10 -> Vlan10, lo0 -> Loopback0
    """
    # Handle irb.X (routed VLAN) -> Vlan X
    m = re.match(r'^irb\.(\d+)$', junos_iface, re.I)
    if m:
        return f"Vlan{m.group(1)}"

    # Handle prefix-slot/subslot/port  e.g. ge-0/0/0
    m = re.match(r'^([a-z]+)-([\d/]+)$', junos_iface, re.I)
    if m:
        prefix = m.group(1).lower()
        nums = m.group(2)  # e.g. "0/0/0"
        cisco_prefix = JUNOS_TO_CISCO_IFACE_PREFIX.get(prefix)
        if cisco_prefix:
            return f"{cisco_prefix}{nums}"

    # Handle lo0 style (no slash)
    m = re.match(r'^([a-z]+)(\d+)$', junos_iface, re.I)
    if m:
        prefix = m.group(1).lower()
        num = m.group(2)
        cisco_prefix = JUNOS_TO_CISCO_IFACE_PREFIX.get(prefix)
        if cisco_prefix:
            return f"{cisco_prefix}{num}"

    # Fallback
    return junos_iface


def _forti_index_to_cisco(index: str) -> str:
    """
    Convert a FortiOS numeric interface index or port name to a Cisco-style interface name.
    e.g. '1' -> 'GigabitEthernet0/0', 'port1' -> 'GigabitEthernet0/0', 'wan1' -> 'GigabitEthernet0/0'
    """
    m = re.search(r'(\d+)', index)
    if m:
        try:
            n = max(0, int(m.group(1)) - 1)
            return f"GigabitEthernet0/{n}"
        except (ValueError, TypeError):
            pass
    return "GigabitEthernet0/0"


def _forti_index_to_junos(index: str) -> str:
    """
    Convert a FortiOS numeric interface index to a Junos-style interface name.
    e.g. '1' -> 'ge-0/0/0', '2' -> 'ge-0/0/1'
    """
    try:
        n = int(index) - 1  # 0-based port
        return f"ge-0/0/{n}"
    except (ValueError, TypeError):
        return f"ge-0/0/{index}"


def _smart_forti_port_name(index: str, description: Optional[str] = None) -> str:
    """
    Generate a clean FortiOS port name from an interface index.
    Tries to use the description as port name if it looks like a port name,
    otherwise uses port1, port2, etc.
    """
    # If description looks like a FortiOS built-in port name (portN, wanN, etc.), use it
    if description and re.match(r'^(port|wan|dmz|lan|mgmt)\d*$', description, re.I):
        return description
    # Otherwise use portN numbering
    try:
        n = int(index)
        return f"port{n}"
    except (ValueError, TypeError):
        return f"port{index}"


def gen_cisco_iosxe(cfg: NormConfig) -> str:
    """Generate Cisco IOS XE configuration from normalized model."""
    out: list[str] = []

    if cfg.hostname:
        out += [f"hostname {cfg.hostname}", "!"]

    # System config
    if cfg.sys_config.domain_name:
        out.append(f"ip domain-name {cfg.sys_config.domain_name}")
    if cfg.sys_config.ssh_enabled:
        out.append(f"ip ssh version {cfg.sys_config.ssh_version}")
        if cfg.sys_config.ssh_timeout:
            out.append(f"ip ssh time-out {cfg.sys_config.ssh_timeout}")
        if cfg.sys_config.ssh_retries:
            out.append(f"ip ssh authentication-retries {cfg.sys_config.ssh_retries}")
    out.append("!")

    # VLANs
    for v in cfg.vlans:
        out.append(f"vlan {v.id}")
        if v.name:
            out.append(f" name {v.name}")
        out.append("!")

    # Interfaces — convert Junos / FortiOS index names to Cisco style
    for it in cfg.interfaces:
        # Determine the Cisco-style interface name
        idx = it.index
        if re.match(r'^\d+$', idx) or re.match(r'^(?:port|wan|lan|internal|dmz)\d*$', idx, re.I):
            # FortiOS numeric index or port name
            cisco_name = _forti_index_to_cisco(idx)
        elif re.match(r'^[a-z]+-[\d/]+$', idx, re.I) or re.match(r'^irb\.\d+$', idx, re.I):
            # Junos-style name
            cisco_name = _junos_iface_to_cisco(idx)
        elif re.match(r'^(?:GigabitEthernet|FastEthernet|TenGigabitEthernet|Vlan|Loopback|Serial|Tunnel|Port-channel)', idx, re.I):
            # Already Cisco-style
            cisco_name = idx
        else:
            cisco_name = _forti_index_to_cisco(idx)

        out.append(f"interface {cisco_name}")
        if it.description:
            out.append(f" description {it.description}")
        if it.ip and it.mask:
            out.append(f" ip address {it.ip} {it.mask}")
        out.append(" no shutdown" if it.enabled else " shutdown")
        out.append("!")

    # Static routes
    for route in cfg.static_routes:
        out.append(f"ip route {route.prefix} {route.mask} {route.next_hop}")
    if cfg.static_routes:
        out.append("!")

    # OSPF
    if cfg.ospf_config:
        out.append(f"router ospf {cfg.ospf_config.process_id}")
        if cfg.ospf_config.router_id:
            out.append(f" router-id {cfg.ospf_config.router_id}")
        for net in cfg.ospf_config.networks:
            out.append(f" network {net.network} {net.wildcard} area {net.area}")
        out.append("!")

    # NTP
    for ntp in cfg.sys_config.ntp_servers:
        out.append(f"ntp server {ntp}")
    if cfg.sys_config.ntp_servers:
        out.append("!")

    # Syslog
    for host in cfg.sys_config.syslog_hosts:
        out.append(f"logging host {host}")
    if cfg.sys_config.syslog_level:
        out.append(f"logging trap {cfg.sys_config.syslog_level}")
    if cfg.sys_config.syslog_buffered_size:
        out.append(f"logging buffered {cfg.sys_config.syslog_buffered_size}")
    if cfg.sys_config.syslog_hosts:
        out.append("!")

    # TACACS
    for tacacs in cfg.sys_config.tacacs_servers:
        out.append(f"tacacs-server host {tacacs}")
    if cfg.sys_config.tacacs_key:
        out.append(f"tacacs-server key {cfg.sys_config.tacacs_key}")
    if cfg.sys_config.tacacs_servers:
        out.append("!")

    # AAA
    if cfg.sys_config.aaa_auth_login:
        out.append(f"aaa authentication login default {cfg.sys_config.aaa_auth_login}")
    if cfg.sys_config.aaa_auth_exec:
        out.append(f"aaa authorization exec default {cfg.sys_config.aaa_auth_exec}")
    if cfg.sys_config.aaa_auth_login or cfg.sys_config.aaa_auth_exec:
        out.append("!")

    # ACLs
    for acl in cfg.acls:
        out.append(f"ip access-list {acl.type} {acl.name}")
        for rule in acl.rules:
            rule_str = f" {rule.action} {rule.protocol} {rule.source}"
            if rule.source_wildcard:
                rule_str += f" {rule.source_wildcard}"
            rule_str += f" {rule.dest}"
            if rule.dest_wildcard:
                rule_str += f" {rule.dest_wildcard}"
            if rule.dest_port:
                rule_str += f" eq {rule.dest_port}"
            if rule.log:
                rule_str += " log"
            out.append(rule_str)
        out.append("!")

    # NAT
    for pool in cfg.nat_pools:
        out.append(f"ip nat pool {pool.name} {pool.start_ip} {pool.end_ip} netmask {pool.netmask}")
    for rule in cfg.nat_rules:
        if rule.interface:
            out.append(f"ip nat inside source list {rule.acl_name} interface {rule.interface} overload")
        elif rule.pool_name:
            out.append(f"ip nat inside source list {rule.acl_name} pool {rule.pool_name}")
    if cfg.nat_pools or cfg.nat_rules:
        out.append("!")

    if cfg.flagged:
        out.append("! --- FLAGGED FOR MANUAL REVIEW (not auto-converted) ---")
        out += [f"! {l}" for l in cfg.flagged]

    return "\n".join(out)


# --------------------------------------------------------------------------
# Juniper Junos Generator (Enhanced)
# --------------------------------------------------------------------------

def cisco_iface_to_junos(cisco_iface: str) -> tuple[str, bool]:
    """
    Convert Cisco interface name to Junos format.
    Returns (junos_name, is_irb) tuple.
    is_irb is True for VLAN SVIs which should use irb.X format.
    """
    # Check for VLAN SVI
    vlan_match = re.match(r'Vlan(\d+)', cisco_iface, re.I)
    if vlan_match:
        return (f"irb.{vlan_match.group(1)}", True)

    # Parse physical interface
    for cisco_prefix, junos_prefix in CISCO_TO_JUNOS_IFACE_PREFIX.items():
        if cisco_iface.startswith(cisco_prefix):
            # Extract slot/subslot/port
            # GigabitEthernet0/0 -> ge-0/0/0
            # GigabitEthernet0/0/1 -> ge-0/0/1
            nums = re.findall(r'\d+', cisco_iface)
            if len(nums) >= 2:
                slot = nums[0]
                port = nums[-1]
                subslot = nums[1] if len(nums) > 2 else "0"
                return (f"{junos_prefix}-{slot}/{subslot}/{port}", False)
            break

    # Fallback: just use the original name
    return (cisco_iface, False)


def gen_junos(cfg: NormConfig) -> str:
    """Generate Juniper Junos configuration from normalized model."""
    out: list[str] = []

    # System configuration
    if cfg.hostname:
        out.append(f"set system host-name {cfg.hostname}")

    # SSH
    if cfg.sys_config.ssh_enabled:
        out.append("set system services ssh")
        if cfg.sys_config.ssh_version:
            out.append(f"set system services ssh protocol-version v{cfg.sys_config.ssh_version}")
        if cfg.sys_config.ssh_timeout:
            out.append(f"set system services ssh idle-timeout {cfg.sys_config.ssh_timeout}")

    # NTP
    for ntp in cfg.sys_config.ntp_servers:
        out.append(f"set system ntp server {ntp}")

    # Syslog
    for host in cfg.sys_config.syslog_hosts:
        out.append(f"set system syslog host {host} any {cfg.sys_config.syslog_level or 'info'}")
    if cfg.sys_config.syslog_buffered_size:
        out.append(f"set system syslog archive size {cfg.sys_config.syslog_buffered_size}")

    # TACACS
    for tacacs in cfg.sys_config.tacacs_servers:
        out.append(f"set system tacplus-server {tacacs}")
    if cfg.sys_config.tacacs_key:
        out.append(f"set system tacplus-server secret \"{cfg.sys_config.tacacs_key}\"")

    # AAA authentication order
    if cfg.sys_config.aaa_auth_login:
        # Parse the AAA string to determine order
        auth_methods = []
        if 'tacacs' in cfg.sys_config.aaa_auth_login.lower():
            auth_methods.append('tacplus')
        if 'local' in cfg.sys_config.aaa_auth_login.lower():
            auth_methods.append('password')
        if auth_methods:
            out.append(f"set system authentication-order [ {' '.join(auth_methods)} ]")

    # Domain name
    if cfg.sys_config.domain_name:
        out.append(f"set system domain-name {cfg.sys_config.domain_name}")

    out.append("")  # Blank line for readability

    # VLANs with L3 interface bindings
    for v in cfg.vlans:
        vlan_name = v.name or f"VLAN{v.id}"
        out.append(f"set vlans {vlan_name} vlan-id {v.id}")
        # Check if any interface is an SVI for this VLAN
        for iface in cfg.interfaces:
            if iface.is_vlan_svi and iface.vlan_id == int(v.id):
                out.append(f"set vlans {vlan_name} l3-interface irb.{v.id}")
                break

    out.append("")

    # Interfaces — convert any source naming to Junos style
    for it in cfg.interfaces:
        # Determine Junos name:
        # - Cisco names like GigabitEthernet0/0 → ge-0/0/0 (via cisco_iface_to_junos)
        # - FortiOS numeric index like "1", "2" → ge-0/0/0, ge-0/0/1
        # - Already-Junos names pass through
        idx = it.index
        if re.match(r'^\d+$', idx):
            # FortiOS numeric index → Junos name
            junos_name = _forti_index_to_junos(idx)
            is_irb = False
        else:
            junos_name, is_irb = cisco_iface_to_junos(idx)

        # For VLAN SVIs, we already created the l3-interface binding above
        # Now output the irb interface config
        if it.is_vlan_svi:
            # irb interface
            if it.description:
                out.append(f'set interfaces {junos_name} description "{it.description}"')
            if it.ip and it.mask:
                cidr = MASK_TO_CIDR.get(it.mask, "24")
                out.append(f"set interfaces {junos_name} family inet address {it.ip}/{cidr}")
            if not it.enabled:
                out.append(f"set interfaces {junos_name} disable")
        else:
            # Physical interface
            if it.description:
                out.append(f'set interfaces {junos_name} description "{it.description}"')

            # L3 interface with IP
            if it.ip and it.mask:
                cidr = MASK_TO_CIDR.get(it.mask, "24")
                out.append(f"set interfaces {junos_name} unit 0 family inet address {it.ip}/{cidr}")

            # Switchport configuration (ethernet-switching)
            if it.switchport_mode:
                mode = "access" if it.switchport_mode == "access" else "trunk"
                out.append(f"set interfaces {junos_name} unit 0 family ethernet-switching interface-mode {mode}")

                if it.switchport_mode == "access" and it.access_vlan:
                    # Find VLAN name for this VLAN ID
                    vlan_name = f"VLAN{it.access_vlan}"
                    for v in cfg.vlans:
                        if v.id == str(it.access_vlan):
                            vlan_name = v.name or vlan_name
                            break
                    out.append(f"set interfaces {junos_name} unit 0 family ethernet-switching vlan members {vlan_name}")

                if it.switchport_mode == "trunk":
                    if it.trunk_allowed_vlans:
                        # Parse allowed VLANs and map to names
                        vlan_ids = [v.strip() for v in it.trunk_allowed_vlans.split(',')]
                        for vid in vlan_ids:
                            vlan_name = f"VLAN{vid}"
                            for v in cfg.vlans:
                                if v.id == vid:
                                    vlan_name = v.name or vlan_name
                                    break
                            out.append(f"set interfaces {junos_name} unit 0 family ethernet-switching vlan members {vlan_name}")

                    if it.trunk_native_vlan:
                        out.append(f"set interfaces {junos_name} native-vlan-id {it.trunk_native_vlan}")

            if not it.enabled:
                out.append(f"set interfaces {junos_name} disable")

    out.append("")

    # Static routes
    for route in cfg.static_routes:
        cidr = MASK_TO_CIDR.get(route.mask, "24")
        prefix = route.prefix
        if route.mask != "0.0.0.0":
            # Convert to CIDR notation
            prefix = f"{route.prefix}/{cidr}"
        out.append(f"set routing-options static route {prefix} next-hop {route.next_hop}")

    out.append("")

    # OSPF
    if cfg.ospf_config:
        for net in cfg.ospf_config.networks:
            # Convert wildcard to CIDR
            # Wildcard 0.0.0.255 means /24 (inverted mask)
            # Each 0 in wildcard = 8 bits must match, each 255 = 8 bits don't need to match
            wildcard_octets = net.wildcard.split('.')
            non_match_octets = sum(1 for o in wildcard_octets if o == '255')
            prefix_len = (4 - non_match_octets) * 8

            # Find interface for this network
            iface_name = None
            for iface in cfg.interfaces:
                if iface.ip:
                    # Check if interface IP is in this network
                    net_parts = net.network.split('.')
                    iface_parts = iface.ip.split('.')
                    wild_parts = net.wildcard.split('.')
                    match = True
                    for i in range(4):
                        net_val = int(net_parts[i])
                        iface_val = int(iface_parts[i])
                        wild_val = int(wild_parts[i])
                        if (net_val & ~wild_val) != (iface_val & ~wild_val):
                            match = False
                            break
                    if match:
                        junos_name, _ = cisco_iface_to_junos(iface.index)
                        iface_name = junos_name
                        break

            if iface_name:
                out.append(f"set protocols ospf area {net.area} interface {iface_name}")
            else:
                # Fallback: use the network directly
                out.append(f"set protocols ospf area {net.area} interface {net.network}/{prefix_len}")

        if cfg.ospf_config.router_id:
            out.append(f"set routing-options router-id {cfg.ospf_config.router_id}")

    out.append("")

    # ACLs → Firewall filters
    for acl in cfg.acls:
        filter_name = acl.name
        out.append(f"set firewall family inet filter {filter_name}")

        term_num = 1
        for rule in acl.rules:
            term_name = f"term{term_num}"
            out.append(f"set firewall family inet filter {filter_name} term {term_name} from protocol {rule.protocol}")

            # Source address
            if rule.source != "any":
                src = rule.source
                if rule.source_wildcard:
                    # Convert wildcard to prefix - wildcard is inverted mask
                    # 0.0.0.255 means 255.255.255.0 which is /24
                    # Formula: prefix_len = 32 - popcount(wildcard)
                    wild_octets = rule.source_wildcard.split('.')
                    # Count the number of 255s in wildcard (inverted from normal mask)
                    prefix_len = sum(int(o) for o in wild_octets) // 255
                    # If wildcard is 0.0.0.255, sum=255, so prefix_len = 1 * 8 = 8 bits... wait that's wrong
                    # Actually: wildcard 0.0.0.255 means first 3 octets must match (24 bits)
                    # So prefix_len = 32 - (number of bits that DON'T need to match)
                    # Each 255 in wildcard = 8 bits don't need to match
                    # Each 0 in wildcard = 8 bits must match
                    # So prefix_len = sum of zeros * 8 = (4 - sum(255s)) * 8
                    non_match_octets = sum(1 for o in wild_octets if o == '255')
                    prefix_len = (4 - non_match_octets) * 8
                    src = f"{rule.source}/{prefix_len}"
                out.append(f"set firewall family inet filter {filter_name} term {term_name} from source-address {src}")

            # Destination address
            if rule.dest != "any":
                dst = rule.dest
                if rule.dest_wildcard:
                    wild_octets = rule.dest_wildcard.split('.')
                    non_match_octets = sum(1 for o in wild_octets if o == '255')
                    prefix_len = (4 - non_match_octets) * 8
                    dst = f"{rule.dest}/{prefix_len}"
                out.append(f"set firewall family inet filter {filter_name} term {term_name} from destination-address {dst}")

            # Destination port
            if rule.dest_port:
                out.append(f"set firewall family inet filter {filter_name} term {term_name} from destination-port {rule.dest_port}")

            # Action
            action = "accept" if rule.action == "permit" else "discard"
            out.append(f"set firewall family inet filter {filter_name} term {term_name} then {action}")

            term_num += 1

        # Implicit deny all at the end
        out.append(f"set firewall family inet filter {filter_name} term default-deny then discard")

    out.append("")

    # Apply firewall filters to interfaces
    for iface in cfg.interfaces:
        if iface.acl_in or iface.acl_out:
            junos_name, _ = cisco_iface_to_junos(iface.index)
            if iface.acl_in:
                out.append(f"set interfaces {junos_name} unit 0 family inet filter input {iface.acl_in}")
            if iface.acl_out:
                out.append(f"set interfaces {junos_name} unit 0 family inet filter output {iface.acl_out}")

    out.append("")

    # NAT
    # Build NAT configuration from pools and rules
    if cfg.nat_pools or cfg.nat_rules:
        # Create NAT pools
        for pool in cfg.nat_pools:
            pool_name = pool.name
            out.append(f"set security nat source pool {pool_name} address {pool.start_ip} to {pool.end_ip}")

        # Create NAT rule-sets
        for i, rule in enumerate(cfg.nat_rules):
            rule_set_name = f"nat-ruleset-{i+1}"

            # Determine NAT interfaces
            nat_inside_ifaces = [iface for iface in cfg.interfaces if iface.nat_inside]
            nat_outside_ifaces = [iface for iface in cfg.interfaces if iface.nat_outside]

            if nat_outside_ifaces:
                junos_outside, _ = cisco_iface_to_junos(nat_outside_ifaces[0].index)
                out.append(f"set security nat source rule-set {rule_set_name} to interface {junos_outside}")

            # Create rule
            rule_name = f"rule-{i+1}"
            out.append(f"set security nat source rule-set {rule_set_name} rule {rule_name} match source-address 0.0.0.0/0")

            if rule.interface and rule.overload:
                junos_iface, _ = cisco_iface_to_junos(rule.interface)
                out.append(f"set security nat source rule-set {rule_set_name} rule {rule_name} then source-nat interface")
            elif rule.pool_name:
                out.append(f"set security nat source rule-set {rule_set_name} rule {rule_name} then source-nat pool {rule.pool_name}")

    out.append("")

    # QoS → Class of Service
    if cfg.qos_class_maps or cfg.qos_policy_maps:
        # Map class-maps to forwarding-classes
        fc_num = 1
        class_to_fc = {}
        for cm in cfg.qos_class_maps:
            fc_name = cm.name
            class_to_fc[cm.name] = fc_name
            out.append(f"set class-of-service forwarding-classes class {fc_name} queue-num {fc_num}")
            fc_num += 1

        out.append("")

        # Create classifiers (map DSCP to forwarding-classes)
        classifier_name = "dscp-classifier"
        out.append(f"set class-of-service classifiers dscp {classifier_name}")
        for cm in cfg.qos_class_maps:
            fc_name = class_to_fc[cm.name]
            for crit_type, crit_val in cm.match_criteria:
                if crit_type == 'dscp':
                    out.append(f"set class-of-service classifiers dscp {classifier_name} forwarding-class {fc_name} loss-priority low code-points {crit_val}")

        out.append("")

        # Create schedulers and scheduler-maps
        for pm in cfg.qos_policy_maps:
            sched_map_name = pm.name
            for class_name, actions in pm.classes:
                sched_name = f"{pm.name}-{class_name}"
                for action_type, action_val in actions:
                    if action_type == 'priority':
                        out.append(f"set class-of-service schedulers {sched_name} priority strict-high")
                        out.append(f"set class-of-service schedulers {sched_name} transmit-rate {action_val}%")
                    elif action_type == 'bandwidth':
                        out.append(f"set class-of-service schedulers {sched_name} transmit-rate {action_val}%")
                    elif action_type == 'fair-queue':
                        out.append(f"set class-of-service schedulers {sched_name} transmit-rate remainder")

                # Map scheduler to forwarding-class
                if class_name in class_to_fc:
                    fc_name = class_to_fc[class_name]
                    out.append(f"set class-of-service scheduler-maps {sched_map_name} forwarding-class {fc_name} scheduler {sched_name}")

        out.append("")

        # Apply to interfaces
        for iface in cfg.interfaces:
            if iface.qos_policy_out:
                junos_name, _ = cisco_iface_to_junos(iface.index)
                out.append(f"set class-of-service interfaces {junos_name} scheduler-map {iface.qos_policy_out}")

    out.append("")

    # Flagged items (should be empty after proper conversion)
    if cfg.flagged:
        out.append("# --- FLAGGED FOR MANUAL REVIEW (not auto-converted) ---")
        out += [f"# {l}" for l in cfg.flagged]

    # Run validation
    junos_lines = out
    warnings = validate_junos_config(junos_lines)
    contradictions = validate_no_contradictions(junos_lines)

    if warnings or contradictions:
        out.append("")
        out.append("# === VALIDATION WARNINGS ===")
        for w in warnings:
            out.append(f"# WARNING: {w}")
        for c in contradictions:
            out.append(f"# ERROR: {c}")

    return "\n".join(out)


# --------------------------------------------------------------------------
# FortiOS Generator
# --------------------------------------------------------------------------

def gen_fortios(cfg: NormConfig) -> str:
    """Generate FortiOS configuration from normalized model."""
    out: list[str] = []

    if cfg.hostname:
        out += ["config system global", f'    set hostname "{cfg.hostname}"', "end"]

    if cfg.interfaces:
        out.append("config system interface")
        for i, it in enumerate(cfg.interfaces, start=1):
            # Build a clean FortiOS port name from the source index
            idx = it.index
            if re.match(r'^\d+$', idx):
                # Already a FortiOS numeric index → portN
                port_name = _smart_forti_port_name(idx, it.description)
            elif re.match(r'^[a-z]+-[\d/]+$', idx, re.I):
                # Junos-style: ge-0/0/0 → extract last number as port index
                nums = re.findall(r'\d+', idx)
                port_name = f"port{int(nums[-1]) + 1}" if nums else f"port{i}"
            elif re.match(r'^[A-Z][a-z]+', idx):
                # Cisco-style: GigabitEthernet0/0 → extract trailing numbers
                nums = re.findall(r'\d+', idx)
                port_name = f"port{int(nums[-1]) + 1}" if nums else f"port{i}"
            else:
                port_name = f"port{i}"

            # Description: don't repeat the port name if it's the same
            desc = it.description if it.description and it.description != port_name else None

            out.append(f'    edit "{port_name}"')
            if desc:
                out.append(f'        set alias "{desc}"')
            if it.ip and it.mask:
                out.append(f"        set ip {it.ip} {it.mask}")
            out.append(f"        set status {'up' if it.enabled else 'down'}")
            out.append("    next")
        out.append("end")

    if cfg.vlans:
        out.append("config system vlan")
        for v in cfg.vlans:
            vlan_name = v.name or f"vlan{v.id}"
            out.append(f'    edit "{vlan_name}"')
            out.append(f"        set vlanid {v.id}")
            out.append("    next")
        out.append("end")

    if cfg.flagged:
        out.append("# --- FLAGGED FOR MANUAL REVIEW (not auto-converted) ---")
        out += [f"# {l}" for l in cfg.flagged]

    return "\n".join(out)


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

_PARSERS = {
    "Cisco IOS XE": parse_cisco_iosxe,
    "Juniper Junos": parse_junos,
    "FortiOS": parse_fortios,
}
_GENERATORS = {
    "Cisco IOS XE": gen_cisco_iosxe,
    "Juniper Junos": gen_junos,
    "FortiOS": gen_fortios,
}

# Map short/lowercase vendor names (from the frontend) to canonical names
_VENDOR_ALIASES = {
    "cisco": "Cisco IOS XE",
    "cisco ios xe": "Cisco IOS XE",
    "ios xe": "Cisco IOS XE",
    "iosxe": "Cisco IOS XE",
    "juniper": "Juniper Junos",
    "juniper junos": "Juniper Junos",
    "junos": "Juniper Junos",
    "fortinet": "FortiOS",
    "fortios": "FortiOS",
    "fortigate": "FortiOS",
}


def _normalize_vendor(name: str) -> str:
    """Resolve a vendor string (short, lowercase, or canonical) to its canonical name."""
    key = name.strip().lower()
    if key in _VENDOR_ALIASES:
        return _VENDOR_ALIASES[key]
    # Also try case-insensitive match against canonical names
    for canonical in _PARSERS:
        if canonical.lower() == key:
            return canonical
    raise ValueError(f"Unsupported vendor: {name}")


def get_supported_pairs() -> list:
    """Return the list of supported source→target conversion pairs."""
    vendors = list(_PARSERS.keys())
    pairs = []
    for src in vendors:
        for tgt in vendors:
            if src != tgt:
                pairs.append({"source": src, "target": tgt})
    return pairs


# --------------------------------------------------------------------------
# Security posture checker
# --------------------------------------------------------------------------

# Keywords that identify ACL/NAT/QoS/security output lines that should always
# be flagged for human review even if syntactically converted correctly.
_REVIEW_KEYWORDS = [
    # Junos
    "firewall family", "security nat", "class-of-service", "scheduler",
    "firewall filter", "source-nat", "destination-nat",
    # Cisco
    "access-list", "ip nat", "policy-map", "class-map", "service-policy",
    "route-map", "permit", "deny",
    # FortiOS
    "config firewall", "config router",
]


def _security_posture_review(normalized: NormConfig) -> list:
    """
    Inspect the parsed config and return a list of security/best-practice
    review items that the operator should address before deployment.

    Each item is a dict: {converted, status, tier, reason}
    """
    items = []

    # ── SSH ────────────────────────────────────────────────────────────────
    if not normalized.sys_config.ssh_enabled:
        items.append({
            "converted": "SSH not configured",
            "status": "needs_review",
            "tier": "tier3",
            "reason": "SECURITY: No SSH configuration detected. Remote management without SSH is a risk.",
        })
    elif normalized.sys_config.ssh_version and normalized.sys_config.ssh_version < 2:
        items.append({
            "converted": f"SSH version {normalized.sys_config.ssh_version} in use",
            "status": "needs_review",
            "tier": "tier3",
            "reason": "SECURITY: SSH v1 is deprecated and vulnerable. Upgrade to SSH v2.",
        })

    # ── Telnet ─────────────────────────────────────────────────────────────
    if normalized.sys_config.telnet_enabled:
        items.append({
            "converted": "Telnet is enabled",
            "status": "needs_review",
            "tier": "tier3",
            "reason": "CRITICAL: Telnet transmits credentials in plaintext. Disable telnet and use SSH.",
        })

    # ── NTP ────────────────────────────────────────────────────────────────
    if not normalized.sys_config.ntp_servers:
        items.append({
            "converted": "No NTP servers configured",
            "status": "needs_review",
            "tier": "tier2",
            "reason": "WARNING: Without NTP, log timestamps and certificate validity checks are unreliable.",
        })

    # ── Logging/Syslog ─────────────────────────────────────────────────────
    if not normalized.sys_config.syslog_hosts:
        items.append({
            "converted": "No syslog server configured",
            "status": "needs_review",
            "tier": "tier2",
            "reason": "WARNING: Centralized logging is required for incident detection and CERT-In compliance.",
        })

    # ── ACLs ───────────────────────────────────────────────────────────────
    if normalized.acls:
        for acl in normalized.acls:
            items.append({
                "converted": f"ACL '{acl.name}' ({len(acl.rules)} rules)",
                "status": "needs_review",
                "tier": "tier2",
                "reason": "ACL converted structurally but rule semantics must be verified manually before deployment.",
            })

    # ── NAT ────────────────────────────────────────────────────────────────
    if normalized.nat_pools or normalized.nat_rules:
        items.append({
            "converted": f"NAT config ({len(normalized.nat_rules)} rule(s), {len(normalized.nat_pools)} pool(s))",
            "status": "needs_review",
            "tier": "tier2",
            "reason": "NAT translated structurally — verify inside/outside interface assignments and overload behaviour.",
        })

    # ── QoS ────────────────────────────────────────────────────────────────
    if normalized.qos_class_maps or normalized.qos_policy_maps:
        items.append({
            "converted": f"QoS policy ({len(normalized.qos_policy_maps)} policy-map(s))",
            "status": "needs_review",
            "tier": "tier2",
            "reason": "QoS scheduling/shaping values differ between vendors — verify queue mappings manually.",
        })

    # ── OSPF ───────────────────────────────────────────────────────────────
    if normalized.ospf_config:
        if not normalized.ospf_config.router_id:
            items.append({
                "converted": "OSPF router-id not set",
                "status": "needs_review",
                "tier": "tier2",
                "reason": "WARNING: No explicit OSPF router-id — the router will auto-select one which can change on reboot.",
            })

    # ── Interfaces without IPs or descriptions ─────────────────────────────
    for iface in normalized.interfaces:
        if not iface.description:
            items.append({
                "converted": f"Interface {iface.index} has no description",
                "status": "needs_review",
                "tier": "tier2",
                "reason": "BEST PRACTICE: All interfaces should have a description for operational clarity.",
            })

    # ── Skipped/unrecognized input lines ───────────────────────────────────
    for skipped in normalized.skipped_lines:
        if " (Invalid IPv4" in skipped:
            cmd, reason = skipped.split(" (", 1)
            clean_reason = reason.rstrip(")")
            items.append({
                "converted": cmd.strip(),
                "status": "not_supported",
                "tier": "tier3",
                "reason": f"Syntax error: {clean_reason}",
            })
        else:
            items.append({
                "converted": skipped,
                "status": "not_supported",
                "tier": "tier3",
                "reason": f"Syntax error or unrecognized command in uploaded configuration: '{skipped}' was not recognized and could not be converted.",
            })

    # ── Parser-flagged items (e.g. FortiOS firewall/router blocks) ──────────
    for note in normalized.review_notes:
        items.append({
            "converted": note,
            "status": "needs_review",
            "tier": "tier2",
            "reason": "Flagged by parser — requires manual review.",
        })

    return items


def _is_review_line(line: str) -> bool:
    """Return True if a converted output line represents ACL/NAT/QoS/security
    content that should always be flagged for human review."""
    low = line.lower()
    return any(kw in low for kw in _REVIEW_KEYWORDS)


def convert_config(source_vendor: str, target_vendor: str, config_text: str) -> dict:
    """Convert configuration from source vendor to target vendor."""
    source_vendor = _normalize_vendor(source_vendor)
    target_vendor = _normalize_vendor(target_vendor)

    # Source == target → passthrough
    if source_vendor == target_vendor:
        input_lines = [l for l in config_text.splitlines() if l.strip()]
        return {
            "output_config": config_text,
            "converted_config": config_text,
            "lines": [{"converted": l, "status": "converted", "tier": "tier1"}
                       for l in input_lines],
            "flagged_items": [],
            "flagged_count": 0,
            "commands_converted": len(input_lines),
            "commands_need_review": 0,
            "conversion_accuracy": 100,
            "review_items": [],
        }

    if source_vendor not in _PARSERS:
        raise ValueError(f"Unsupported source vendor: {source_vendor}")
    if target_vendor not in _GENERATORS:
        raise ValueError(f"Unsupported target vendor: {target_vendor}")

    normalized = _PARSERS[source_vendor](config_text)

    # Detect zero-parameters-parsed
    total_parsed = (
        len(normalized.interfaces) +
        len(normalized.vlans) +
        len(normalized.static_routes) +
        len(normalized.acls) +
        len(normalized.nat_pools) +
        len(normalized.nat_rules) +
        len(normalized.qos_class_maps) +
        len(normalized.qos_policy_maps) +
        (1 if normalized.hostname else 0) +
        (1 if normalized.ospf_config else 0) +
        len(normalized.sys_config.ntp_servers) +
        len(normalized.sys_config.syslog_hosts) +
        len(normalized.sys_config.tacacs_servers)
    )
    if total_parsed == 0 and not normalized.flagged:
        raise ValueError(
            f"No recognizable configuration parameters found in input for source type '{source_vendor}'. "
            f"Ensure the input is a valid {source_vendor} configuration."
        )

    converted = _GENERATORS[target_vendor](normalized)

    # ── Build per-line output with status info ──────────────────────────────
    lines = []
    for line in converted.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip generator-emitted section headers (not real commands)
        if "FLAGGED FOR MANUAL REVIEW" in stripped:
            continue
        if "VALIDATION WARNINGS" in stripped:
            continue
        if stripped.startswith("# WARNING:") or stripped.startswith("# ERROR:"):
            continue

        # Commented-out lines ("! cmd" / "# cmd") are explicit review items
        if (stripped.startswith("!") or stripped.startswith("#")) and len(stripped) > 1:
            raw_cmd = stripped.lstrip("!# ")
            if raw_cmd:
                lines.append({
                    "converted": raw_cmd,
                    "status": "needs_review",
                    "tier": "tier2",
                    "reason": "Requires manual review — complex rule not auto-converted",
                })
            continue

        # ACL/NAT/QoS/security lines: always flag even if syntactically converted
        if _is_review_line(stripped):
            lines.append({
                "converted": stripped,
                "status": "needs_review",
                "tier": "tier2",
                "reason": "ACL/NAT/QoS/security directive — verify semantics before deployment",
            })
        else:
            lines.append({"converted": stripped, "status": "converted", "tier": "tier1"})

    # ── Security posture + unrecognized-line review items ───────────────────
    review_items = _security_posture_review(normalized)

    converted_count = sum(1 for l in lines if l["status"] == "converted")
    review_count = (
        sum(1 for l in lines if l["status"] in ("needs_review", "not_supported"))
        + len(review_items)
    )
    total_count = converted_count + review_count
    accuracy = round(converted_count / total_count * 100) if total_count else 0

    return {
        "output_config": converted,
        "converted_config": converted,
        "lines": lines,
        "flagged_items": normalized.flagged,
        "flagged_count": len(normalized.flagged),
        "commands_converted": converted_count,
        "commands_need_review": review_count,
        "conversion_accuracy": accuracy,
        # Structured review items shown in the UI review panel
        "review_items": review_items,
    }
