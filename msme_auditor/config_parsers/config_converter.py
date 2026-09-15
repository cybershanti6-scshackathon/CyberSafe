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

    lines = text.split('\n')

    for raw in lines:
        line = raw.rstrip('\r')
        trimmed = line.strip()
        if not trimmed:
            continue

        # Track OSPF router section
        if re.match(r'^router\s+ospf\s+(\d+)', trimmed, re.I):
            m = re.match(r'^router\s+ospf\s+(\d+)', trimmed, re.I)
            cfg.ospf_config = NormOspfConfig(process_id=m.group(1))
            in_router_ospf = True
            continue

        if in_router_ospf:
            if trimmed.startswith('!') or trimmed.startswith('router ') and not trimmed.startswith('router ospf'):
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
                continue

        # Track class-map section
        m = re.match(r'^class-map\s+(match-all|match-any)\s+(\S+)', trimmed, re.I)
        if m:
            cur_class_map = NormQosClassMap(name=m.group(2), match_type=m.group(1))
            in_class_map = True
            continue

        if in_class_map:
            if trimmed.startswith('!') or re.match(r'^(class-map|policy-map)\s+', trimmed, re.I):
                if cur_class_map:
                    cfg.qos_class_maps.append(cur_class_map)
                    cur_class_map = None
                in_class_map = False
            else:
                m = re.match(r'^match\s+(?:dscp\s+)?(\S+)', trimmed, re.I)
                if m and cur_class_map:
                    cur_class_map.match_criteria.append(('dscp', m.group(1)))
                continue

        # Track policy-map section
        m = re.match(r'^policy-map\s+(\S+)', trimmed, re.I)
        if m:
            cur_policy_map = NormQosPolicyMap(name=m.group(1))
            in_policy_map = True
            continue

        if in_policy_map:
            if trimmed.startswith('!') or re.match(r'^policy-map\s+', trimmed, re.I):
                if cur_policy_map:
                    cfg.qos_policy_maps.append(cur_policy_map)
                    cur_policy_map = None
                in_policy_map = False
                in_policy_class_block = False
            else:
                m = re.match(r'^class\s+(\S+)', trimmed, re.I)
                if m:
                    cur_policy_class = m.group(1)
                    in_policy_class_block = True
                    continue
                if in_policy_class_block and cur_policy_map and cur_policy_class:
                    # Parse policy actions
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

        # VLAN definitions
        if trimmed in ('!', 'exit'):
            if cur_iface:
                cfg.interfaces.append(cur_iface)
                cur_iface = None
            if cur_vlan:
                cfg.vlans.append(cur_vlan)
                cur_vlan = None
            if cur_acl:
                cfg.acls.append(cur_acl)
                cur_acl = None
            continue

        # Hostname
        m = re.match(r'^hostname\s+(\S+)', trimmed, re.I)
        if m:
            cfg.hostname = m.group(1)
            cfg.sys_config.hostname = m.group(1)
            continue

        # Domain name
        m = re.match(r'^ip\s+domain-name\s+(\S+)', trimmed, re.I)
        if m:
            cfg.sys_config.domain_name = m.group(1)
            continue

        # SSH configuration
        m = re.match(r'^ip\s+ssh\s+version\s+(\d+)', trimmed, re.I)
        if m:
            cfg.sys_config.ssh_enabled = True
            cfg.sys_config.ssh_version = int(m.group(1))
            continue

        m = re.match(r'^ip\s+ssh\s+time-out\s+(\d+)', trimmed, re.I)
        if m:
            cfg.sys_config.ssh_timeout = int(m.group(1))
            cfg.sys_config.ssh_enabled = True
            continue

        m = re.match(r'^ip\s+ssh\s+authentication-retries\s+(\d+)', trimmed, re.I)
        if m:
            cfg.sys_config.ssh_retries = int(m.group(1))
            cfg.sys_config.ssh_enabled = True
            continue

        if re.match(r'^crypto\s+key\s+generate\s+rsa', trimmed, re.I):
            cfg.sys_config.ssh_enabled = True
            continue

        # NTP servers
        m = re.match(r'^ntp\s+server\s+(\S+)(?:\s+prefer)?', trimmed, re.I)
        if m:
            cfg.sys_config.ntp_servers.append(m.group(1))
            continue

        # Syslog configuration
        m = re.match(r'^logging\s+host\s+(\S+)', trimmed, re.I)
        if m:
            cfg.sys_config.syslog_hosts.append(m.group(1))
            continue

        m = re.match(r'^logging\s+trap\s+(\S+)', trimmed, re.I)
        if m:
            cfg.sys_config.syslog_level = m.group(1)
            continue

        m = re.match(r'^logging\s+buffered\s+(\d+)', trimmed, re.I)
        if m:
            cfg.sys_config.syslog_buffered_size = int(m.group(1))
            continue

        m = re.match(r'^logging\s+source-interface\s+(\S+)', trimmed, re.I)
        if m:
            cfg.sys_config.syslog_source_interface = m.group(1)
            continue

        # TACACS configuration
        m = re.match(r'^tacacs-server\s+host\s+(\S+)', trimmed, re.I)
        if m:
            cfg.sys_config.tacacs_servers.append(m.group(1))
            continue

        m = re.match(r'^tacacs-server\s+key\s+(?:\d+\s+)?(\S+)', trimmed, re.I)
        if m:
            cfg.sys_config.tacacs_key = m.group(1)
            continue

        # AAA configuration
        m = re.match(r'^aaa\s+authentication\s+login\s+\S+\s+(.+)', trimmed, re.I)
        if m:
            cfg.sys_config.aaa_auth_login = m.group(1)
            continue

        m = re.match(r'^aaa\s+authorization\s+exec\s+\S+\s+(.+)', trimmed, re.I)
        if m:
            cfg.sys_config.aaa_auth_exec = m.group(1)
            continue

        # Static routes
        m = re.match(r'^ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)', trimmed, re.I)
        if m:
            cfg.static_routes.append(NormStaticRoute(
                prefix=m.group(1),
                mask=m.group(2),
                next_hop=m.group(3)
            ))
            continue

        # VLANs
        m = re.match(r'^vlan\s+(\d+)', trimmed, re.I)
        if m:
            if cur_vlan:
                cfg.vlans.append(cur_vlan)
            cur_vlan = NormVlan(id=m.group(1))
            continue

        if cur_vlan:
            m = re.match(r'^name\s+(.+)$', trimmed, re.I)
            if m:
                cur_vlan.name = m.group(1)
                continue

        # Interfaces
        m = re.match(r'^interface\s+(\S+)\s*$', trimmed, re.I)
        if m:
            # Check if we have a current interface to save
            if cur_iface:
                # Check if this interface already exists in the config
                existing_idx = -1
                for i, existing in enumerate(cfg.interfaces):
                    if existing.index == cur_iface.index:
                        existing_idx = i
                        break

                if existing_idx >= 0:
                    # Update existing interface
                    cfg.interfaces[existing_idx] = cur_iface
                else:
                    # Add new interface
                    cfg.interfaces.append(cur_iface)

            iface_name = m.group(1)
            is_vlan_svi = iface_name.lower().startswith('vlan')
            vlan_id = None

            if is_vlan_svi:
                vlan_id_match = re.match(r'vlan(\d+)', iface_name, re.I)
                if vlan_id_match:
                    vlan_id = int(vlan_id_match.group(1))

            # Check if this interface already exists
            existing_iface = None
            for existing in cfg.interfaces:
                if existing.index == iface_name:
                    existing_iface = existing
                    break

            if existing_iface:
                # Use existing interface
                cur_iface = existing_iface
            else:
                # Create new interface
                cur_iface = NormInterface(
                    index=iface_name,
                    enabled=False,
                    is_vlan_svi=is_vlan_svi,
                    vlan_id=vlan_id
                )
            continue

        if cur_iface:
            # Interface description
            m = re.match(r'^description\s+(.+)$', trimmed, re.I)
            if m:
                cur_iface.description = m.group(1)
                continue

            # IP address
            m = re.match(r'^ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', trimmed, re.I)
            if m:
                cur_iface.ip = m.group(1)
                cur_iface.mask = m.group(2)
                continue

            # Shutdown status
            if re.match(r'^no\s+shutdown', trimmed, re.I):
                cur_iface.enabled = True
                continue
            if re.match(r'^shutdown$', trimmed, re.I):
                cur_iface.enabled = False
                continue

            # Switchport mode
            m = re.match(r'^switchport\s+mode\s+(access|trunk)', trimmed, re.I)
            if m:
                cur_iface.switchport_mode = m.group(1).lower()
                continue

            # Switchport access vlan
            m = re.match(r'^switchport\s+access\s+vlan\s+(\d+)', trimmed, re.I)
            if m:
                cur_iface.access_vlan = int(m.group(1))
                continue

            # Switchport trunk allowed vlan
            m = re.match(r'^switchport\s+trunk\s+allowed\s+vlan\s+(.+)$', trimmed, re.I)
            if m:
                cur_iface.trunk_allowed_vlans = m.group(1)
                continue

            # Switchport trunk native vlan
            m = re.match(r'^switchport\s+trunk\s+native\s+vlan\s+(\d+)', trimmed, re.I)
            if m:
                cur_iface.trunk_native_vlan = int(m.group(1))
                continue

            # NAT inside/outside
            if re.match(r'^ip\s+nat\s+inside', trimmed, re.I):
                cur_iface.nat_inside = True
                continue
            if re.match(r'^ip\s+nat\s+outside', trimmed, re.I):
                cur_iface.nat_outside = True
                continue

            # ACL on interface
            m = re.match(r'^ip\s+access-group\s+(\S+)\s+(in|out)', trimmed, re.I)
            if m:
                if m.group(2).lower() == 'in':
                    cur_iface.acl_in = m.group(1)
                else:
                    cur_iface.acl_out = m.group(1)
                continue

            # QoS service-policy on interface
            m = re.match(r'^service-policy\s+output\s+(\S+)', trimmed, re.I)
            if m:
                cur_iface.qos_policy_out = m.group(1)
                continue

        # ACLs - extended
        m = re.match(r'^ip\s+access-list\s+extended\s+(\S+)', trimmed, re.I)
        if m:
            if cur_acl:
                cfg.acls.append(cur_acl)
            cur_acl = NormAcl(name=m.group(1), type='extended')
            continue

        # ACLs - standard
        m = re.match(r'^ip\s+access-list\s+standard\s+(\S+)', trimmed, re.I)
        if m:
            if cur_acl:
                cfg.acls.append(cur_acl)
            cur_acl = NormAcl(name=m.group(1), type='standard')
            continue

        # ACL rules (inside ACL block)
        if cur_acl:
            # Extended ACL: permit/deny protocol src [wildcard] dest [wildcard] [operator port]
            # Parse step by step to avoid greedy matching issues
            m = re.match(r'^(permit|deny)\s+(ip|tcp|udp|icmp)\s+(.+)$', trimmed, re.I)
            if m:
                action = m.group(1).lower()
                protocol = m.group(2).lower()
                rest = m.group(3).strip()

                # Parse source and destination
                parts = rest.split()
                source = parts[0] if parts else 'any'
                source_wildcard = None
                dest = 'any'
                dest_wildcard = None
                dest_port = None
                log = 'log' in trimmed.lower()

                idx = 1
                # Source wildcard (if next part is an IP-like pattern, not 'any' or 'host')
                if idx < len(parts) and not parts[idx] in ('any', 'host') and re.match(r'^\d+\.', parts[idx]):
                    source_wildcard = parts[idx]
                    idx += 1

                # Skip 'host' keyword
                if idx < len(parts) and parts[idx] == 'host':
                    idx += 1

                # Destination
                if idx < len(parts):
                    dest = parts[idx]
                    idx += 1

                # Destination wildcard
                if idx < len(parts) and re.match(r'^\d+\.', parts[idx]):
                    dest_wildcard = parts[idx]
                    idx += 1

                # Check for port specification (eq X)
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

            # Standard ACL simpler format
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

        # NAT pools
        m = re.match(r'^ip\s+nat\s+pool\s+(\S+)\s+(\S+)\s+(\S+)\s+netmask\s+(\S+)', trimmed, re.I)
        if m:
            cfg.nat_pools.append(NormNatPool(
                name=m.group(1),
                start_ip=m.group(2),
                end_ip=m.group(3),
                netmask=m.group(4)
            ))
            continue

        # NAT rules
        m = re.match(r'^ip\s+nat\s+inside\s+source\s+list\s+(\S+)\s+interface\s+(\S+)\s+overload', trimmed, re.I)
        if m:
            cfg.nat_rules.append(NormNatRule(
                acl_name=m.group(1),
                interface=m.group(2),
                overload=True
            ))
            continue

        m = re.match(r'^ip\s+nat\s+inside\s+source\s+list\s+(\S+)\s+pool\s+(\S+)', trimmed, re.I)
        if m:
            cfg.nat_rules.append(NormNatRule(
                acl_name=m.group(1),
                pool_name=m.group(2)
            ))
            continue

    # Flush remaining items
    if cur_iface:
        cfg.interfaces.append(cur_iface)
    if cur_vlan:
        cfg.vlans.append(cur_vlan)
    if cur_acl:
        cfg.acls.append(cur_acl)
    if cur_class_map:
        cfg.qos_class_maps.append(cur_class_map)
    if cur_policy_map:
        cfg.qos_policy_maps.append(cur_policy_map)

    return cfg


# --------------------------------------------------------------------------
# Junos Parser
# --------------------------------------------------------------------------

def parse_junos(text: str) -> NormConfig:
    """Parse Juniper Junos configuration into normalized model."""
    cfg = NormConfig()
    iface_map: dict[str, NormInterface] = {}
    vlan_map: dict[str, NormVlan] = {}

    for raw in text.split('\n'):
        line = raw.strip()
        if not line:
            continue

        # Hostname
        m = re.match(r'^set\s+system\s+host-name\s+(\S+)', line, re.I)
        if m:
            cfg.hostname = m.group(1)
            cfg.sys_config.hostname = m.group(1)
            continue

        # Interface description
        m = re.match(r'^set\s+interfaces\s+(\S+)\s+description\s+"([^"]+)"', line, re.I)
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.description = m.group(2)
            continue

        # Interface IP
        m = re.match(
            r'^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+inet\s+address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)',
            line, re.I
        )
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.ip = m.group(2)
            it.mask = CIDR_TO_MASK.get(m.group(3), "255.255.255.0")
            continue

        # Interface disable
        m = re.match(r'^set\s+interfaces\s+(\S+)\s+disable', line, re.I)
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

    cfg.interfaces = list(iface_map.values())
    cfg.vlans = list(vlan_map.values())
    return cfg


# --------------------------------------------------------------------------
# FortiOS Parser
# --------------------------------------------------------------------------

def parse_fortios(text: str) -> NormConfig:
    """Parse FortiOS configuration into normalized model."""
    cfg = NormConfig()
    context: Optional[str] = None
    cur_iface: Optional[NormInterface] = None
    cur_vlan: Optional[NormVlan] = None
    port_counter = 0
    port_index_of: dict[str, str] = {}

    for raw in text.split('\n'):
        line = raw.strip()
        if not line:
            continue

        if re.match(r'^config\s+system\s+global', line, re.I):
            context = "global"
            continue
        if re.match(r'^config\s+system\s+interface', line, re.I):
            context = "interface"
            continue
        if re.match(r'^config\s+(system\s+vlan|vlan)', line, re.I):
            context = "vlan"
            continue
        if re.match(r'^config\s+(firewall|router)', line, re.I):
            context = "flagged"
            cfg.flagged.append(line)
            continue
        if re.match(r'^end$', line, re.I):
            context = None
            continue

        if context == "flagged":
            cfg.flagged.append(line)
            continue

        if context == "global":
            m = re.match(r'^set\s+hostname\s+"([^"]+)"', line, re.I)
            if m:
                cfg.hostname = m.group(1)
                cfg.sys_config.hostname = m.group(1)
            continue

        if context == "interface":
            m = re.match(r'^edit\s+"([^"]+)"', line, re.I)
            if m:
                if cur_iface:
                    cfg.interfaces.append(cur_iface)
                port_name = m.group(1)
                if port_name not in port_index_of:
                    port_counter += 1
                    port_index_of[port_name] = str(port_counter)
                cur_iface = NormInterface(index=port_index_of[port_name], enabled=True)
                continue
            if re.match(r'^next$', line, re.I):
                if cur_iface:
                    cfg.interfaces.append(cur_iface)
                cur_iface = None
                continue
            if cur_iface:
                m = re.match(r'^set\s+alias\s+"([^"]+)"', line, re.I)
                if m:
                    cur_iface.description = m.group(1)
                    continue
                m = re.match(r'^set\s+ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', line, re.I)
                if m:
                    cur_iface.ip = m.group(1)
                    cur_iface.mask = m.group(2)
                    continue
                m = re.match(r'^set\s+status\s+(up|down)', line, re.I)
                if m:
                    cur_iface.enabled = m.group(1).lower() == "up"
                    continue
            continue

        if context == "vlan":
            m = re.match(r'^edit\s+"([^"]+)"', line, re.I)
            if m:
                if cur_vlan:
                    cfg.vlans.append(cur_vlan)
                cur_vlan = NormVlan(id=m.group(1))
                continue
            if re.match(r'^next$', line, re.I):
                if cur_vlan:
                    cfg.vlans.append(cur_vlan)
                cur_vlan = None
                continue
            continue

    if cur_iface:
        cfg.interfaces.append(cur_iface)
    if cur_vlan:
        cfg.vlans.append(cur_vlan)
    return cfg


# --------------------------------------------------------------------------
# Cisco IOS XE Generator
# --------------------------------------------------------------------------

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

    # Interfaces
    for it in cfg.interfaces:
        out.append(f"interface {it.index}")
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

    # Interfaces
    for it in cfg.interfaces:
        junos_name, is_irb = cisco_iface_to_junos(it.index)

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
        for it in cfg.interfaces:
            port_num = re.sub(r"\D", "", it.index) or it.index
            out.append(f'    edit "port{port_num}"')
            if it.description:
                out.append(f'        set alias "{it.description}"')
            if it.ip and it.mask:
                out.append(f"        set ip {it.ip} {it.mask}")
            out.append(f"        set status {'up' if it.enabled else 'down'}")
            out.append("    next")
        out.append("end")

    if cfg.vlans:
        out.append("config system interface")
        for v in cfg.vlans:
            out.append(f'    edit "{v.name or "vlan" + v.id}"')
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


def convert_config(source_vendor: str, target_vendor: str, config_text: str) -> dict:
    """Convert configuration from source vendor to target vendor."""
    source_vendor = _normalize_vendor(source_vendor)
    target_vendor = _normalize_vendor(target_vendor)

    # Source == target → passthrough
    if source_vendor == target_vendor:
        return {
            "output_config": config_text,
            "converted_config": config_text,
            "lines": [{"converted": l, "status": "converted", "tier": "tier1"}
                       for l in config_text.splitlines() if l.strip()],
            "flagged_items": [],
            "flagged_count": 0,
            "commands_converted": len([l for l in config_text.splitlines() if l.strip()]),
            "commands_need_review": 0,
            "conversion_accuracy": 100,
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

    # Build per-line output with status info
    lines = []
    for line in converted.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip the "FLAGGED FOR MANUAL REVIEW" header emitted by the generators
        if "FLAGGED FOR MANUAL REVIEW" in stripped:
            continue
        # Skip validation warnings section
        if "VALIDATION WARNINGS" in stripped:
            continue
        if stripped.startswith("# WARNING:") or stripped.startswith("# ERROR:"):
            continue
        # A commented-out command ("! cmd" / "# cmd") is a flagged review item.
        # A standalone "!" or "#" is just a structural separator — not a review item.
        if (stripped.startswith("!") or stripped.startswith("#")) and len(stripped) > 1:
            raw_cmd = stripped.lstrip("!# ")
            if raw_cmd:
                lines.append({
                    "converted": raw_cmd,
                    "status": "needs_review",
                    "tier": "tier2" if any(kw in raw_cmd.upper() for kw in ["ACCESS-LIST", "NAT", "PERMIT", "DENY", "ROUTE-MAP", "CLASS-MAP", "POLICY-MAP", "SERVICE-POLICY"]) else "tier3",
                    "reason": "Requires manual review — ACL/NAT/QoS rules should not be auto-converted",
                })
        else:
            lines.append({"converted": stripped, "status": "converted", "tier": "tier1"})

    converted_count = sum(1 for l in lines if l["status"] == "converted")
    review_count = sum(1 for l in lines if l["status"] in ("needs_review", "not_supported"))
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
    }
