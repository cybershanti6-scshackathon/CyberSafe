"""Vendor-neutral network config converter.

Parses Cisco IOS XE / Juniper Junos / FortiOS configuration text into a
shared normalized structure, then re-emits it in the target vendor's
syntax. ACLs, NAT, QoS, route-maps, and firewall policies are NOT
auto-translated — they are pulled out and returned as flagged items for
manual review, since blindly translating security-rule semantics across
vendors is unsafe.

Add this file to your FastAPI backend (e.g. app/config_converter.py) and
import `convert_config` from your route.
"""
"""
Vendor-neutral network config converter.

Parses Cisco IOS XE / Juniper Junos / FortiOS configuration text into a
shared normalized structure, then re-emits it in the target vendor's
syntax. ACLs, NAT, QoS, route-maps, and firewall policies are NOT
auto-translated — they are pulled out and returned as flagged items for
manual review, since blindly translating security-rule semantics across
vendors is unsafe.

Add this file to your FastAPI backend (e.g. app/config_converter.py) and
import `convert_config` from your route.
"""
"""
Vendor-neutral network config converter.

Parses Cisco IOS XE / Juniper Junos / FortiOS configuration text into a
shared normalized structure, then re-emits it in the target vendor's
syntax. ACLs, NAT, QoS, route-maps, and firewall policies are NOT
auto-translated — they are pulled out and returned as flagged items for
manual review, since blindly translating security-rule semantics across
vendors is unsafe.

Add this file to your FastAPI backend (e.g. app/config_converter.py) and
import `convert_config` from your route.
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Normalized model
# --------------------------------------------------------------------------

@dataclass
class NormInterface:
    index: str
    description: Optional[str] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    enabled: bool = False


@dataclass
class NormVlan:
    id: str
    name: Optional[str] = None


@dataclass
class NormConfig:
    hostname: Optional[str] = None
    interfaces: list[NormInterface] = field(default_factory=list)
    vlans: list[NormVlan] = field(default_factory=list)
    flagged: list[str] = field(default_factory=list)


CIDR_TO_MASK = {
    "8": "255.0.0.0", "16": "255.255.0.0", "24": "255.255.255.0",
    "25": "255.255.255.128", "26": "255.255.255.192", "27": "255.255.255.224",
    "28": "255.255.255.240", "30": "255.255.255.252", "32": "255.255.255.255",
}
MASK_TO_CIDR = {v: k for k, v in CIDR_TO_MASK.items()}

FLAG_PATTERNS = [
    re.compile(r"^\s*(ip )?access-list", re.I),
    re.compile(r"^\s*(permit|deny)\s", re.I),
    re.compile(r"^\s*ip nat", re.I),
    re.compile(r"^\s*nat\b", re.I),
    re.compile(r"^\s*route-map", re.I),
    re.compile(r"^\s*class-map", re.I),
    re.compile(r"^\s*policy-map", re.I),
    re.compile(r"^\s*config firewall (policy|nat)", re.I),
    re.compile(r"^\s*set firewall (filter|policer)", re.I),
    re.compile(r"^\s*set (source-nat|destination-nat|static-nat)", re.I),
    re.compile(r"^\s*set security nat", re.I),
    re.compile(r"^\s*service-policy", re.I),
]


def is_flagged_line(line: str) -> bool:
    return any(p.search(line) for p in FLAG_PATTERNS)


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------

def parse_cisco_iosxe(text: str) -> NormConfig:
    cfg = NormConfig()
    cur_iface: Optional[NormInterface] = None
    cur_vlan: Optional[NormVlan] = None
    in_flagged_block = False

    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        trimmed = line.strip()
        if not trimmed:
            continue

        if trimmed in ("!", "exit"):
            if cur_iface:
                cfg.interfaces.append(cur_iface)
            cur_iface = None
            cur_vlan = None
            in_flagged_block = False
            continue

        if is_flagged_line(trimmed):
            cfg.flagged.append(trimmed)
            in_flagged_block = True
            continue
        if in_flagged_block and re.match(r"^\s+\S", line):
            cfg.flagged.append(trimmed)
            continue

        m = re.match(r"^hostname\s+(\S+)", trimmed, re.I)
        if m:
            cfg.hostname = m.group(1)
            continue

        m = re.match(r"^interface\s+\S+?(\d+/\d+|\d+)\s*$", trimmed, re.I)
        if m:
            if cur_iface:
                cfg.interfaces.append(cur_iface)
            cur_iface = NormInterface(index=m.group(1), enabled=False)
            continue

        m = re.match(r"^vlan\s+(\d+)", trimmed, re.I)
        if m:
            if cur_vlan:
                cfg.vlans.append(cur_vlan)
            cur_vlan = NormVlan(id=m.group(1))
            continue

        if cur_vlan:
            m = re.match(r"^name\s+(\S+)", trimmed, re.I)
            if m:
                cur_vlan.name = m.group(1)
                continue

        if cur_iface:
            m = re.match(r"^description\s+(.+)", trimmed, re.I)
            if m:
                cur_iface.description = m.group(1)
                continue
            m = re.match(r"^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", trimmed, re.I)
            if m:
                cur_iface.ip, cur_iface.mask = m.group(1), m.group(2)
                continue
            if re.match(r"^no shutdown", trimmed, re.I):
                cur_iface.enabled = True
                continue
            if re.match(r"^shutdown", trimmed, re.I):
                cur_iface.enabled = False
                continue

    if cur_iface:
        cfg.interfaces.append(cur_iface)
    if cur_vlan:
        cfg.vlans.append(cur_vlan)
    return cfg


def parse_junos(text: str) -> NormConfig:
    cfg = NormConfig()
    iface_map: dict[str, NormInterface] = {}
    vlan_map: dict[str, NormVlan] = {}

    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue
        if is_flagged_line(line):
            cfg.flagged.append(line)
            continue

        m = re.match(r"^set system host-name\s+(\S+)", line, re.I)
        if m:
            cfg.hostname = m.group(1)
            continue

        m = re.match(r'^set interfaces\s+\S*?(\d+/\d+|\d+)\s+description\s+"?([^"]+)"?', line, re.I)
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.description = m.group(2)
            continue

        m = re.match(
            r"^set interfaces\s+\S*?(\d+/\d+|\d+)\s+unit\s+\d+\s+family inet address\s+(\d+\.\d+\.\d+\.\d+)/(\d+)",
            line, re.I,
        )
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.ip = m.group(2)
            it.mask = CIDR_TO_MASK.get(m.group(3), "255.255.255.0")
            continue

        m = re.match(r"^set interfaces\s+\S*?(\d+/\d+|\d+)\s+disable", line, re.I)
        if m:
            idx = m.group(1)
            it = iface_map.setdefault(idx, NormInterface(index=idx, enabled=True))
            it.enabled = False
            continue

        m = re.match(r"^set vlans\s+(\S+)\s+vlan-id\s+(\d+)", line, re.I)
        if m:
            vlan_map[m.group(2)] = NormVlan(id=m.group(2), name=m.group(1))
            continue

    cfg.interfaces = list(iface_map.values())
    cfg.vlans = list(vlan_map.values())
    return cfg


def parse_fortios(text: str) -> NormConfig:
    cfg = NormConfig()
    context: Optional[str] = None
    cur_iface: Optional[NormInterface] = None
    cur_vlan: Optional[NormVlan] = None
    port_counter = 0
    port_index_of: dict[str, str] = {}

    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            continue

        if re.match(r"^config system global", line, re.I):
            context = "global"; continue
        if re.match(r"^config system interface", line, re.I):
            context = "interface"; continue
        if re.match(r"^config (system vlan|vlan)", line, re.I):
            context = "vlan"; continue
        if re.match(r"^config (firewall|router)", line, re.I):
            context = "flagged"
            cfg.flagged.append(line)
            continue
        if re.match(r"^end$", line, re.I):
            context = None
            continue

        if context == "flagged":
            cfg.flagged.append(line)
            continue

        if context == "global":
            m = re.match(r'^set hostname\s+"?([^"]+)"?', line, re.I)
            if m:
                cfg.hostname = m.group(1)
            continue

        if context == "interface":
            m = re.match(r'^edit\s+"?([^"]+)"?', line, re.I)
            if m:
                if cur_iface:
                    cfg.interfaces.append(cur_iface)
                port_name = m.group(1)
                if port_name not in port_index_of:
                    port_counter += 1
                    port_index_of[port_name] = str(port_counter)
                cur_iface = NormInterface(index=port_index_of[port_name], enabled=True)
                continue
            if re.match(r"^next$", line, re.I):
                if cur_iface:
                    cfg.interfaces.append(cur_iface)
                cur_iface = None
                continue
            if cur_iface:
                m = re.match(r'^set alias\s+"?([^"]+)"?', line, re.I)
                if m:
                    cur_iface.description = m.group(1); continue
                m = re.match(r"^set ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line, re.I)
                if m:
                    cur_iface.ip, cur_iface.mask = m.group(1), m.group(2); continue
                m = re.match(r"^set status\s+(up|down)", line, re.I)
                if m:
                    cur_iface.enabled = m.group(1).lower() == "up"; continue
            continue

        if context == "vlan":
            m = re.match(r'^edit\s+"?([^"]+)"?', line, re.I)
            if m:
                if cur_vlan:
                    cfg.vlans.append(cur_vlan)
                cur_vlan = NormVlan(id=m.group(1))
                continue
            if re.match(r"^next$", line, re.I):
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
# Generators
# --------------------------------------------------------------------------

def gen_cisco_iosxe(cfg: NormConfig) -> str:
    out: list[str] = []
    if cfg.hostname:
        out += [f"hostname {cfg.hostname}", "!"]
    for it in cfg.interfaces:
        out.append(f"interface GigabitEthernet{it.index}")
        if it.description:
            out.append(f" description {it.description}")
        if it.ip and it.mask:
            out.append(f" ip address {it.ip} {it.mask}")
        out.append(" no shutdown" if it.enabled else " shutdown")
        out.append("!")
    for v in cfg.vlans:
        out.append(f"vlan {v.id}")
        if v.name:
            out.append(f" name {v.name}")
        out.append("!")
    if cfg.flagged:
        out.append("! --- FLAGGED FOR MANUAL REVIEW (not auto-converted) ---")
        out += [f"! {l}" for l in cfg.flagged]
    return "\n".join(out)


def gen_junos(cfg: NormConfig) -> str:
    out: list[str] = []
    if cfg.hostname:
        out.append(f"set system host-name {cfg.hostname}")
    for it in cfg.interfaces:
        name = f"ge-0/0/{it.index.split('/')[-1]}"
        if it.description:
            out.append(f'set interfaces {name} description "{it.description}"')
        if it.ip and it.mask:
            cidr = MASK_TO_CIDR.get(it.mask, "24")
            out.append(f"set interfaces {name} unit 0 family inet address {it.ip}/{cidr}")
        if not it.enabled:
            out.append(f"set interfaces {name} disable")
    for v in cfg.vlans:
        out.append(f"set vlans {v.name or 'VLAN' + v.id} vlan-id {v.id}")
    if cfg.flagged:
        out.append("# --- FLAGGED FOR MANUAL REVIEW (not auto-converted) ---")
        out += [f"# {l}" for l in cfg.flagged]
    return "\n".join(out)


def gen_fortios(cfg: NormConfig) -> str:
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


def convert_config(source_vendor: str, target_vendor: str, config_text: str) -> dict:
    if source_vendor not in _PARSERS:
        raise ValueError(f"Unsupported source vendor: {source_vendor}")
    if target_vendor not in _GENERATORS:
        raise ValueError(f"Unsupported target vendor: {target_vendor}")

    normalized = _PARSERS[source_vendor](config_text)
    converted = _GENERATORS[target_vendor](normalized)

    return {
        "converted_config": converted,
        "flagged_items": normalized.flagged,
        "flagged_count": len(normalized.flagged),
    }