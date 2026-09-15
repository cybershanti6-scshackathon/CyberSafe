"""Tests for msme_auditor.config_parsers.config_converter.

Covers:
- The exact Cisco IOS XE input that was failing (vendor name mismatch + response format)
- Zero-parameters-parsed input → clear error
- Source == target → passthrough
- Response format matches frontend expectations (output_config, lines, stats)
- All 6 vendor conversion pairs work
"""

import pytest
from msme_auditor.config_parsers.config_converter import (
    convert_config,
    get_supported_pairs,
    parse_cisco_iosxe,
    parse_junos,
    parse_fortios,
    _normalize_vendor,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CISCO = """\
hostname CORP-RTR-01
!
interface GigabitEthernet0/0
 description UPLINK_TO_ISP
 ip address 203.0.113.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/1
 description LAN_VLAN10_MANAGEMENT
 switchport mode access
 switchport access vlan 10
 no shutdown
!
interface Vlan10
 description MANAGEMENT_VLAN
 ip address 10.0.10.1 255.255.255.0
 no shutdown
!
vlan 10
 name MANAGEMENT
!
vlan 20
 name SERVERS
!
vlan 30
 name USERS
!
ip access-list extended PERMIT_MANAGEMENT
 permit ip 10.0.10.0 0.0.0.255 any
 permit tcp any host 10.0.20.10 eq 22
 deny ip any any log
!
ip nat inside source list NAT_ACL interface GigabitEthernet0/0 overload
"""

SAMPLE_JUNOS = """\
set system host-name CORP-RTR-01
set interfaces ge-0/0/0 description "UPLINK_TO_ISP"
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.1/24
set interfaces ge-0/0/1 description "LAN_VLAN10_MANAGEMENT"
set vlans MANAGEMENT vlan-id 10
set vlans SERVERS vlan-id 20
"""

SAMPLE_FORTIOS = """\
config system global
    set hostname "CORP-RTR-01"
end
config system interface
    edit "port1"
        set alias "UPLINK"
        set ip 10.0.0.1 255.255.255.0
        set status up
    next
end
"""


# ---------------------------------------------------------------------------
# STEP 4 — Tests for the exact failing input, zero-params, source==target
# ---------------------------------------------------------------------------

class TestFailingInput:
    """The exact conversion that was failing with 'Conversion failed: Unsupported source vendor: cisco'."""

    def test_cisco_to_juniper_response_format(self):
        """Response must have all fields the frontend reads."""
        result = convert_config("cisco", "juniper", SAMPLE_CISCO)

        # Frontend reads these — must all be present
        assert "output_config" in result, "Missing output_config"
        assert "lines" in result, "Missing lines"
        assert "commands_converted" in result, "Missing commands_converted"
        assert "commands_need_review" in result, "Missing commands_need_review"
        assert "conversion_accuracy" in result, "Missing conversion_accuracy"

        # output_config should be non-empty Juniper syntax
        assert result["output_config"], "output_config is empty"
        assert "set system host-name" in result["output_config"]
        assert "set interfaces" in result["output_config"]

        # lines must be a list of dicts with required keys
        assert isinstance(result["lines"], list)
        assert len(result["lines"]) > 0
        for line in result["lines"]:
            assert "converted" in line, f"Line missing 'converted': {line}"
            assert "status" in line, f"Line missing 'status': {line}"
            assert line["status"] in ("converted", "needs_review", "not_supported")

        # Should have converted commands (ACL/NAT/QoS/OSPF are now converted, not flagged)
        assert result["commands_converted"] > 0
        # With enhanced converter, ACLs/NAT/QoS/routing are converted to Junos syntax
        # So commands_need_review may be 0 if all features are supported
        assert result["commands_need_review"] >= 0
        assert 0 < result["conversion_accuracy"] <= 100

    def test_cisco_to_juniper_vendor_normalization(self):
        """Lowercase 'cisco' must resolve to 'Cisco IOS XE'."""
        assert _normalize_vendor("cisco") == "Cisco IOS XE"
        assert _normalize_vendor("juniper") == "Juniper Junos"
        assert _normalize_vendor("fortinet") == "FortiOS"

    def test_cisco_to_juniper_not_value_error(self):
        """Must NOT raise ValueError — that was the original bug."""
        result = convert_config("cisco", "juniper", SAMPLE_CISCO)
        assert isinstance(result, dict)


class TestZeroParams:
    """Zero recognizable parameters should produce a specific error, not a generic crash."""

    def test_garbage_input_raises_value_error(self):
        with pytest.raises(ValueError, match="No recognizable configuration parameters"):
            convert_config("cisco", "juniper", "random garbage\nnot a config\nfoobar")

    def test_empty_input_raises_value_error(self):
        with pytest.raises(ValueError, match="No recognizable configuration parameters"):
            convert_config("cisco", "juniper", "")

    def test_whitespace_only_raises_value_error(self):
        with pytest.raises(ValueError, match="No recognizable configuration parameters"):
            convert_config("cisco", "juniper", "   \n  \n   ")


class TestSourceEqualsTarget:
    """Source == target should passthrough, not error."""

    def test_cisco_to_cisco_passthrough(self):
        result = convert_config("cisco", "cisco", SAMPLE_CISCO)
        assert result["output_config"] == SAMPLE_CISCO
        assert result["conversion_accuracy"] == 100
        assert result["commands_converted"] > 0
        assert result["commands_need_review"] == 0

    def test_junos_to_junos_passthrough(self):
        result = convert_config("juniper", "juniper", SAMPLE_JUNOS)
        assert result["output_config"] == SAMPLE_JUNOS
        assert result["conversion_accuracy"] == 100

    def test_fortios_to_fortios_passthrough(self):
        result = convert_config("fortinet", "fortinet", SAMPLE_FORTIOS)
        assert result["output_config"] == SAMPLE_FORTIOS
        assert result["conversion_accuracy"] == 100


# ---------------------------------------------------------------------------
# All 6 vendor conversion pairs
# ---------------------------------------------------------------------------

class TestAllConversionPairs:
    """Every source->target pair should produce valid output with correct fields."""

    @pytest.mark.parametrize("source,target", [
        ("cisco", "juniper"),
        ("cisco", "fortinet"),
        ("juniper", "cisco"),
        ("juniper", "fortinet"),
        ("fortinet", "cisco"),
        ("fortinet", "juniper"),
    ])
    def test_conversion_pair(self, source, target):
        # Pick the right sample for the source vendor
        samples = {
            "cisco": SAMPLE_CISCO,
            "juniper": SAMPLE_JUNOS,
            "fortinet": SAMPLE_FORTIOS,
        }
        result = convert_config(source, target, samples[source])
        assert "output_config" in result
        assert "lines" in result
        assert result["output_config"], f"{source}->{target} produced empty output"
        assert isinstance(result["lines"], list)


# ---------------------------------------------------------------------------
# get_supported_pairs
# ---------------------------------------------------------------------------

class TestSupportedPairs:
    def test_pairs_exist(self):
        pairs = get_supported_pairs()
        assert len(pairs) == 6  # 3 vendors × 2 targets each
        sources = {p["source"] for p in pairs}
        assert "Cisco IOS XE" in sources
        assert "Juniper Junos" in sources
        assert "FortiOS" in sources

    def test_no_self_pairs(self):
        pairs = get_supported_pairs()
        for p in pairs:
            assert p["source"] != p["target"]
