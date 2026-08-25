def get_cisco_remediation(
    rule_id
):

    rules = {

        "NET-SSH-001": [

            "configure terminal",

            "ip ssh version 2",

            "end",

            "write memory"
        ],


        "NET-TELNET-001": [

            "configure terminal",

            "line vty 0 15",

            "transport input ssh",

            "end",

            "write memory"
        ],


        "NET-HTTP-001": [

            "configure terminal",

            "no ip http server",

            "end",

            "write memory"
        ],


        "NET-LOG-001": [

            "configure terminal",

            "logging host <SYSLOG_SERVER_IP>",

            "end",

            "write memory"
        ],


        "NET-TIMEOUT-001": [

            "configure terminal",

            "line vty 0 15",

            "exec-timeout 15",

            "end",

            "write memory"
        ]
    }


    return rules.get(
        rule_id,
        []
    )



def get_juniper_remediation(
    rule_id
):

    rules = {

        "NET-TELNET-001": [

            "delete system services telnet",

            "commit"
        ],


        "NET-HTTP-001": [

            "delete system services web-management http",

            "commit"
        ],


        "NET-LOG-001": [

            "set system syslog host <SYSLOG_SERVER_IP> any any",

            "commit"
        ],


        "NET-TIMEOUT-001": [

            "set system login idle-timeout 15",

            "commit"
        ]
    }


    return rules.get(
        rule_id,
        []
    )



def get_fortinet_remediation(
    rule_id
):

    rules = {

        "NET-TELNET-001": [

            "config system interface",

            "edit <INTERFACE_NAME>",

            "set allowaccess ssh https",

            "next",

            "end"
        ],


        "NET-HTTP-001": [

            "config system interface",

            "edit <INTERFACE_NAME>",

            "set allowaccess ssh https",

            "next",

            "end"
        ],


        "NET-TIMEOUT-001": [

            "config system global",

            "set admin-ssh-grace-time 15",

            "end"
        ]
    }


    return rules.get(
        rule_id,
        []
    )



def get_remediation(
    vendor,
    rule_id
):

    vendor = vendor.lower()


    if vendor == "cisco":

        return get_cisco_remediation(
            rule_id
        )


    if vendor == "juniper":

        return get_juniper_remediation(
            rule_id
        )


    if vendor == "fortinet":

        return get_fortinet_remediation(
            rule_id
        )


    return []



def add_remediation(
    vendor,
    results
):

    for finding in results["findings"]:

        if finding["status"] == "FAIL":

            finding["remediation"] = (
                get_remediation(
                    vendor,
                    finding["rule_id"]
                )
            )

        else:

            finding["remediation"] = []


    return results