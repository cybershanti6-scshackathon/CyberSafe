def check_ssh_version(device):
    
    ssh_version = (
        device.security.ssh_version
    )


    if ssh_version == 2:

        return {

            "rule_id": "NET-SSH-001",

            "title":
                "Secure SSH Version Required",

            "status": "PASS",

            "severity": "INFO",

            "description":
                "SSH Version 2 is configured."
        }


    return {

        "rule_id": "NET-SSH-001",

        "title":
            "Secure SSH Version Required",

        "status": "FAIL",

        "severity": "HIGH",

        "description":
            "SSH Version 2 is not configured."
    }



def check_telnet(device):

    telnet = (
        device.security.telnet_enabled
    )


    if telnet is False:

        return {

            "rule_id":
                "NET-TELNET-001",

            "title":
                "Telnet Must Be Disabled",

            "status": "PASS",

            "severity": "INFO",

            "description":
                "Telnet is disabled."
        }


    if telnet is True:

        return {

            "rule_id":
                "NET-TELNET-001",

            "title":
                "Telnet Must Be Disabled",

            "status": "FAIL",

            "severity": "CRITICAL",

            "description":
                "Telnet is enabled."
        }


    return {

        "rule_id":
            "NET-TELNET-001",

        "title":
            "Telnet Must Be Disabled",

        "status": "UNKNOWN",

        "severity": "MEDIUM",

        "description":
            "Unable to determine Telnet configuration."
    }



def check_http(device):

    http = (
        device.security.http_enabled
    )


    if http is False:

        return {

            "rule_id":
                "NET-HTTP-001",

            "title":
                "Insecure HTTP Must Be Disabled",

            "status": "PASS",

            "severity": "INFO",

            "description":
                "HTTP management access is disabled."
        }


    if http is True:

        return {

            "rule_id":
                "NET-HTTP-001",

            "title":
                "Insecure HTTP Must Be Disabled",

            "status": "FAIL",

            "severity": "HIGH",

            "description":
                "HTTP management access is enabled."
        }


    return {

        "rule_id":
            "NET-HTTP-001",

        "title":
            "Insecure HTTP Must Be Disabled",

        "status": "UNKNOWN",

        "severity": "MEDIUM",

        "description":
            "Unable to determine HTTP configuration."
    }



def check_logging(device):

    logging = (
        device.security.logging_enabled
    )


    if logging:

        return {

            "rule_id":
                "NET-LOG-001",

            "title":
                "Security Logging Must Be Enabled",

            "status": "PASS",

            "severity": "INFO",

            "description":
                "Logging configuration detected."
        }


    return {

        "rule_id":
            "NET-LOG-001",

        "title":
            "Security Logging Must Be Enabled",

        "status": "FAIL",

        "severity": "MEDIUM",

        "description":
            "No logging configuration detected."
    }



def check_session_timeout(device):

    timeout = (
        device.security.session_timeout
    )


    if timeout is None:

        return {

            "rule_id":
                "NET-TIMEOUT-001",

            "title":
                "Administrative Session Timeout",

            "status": "UNKNOWN",

            "severity": "MEDIUM",

            "description":
                "Session timeout could not be determined."
        }


    if timeout <= 900:

        return {

            "rule_id":
                "NET-TIMEOUT-001",

            "title":
                "Administrative Session Timeout",

            "status": "PASS",

            "severity": "INFO",

            "description":
                f"Session timeout is {timeout} seconds."
        }


    return {

        "rule_id":
            "NET-TIMEOUT-001",

        "title":
            "Administrative Session Timeout",

        "status": "FAIL",

        "severity": "MEDIUM",

        "description":
            f"Session timeout is too high: {timeout} seconds."
    }