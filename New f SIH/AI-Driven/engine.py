from compliance.rules import (
    check_ssh_version,
    check_telnet,
    check_http,
    check_logging,
    check_session_timeout
)


def run_compliance_scan(
    device
):

    findings = [

        check_ssh_version(device),

        check_telnet(device),

        check_http(device),

        check_logging(device),

        check_session_timeout(device)
    ]


    total = len(
        findings
    )


    passed = len(

        [
            finding

            for finding in findings

            if finding["status"] == "PASS"
        ]

    )


    failed = len(

        [
            finding

            for finding in findings

            if finding["status"] == "FAIL"
        ]

    )


    unknown = len(

        [
            finding

            for finding in findings

            if finding["status"] == "UNKNOWN"
        ]

    )


    score = int(

        (
            passed / total
        ) * 100

    )


    return {

        "framework":
            "Network Security Baseline",

        "compliance_score":
            score,

        "summary": {

            "total":
                total,

            "passed":
                passed,

            "failed":
                failed,

            "unknown":
                unknown
        },

        "findings":
            findings
    }