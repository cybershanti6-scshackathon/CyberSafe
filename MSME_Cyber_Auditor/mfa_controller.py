def evaluate_mfa(admin_mfa, remote_mfa, critical_mfa):

    score = 0

    if admin_mfa:
        score += 1

    if remote_mfa:
        score += 1

    if critical_mfa:
        score += 1

    percentage = int((score / 3) * 100)

    if score == 3:
        status = "Passed"
        finding = "MFA is enabled for all required systems."
        remediation = "Continue monitoring MFA settings."

    else:
        status = "Failed"
        finding = "MFA is missing on one or more required systems."
        remediation = (
            "Enable MFA for administrative accounts, "
            "remote access, and critical systems."
        )

    return {
        "control_id": "RPP",
        "sub_control": "RPP.3",
        "status": status,
        "score": percentage,
        "finding": finding,
        "ai_remediation": remediation
    }