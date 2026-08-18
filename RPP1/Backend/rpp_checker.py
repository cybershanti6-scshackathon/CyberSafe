def check_rpp_policy(policy):

    findings = []
    recommendations = []

    passed_checks = 0
    total_checks = 9

    # -----------------------------------------
    # CHECK 1
    # PASSWORD LENGTH
    # -----------------------------------------

    if 8 <= policy.minimum_length <= 12:
        findings.append(
            f"PASS: Minimum password length is "
            f"{policy.minimum_length} characters."
        )
        passed_checks += 1
    else:
        findings.append(
            f"FAIL: Minimum password length is "
            f"{policy.minimum_length} characters."
        )

        recommendations.append(
            "Set the minimum password length between "
            "8 and 12 characters."
        )

    # -----------------------------------------
    # CHECK 2
    # UPPERCASE
    # -----------------------------------------

    if policy.requires_uppercase:
        findings.append(
            "PASS: Uppercase letters are required."
        )
        passed_checks += 1
    else:
        findings.append(
            "FAIL: Uppercase letters are not required."
        )

        recommendations.append(
            "Require at least one uppercase letter."
        )

    # -----------------------------------------
    # CHECK 3
    # LOWERCASE
    # -----------------------------------------

    if policy.requires_lowercase:
        findings.append(
            "PASS: Lowercase letters are required."
        )
        passed_checks += 1
    else:
        findings.append(
            "FAIL: Lowercase letters are not required."
        )

        recommendations.append(
            "Require at least one lowercase letter."
        )

    # -----------------------------------------
    # CHECK 4
    # NUMBERS
    # -----------------------------------------

    if policy.requires_number:
        findings.append(
            "PASS: Numbers are required."
        )
        passed_checks += 1
    else:
        findings.append(
            "FAIL: Numbers are not required."
        )

        recommendations.append(
            "Require at least one numeric character."
        )

    # -----------------------------------------
    # CHECK 5
    # SPECIAL CHARACTERS
    # -----------------------------------------

    if policy.requires_special_character:
        findings.append(
            "PASS: Special characters are required."
        )
        passed_checks += 1
    else:
        findings.append(
            "FAIL: Special characters are not required."
        )

        recommendations.append(
            "Require at least one special character."
        )

    # -----------------------------------------
    # CHECK 6
    # PASSWORD EXPIRY
    # -----------------------------------------

    if 30 <= policy.password_expiry_days <= 180:
        findings.append(
            f"PASS: Password expiry is set to "
            f"{policy.password_expiry_days} days."
        )
        passed_checks += 1

    elif policy.password_expiry_days == 0:

        findings.append(
            "FAIL: Password expiry policy is not configured."
        )

        recommendations.append(
            "Configure a password review or expiry interval "
            "according to organizational risk."
        )

    else:

        findings.append(
            f"WARNING: Password expiry is "
            f"{policy.password_expiry_days} days."
        )

        recommendations.append(
            "Review whether the password lifecycle policy "
            "matches your organization's security requirements."
        )

    # -----------------------------------------
    # CHECK 7
    # PASSWORD REUSE
    # -----------------------------------------

    if policy.password_history_count >= 5:

        findings.append(
            f"PASS: Last {policy.password_history_count} "
            "passwords cannot be reused."
        )

        passed_checks += 1

    else:

        findings.append(
            "FAIL: Password history restriction is too weak."
        )

        recommendations.append(
            "Prevent reuse of at least the previous "
            "5 passwords."
        )

    # -----------------------------------------
    # CHECK 8
    # CREDENTIAL SHARING
    # -----------------------------------------

    if policy.prevents_credential_sharing:

        findings.append(
            "PASS: Credential sharing is prohibited."
        )

        passed_checks += 1

    else:

        findings.append(
            "FAIL: No policy preventing credential sharing."
        )

        recommendations.append(
            "Create and enforce a policy prohibiting "
            "password and credential sharing."
        )

    # -----------------------------------------
    # CHECK 9
    # USER EDUCATION
    # -----------------------------------------

    if policy.user_password_security_training:

        findings.append(
            "PASS: Users receive password security awareness training."
        )

        passed_checks += 1

    else:

        findings.append(
            "FAIL: Password security awareness training "
            "is not implemented."
        )

        recommendations.append(
            "Educate employees about password security, "
            "phishing, and credential sharing risks."
        )

    # -----------------------------------------
    # SCORE CALCULATION
    # -----------------------------------------

    score = int(
        (passed_checks / total_checks) * 100
    )

    # -----------------------------------------
    # FINAL STATUS
    # -----------------------------------------

    if score >= 90:
        status = "COMPLIANT"

    elif score >= 60:
        status = "PARTIALLY COMPLIANT"

    else:
        status = "NON-COMPLIANT"

    return {
        "control": "RPP.1 - Robust Password Policy",

        "status": status,

        "score": score,

        "total_checks": total_checks,

        "passed_checks": passed_checks,

        "findings": findings,

        "recommendations": recommendations
    }