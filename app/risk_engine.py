def calculate_risk_score(failed_attempts):
    failed_attempts = max(0, int(failed_attempts))

    if failed_attempts == 0:
        score = 0
        severity = "Low"
        reason = "No failed login attempts were detected."
        recommendation = "Continue monitoring security events."

    elif failed_attempts < 3:
        score = 20
        severity = "Low"
        reason = (
            f"{failed_attempts} failed login attempt(s) detected. "
            "This is currently a low-risk signal."
        )
        recommendation = (
            "Monitor the source IP for repeated failed attempts."
        )

    elif failed_attempts < 5:
        score = 40
        severity = "Medium"
        reason = (
            f"{failed_attempts} failed login attempts detected. "
            "Repeated failures may indicate suspicious activity."
        )
        recommendation = (
            "Review the account activity and monitor the source IP."
        )

    elif failed_attempts < 8:
        score = 60
        severity = "High"
        reason = (
            f"{failed_attempts} failed login attempts detected. "
            "The activity reached the brute-force detection threshold."
        )
        recommendation = (
            "Investigate the source IP, review authentication logs, "
            "and apply appropriate access protections if confirmed."
        )

    else:
        score = 90
        severity = "Critical"
        reason = (
            f"{failed_attempts} failed login attempts detected. "
            "The volume of failures indicates a high-priority "
            "potential brute-force incident."
        )
        recommendation = (
            "Prioritize investigation, verify the affected accounts, "
            "and consider temporary protective controls."
        )

    return {
        "risk_score": score,
        "severity": severity,
        "reason": reason,
        "recommendation": recommendation,
        "failed_attempts": failed_attempts
    }