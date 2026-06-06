def correlate_findings(findings):
    correlated_risks = []

    has_public_exposure = any(
        "public" in finding["title"].lower()
        for finding in findings
    )

    has_critical_vulnerability = any(
        finding["severity"].lower() == "critical"
        for finding in findings
    )

    has_privileged_access = any(
        "privilege" in finding["title"].lower()
        or "admin" in finding["title"].lower()
        for finding in findings
    )

    if (
        has_public_exposure
        and has_critical_vulnerability
        and has_privileged_access
    ):
        correlated_risks.append({
            "risk": "Potential Cloud Attack Path",
            "severity": "CRITICAL",
            "description": (
                "Public exposure combined with "
                "critical vulnerabilities and privileged access "
                "may allow full environment compromise."
            )
        })

    return correlated_risks