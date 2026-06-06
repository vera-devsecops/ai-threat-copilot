def correlate_findings(findings):
    correlated_risks = []

    def finding_text(finding):
        return (
            f"{finding.get('issue', '')} "
            f"{finding.get('description', '')} "
            f"{finding.get('resource', '')}"
        ).lower()

    has_public_exposure = any(
        "public" in finding_text(finding)
        or "exposed" in finding_text(finding)
        for finding in findings
    )

    has_critical_vulnerability = any(
        finding.get("severity", "").lower() == "critical"
        or "critical" in finding_text(finding)
        or "vulnerability" in finding_text(finding)
        for finding in findings
    )

    has_privileged_access = any(
        "privilege" in finding_text(finding)
        or "admin" in finding_text(finding)
        for finding in findings
    )

    if (
        has_public_exposure
        and has_critical_vulnerability
        and has_privileged_access
    ):
        correlated_risks.append(
            {
                "risk": "Potential Cloud Attack Path",
                "severity": "CRITICAL",
                "description": (
                    "Public exposure combined with critical vulnerabilities "
                    "and privileged access may allow full environment compromise."
                ),
            }
        )

    return correlated_risks