from app.schemas import RawFinding, NormalizedFinding
from app.risk_scoring import calculate_risk_score
from app.remediation_engine import generate_remediation


def normalize_finding(finding: RawFinding) -> NormalizedFinding:
    combined_text = f"{finding.issue} {finding.description}"
    combined_text_lower = combined_text.lower()

    if "public" in combined_text_lower:
        stride = "Information Disclosure"
        impact = "Sensitive data exposure"

    elif "privilege" in combined_text_lower:
        stride = "Elevation of Privilege"
        impact = "Potential privilege escalation"

    elif "denial" in combined_text_lower:
        stride = "Denial of Service"
        impact = "Service disruption"

    else:
        stride = "Tampering"
        impact = "Potential unauthorized modification"

    risk_score = calculate_risk_score(
        severity=finding.severity,
        public_exposure="public" in combined_text_lower or "exposed" in combined_text_lower,
        privileged_access="privilege" in combined_text_lower or "admin" in combined_text_lower,
        runtime_activity="shell" in combined_text_lower or "runtime" in combined_text_lower,
    )

    remediation = generate_remediation(finding)

    return NormalizedFinding(
        source_tool=finding.provider,
        severity=finding.severity,
        affected_resource=finding.resource,
        issue=finding.issue,
        description=finding.description,
        stride_category=stride,
        likely_impact=impact,
        risk_score=risk_score,
        remediation=remediation,
    )


def normalize_findings(findings: list[RawFinding]) -> list[NormalizedFinding]:
    return [normalize_finding(finding) for finding in findings]
