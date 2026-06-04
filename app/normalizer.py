# app/normalizer.py

from app.schemas import RawFinding, NormalizedFinding


def map_stride(text: str) -> str:

    text = text.lower()

    if "privilege" in text or "rbac" in text:
        return "Elevation of Privilege"

    if "secret" in text or "exposure" in text or "data" in text:
        return "Information Disclosure"

    if "injection" in text or "tamper" in text:
        return "Tampering"

    if "denial" in text:
        return "Denial of Service"

    if "identity" in text or "spoof" in text:
        return "Spoofing"

    return "Security Misconfiguration"


def normalize_finding(finding: RawFinding) -> NormalizedFinding:

    combined_text = (
        f"{finding.title} "
        f"{finding.description} "
        f"{finding.category or ''}"
    )

    return NormalizedFinding(
        source_tool=finding.tool,
        severity=finding.severity,
        affected_resource=finding.resource,
        issue=finding.title,
        description=finding.description,
        stride_category=map_stride(combined_text),
        likely_impact=(
            "Potential security weakness that may increase "
            "attack surface or compromise risk."
        ),
    )


def normalize_findings(
    findings: list[RawFinding],
) -> list[NormalizedFinding]:

    return [normalize_finding(f) for f in findings]