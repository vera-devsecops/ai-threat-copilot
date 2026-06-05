# app/cloud_adapters/gcp_scc.py

from app.schemas import RawFinding


def from_gcp_scc(finding: dict) -> RawFinding:
    return RawFinding(
        tool="Google Security Command Center",
        severity=finding.get("severity", "Unknown"),
        resource=finding.get("resourceName", "unknown"),
        title=finding.get("category", "Untitled GCP finding"),
        description=finding.get("description", "No description provided."),
        category=finding.get("findingClass", ""),
    )