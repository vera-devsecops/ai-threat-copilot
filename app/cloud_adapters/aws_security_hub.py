# app/cloud_adapters/aws_security_hub.py

from app.schemas import RawFinding


def from_aws_security_hub(finding: dict) -> RawFinding:
    resources = finding.get("Resources", [])
    resource = resources[0].get("Id", "unknown") if resources else "unknown"

    return RawFinding(
        provider="AWS Security Hub",
        severity=finding.get("Severity", {}).get("Label", "Unknown"),
        resource=resource,
        issue=finding.get("Title", "Untitled AWS finding"),
        description=finding.get("Description", "No description provided."),
    )