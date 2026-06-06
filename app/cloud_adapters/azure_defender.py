# app/cloud_adapters/azure_defender.py

from app.schemas import RawFinding


def from_azure_defender(alert: dict) -> RawFinding:
    properties = alert.get("properties", {})
    resource_ids = properties.get("resourceIdentifiers", [])

    resource = "unknown"
    if resource_ids:
        resource = resource_ids[0].get("azureResourceId", "unknown")

    return RawFinding(
        provider="Microsoft Defender for Cloud",
        severity=properties.get("severity", "Unknown"),
        resource=resource,
        issue=properties.get("alertDisplayName", "Untitled Azure alert"),
        description=properties.get("description", "No description provided."),
    )