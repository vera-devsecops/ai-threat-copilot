# tests/test_cloud_adapters.py

from app.cloud_adapters.aws_security_hub import (
    from_aws_security_hub,
)

from app.cloud_adapters.azure_defender import (
    from_azure_defender,
)

from app.cloud_adapters.gcp_scc import (
    from_gcp_scc,
)


def test_aws_adapter():

    finding = {
        "Title": "Privilege escalation risk",
        "Description": "IAM permissions are overly permissive.",
        "Severity": {
            "Label": "High"
        },
        "Resources": [
            {
                "Id": "arn:aws:iam::123456789:role/admin"
            }
        ],
        "Types": [
            "PrivilegeEscalation"
        ]
    }

    adapted = from_aws_security_hub(finding)

    assert adapted.provider == "AWS Security Hub"
    assert adapted.severity == "High"
    assert adapted.resource == "arn:aws:iam::123456789:role/admin"
    assert adapted.issue == "Privilege escalation risk"


def test_azure_adapter():

    finding = {
        "properties": {
            "severity": "Medium",
            "alertDisplayName": "Suspicious login",
            "description": "Potential identity compromise.",
            "alertType": "IdentityRisk",
            "resourceIdentifiers": [
                {
                    "azureResourceId": "vm-prod-01"
                }
            ]
        }
    }

    adapted = from_azure_defender(finding)

    assert adapted.provider == "Microsoft Defender for Cloud"
    assert adapted.severity == "Medium"
    assert adapted.resource == "vm-prod-01"
    assert adapted.issue == "Suspicious login"


def test_gcp_adapter():

    finding = {
        "severity": "High",
        "resourceName": "gke-cluster-prod",
        "category": "ContainerThreat",
        "description": "Container attack detected.",
        "findingClass": "Threat"
    }

    adapted = from_gcp_scc(finding)

    assert adapted.provider == "Google Security Command Center"
    assert adapted.severity == "High"
    assert adapted.resource == "gke-cluster-prod"
    assert adapted.issue == "ContainerThreat"