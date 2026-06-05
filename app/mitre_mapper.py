MITRE_MAPPINGS = {
    "Public S3 Bucket": {
        "technique": "T1530",
        "name": "Data from Cloud Storage"
    },
    "Container Privilege Escalation": {
        "technique": "T1611",
        "name": "Escape to Host"
    },
    "Exposed Kubernetes Dashboard": {
        "technique": "T1580",
        "name": "Cloud Infrastructure Discovery"
    },
    "Suspicious IAM Policy": {
        "technique": "T1098",
        "name": "Account Manipulation"
    }
}


def map_to_mitre(finding_title: str):
    return MITRE_MAPPINGS.get(
        finding_title,
        {
            "technique": "UNKNOWN",
            "name": "Unknown Technique"
        }
    )