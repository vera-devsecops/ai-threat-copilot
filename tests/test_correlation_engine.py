from app.correlation_engine import correlate_findings


def test_attack_path_detection():
    findings = [
        {
            "issue": "Public S3 Bucket",
            "description": "Bucket is publicly exposed",
            "resource": "s3-bucket",
            "severity": "HIGH"
        },
        {
            "issue": "Critical Container Vulnerability",
            "description": "Critical remote code execution vulnerability",
            "resource": "container-image",
            "severity": "CRITICAL"
        },
        {
            "issue": "Privilege Escalation Risk",
            "description": "Container has admin privileges",
            "resource": "cluster-admin-role",
            "severity": "HIGH"
        }
    ]

    result = correlate_findings(findings)

    assert len(result) == 1
    assert result[0]["severity"] == "CRITICAL"


def test_no_attack_path():
    findings = [
        {
            "issue": "Low Risk Finding",
            "description": "Minor informational finding",
            "resource": "test-resource",
            "severity": "LOW"
        }
    ]

    result = correlate_findings(findings)

    assert result == []