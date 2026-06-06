from app.correlation_engine import correlate_findings


def test_attack_path_detection():
    findings = [
        {
            "title": "Public S3 Bucket",
            "severity": "HIGH"
        },
        {
            "title": "Critical Container Vulnerability",
            "severity": "CRITICAL"
        },
        {
            "title": "Privilege Escalation Risk",
            "severity": "HIGH"
        }
    ]

    result = correlate_findings(findings)

    assert len(result) == 1
    assert result[0]["severity"] == "CRITICAL"


def test_no_attack_path():
    findings = [
        {
            "title": "Low Risk Finding",
            "severity": "LOW"
        }
    ]

    result = correlate_findings(findings)

    assert result == []