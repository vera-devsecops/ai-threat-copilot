from app.schemas import RawFinding
from app.remediation_engine import generate_remediation


def test_privilege_remediation():
    finding = RawFinding(
        provider="Kubernetes",
        severity="High",
        resource="cluster-admin-role",
        issue="Privilege escalation risk",
        description="Workload has admin privileges",
    )

    result = generate_remediation(finding)

    assert "least privilege" in result.lower()


def test_public_exposure_remediation():
    finding = RawFinding(
        provider="AWS",
        severity="High",
        resource="s3-bucket",
        issue="Public S3 bucket",
        description="Bucket is publicly exposed",
    )

    result = generate_remediation(finding)

    assert "public exposure" in result.lower()