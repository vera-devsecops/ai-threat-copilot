from app.schemas import RawFinding
from app.normalizer import normalize_finding


def test_public_s3_bucket_normalization():

    finding = RawFinding(
        provider="AWS",
        severity="HIGH",
        resource="s3://sensitive-bucket",
        issue="Public S3 Bucket",
        description="Bucket allows public access"
    )

    normalized = normalize_finding(finding)

    assert normalized.stride_category == "Information Disclosure"
    assert normalized.risk_score > 0


def test_privilege_escalation_normalization():

    finding = RawFinding(
        provider="Kubernetes",
        severity="CRITICAL",
        resource="cluster-admin-role",
        issue="Privilege Escalation Risk",
        description="Container has cluster-admin privileges"
    )

    normalized = normalize_finding(finding)

    assert normalized.stride_category == "Elevation of Privilege"
    assert normalized.risk_score > 0