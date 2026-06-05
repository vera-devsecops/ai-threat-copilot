# tests/test_normalizer.py

from app.schemas import RawFinding
from app.normalizer import normalize_finding


def test_normalize_privileged_container():

    finding = RawFinding(
        tool="Kubescape",
        severity="High",
        resource="deployment/test-api",
        title="Privileged container detected",
        description="Container is running with privileged permissions.",
    )

    normalized = normalize_finding(finding)

    assert normalized.source_tool == "Kubescape"
    assert normalized.severity == "High"
    assert normalized.stride_category == "Elevation of Privilege"


def test_normalize_secret_exposure():

    finding = RawFinding(
        tool="Trivy",
        severity="Critical",
        resource="s3/public-bucket",
        title="Public secret exposure",
        description="Sensitive data may be publicly accessible.",
    )

    normalized = normalize_finding(finding)

    assert normalized.stride_category == "Information Disclosure"