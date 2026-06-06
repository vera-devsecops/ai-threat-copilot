from app.schemas import NormalizedFinding
from app.llm_remediation import build_remediation_prompt, generate_llm_remediation_stub


def test_build_remediation_prompt_contains_finding_context():
    finding = NormalizedFinding(
        source_tool="AWS",
        severity="High",
        affected_resource="s3-bucket",
        issue="Public S3 bucket",
        description="Bucket is publicly exposed",
        stride_category="Information Disclosure",
        likely_impact="Sensitive data exposure",
        risk_score=60,
        remediation="Restrict public access"
    )

    prompt = build_remediation_prompt(finding)

    assert "Public S3 bucket" in prompt
    assert "Information Disclosure" in prompt
    assert "Risk Score: 60" in prompt


def test_generate_llm_remediation_stub():
    finding = NormalizedFinding(
        source_tool="AWS",
        severity="High",
        affected_resource="s3-bucket",
        issue="Public S3 bucket",
        description="Bucket is publicly exposed",
        stride_category="Information Disclosure",
        likely_impact="Sensitive data exposure",
        risk_score=60,
        remediation="Restrict public access"
    )

    result = generate_llm_remediation_stub(finding)

    assert result["status"] == "stub"
    assert "prompt" in result