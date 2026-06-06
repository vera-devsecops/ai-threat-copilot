from app.llm_models import StructuredRemediation, RemediationStep


def test_structured_remediation_model():
    remediation = StructuredRemediation(
        issue="Public S3 bucket",
        severity="High",
        risk_score=60,
        attack_scenario="An attacker may access exposed data.",
        remediation_steps=[
            RemediationStep(
                step="Disable public access",
                reason="Prevents unauthorised internet access."
            )
        ],
        validation_steps=[
            "Confirm bucket public access is blocked."
        ],
        priority="High"
    )

    assert remediation.issue == "Public S3 bucket"
    assert remediation.remediation_steps[0].step == "Disable public access"
    assert remediation.priority == "High"