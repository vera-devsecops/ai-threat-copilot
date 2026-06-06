import json

from app.llm_parser import parse_structured_remediation


def test_parse_structured_remediation():
    raw_response = json.dumps(
        {
            "issue": "Public S3 bucket",
            "severity": "High",
            "risk_score": 60,
            "attack_scenario": "An attacker may access exposed data.",
            "remediation_steps": [
                {
                    "step": "Disable public access",
                    "reason": "Prevents unauthorised internet access."
                }
            ],
            "validation_steps": [
                "Confirm public access is blocked."
            ],
            "priority": "High"
        }
    )

    result = parse_structured_remediation(raw_response)

    assert result.issue == "Public S3 bucket"
    assert result.priority == "High"
    assert result.remediation_steps[0].step == "Disable public access"