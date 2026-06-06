from app.llm_models import StructuredRemediation, RemediationStep
from app.openai_client import generate_openai_response, has_openai_api_key


def build_remediation_prompt(finding):
    return f"""
You are a senior cloud security engineer.

Explain the following security finding and provide practical remediation steps.

Provider: {finding.source_tool}
Severity: {finding.severity}
Resource: {finding.affected_resource}
Issue: {finding.issue}
Description: {finding.description}
STRIDE Category: {finding.stride_category}
Risk Score: {finding.risk_score}

Return:
1. Why this matters
2. Possible attack scenario
3. Recommended remediation
4. Validation steps
"""


def generate_structured_remediation_stub(finding):
    return StructuredRemediation(
        issue=finding.issue,
        severity=finding.severity,
        risk_score=finding.risk_score,
        attack_scenario=(
            f"An attacker may exploit {finding.issue} affecting "
            f"{finding.affected_resource}."
        ),
        remediation_steps=[
            RemediationStep(
                step=finding.remediation,
                reason="This reduces the likelihood or impact of the identified risk.",
            )
        ],
        validation_steps=[
            "Confirm the affected resource has been remediated.",
            "Re-run relevant security checks.",
        ],
        priority="High" if finding.risk_score >= 60 else "Medium",
    )


def generate_llm_remediation(finding):
    prompt = build_remediation_prompt(finding)

    if not has_openai_api_key():
        structured = generate_structured_remediation_stub(finding)

        return {
            "status": "stub",
            "prompt": prompt,
            "remediation": structured.model_dump(),
        }

    return {
        "status": "generated",
        "prompt": prompt,
        "message": generate_openai_response(prompt),
    }