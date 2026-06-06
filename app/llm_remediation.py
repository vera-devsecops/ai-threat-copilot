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


def generate_llm_remediation_stub(finding):
    prompt = build_remediation_prompt(finding)

    return {
        "prompt": prompt,
        "status": "stub",
        "message": "LLM integration placeholder. Connect OpenAI or local Ollama later."
    }