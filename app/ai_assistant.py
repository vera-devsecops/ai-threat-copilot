# app/ai_assistant.py

import os
import json
from openai import OpenAI
from app.schemas import NormalizedFinding

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)


def build_ai_context(
    findings: list[NormalizedFinding],
) -> str:

    return json.dumps(
        [finding.model_dump() for finding in findings],
        indent=2,
    )


def generate_ai_assisted_analysis(
    findings: list[NormalizedFinding],
) -> dict:

    prompt = f"""
You are a senior cloud and Kubernetes security engineer.

Analyze these threat findings and generate:

- executive_summary
- key_risks
- likely_attack_paths
- remediation_plan
- confidence_level
- limitations

Threat Findings:
{build_ai_context(findings)}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )

    return {
        "raw_response": response.output_text
    }