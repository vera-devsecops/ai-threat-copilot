from fastapi import FastAPI

from app.schemas import (
    ProviderFindingsRequest,
    RawFinding,
    CopilotReport,
)

from app.normalizer import normalize_findings

from app.cloud_adapters.aws_security_hub import (
    from_aws_security_hub,
)

from app.cloud_adapters.azure_defender import (
    from_azure_defender,
)

from app.cloud_adapters.gcp_scc import (
    from_gcp_scc,
)

from app.correlation_engine import correlate_findings

from app.llm_remediation import (
    generate_llm_remediation_stub,
)


app = FastAPI(
    title="AI Threat Copilot",
    version="0.1.0",
)


def adapt_findings(
    request: ProviderFindingsRequest,
) -> list[RawFinding]:

    if request.provider == "generic":
        return request.findings

    if request.provider == "aws":
        return [
            from_aws_security_hub(finding)
            for finding in request.findings
        ]

    if request.provider == "azure":
        return [
            from_azure_defender(finding)
            for finding in request.findings
        ]

    if request.provider == "gcp":
        return [
            from_gcp_scc(finding)
            for finding in request.findings
        ]

    raise ValueError(
        f"Unsupported provider: {request.provider}"
    )


@app.get("/")
def root():
    return {
        "message": "AI Threat Copilot API is running"
    }


@app.post("/analyze", response_model=CopilotReport)
def analyze(request: ProviderFindingsRequest):

    raw_findings = adapt_findings(request)

    normalized = normalize_findings(raw_findings)

    correlated_risks = correlate_findings(
        [finding.model_dump() for finding in raw_findings]
    )

    highest = sorted(
        normalized,
        key=lambda finding: finding.risk_score,
        reverse=True,
    )[:5]

    actions = []

    for finding in highest:
        if finding.remediation not in actions:
            actions.append(finding.remediation)

    return CopilotReport(
        summary=(
            f"Analyzed {len(normalized)} findings "
            f"from {request.provider}."
        ),
        highest_risks=highest,
        recommended_actions=actions,
        correlated_risks=correlated_risks,
    )


@app.post("/llm-remediation")
def llm_remediation(request: ProviderFindingsRequest):

    raw_findings = adapt_findings(request)

    normalized = normalize_findings(raw_findings)

    results = [
        generate_llm_remediation_stub(finding)
        for finding in normalized
    ]

    return {
        "summary": (
            f"Generated LLM remediation prompts "
            f"for {len(results)} findings."
        ),
        "results": results,
    }