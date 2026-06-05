# app/main.py

from fastapi import FastAPI
from app.schemas import (
    RawFinding,
    ProviderFindingsRequest,
    CopilotReport,
    AIAssistedReport,
)
from app.normalizer import normalize_findings
from app.correlator import get_highest_risks, recommend_actions
from app.ai_assistant import generate_ai_assisted_analysis

from app.cloud_adapters.aws_security_hub import from_aws_security_hub
from app.cloud_adapters.azure_defender import from_azure_defender
from app.cloud_adapters.gcp_scc import from_gcp_scc


app = FastAPI(
    title="AI Threat Copilot",
    version="0.2.0",
    description="AI-assisted threat modeling and cloud security analysis platform.",
)


def adapt_findings(request: ProviderFindingsRequest) -> list[RawFinding]:
    if request.provider == "generic":
        return [RawFinding(**finding) for finding in request.findings]

    if request.provider == "aws":
        return [from_aws_security_hub(finding) for finding in request.findings]

    if request.provider == "azure":
        return [from_azure_defender(finding) for finding in request.findings]

    if request.provider == "gcp":
        return [from_gcp_scc(finding) for finding in request.findings]

    raise ValueError(f"Unsupported provider: {request.provider}")


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "project": "AI Threat Copilot",
        "version": "0.2.0",
    }


@app.post("/analyze", response_model=CopilotReport)
def analyze(request: ProviderFindingsRequest):
    raw_findings = adapt_findings(request)
    normalized = normalize_findings(raw_findings)
    highest = get_highest_risks(normalized)
    actions = recommend_actions(highest)

    return CopilotReport(
        summary=f"Analyzed {len(raw_findings)} findings from {request.provider}.",
        highest_risks=highest,
        recommended_actions=actions,
    )


@app.post("/ai-assisted-analysis", response_model=AIAssistedReport)
def ai_assisted_analysis(request: ProviderFindingsRequest):
    raw_findings = adapt_findings(request)
    normalized = normalize_findings(raw_findings)
    highest = get_highest_risks(normalized)
    ai_analysis = generate_ai_assisted_analysis(highest)

    return AIAssistedReport(
        summary=f"Generated AI-assisted analysis from {len(raw_findings)} {request.provider} findings.",
        normalized_findings=highest,
        ai_analysis=ai_analysis,
    )