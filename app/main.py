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

app = FastAPI(
    title="AI Threat Copilot",
    version="0.1.0",
    description="AI-assisted threat modeling and cloud security analysis platform."
)


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "project": "AI Threat Copilot"
    }


@app.post("/analyze", response_model=CopilotReport)
def analyze(request: ProviderFindingsRequest):

    normalized = normalize_findings(request.findings)

    highest = get_highest_risks(normalized)

    actions = recommend_actions(highest)

    return CopilotReport(
        summary=f"Analyzed {len(request.findings)} findings.",
        highest_risks=highest,
        recommended_actions=actions,
    )


@app.post("/ai-assisted-analysis", response_model=AIAssistedReport)
def ai_assisted_analysis(request: ProviderFindingsRequest):

    normalized = normalize_findings(request.findings)

    highest = get_highest_risks(normalized)

    ai_analysis = generate_ai_assisted_analysis(highest)

    return AIAssistedReport(
        summary=f"Generated AI-assisted analysis from {len(request.findings)} findings.",
        normalized_findings=highest,
        ai_analysis=ai_analysis,
    )