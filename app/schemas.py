from pydantic import BaseModel
from typing import List


class RawFinding(BaseModel):
    provider: str
    severity: str
    resource: str
    issue: str
    description: str


class NormalizedFinding(BaseModel):
    source_tool: str
    severity: str
    affected_resource: str
    issue: str
    description: str
    stride_category: str
    likely_impact: str
    risk_score: int = 0
    remediation: str = ""


class CorrelatedRisk(BaseModel):
    risk: str
    severity: str
    description: str


class CopilotReport(BaseModel):
    summary: str
    highest_risks: List[NormalizedFinding]
    recommended_actions: List[str]
    correlated_risks: List[CorrelatedRisk]