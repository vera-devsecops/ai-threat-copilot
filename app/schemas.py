 # app/schemas.py

from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class RawFinding(BaseModel):
    tool: str
    severity: str
    resource: str
    title: str
    description: str
    namespace: Optional[str] = None
    category: Optional[str] = None


class ProviderFindingsRequest(BaseModel):
    provider: str = "generic"
    findings: List[RawFinding]


class NormalizedFinding(BaseModel):
    source_tool: str
    severity: str
    affected_resource: str
    issue: str
    description: str
    stride_category: str
    likely_impact: str


class CopilotReport(BaseModel):
    summary: str
    highest_risks: List[NormalizedFinding]
    recommended_actions: List[str]


class AIAssistedReport(BaseModel):
    summary: str
    normalized_findings: List[NormalizedFinding]
    ai_analysis: Dict[str, Any]