from pydantic import BaseModel
from typing import List


class RemediationStep(BaseModel):
    step: str
    reason: str


class StructuredRemediation(BaseModel):
    issue: str
    severity: str
    risk_score: int
    attack_scenario: str
    remediation_steps: List[RemediationStep]
    validation_steps: List[str]
    priority: str