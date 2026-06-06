import json

from app.llm_models import StructuredRemediation


def parse_structured_remediation(raw_response: str) -> StructuredRemediation:
    data = json.loads(raw_response)
    return StructuredRemediation(**data)