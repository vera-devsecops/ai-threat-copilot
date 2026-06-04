# app/correlator.py

from app.schemas import NormalizedFinding


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def get_highest_risks(
    findings: list[NormalizedFinding],
) -> list[NormalizedFinding]:

    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(
            f.severity.lower(),
            0,
        ),
        reverse=True,
    )[:5]


def recommend_actions(
    findings: list[NormalizedFinding],
) -> list[str]:

    actions = []

    categories = {f.stride_category for f in findings}

    if "Elevation of Privilege" in categories:
        actions.append(
            "Review Kubernetes RBAC, privileged containers, "
            "and service account permissions."
        )

    if "Information Disclosure" in categories:
        actions.append(
            "Review secrets management, encryption, "
            "and public exposure risks."
        )

    if "Tampering" in categories:
        actions.append(
            "Validate untrusted inputs and review "
            "prompt or pipeline injection risks."
        )

    if "Spoofing" in categories:
        actions.append(
            "Review authentication flows and identity controls."
        )

    if not actions:
        actions.append(
            "Review findings manually and prioritise "
            "based on exploitability and business impact."
        )

    return actions