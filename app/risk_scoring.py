def calculate_risk_score(
    severity,
    public_exposure=False,
    privileged_access=False,
    runtime_activity=False
):
    score = 0

    severity = severity.upper()

    if severity == "CRITICAL":
        score += 50
    elif severity == "HIGH":
        score += 35
    elif severity == "MEDIUM":
        score += 20
    elif severity == "LOW":
        score += 10

    if public_exposure:
        score += 25

    if privileged_access:
        score += 15

    if runtime_activity:
        score += 10

    return min(score, 100)