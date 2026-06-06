from app.risk_scoring import calculate_risk_score


def test_critical_public_risk():
    score = calculate_risk_score(
        severity="CRITICAL",
        public_exposure=True,
        privileged_access=True
    )

    assert score >= 90


def test_low_risk():
    score = calculate_risk_score(
        severity="LOW"
    )

    assert score == 10