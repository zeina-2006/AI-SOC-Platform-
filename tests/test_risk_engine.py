from app.risk_engine import calculate_risk_score


def test_zero_attempts_are_low_risk():
    result = calculate_risk_score(0)

    assert result["risk_score"] == 0
    assert result["severity"] == "Low"


def test_one_attempt_is_low_risk():
    result = calculate_risk_score(1)

    assert result["risk_score"] == 20
    assert result["severity"] == "Low"


def test_three_attempts_are_medium_risk():
    result = calculate_risk_score(3)

    assert result["risk_score"] == 40
    assert result["severity"] == "Medium"


def test_five_attempts_are_high_risk():
    result = calculate_risk_score(5)

    assert result["risk_score"] == 60
    assert result["severity"] == "High"


def test_eight_attempts_are_critical_risk():
    result = calculate_risk_score(8)

    assert result["risk_score"] == 90
    assert result["severity"] == "Critical"


def test_result_contains_explanation_and_recommendation():
    result = calculate_risk_score(5)

    assert result["reason"]
    assert result["recommendation"]
    assert result["failed_attempts"] == 5


def test_negative_attempts_are_handled_safely():
    result = calculate_risk_score(-5)

    assert result["failed_attempts"] == 0
    assert result["risk_score"] == 0
    assert result["severity"] == "Low"