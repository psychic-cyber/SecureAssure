import pytest

from backend.app.risk_engine.calculator import (
    RiskLevel,
    calculate_risk,
    calculate_risk_level,
    calculate_risk_score,
)


def test_low_risk():
    score, level = calculate_risk(1, 1)

    assert score == 1
    assert level == RiskLevel.LOW


def test_medium_risk():
    score, level = calculate_risk(2, 4)

    assert score == 8
    assert level == RiskLevel.MEDIUM


def test_high_risk():
    score, level = calculate_risk(3, 4)

    assert score == 12
    assert level == RiskLevel.HIGH


def test_critical_risk():
    score, level = calculate_risk(5, 5)

    assert score == 25
    assert level == RiskLevel.CRITICAL


def test_invalid_likelihood():
    with pytest.raises(ValueError):
        calculate_risk_score(0, 5)


def test_invalid_impact():
    with pytest.raises(ValueError):
        calculate_risk_score(5, 6)


def test_invalid_risk_score():
    with pytest.raises(ValueError):
        calculate_risk_level(0)


def test_invalid_high_risk_score():
    with pytest.raises(ValueError):
        calculate_risk_level(26)

def test_risk_score_boundaries():
    assert calculate_risk_score(1, 1) == 1
    assert calculate_risk_score(5, 5) == 25


def test_risk_level_boundaries():
    assert calculate_risk_level(4) == RiskLevel.LOW
    assert calculate_risk_level(5) == RiskLevel.MEDIUM
    assert calculate_risk_level(9) == RiskLevel.MEDIUM
    assert calculate_risk_level(10) == RiskLevel.HIGH
    assert calculate_risk_level(16) == RiskLevel.HIGH
    assert calculate_risk_level(17) == RiskLevel.CRITICAL
    assert calculate_risk_level(25) == RiskLevel.CRITICAL