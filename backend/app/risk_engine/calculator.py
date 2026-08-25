from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Calculate risk score using:

        Risk Score = Likelihood × Impact

    Both likelihood and impact must be between 1 and 5.
    """

    if not 1 <= likelihood <= 5:
        raise ValueError("Likelihood must be between 1 and 5.")

    if not 1 <= impact <= 5:
        raise ValueError("Impact must be between 1 and 5.")

    return likelihood * impact


def calculate_risk_level(score: int) -> RiskLevel:
    """
    Convert a risk score into a risk level.

    Score ranges:
        1–4    → LOW
        5–9    → MEDIUM
        10–16  → HIGH
        17–25  → CRITICAL
    """

    if not 1 <= score <= 25:
        raise ValueError("Risk score must be between 1 and 25.")

    if score <= 4:
        return RiskLevel.LOW

    if score <= 9:
        return RiskLevel.MEDIUM

    if score <= 16:
        return RiskLevel.HIGH

    return RiskLevel.CRITICAL


def calculate_risk(
    likelihood: int,
    impact: int,
) -> tuple[int, RiskLevel]:
    """
    Calculate both risk score and risk level.
    """

    score = calculate_risk_score(likelihood, impact)
    level = calculate_risk_level(score)

    return score, level