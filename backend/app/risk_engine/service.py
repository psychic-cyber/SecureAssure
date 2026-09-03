from sqlalchemy.orm import Session

from backend.app.models import Finding, RiskAssessment
from backend.app.risk_engine.calculator import calculate_risk


class RiskAssessmentService:
    """
    Creates or updates risk assessments for findings.
    """

    ASSESSMENT_METHOD = "Likelihood x Impact"

    def assess_finding(
        self,
        db: Session,
        finding: Finding,
        *,
        likelihood: int,
        impact: int,
        confidentiality: int,
        integrity: int,
        availability: int,
    ) -> RiskAssessment:
        """
        Assess the risk of a finding and persist the result.

        Risk score is calculated as:

            Likelihood × Impact
        """

        score, risk_level = calculate_risk(
            likelihood,
            impact,
        )

        assessment = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.finding_id == finding.id
            )
            .first()
        )

        if assessment is None:
            assessment = RiskAssessment(
                finding_id=finding.id,
            )
            db.add(assessment)

        assessment.likelihood = likelihood
        assessment.impact = impact
        assessment.confidentiality = confidentiality
        assessment.integrity = integrity
        assessment.availability = availability
        assessment.risk_score = score
        assessment.risk_level = risk_level.value
        assessment.assessment_method = (
            self.ASSESSMENT_METHOD
        )

        db.commit()
        db.refresh(assessment)

        return assessment
