import pytest

from backend.app.core.database import SessionLocal
from backend.app.models import Asset, Finding, RiskAssessment, Scan
from backend.app.risk_engine.service import RiskAssessmentService


@pytest.fixture
def db():
    session = SessionLocal()

    try:
        yield session

    finally:
        session.rollback()
        session.close()


def create_scan(db):
    scan = Scan(
        scanner="nmap",
        scan_type="service_detection",
        target="192.168.56.101",
        status="COMPLETED",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def create_finding(db, scan):
    asset = Asset(
        ip_address="192.168.56.101",
        hostname="risk-test-host",
        asset_type="HOST",
        criticality="HIGH",
        status="ACTIVE",
    )

    finding = Finding(
        asset=asset,
        scan=scan,
        title="Exposed Database Service",
        description="Database service is exposed.",
        severity="HIGH",
        status="OPEN",
        detection_source="SA-DB-001",
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


def test_assess_finding_creates_risk_assessment(db):
    scan = create_scan(db)
    finding = create_finding(db, scan)

    service = RiskAssessmentService()

    assessment = service.assess_finding(
        db,
        finding,
        likelihood=3,
        impact=4,
        confidentiality=4,
        integrity=4,
        availability=3,
    )

    assert assessment.id is not None
    assert assessment.finding_id == finding.id
    assert assessment.likelihood == 3
    assert assessment.impact == 4
    assert assessment.confidentiality == 4
    assert assessment.integrity == 4
    assert assessment.availability == 3
    assert assessment.risk_score == 12
    assert assessment.risk_level == "HIGH"
    assert assessment.assessment_method == "Likelihood x Impact"


def test_assess_finding_persists_database_record(db):
    scan = create_scan(db)
    finding = create_finding(db, scan)

    service = RiskAssessmentService()

    assessment = service.assess_finding(
        db,
        finding,
        likelihood=2,
        impact=5,
        confidentiality=3,
        integrity=4,
        availability=2,
    )

    persisted = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.id == assessment.id
        )
        .first()
    )

    assert persisted is not None
    assert persisted.finding_id == finding.id
    assert persisted.risk_score == 10
    assert persisted.risk_level == "HIGH"


def test_assess_finding_updates_existing_assessment(db):
    scan = create_scan(db)
    finding = create_finding(db, scan)

    service = RiskAssessmentService()

    first = service.assess_finding(
        db,
        finding,
        likelihood=2,
        impact=2,
        confidentiality=2,
        integrity=2,
        availability=2,
    )

    second = service.assess_finding(
        db,
        finding,
        likelihood=5,
        impact=5,
        confidentiality=5,
        integrity=4,
        availability=3,
    )

    assert second.id == first.id
    assert second.finding_id == finding.id
    assert second.likelihood == 5
    assert second.impact == 5
    assert second.confidentiality == 5
    assert second.integrity == 4
    assert second.availability == 3
    assert second.risk_score == 25
    assert second.risk_level == "CRITICAL"

    assessments = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.finding_id == finding.id
        )
        .all()
    )

    assert len(assessments) == 1


def test_assess_finding_rejects_invalid_likelihood(db):
    scan = create_scan(db)
    finding = create_finding(db, scan)

    service = RiskAssessmentService()

    with pytest.raises(
        ValueError,
        match="Likelihood must be between 1 and 5",
    ):
        service.assess_finding(
            db,
            finding,
            likelihood=0,
            impact=4,
            confidentiality=3,
            integrity=3,
            availability=3,
        )


def test_assess_finding_rejects_invalid_impact(db):
    scan = create_scan(db)
    finding = create_finding(db, scan)

    service = RiskAssessmentService()

    with pytest.raises(
        ValueError,
        match="Impact must be between 1 and 5",
    ):
        service.assess_finding(
            db,
            finding,
            likelihood=3,
            impact=6,
            confidentiality=3,
            integrity=3,
            availability=3,
        )
