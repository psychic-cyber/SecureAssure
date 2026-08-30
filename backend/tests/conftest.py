import pytest

from backend.app.core.database import SessionLocal
from backend.app.models import (
    Asset,
    Evidence,
    Finding,
    Remediation,
    RiskAssessment,
    Scan,
    SecurityControl,
    Service,
)
from backend.app.models.security_control import finding_controls


@pytest.fixture(autouse=True)
def clean_database():
    db = SessionLocal()

    try:
        yield

    finally:
        db.rollback()

        db.execute(finding_controls.delete())

        db.query(Evidence).delete()
        db.query(Remediation).delete()
        db.query(RiskAssessment).delete()
        db.query(Finding).delete()
        db.query(SecurityControl).delete()
        db.query(Service).delete()
        db.query(Asset).delete()
        db.query(Scan).delete()

        db.commit()
        db.close()
