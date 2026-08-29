from sqlalchemy import inspect

from backend.app.core.database import SessionLocal, engine
from backend.app.models import Remediation

def test_remediations_table_exists():
    inspector = inspect(engine)

    assert "remediations" in inspector.get_table_names()


def test_remediation_model_is_registered():
    assert Remediation.__tablename__ == "remediations"


def test_remediation_finding_foreign_key():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("remediations")

    assert len(foreign_keys) == 1
    assert foreign_keys[0]["referred_table"] == "findings"
    assert foreign_keys[0]["constrained_columns"] == ["finding_id"]


def test_remediation_required_columns_exist():
    inspector = inspect(engine)

    columns = {
        column["name"]: column
        for column in inspector.get_columns("remediations")
    }

    required_columns = {
        "id",
        "finding_id",
        "recommendation",
        "priority",
        "status",
        "created_at",
        "updated_at",
    }

    assert required_columns.issubset(columns.keys())


def test_remediation_finding_relationship():
    from backend.app.models import Asset, Finding

    db = SessionLocal()

    asset = Asset(
        ip_address="192.168.56.210",
        hostname="remediation-test",
        operating_system="Kali Linux",
        asset_type="SERVER",
        criticality="HIGH",
        status="ACTIVE",
    )

    finding = Finding(
        title="Remediation Relationship Test",
        description="Finding created for remediation relationship testing.",
        severity="HIGH",
        status="OPEN",
        detection_source="TEST",
        asset=asset,
    )

    remediation = Remediation(
        recommendation="Restrict the exposed service.",
        assigned_user="security-team",
        priority="HIGH",
        status="OPEN",
        finding=finding,
    )

    db.add(remediation)
    db.commit()
    db.refresh(remediation)

    assert remediation.finding_id == finding.id
    assert remediation.finding.id == finding.id

    db.delete(remediation)
    db.delete(finding)
    db.delete(asset)
    db.commit()

    db.close()
