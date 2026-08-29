from sqlalchemy import inspect

from backend.app.core.database import engine
from backend.app.models import Evidence


def test_evidence_table_exists():
    inspector = inspect(engine)

    assert "evidence" in inspector.get_table_names()


def test_evidence_model_is_registered():
    assert Evidence.__tablename__ == "evidence"


def test_evidence_finding_foreign_key():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("evidence")

    assert len(foreign_keys) == 1
    assert foreign_keys[0]["referred_table"] == "findings"
    assert foreign_keys[0]["constrained_columns"] == ["finding_id"]


def test_evidence_required_columns_exist():
    inspector = inspect(engine)

    columns = {
        column["name"]
        for column in inspector.get_columns("evidence")
    }

    expected_columns = {
        "id",
        "finding_id",
        "source",
        "command_or_check",
        "observed_value",
        "expected_value",
        "evidence_type",
        "collected_at",
    }

    assert expected_columns.issubset(columns)


from sqlalchemy.orm import Session

from backend.app.models import Asset, Finding, Evidence


def test_finding_evidence_relationship():
    session = Session(engine)

    asset = Asset(
        ip_address="192.168.56.102",
        hostname="evidence-test-host",
        operating_system="Kali Linux",
        asset_type="SERVER",
        criticality="HIGH",
        status="ACTIVE",
    )

    finding = Finding(
        title="Exposed Test Service",
        description="Test finding for evidence relationship.",
        severity="HIGH",
        status="OPEN",
        detection_source="TEST",
        asset=asset,
    )

    evidence = Evidence(
        source="TEST",
        command_or_check="test-command",
        observed_value="3306/tcp open mysql",
        expected_value="Database service should not be exposed",
        evidence_type="COMMAND_OUTPUT",
    )

    finding.evidence.append(evidence)

    session.add(finding)
    session.commit()
    session.refresh(finding)

    assert len(finding.evidence) == 1
    assert finding.evidence[0].source == "TEST"
    assert finding.evidence[0].evidence_type == "COMMAND_OUTPUT"

    session.close()
