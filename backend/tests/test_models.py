from sqlalchemy import inspect
from sqlalchemy.orm import Session

from backend.app.core.database import engine
from backend.app.models import Asset, Service


def test_assets_table_exists():
    inspector = inspect(engine)

    assert "assets" in inspector.get_table_names()


def test_services_table_exists():
    inspector = inspect(engine)

    assert "services" in inspector.get_table_names()


def test_asset_model_is_registered():
    assert Asset.__tablename__ == "assets"


def test_service_model_is_registered():
    assert Service.__tablename__ == "services"


def test_service_has_asset_foreign_key():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("services")

    assert len(foreign_keys) == 1
    assert foreign_keys[0]["referred_table"] == "assets"
    assert foreign_keys[0]["constrained_columns"] == ["asset_id"]

def test_scans_table_exists():
    inspector = inspect(engine)

    assert "scans" in inspector.get_table_names()


def test_scan_model_is_registered():
    from backend.app.models import Scan

    assert Scan.__tablename__ == "scans"


def test_findings_table_exists():
    inspector = inspect(engine)

    assert "findings" in inspector.get_table_names()


def test_finding_model_is_registered():
    from backend.app.models import Finding

    assert Finding.__tablename__ == "findings"


def test_finding_foreign_keys():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("findings")

    foreign_key_map = {
        fk["constrained_columns"][0]: fk["referred_table"]
        for fk in foreign_keys
    }

    assert foreign_key_map["asset_id"] == "assets"
    assert foreign_key_map["service_id"] == "services"
    assert foreign_key_map["scan_id"] == "scans"


def test_risk_assessments_table_exists():
    inspector = inspect(engine)

    assert "risk_assessments" in inspector.get_table_names()


def test_risk_assessment_model_is_registered():
    from backend.app.models import RiskAssessment

    assert RiskAssessment.__tablename__ == "risk_assessments"


def test_risk_assessment_finding_foreign_key():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("risk_assessments")

    assert len(foreign_keys) == 1
    assert foreign_keys[0]["referred_table"] == "findings"
    assert foreign_keys[0]["constrained_columns"] == ["finding_id"]


def test_risk_assessment_finding_is_unique():
    inspector = inspect(engine)

    indexes = inspector.get_indexes("risk_assessments")

    unique_columns = [
        index["column_names"]
        for index in indexes
        if index["unique"]
    ]

    assert ["finding_id"] in unique_columns

def test_security_controls_table_exists():
    inspector = inspect(engine)

    assert "security_controls" in inspector.get_table_names()


def test_finding_controls_table_exists():
    inspector = inspect(engine)

    assert "finding_controls" in inspector.get_table_names()


def test_security_control_model_is_registered():
    from backend.app.models import SecurityControl

    assert SecurityControl.__tablename__ == "security_controls"


def test_security_control_code_is_unique():
    inspector = inspect(engine)

    indexes = inspector.get_indexes("security_controls")

    unique_columns = [
        index["column_names"]
        for index in indexes
        if index["unique"]
    ]

    assert ["control_code"] in unique_columns


def test_finding_controls_foreign_keys():
    inspector = inspect(engine)

    foreign_keys = inspector.get_foreign_keys("finding_controls")

    foreign_key_map = {
        fk["constrained_columns"][0]: fk["referred_table"]
        for fk in foreign_keys
    }

    assert foreign_key_map["finding_id"] == "findings"
    assert foreign_key_map["control_id"] == "security_controls"


def test_finding_controls_composite_primary_key():
    inspector = inspect(engine)

    primary_key = inspector.get_pk_constraint("finding_controls")

    assert set(primary_key["constrained_columns"]) == {
        "finding_id",
        "control_id",
    }


def test_finding_security_control_relationship():
    from uuid import uuid4

    from backend.app.models import Asset, Finding, SecurityControl

    session = Session(engine)

    unique_code = f"TEST-AC-{uuid4().hex[:8].upper()}"

    asset = Asset(
        ip_address="192.168.56.101",
        hostname="test-host",
        operating_system="Kali Linux",
        asset_type="SERVER",
        criticality="HIGH",
        status="ACTIVE",
    )

    finding = Finding(
        title="Test Security Finding",
        description="Test finding for security control mapping.",
        severity="HIGH",
        status="OPEN",
        detection_source="TEST",
        asset=asset,
    )

    control = SecurityControl(
        control_code=unique_code,
        name="Test Access Control",
        category="Preventive",
        description="Test security control.",
        framework="SecureAssure",
        implementation_status="IMPLEMENTED",
    )

    finding.security_controls.append(control)

    session.add(finding)
    session.commit()
    session.refresh(finding)

    assert len(finding.security_controls) == 1
    assert finding.security_controls[0].control_code == unique_code

    session.close()