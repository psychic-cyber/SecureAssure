import pytest

from backend.app.core.database import SessionLocal
from backend.app.models import Asset, Finding, Scan, Service
from backend.app.detection_rules.persistence import (
    persist_detected_findings,
)


@pytest.fixture
def db():
    session = SessionLocal()

    try:
        session.query(Finding).delete()
        session.query(Service).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()
        session.commit()

        yield session

    finally:
        session.rollback()

        session.query(Finding).delete()
        session.query(Service).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()

        session.commit()
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


def create_asset(db):
    asset = Asset(
        ip_address="192.168.56.101",
        hostname="test-server",
        asset_type="HOST",
        criticality="HIGH",
        status="ACTIVE",
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


def test_persist_detected_finding(db):
    scan = create_scan(db)
    asset = create_asset(db)

    findings = [
        {
            "rule_id": "SA-DB-001",
            "title": "Exposed Database Service",
            "description": (
                "An exposed MySQL database service "
                "was detected on port 3306."
            ),
            "severity": "HIGH",
            "status": "OPEN",
            "detection_source": "SA-DB-001",
            "recommendation": (
                "Restrict database access to "
                "authorized hosts and networks."
            ),
            "port": 3306,
            "protocol": "tcp",
        }
    ]

    persisted = persist_detected_findings(
        db,
        scan,
        asset,
        findings,
    )

    assert len(persisted) == 1

    finding = persisted[0]

    assert finding.id is not None
    assert finding.asset_id == asset.id
    assert finding.scan_id == scan.id
    assert finding.service_id is None

    assert finding.title == "Exposed Database Service"
    assert finding.severity == "HIGH"
    assert finding.status == "OPEN"
    assert finding.detection_source == "SA-DB-001"


def test_persist_detected_finding_links_service(db):
    scan = create_scan(db)
    asset = create_asset(db)

    service = Service(
        asset_id=asset.id,
        port=3306,
        protocol="tcp",
        service_name="mysql",
        service_version="MySQL 8.0",
        state="open",
    )

    db.add(service)
    db.commit()
    db.refresh(service)

    findings = [
        {
            "rule_id": "SA-DB-001",
            "title": "Exposed Database Service",
            "description": "Exposed MySQL service detected.",
            "severity": "HIGH",
            "status": "OPEN",
            "detection_source": "SA-DB-001",
            "recommendation": "Restrict access.",
            "port": 3306,
            "protocol": "tcp",
        }
    ]

    persisted = persist_detected_findings(
        db,
        scan,
        asset,
        findings,
        service_map={
            (3306, "tcp"): service,
        },
    )

    assert len(persisted) == 1
    assert persisted[0].service_id == service.id


def test_persist_multiple_findings(db):
    scan = create_scan(db)
    asset = create_asset(db)

    findings = [
        {
            "rule_id": "SA-SSH-001",
            "title": "Exposed SSH Service",
            "description": "SSH is exposed.",
            "severity": "MEDIUM",
            "status": "OPEN",
            "detection_source": "SA-SSH-001",
            "recommendation": "Restrict SSH access.",
        },
        {
            "rule_id": "SA-DB-001",
            "title": "Exposed Database Service",
            "description": "Database is exposed.",
            "severity": "HIGH",
            "status": "OPEN",
            "detection_source": "SA-DB-001",
            "recommendation": "Restrict database access.",
        },
    ]

    persisted = persist_detected_findings(
        db,
        scan,
        asset,
        findings,
    )

    assert len(persisted) == 2


def test_invalid_findings_input_is_rejected(db):
    scan = create_scan(db)
    asset = create_asset(db)

    with pytest.raises(ValueError):
        persist_detected_findings(
            db,
            scan,
            asset,
            None,
        )


def test_invalid_finding_records_are_skipped(db):
    scan = create_scan(db)
    asset = create_asset(db)

    findings = [
        {
            "title": "Incomplete Finding",
        },
        {
            "title": "Valid Finding",
            "description": "Valid description.",
            "severity": "LOW",
            "status": "OPEN",
            "detection_source": "TEST-001",
        },
    ]

    persisted = persist_detected_findings(
        db,
        scan,
        asset,
        findings,
    )

    assert len(persisted) == 1
    assert persisted[0].title == "Valid Finding"
