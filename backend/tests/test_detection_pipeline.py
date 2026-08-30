import pytest

from backend.app.core.database import SessionLocal
from backend.app.detection_rules.service import DetectionService
from backend.app.models import Asset, Finding, Scan, Service


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
        hostname="detection-test-host",
        asset_type="HOST",
        criticality="HIGH",
        status="ACTIVE",
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


def test_detection_service_creates_database_finding(db):
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

    detection_service = DetectionService()

    findings = detection_service.detect_for_asset(
        db,
        scan,
        asset,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.id is not None
    assert finding.asset_id == asset.id
    assert finding.service_id == service.id
    assert finding.scan_id == scan.id
    assert finding.detection_source == "SA-DB-001"
    assert finding.title == "Exposed Database Service"
    assert finding.severity == "HIGH"


def test_detection_service_ignores_non_matching_service(db):
    scan = create_scan(db)
    asset = create_asset(db)

    service = Service(
        asset_id=asset.id,
        port=8080,
        protocol="tcp",
        service_name="http",
        service_version="nginx",
        state="open",
    )

    db.add(service)
    db.commit()

    detection_service = DetectionService()

    findings = detection_service.detect_for_asset(
        db,
        scan,
        asset,
    )

    assert findings == []


def test_detection_service_detects_multiple_findings(db):
    scan = create_scan(db)
    asset = create_asset(db)

    ssh_service = Service(
        asset_id=asset.id,
        port=22,
        protocol="tcp",
        service_name="ssh",
        service_version="OpenSSH 9.9",
        state="open",
    )

    mysql_service = Service(
        asset_id=asset.id,
        port=3306,
        protocol="tcp",
        service_name="mysql",
        service_version="MySQL 8.0",
        state="open",
    )

    db.add_all(
        [
            ssh_service,
            mysql_service,
        ]
    )
    db.commit()

    detection_service = DetectionService()

    findings = detection_service.detect_for_asset(
        db,
        scan,
        asset,
    )

    assert len(findings) == 2

    rule_ids = {
 	finding.detection_source
    	for finding in findings
    }
    assert rule_ids == {
        "SA-SSH-001",
        "SA-DB-001",
    }


def test_detection_service_returns_empty_without_services(db):
    scan = create_scan(db)
    asset = create_asset(db)

    detection_service = DetectionService()

    findings = detection_service.detect_for_asset(
        db,
        scan,
        asset,
    )

    assert findings == []
