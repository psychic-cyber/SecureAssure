import pytest

from backend.app.core.database import SessionLocal
from backend.app.models import Asset, Scan, Service
from backend.app.scanners.persistence import persist_nmap_results


@pytest.fixture
def db():
    session = SessionLocal()

    try:
        # Clean test data BEFORE each test
        session.query(Service).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()
        session.commit()

        yield session

    finally:
        session.rollback()

        # Clean test data AFTER each test
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


def test_persist_nmap_creates_asset_and_services(db):
    scan = create_scan(db)

    parsed_results = {
        "hosts": [
            {
                "address": "192.168.56.101",
                "hostname": "test-server",
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "version": "OpenSSH 9.9",
                    },
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "nginx 1.27",
                    },
                ],
            }
        ]
    }

    assets = persist_nmap_results(
        db,
        scan,
        parsed_results,
    )

    assert len(assets) == 1

    asset = assets[0]

    assert asset.ip_address == "192.168.56.101"
    assert asset.hostname == "test-server"

    services = (
        db.query(Service)
        .filter(Service.asset_id == asset.id)
        .order_by(Service.port)
        .all()
    )

    assert len(services) == 2

    assert services[0].port == 22
    assert services[0].protocol == "tcp"
    assert services[0].service_name == "ssh"
    assert services[0].service_version == "OpenSSH 9.9"

    assert services[1].port == 80
    assert services[1].protocol == "tcp"
    assert services[1].service_name == "http"
    assert services[1].service_version == "nginx 1.27"


def test_persist_nmap_reuses_existing_asset(db):
    scan = create_scan(db)

    existing_asset = Asset(
        ip_address="192.168.56.102",
        hostname="existing-host",
        asset_type="HOST",
        criticality="MEDIUM",
        status="ACTIVE",
    )

    db.add(existing_asset)
    db.commit()
    db.refresh(existing_asset)

    parsed_results = {
        "hosts": [
            {
                "address": "192.168.56.102",
                "hostname": "existing-host",
                "ports": [],
            }
        ]
    }

    assets = persist_nmap_results(
        db,
        scan,
        parsed_results,
    )

    assert len(assets) == 1
    assert assets[0].id == existing_asset.id

    matching_assets = (
        db.query(Asset)
        .filter(
            Asset.ip_address == "192.168.56.102"
        )
        .all()
    )

    assert len(matching_assets) == 1


def test_persist_nmap_reuses_existing_service(db):
    scan = create_scan(db)

    asset = Asset(
        ip_address="192.168.56.103",
        hostname="service-host",
        asset_type="HOST",
        criticality="MEDIUM",
        status="ACTIVE",
    )

    db.add(asset)
    db.flush()

    existing_service = Service(
        asset_id=asset.id,
        port=443,
        protocol="tcp",
        service_name="https",
        service_version="nginx 1.27",
        state="open",
    )

    db.add(existing_service)
    db.commit()
    db.refresh(existing_service)

    parsed_results = {
        "hosts": [
            {
                "address": "192.168.56.103",
                "hostname": "service-host",
                "ports": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "https",
                        "version": "nginx 1.28",
                    }
                ],
            }
        ]
    }

    persist_nmap_results(
        db,
        scan,
        parsed_results,
    )

    services = (
        db.query(Service)
        .filter(
            Service.asset_id == asset.id,
            Service.port == 443,
            Service.protocol == "tcp",
        )
        .all()
    )

    assert len(services) == 1
    assert services[0].id == existing_service.id
    assert services[0].service_version == "nginx 1.28"


def test_persist_nmap_rejects_invalid_results(db):
    scan = create_scan(db)

    with pytest.raises(ValueError):
        persist_nmap_results(
            db,
            scan,
            None,
        )
