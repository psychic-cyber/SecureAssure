from fastapi.testclient import TestClient

from backend.app.core.database import SessionLocal
from backend.app.main import app
from backend.app.models import Asset, Scan, Service


client = TestClient(app)


def cleanup_scan_data():
    db = SessionLocal()

    try:
        db.query(Service).delete()
        db.query(Asset).delete()
        db.query(Scan).delete()
        db.commit()
    finally:
        db.close()


def test_real_localhost_scan_end_to_end():
    cleanup_scan_data()

    response = client.post(
        "/api/v1/scans",
        json={
            "target": "127.0.0.1",
            "scan_type": "service_detection",
            "scanner": "nmap",
            "timeout": 60,
        },
    )

    assert response.status_code == 201

    scan_data = response.json()

    assert scan_data["id"] is not None
    assert scan_data["target"] == "127.0.0.1"
    assert scan_data["scanner"] == "nmap"
    assert scan_data["status"] == "PENDING"

    scan_id = scan_data["id"]

    db = SessionLocal()

    try:
        scan = db.get(Scan, scan_id)

        assert scan is not None

        assert scan.status == "COMPLETED"
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.error_message is None

        assets = (
            db.query(Asset)
            .filter(
                Asset.ip_address == "127.0.0.1"
            )
            .all()
        )

        assert len(assets) == 1

        asset = assets[0]

        services = (
            db.query(Service)
            .filter(
                Service.asset_id == asset.id
            )
            .all()
        )

        assert services is not None

    finally:
        db.close()

        cleanup_scan_data()
