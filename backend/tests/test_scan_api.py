from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.database import SessionLocal
from backend.app.models import Scan


client = TestClient(app)


def test_create_scan():
    response = client.post(
        "/api/v1/scans",
        json={
            "target": "192.168.56.101",
            "scan_type": "service_detection",
            "scanner": "nmap",
            "timeout": 30,
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["scanner"] == "nmap"
    assert data["target"] == "192.168.56.101"
    assert data["scan_type"] == "service_detection"
    assert data["status"] == "PENDING"
    assert data["id"] is not None


def test_get_scan():
    db = SessionLocal()

    try:
        scan = Scan(
            scanner="nmap",
            scan_type="service_detection",
            target="192.168.56.102",
            status="PENDING",
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        scan_id = scan.id

    finally:
        db.close()

    response = client.get(
        f"/api/v1/scans/{scan_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == scan_id
    assert data["scanner"] == "nmap"
    assert data["target"] == "192.168.56.102"
    assert data["status"] == "PENDING"


def test_get_scan_not_found():
    response = client.get(
        "/api/v1/scans/999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_create_scan_rejects_empty_target():
    response = client.post(
        "/api/v1/scans",
        json={
            "target": "   ",
            "scanner": "nmap",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Target must not be empty"


def test_create_scan_rejects_invalid_timeout():
    response = client.post(
        "/api/v1/scans",
        json={
            "target": "192.168.56.101",
            "scanner": "nmap",
            "timeout": 0,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Timeout must be greater than zero"


def test_create_scan_rejects_unsupported_scanner():
    response = client.post(
        "/api/v1/scans",
        json={
            "target": "192.168.56.101",
            "scanner": "masscan",
        },
    )

    assert response.status_code == 400
    assert (
        response.json()["detail"]
        == "Only Nmap scanner is currently supported"
    )
