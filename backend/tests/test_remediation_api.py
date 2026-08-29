from datetime import datetime

from fastapi.testclient import TestClient

from backend.app.core.database import SessionLocal
from backend.app.main import app
from backend.app.models import Asset, Finding


client = TestClient(app)


def create_test_finding():
    db = SessionLocal()

    asset = Asset(
        ip_address="192.168.56.220",
        hostname="remediation-api-test",
        operating_system="Kali Linux",
        asset_type="SERVER",
        criticality="HIGH",
        status="ACTIVE",
    )

    finding = Finding(
        title="Remediation API Test Finding",
        description="Finding used for remediation API tests.",
        severity="HIGH",
        status="OPEN",
        detection_source="TEST",
        recommendation="Test recommendation",
        asset=asset,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    finding_id = finding.id

    db.close()

    return finding_id


def test_create_remediation():
    finding_id = create_test_finding()

    response = client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "Apply security patch.",
            "assigned_user": "security-team",
            "priority": "HIGH",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["finding_id"] == finding_id
    assert data["recommendation"] == "Apply security patch."
    assert data["assigned_user"] == "security-team"
    assert data["priority"] == "HIGH"
    assert data["status"] == "OPEN"


def test_create_remediation_invalid_finding():
    response = client.post(
        "/api/v1/remediations",
        json={
            "finding_id": 999999,
            "recommendation": "Test recommendation",
            "priority": "HIGH",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"


def test_create_remediation_invalid_priority():
    finding_id = create_test_finding()

    response = client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "Test recommendation",
            "priority": "INVALID",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid remediation priority"


def test_get_remediation():
    finding_id = create_test_finding()

    create_response = client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "Test recommendation",
            "priority": "MEDIUM",
        },
    )

    remediation_id = create_response.json()["id"]

    response = client.get(
        f"/api/v1/remediations/{remediation_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == remediation_id
    assert data["finding_id"] == finding_id
    assert data["status"] == "OPEN"


def test_get_remediation_not_found():
    response = client.get(
        "/api/v1/remediations/999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Remediation not found"


def test_get_finding_remediations():
    finding_id = create_test_finding()

    client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "First remediation",
            "priority": "HIGH",
        },
    )

    client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "Second remediation",
            "priority": "MEDIUM",
        },
    )

    response = client.get(
        f"/api/v1/remediations/finding/{finding_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert data[0]["finding_id"] == finding_id
    assert data[1]["finding_id"] == finding_id


def test_get_finding_remediations_invalid_finding():
    response = client.get(
        "/api/v1/remediations/finding/999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"


def test_update_remediation():
    finding_id = create_test_finding()

    create_response = client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "Fix the vulnerability.",
            "priority": "HIGH",
        },
    )

    remediation_id = create_response.json()["id"]

    response = client.patch(
        f"/api/v1/remediations/{remediation_id}",
        json={
            "status": "IN_PROGRESS",
            "assigned_user": "admin",
            "priority": "CRITICAL",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "IN_PROGRESS"
    assert data["assigned_user"] == "admin"
    assert data["priority"] == "CRITICAL"


def test_update_remediation_invalid_status():
    finding_id = create_test_finding()

    create_response = client.post(
        "/api/v1/remediations",
        json={
            "finding_id": finding_id,
            "recommendation": "Test recommendation",
            "priority": "LOW",
        },
    )

    remediation_id = create_response.json()["id"]

    response = client.patch(
        f"/api/v1/remediations/{remediation_id}",
        json={
            "status": "INVALID_STATUS",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid remediation status"


def test_update_remediation_not_found():
    response = client.patch(
        "/api/v1/remediations/999999",
        json={
            "status": "CLOSED",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Remediation not found"
