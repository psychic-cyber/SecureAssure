import pytest
from fastapi.testclient import TestClient

from backend.app.core.database import SessionLocal
from backend.app.main import app
from backend.app.models import Asset, Evidence, Finding


client = TestClient(app)


@pytest.fixture
def test_finding():
    db = SessionLocal()

    asset = Asset(
        ip_address="192.168.56.200",
        hostname="evidence-api-test",
        operating_system="Kali Linux",
        asset_type="SERVER",
        criticality="HIGH",
        status="ACTIVE",
    )

    finding = Finding(
        title="Evidence API Test Finding",
        description="Finding created for Evidence API integration tests.",
        severity="HIGH",
        status="OPEN",
        detection_source="TEST",
        asset=asset,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    finding_id = finding.id

    db.close()

    yield finding_id

    # Cleanup test data
    db = SessionLocal()

    db.query(Evidence).filter(
        Evidence.finding_id == finding_id
    ).delete(synchronize_session=False)

    finding = db.get(Finding, finding_id)

    if finding is not None:
        asset_id = finding.asset_id

        db.delete(finding)
        db.commit()

        asset = db.get(Asset, asset_id)

        if asset is not None:
            db.delete(asset)
            db.commit()

    db.close()


def test_create_evidence(test_finding):
    response = client.post(
        "/api/v1/evidence",
        json={
            "finding_id": test_finding,
            "source": "Nmap",
            "command_or_check": "nmap -sV 192.168.56.200",
            "observed_value": "3306/tcp open mysql",
            "expected_value": "Database service should not be publicly exposed",
            "evidence_type": "SCAN_OUTPUT",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["finding_id"] == test_finding
    assert data["source"] == "Nmap"
    assert data["command_or_check"] == "nmap -sV 192.168.56.200"
    assert data["observed_value"] == "3306/tcp open mysql"
    assert data["expected_value"] == (
        "Database service should not be publicly exposed"
    )
    assert data["evidence_type"] == "SCAN_OUTPUT"
    assert "id" in data
    assert "collected_at" in data


def test_create_evidence_with_missing_finding():
    response = client.post(
        "/api/v1/evidence",
        json={
            "finding_id": 999999,
            "source": "Nmap",
            "command_or_check": "nmap -sV 192.168.56.200",
            "observed_value": "3306/tcp open mysql",
            "expected_value": "Database service should not be publicly exposed",
            "evidence_type": "SCAN_OUTPUT",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"


def test_get_evidence(test_finding):
    create_response = client.post(
        "/api/v1/evidence",
        json={
            "finding_id": test_finding,
            "source": "Nmap",
            "command_or_check": "nmap -sV 192.168.56.200",
            "observed_value": "3306/tcp open mysql",
            "expected_value": "Database service should not be publicly exposed",
            "evidence_type": "SCAN_OUTPUT",
        },
    )

    evidence_id = create_response.json()["id"]

    response = client.get(
        f"/api/v1/evidence/{evidence_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == evidence_id
    assert data["finding_id"] == test_finding
    assert data["source"] == "Nmap"


def test_get_missing_evidence():
    response = client.get(
        "/api/v1/evidence/999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Evidence not found"


def test_get_finding_evidence(test_finding):
    first_response = client.post(
        "/api/v1/evidence",
        json={
            "finding_id": test_finding,
            "source": "Nmap",
            "command_or_check": "nmap -sV 192.168.56.200",
            "observed_value": "3306/tcp open mysql",
            "expected_value": "Database service should not be publicly exposed",
            "evidence_type": "SCAN_OUTPUT",
        },
    )

    second_response = client.post(
        "/api/v1/evidence",
        json={
            "finding_id": test_finding,
            "source": "Manual Review",
            "command_or_check": "Verify database exposure",
            "observed_value": "MySQL accessible",
            "expected_value": "Database should be restricted",
            "evidence_type": "MANUAL_CHECK",
        },
    )

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    response = client.get(
        f"/api/v1/evidence/finding/{test_finding}"
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 2
    assert data[0]["finding_id"] == test_finding
    assert data[1]["finding_id"] == test_finding


def test_get_evidence_for_missing_finding():
    response = client.get(
        "/api/v1/evidence/finding/999999"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Finding not found"
