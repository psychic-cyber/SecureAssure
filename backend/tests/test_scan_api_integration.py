from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from backend.app.core.database import SessionLocal
from backend.app.main import app
from backend.app.models import Scan
from backend.app.scanners import orchestrator as orchestrator_module

client = TestClient(app)


@pytest.fixture
def clean_scans():
    db = SessionLocal()

    try:
        yield
    finally:
        db.query(Scan).delete()
        db.commit()
        db.close()

def test_scan_api_completes_scan(monkeypatch, clean_scans):
    def fake_run_nmap_scan(
        self,
        db,
        scan,
        *,
        timeout=300,
        arguments=None,
    ):
        scan.status = "COMPLETED"
        scan.started_at = datetime.utcnow()
        scan.completed_at = datetime.utcnow()
        scan.error_message = None

        db.commit()
        db.refresh(scan)

        return {
            "scan": scan,
            "assets": [],
            "parsed_results": {
                "hosts": [],
            },
        }

    monkeypatch.setattr(
        orchestrator_module.ScanOrchestrator,
        "run_nmap_scan",
        fake_run_nmap_scan,
    )

    response = client.post(
        "/api/v1/scans",
        json={
            "target": "127.0.0.1",
            "scan_type": "service_detection",
            "scanner": "nmap",
            "timeout": 30,
        },
    )

    assert response.status_code == 201

    created_scan = response.json()

    assert created_scan["status"] == "PENDING"

    scan_id = created_scan["id"]

    db = SessionLocal()

    try:
        scan = db.get(orchestrator_module.Scan, scan_id)

        assert scan is not None
        assert scan.status == "COMPLETED"
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.error_message is None

    finally:
        db.close()


def test_scan_api_marks_scan_failed(monkeypatch, clean_scans):
    def fake_run_nmap_scan(
        self,
        db,
        scan,
        *,
        timeout=300,
        arguments=None,
    ):
        scan.status = "FAILED"
        scan.started_at = datetime.utcnow()
        scan.completed_at = datetime.utcnow()
        scan.error_message = "simulated scanner failure"

        db.commit()
        db.refresh(scan)

        return None

    monkeypatch.setattr(
        orchestrator_module.ScanOrchestrator,
        "run_nmap_scan",
        fake_run_nmap_scan,
    )

    response = client.post(
        "/api/v1/scans",
        json={
            "target": "127.0.0.1",
            "scanner": "nmap",
            "timeout": 30,
        },
    )

    assert response.status_code == 201

    created_scan = response.json()

    assert created_scan["status"] == "PENDING"

    scan_id = created_scan["id"]

    db = SessionLocal()

    try:
        scan = db.get(orchestrator_module.Scan, scan_id)

        assert scan is not None
        assert scan.status == "FAILED"
        assert scan.started_at is not None
        assert scan.completed_at is not None
        assert scan.error_message == "simulated scanner failure"

    finally:
        db.close()
