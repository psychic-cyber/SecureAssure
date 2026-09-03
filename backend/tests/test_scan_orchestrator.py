from datetime import datetime

import pytest

from backend.app.core.database import SessionLocal
from backend.app.models import Asset, Finding, Scan, Service
from backend.app.scanners.orchestrator import ScanOrchestrator


class FakeScanner:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def scan(self, target, *, arguments=None, timeout=300):
        if self.error:
            raise self.error

        return self.result


class FakeParser:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def parse(self, xml_output):
        if self.error:
            raise self.error

        return self.result


@pytest.fixture
def db():
    session = SessionLocal()

    try:
        session.query(Service).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()
        session.commit()

        yield session

    finally:
        session.rollback()

        session.query(Service).delete()
        session.query(Asset).delete()
        session.query(Scan).delete()

        session.commit()
        session.close()


def create_scan(db, status="PENDING"):
    scan = Scan(
        scanner="nmap",
        scan_type="service_detection",
        target="192.168.56.101",
        status=status,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan

class FakeDetectionService:
    def __init__(self, findings=None):
        self.findings = findings or []
        self.calls = []

    def detect_for_asset(self, db, scan, asset):
        self.calls.append((scan.id, asset.id))
        return self.findings

def test_successful_scan_lifecycle(db):
    scan = create_scan(db)

    scanner = FakeScanner(
        result={
            "scanner": "nmap",
            "target": "192.168.56.101",
            "command": ["/usr/bin/nmap", "-sV", "192.168.56.101"],
            "return_code": 0,
            "stdout": "<nmaprun></nmaprun>",
            "stderr": "",
        }
    )

    parser = FakeParser(
        result={
            "hosts": []
        }
    )

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        parser=parser,
    )

    result = orchestrator.run_nmap_scan(
        db,
        scan,
    )

    assert result["scan"].id == scan.id
    assert result["assets"] == []
    assert result["parsed_results"] == {"hosts": []}

    assert scan.status == "COMPLETED"
    assert scan.started_at is not None
    assert scan.completed_at is not None
    assert scan.error_message is None

    assert isinstance(scan.started_at, datetime)
    assert isinstance(scan.completed_at, datetime)


def test_scan_failure_marks_scan_failed(db):
    scan = create_scan(db)

    scanner = FakeScanner(
        error=RuntimeError("scanner execution failed")
    )

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        parser=FakeParser(),
    )

    with pytest.raises(RuntimeError, match="scanner execution failed"):
        orchestrator.run_nmap_scan(
            db,
            scan,
        )

    db.refresh(scan)

    assert scan.status == "FAILED"
    assert scan.started_at is not None
    assert scan.completed_at is not None
    assert scan.error_message == "scanner execution failed"


def test_nmap_nonzero_return_code_marks_scan_failed(db):
    scan = create_scan(db)

    scanner = FakeScanner(
        result={
            "scanner": "nmap",
            "target": "192.168.56.101",
            "command": ["/usr/bin/nmap", "-sV", "192.168.56.101"],
            "return_code": 1,
            "stdout": "",
            "stderr": "Nmap execution failed",
        }
    )

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        parser=FakeParser(),
    )

    with pytest.raises(RuntimeError, match="Nmap execution failed"):
        orchestrator.run_nmap_scan(
            db,
            scan,
        )

    db.refresh(scan)

    assert scan.status == "FAILED"
    assert scan.error_message == "Nmap execution failed"
    assert scan.completed_at is not None


def test_parser_failure_marks_scan_failed(db):
    scan = create_scan(db)

    scanner = FakeScanner(
        result={
            "scanner": "nmap",
            "target": "192.168.56.101",
            "command": ["/usr/bin/nmap", "-sV", "192.168.56.101"],
            "return_code": 0,
            "stdout": "<invalid>",
            "stderr": "",
        }
    )

    parser = FakeParser(
        error=ValueError("Invalid Nmap XML output.")
    )

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        parser=parser,
    )

    with pytest.raises(ValueError, match="Invalid Nmap XML output."):
        orchestrator.run_nmap_scan(
            db,
            scan,
        )

    db.refresh(scan)

    assert scan.status == "FAILED"
    assert scan.error_message == "Invalid Nmap XML output."
    assert scan.completed_at is not None


def test_completed_scan_cannot_be_rerun(db):
    scan = create_scan(
        db,
        status="COMPLETED",
    )

    orchestrator = ScanOrchestrator(
        scanner=FakeScanner(),
        parser=FakeParser(),
    )

    with pytest.raises(
        ValueError,
        match="Scan cannot be executed",
    ):
        orchestrator.run_nmap_scan(
            db,
            scan,
        )


def test_failed_scan_cannot_be_rerun(db):
    scan = create_scan(
        db,
        status="FAILED",
    )

    orchestrator = ScanOrchestrator(
        scanner=FakeScanner(),
        parser=FakeParser(),
    )

    with pytest.raises(
        ValueError,
        match="Scan cannot be executed",
    ):
        orchestrator.run_nmap_scan(
            db,
            scan,
        )

def test_successful_scan_runs_detection_for_persisted_assets(db):
    scan = create_scan(db)

    scanner = FakeScanner(
        result={
            "scanner": "nmap",
            "target": "192.168.56.101",
            "command": ["/usr/bin/nmap", "-sV", "192.168.56.101"],
            "return_code": 0,
            "stdout": "<nmaprun></nmaprun>",
            "stderr": "",
        }
    )

    parser = FakeParser(
        result={
            "hosts": [
                {
                    "address": "192.168.56.101",
                    "hostname": "test-host",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH",
                        }
                    ],
                }
            ]
        }
    )

    detection_service = FakeDetectionService(
        findings=["finding-1"]
    )

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        parser=parser,
        detection_service=detection_service,
    )

    result = orchestrator.run_nmap_scan(
        db,
        scan,
    )

    assert result["scan"].id == scan.id
    assert len(result["assets"]) == 1
    assert result["findings"] == ["finding-1"]

    asset = result["assets"][0]

    assert detection_service.calls == [
        (scan.id, asset.id)
    ]

    assert scan.status == "COMPLETED"
    assert scan.error_message is None


def test_successful_scan_persists_detected_findings(db):
    scan = create_scan(db)

    scanner = FakeScanner(
        result={
            "scanner": "nmap",
            "target": "192.168.56.101",
            "command": ["/usr/bin/nmap", "-sV", "192.168.56.101"],
            "return_code": 0,
            "stdout": "<nmaprun></nmaprun>",
            "stderr": "",
        }
    )

    parser = FakeParser(
        result={
            "hosts": [
                {
                    "address": "192.168.56.101",
                    "hostname": "integration-test-host",
                    "ports": [
                        {
                            "port": 3306,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "mysql",
                            "version": "MySQL 8.0",
                        }
                    ],
                }
            ]
        }
    )

    orchestrator = ScanOrchestrator(
        scanner=scanner,
        parser=parser,
    )

    result = orchestrator.run_nmap_scan(
        db,
        scan,
    )

    assert scan.status == "COMPLETED"

    assert len(result["assets"]) == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding.id is not None
    assert finding.asset_id == result["assets"][0].id
    assert finding.scan_id == scan.id
    assert finding.detection_source == "SA-DB-001"
    assert finding.title == "Exposed Database Service"
    assert finding.severity == "HIGH"

    persisted_finding = (
        db.query(Finding)
        .filter(Finding.id == finding.id)
        .first()
    )

    assert persisted_finding is not None
    assert persisted_finding.service_id is not None