from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from backend.app.detection_rules.service import DetectionService
from backend.app.models import Scan
from backend.app.scanners.nmap import NmapScanner
from backend.app.scanners.parser import NmapParser
from backend.app.scanners.persistence import persist_nmap_results


class ScanOrchestrator:
    """
    Coordinates the complete Nmap scan workflow.

    Lifecycle:
        PENDING -> RUNNING -> COMPLETED

    Failure:
        RUNNING -> FAILED
    """

    def __init__(
        self,
        scanner: NmapScanner | None = None,
        parser: NmapParser | None = None,
        detection_service: DetectionService | None = None,
    ) -> None:
        self.scanner = scanner or NmapScanner()
        self.parser = parser or NmapParser()
        self.detection_service = (
            detection_service or DetectionService()
        )

    def run_nmap_scan(
        self,
        db: Session,
        scan: Scan,
        *,
        timeout: int = 300,
        arguments: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Execute a complete Nmap scan workflow.

        The Scan record is updated throughout the lifecycle.
        """

        if scan.status not in {"PENDING", "RUNNING"}:
            raise ValueError(
                f"Scan cannot be executed from status '{scan.status}'."
            )

        scan.status = "RUNNING"
        scan.started_at = datetime.utcnow()
        scan.error_message = None

        db.commit()
        db.refresh(scan)

        try:
            scan_result = self.scanner.scan(
                scan.target,
                arguments=arguments,
                timeout=timeout,
            )

            if scan_result["return_code"] != 0:
                error_message = (
                    scan_result.get("stderr")
                    or "Nmap scan failed."
                )

                raise RuntimeError(error_message)

            parsed_results = self.parser.parse(
                scan_result["stdout"]
            )

            assets = persist_nmap_results(
                db,
                scan,
                parsed_results,
            )

            findings = []

            for asset in assets:
                asset_findings = (
                    self.detection_service.detect_for_asset(
                        db,
                        scan,
                        asset,
                    )
                )

                findings.extend(asset_findings)

            scan.status = "COMPLETED"
            scan.completed_at = datetime.utcnow()

            db.commit()
            db.refresh(scan)

            return {
                "scan": scan,
                "assets": assets,
                "parsed_results": parsed_results,
                "findings": findings,
            }

        except Exception as exc:
            db.rollback()

            scan = db.get(Scan, scan.id)

            if scan is None:
                raise

            scan.status = "FAILED"
            scan.error_message = str(exc)
            scan.completed_at = datetime.utcnow()

            db.commit()
            db.refresh(scan)

            raise
