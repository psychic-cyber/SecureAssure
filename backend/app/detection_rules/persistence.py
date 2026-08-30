from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from backend.app.models import Asset, Finding, Scan, Service


def persist_detected_findings(
    db: Session,
    scan: Scan,
    asset: Asset,
    findings: list[dict[str, Any]],
    service_map: dict[tuple[int, str], Service] | None = None,
) -> list[Finding]:
    """
    Persist detection-rule results as Finding records.

    Each finding is associated with:
    - the asset that was evaluated
    - the scan that produced the detection
    - the matching service, when available
    """

    if not isinstance(findings, list):
        raise ValueError("Findings must be provided as a list.")

    if service_map is None:
        service_map = {}

    persisted_findings: list[Finding] = []

    for finding_data in findings:
        if not isinstance(finding_data, dict):
            continue

        title = finding_data.get("title")
        description = finding_data.get("description")
        severity = finding_data.get("severity")
        status = finding_data.get("status")
        detection_source = finding_data.get(
            "detection_source"
        )

        if not title or not description:
            continue

        if not severity or not status:
            continue

        if not detection_source:
            continue

        service = None

        port = finding_data.get("port")
        protocol = finding_data.get("protocol")

        if port is not None and protocol:
            service = service_map.get(
                (port, protocol)
            )

        finding = Finding(
            asset_id=asset.id,
            service_id=(
                service.id
                if service is not None
                else None
            ),
            scan_id=scan.id,
            title=title,
            description=description,
            severity=severity,
            status=status,
            detection_source=detection_source,
            recommendation=finding_data.get(
                "recommendation"
            ),
            detected_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(finding)
        persisted_findings.append(finding)

    db.commit()

    for finding in persisted_findings:
        db.refresh(finding)

    return persisted_findings
