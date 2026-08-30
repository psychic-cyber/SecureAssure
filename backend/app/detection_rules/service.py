from typing import Any

from sqlalchemy.orm import Session

from backend.app.detection_rules.engine import DetectionRuleEngine
from backend.app.detection_rules.persistence import (
    persist_detected_findings,
)
from backend.app.detection_rules.rules import get_default_rules
from backend.app.models import Asset, Finding, Scan, Service


class DetectionService:
    """
    Coordinates detection-rule evaluation for persisted services
    and stores matching findings in the database.
    """

    def __init__(
        self,
        engine: DetectionRuleEngine | None = None,
    ) -> None:
        self.engine = engine or DetectionRuleEngine(
            get_default_rules()
        )

    def detect_for_asset(
        self,
        db: Session,
        scan: Scan,
        asset: Asset,
    ) -> list[Finding]:
        """
        Evaluate all services belonging to an asset.

        Returns:
            Persisted Finding records created by matching rules.
        """

        services = (
            db.query(Service)
            .filter(Service.asset_id == asset.id)
            .order_by(Service.port)
            .all()
        )

        if not services:
            return []

        service_map = {
            (service.port, service.protocol): service
            for service in services
        }

        service_payloads: list[dict[str, Any]] = []

        for service in services:
            service_payloads.append(
                {
                    "port": service.port,
                    "protocol": service.protocol,
                    "state": service.state,
                    "service": service.service_name,
                    "version": service.service_version,
                }
            )

        detected_findings = self.engine.evaluate_services(
            service_payloads
        )

        return persist_detected_findings(
            db,
            scan,
            asset,
            detected_findings,
            service_map=service_map,
        )
