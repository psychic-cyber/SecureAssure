from typing import Any

from backend.app.detection_rules.base import DetectionRule


class ExposedDatabaseRule(DetectionRule):
    """
    Detect publicly exposed database services.

    Current database signatures:
    - MySQL: 3306
    - PostgreSQL: 5432
    - Microsoft SQL Server: 1433
    - MongoDB: 27017
    """

    DATABASE_PORTS = {
        3306: "mysql",
        5432: "postgresql",
        1433: "mssql",
        27017: "mongodb",
    }

    @property
    def rule_id(self) -> str:
        return "SA-DB-001"

    @property
    def name(self) -> str:
        return "Exposed Database Service"

    def evaluate(
        self,
        service: dict[str, Any],
    ) -> dict[str, Any] | None:
        port = service.get("port")
        state = service.get("state")

        if state != "open":
            return None

        database_name = self.DATABASE_PORTS.get(port)

        if database_name is None:
            return None

        return {
            "rule_id": self.rule_id,
            "title": self.name,
            "severity": "HIGH",
            "status": "OPEN",
            "detection_source": self.rule_id,
            "description": (
                f"An exposed {database_name} database service "
                f"was detected on port {port}."
            ),
            "recommendation": (
                "Restrict database access to authorized hosts "
                "and networks."
            ),
        }


class OpenSSHRule(DetectionRule):
    """
    Detect an exposed SSH service.
    """

    @property
    def rule_id(self) -> str:
        return "SA-SSH-001"

    @property
    def name(self) -> str:
        return "Exposed SSH Service"

    def evaluate(
        self,
        service: dict[str, Any],
    ) -> dict[str, Any] | None:
        if (
            service.get("port") == 22
            and service.get("protocol") == "tcp"
            and service.get("state") == "open"
        ):
            return {
                "rule_id": self.rule_id,
                "title": self.name,
                "severity": "MEDIUM",
                "status": "OPEN",
                "detection_source": self.rule_id,
                "description": (
                    "An exposed SSH service was detected "
                    "on port 22."
                ),
                "recommendation": (
                    "Restrict SSH access to authorized "
                    "administrative hosts."
                ),
            }

        return None


def get_default_rules() -> list[DetectionRule]:
    """
    Return the default SecureAssure detection rules.
    """

    return [
        ExposedDatabaseRule(),
        OpenSSHRule(),
    ]
