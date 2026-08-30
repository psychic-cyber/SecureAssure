from typing import Any

from backend.app.detection_rules.base import DetectionRule


class DetectionRuleEngine:
    """
    Executes registered detection rules against discovered services.
    """

    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    def evaluate_service(
        self,
        service: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Run all registered rules against a single service.

        Returns:
            A list containing all matching findings.
        """

        findings: list[dict[str, Any]] = []

        for rule in self.rules:
            finding = rule.evaluate(service)

            if finding is not None:
                finding = {
                    **finding,
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                }

                findings.append(finding)

        return findings

    def evaluate_services(
        self,
        services: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Run all registered rules against multiple services.
        """

        findings: list[dict[str, Any]] = []

        for service in services:
            findings.extend(
                self.evaluate_service(service)
            )

        return findings
