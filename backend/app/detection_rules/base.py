from abc import ABC, abstractmethod
from typing import Any


class DetectionRule(ABC):
    """
    Base interface for SecureAssure finding detection rules.

    A rule evaluates a discovered service and optionally
    returns normalized finding data.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Return the unique rule identifier."""
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the human-readable rule name."""
        raise NotImplementedError

    @abstractmethod
    def evaluate(
        self,
        service: dict[str, Any],
    ) -> dict[str, Any] | None:
        """
        Evaluate a service.

        Returns:
            Finding data when the rule matches,
            otherwise None.
        """
        raise NotImplementedError
