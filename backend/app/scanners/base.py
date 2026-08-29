from abc import ABC, abstractmethod
from typing import Any


class Scanner(ABC):
    """
    Base interface for all SecureAssure scanners.

    Scanners must implement:
    - scan()
    - scanner_name()
    """

    @abstractmethod
    def scanner_name(self) -> str:
        """Return the scanner name."""
        raise NotImplementedError

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> Any:
        """Execute a scan against an authorized target."""
        raise NotImplementedError
