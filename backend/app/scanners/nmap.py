from typing import Any

from backend.app.scanners.base import Scanner


class NmapScanner(Scanner):
    """
    Nmap scanner implementation.

    This class will later be responsible for executing
    authorized Nmap scans and returning normalized results.
    """

    def scanner_name(self) -> str:
        return "nmap"

    def scan(self, target: str, **kwargs: Any) -> Any:
        """
        Execute an authorized Nmap scan.

        Actual Nmap execution will be implemented in the
        next scanner milestone.
        """
        raise NotImplementedError(
            "Nmap execution is not implemented yet."
        )
