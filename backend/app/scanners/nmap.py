import subprocess
from typing import Any

from backend.app.scanners.base import Scanner


class NmapScanner(Scanner):
    """
    Nmap scanner implementation.

    Executes authorized Nmap scans and returns
    the raw scan output.
    """

    def scanner_name(self) -> str:
        return "nmap"

    def scan(
        self,
        target: str,
        *,
        arguments: list[str] | None = None,
        timeout: int = 300,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Execute an authorized Nmap scan.

        Returns:
            A normalized result containing:
            - scanner
            - target
            - command
            - return_code
            - stdout
            - stderr
        """

        if not target or not target.strip():
            raise ValueError("Target must not be empty.")

        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        if arguments is None:
            arguments = ["-sV"]

        command = [
            "/usr/bin/nmap",
            *arguments,
            target.strip(),
        ]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"Nmap scan timed out after {timeout} seconds."
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                f"Failed to execute Nmap: {exc}"
            ) from exc

        return {
            "scanner": self.scanner_name(),
            "target": target.strip(),
            "command": command,
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
