import subprocess

import pytest

from backend.app.scanners import NmapScanner, Scanner


def test_nmap_scanner_is_scanner():
    scanner = NmapScanner()

    assert isinstance(scanner, Scanner)


def test_nmap_scanner_name():
    scanner = NmapScanner()

    assert scanner.scanner_name() == "nmap"


def test_nmap_scan_executes_command(monkeypatch):
    scanner = NmapScanner()

    def fake_run(command, **kwargs):
        assert command == [
            "/usr/bin/nmap",
            "-sV",
            "127.0.0.1",
        ]

        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 30
        assert kwargs["check"] is False

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="Nmap scan output",
            stderr="",
        )

    monkeypatch.setattr(
        "backend.app.scanners.nmap.subprocess.run",
        fake_run,
    )

    result = scanner.scan(
        "127.0.0.1",
        timeout=30,
    )

    assert result["scanner"] == "nmap"
    assert result["target"] == "127.0.0.1"
    assert result["return_code"] == 0
    assert result["stdout"] == "Nmap scan output"
    assert result["stderr"] == ""


def test_nmap_scan_rejects_empty_target():
    scanner = NmapScanner()

    with pytest.raises(ValueError, match="Target must not be empty"):
        scanner.scan("")


def test_nmap_scan_rejects_invalid_timeout():
    scanner = NmapScanner()

    with pytest.raises(ValueError, match="Timeout must be greater than zero"):
        scanner.scan("127.0.0.1", timeout=0)


def test_nmap_scan_handles_timeout(monkeypatch):
    scanner = NmapScanner()

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=args[0],
            timeout=kwargs["timeout"],
        )

    monkeypatch.setattr(
        "backend.app.scanners.nmap.subprocess.run",
        fake_run,
    )

    with pytest.raises(TimeoutError, match="timed out"):
        scanner.scan("127.0.0.1", timeout=1)


def test_nmap_scan_handles_execution_error(monkeypatch):
    scanner = NmapScanner()

    def fake_run(*args, **kwargs):
        raise OSError("nmap executable not found")

    monkeypatch.setattr(
        "backend.app.scanners.nmap.subprocess.run",
        fake_run,
    )

    with pytest.raises(RuntimeError, match="Failed to execute Nmap"):
        scanner.scan("127.0.0.1")
