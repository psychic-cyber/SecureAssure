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
            "-oX",
            "-",
            "127.0.0.1",
        ]

        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["timeout"] == 30
        assert kwargs["check"] is False

        return subprocess.CompletedProcess(
            command,
            0,
            stdout="<nmaprun></nmaprun>",
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
    assert result["stdout"] == "<nmaprun></nmaprun>"
    assert result["stderr"] == ""


def test_nmap_scan_rejects_empty_target():
    scanner = NmapScanner()

    with pytest.raises(ValueError):
        scanner.scan("")


def test_nmap_scan_rejects_invalid_timeout():
    scanner = NmapScanner()

    with pytest.raises(ValueError):
        scanner.scan("127.0.0.1", timeout=0)


def test_nmap_scan_handles_timeout(monkeypatch):
    scanner = NmapScanner()

    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            command,
            kwargs["timeout"],
        )

    monkeypatch.setattr(
        "backend.app.scanners.nmap.subprocess.run",
        fake_run,
    )

    with pytest.raises(TimeoutError):
        scanner.scan(
            "127.0.0.1",
            timeout=30,
        )


def test_nmap_scan_handles_execution_error(monkeypatch):
    scanner = NmapScanner()

    def fake_run(command, **kwargs):
        raise OSError("nmap not found")

    monkeypatch.setattr(
        "backend.app.scanners.nmap.subprocess.run",
        fake_run,
    )

    with pytest.raises(RuntimeError):
        scanner.scan("127.0.0.1")
