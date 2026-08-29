import pytest

from backend.app.scanners import NmapScanner, Scanner


def test_nmap_scanner_is_scanner():
    scanner = NmapScanner()

    assert isinstance(scanner, Scanner)


def test_nmap_scanner_name():
    scanner = NmapScanner()

    assert scanner.scanner_name() == "nmap"


def test_nmap_scan_not_implemented_yet():
    scanner = NmapScanner()

    with pytest.raises(NotImplementedError):
        scanner.scan("192.168.56.101")
