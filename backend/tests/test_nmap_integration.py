import subprocess

from backend.app.scanners import NmapScanner
from backend.app.scanners.parser import NmapParser


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>

        <hostnames>
            <hostname name="localhost"/>
        </hostnames>

        <ports>
            <port protocol="tcp" portid="22">
                <state state="open"/>
                <service
                    name="ssh"
                    product="OpenSSH"
                    version="9.9"
                />
            </port>
        </ports>
    </host>
</nmaprun>
"""


def test_nmap_scanner_output_can_be_parsed(monkeypatch):
    scanner = NmapScanner()
    parser = NmapParser()

    def fake_run(command, **kwargs):
        assert "/usr/bin/nmap" == command[0]
        assert "-oX" in command
        assert "-" in command

        return subprocess.CompletedProcess(
            command,
            0,
            stdout=SAMPLE_NMAP_XML,
            stderr="",
        )

    monkeypatch.setattr(
        "backend.app.scanners.nmap.subprocess.run",
        fake_run,
    )

    scan_result = scanner.scan(
        "127.0.0.1",
        timeout=30,
    )

    assert scan_result["return_code"] == 0

    parsed_result = parser.parse(
        scan_result["stdout"]
    )

    assert len(parsed_result["hosts"]) == 1

    host = parsed_result["hosts"][0]

    assert host["address"] == "127.0.0.1"
    assert host["hostname"] == "localhost"

    assert len(host["ports"]) == 1

    port = host["ports"][0]

    assert port["port"] == 22
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "ssh"
    assert port["version"] == "OpenSSH 9.9"
