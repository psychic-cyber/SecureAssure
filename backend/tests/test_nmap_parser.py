import pytest

from backend.app.scanners.parser import NmapParser


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.56.101" addrtype="ipv4"/>

        <hostnames>
            <hostname name="security-lab"/>
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

            <port protocol="tcp" portid="3306">
                <state state="open"/>
                <service
                    name="mysql"
                    product="MySQL"
                    version="8.0.36"
                />
            </port>
        </ports>
    </host>
</nmaprun>
"""


def test_parser_returns_hosts():
    parser = NmapParser()

    result = parser.parse(SAMPLE_NMAP_XML)

    assert "hosts" in result
    assert len(result["hosts"]) == 1


def test_parser_extracts_host_address():
    parser = NmapParser()

    result = parser.parse(SAMPLE_NMAP_XML)

    host = result["hosts"][0]

    assert host["address"] == "192.168.56.101"


def test_parser_extracts_hostname():
    parser = NmapParser()

    result = parser.parse(SAMPLE_NMAP_XML)

    host = result["hosts"][0]

    assert host["hostname"] == "security-lab"


def test_parser_extracts_ports():
    parser = NmapParser()

    result = parser.parse(SAMPLE_NMAP_XML)

    host = result["hosts"][0]

    assert len(host["ports"]) == 2


def test_parser_extracts_ssh_service():
    parser = NmapParser()

    result = parser.parse(SAMPLE_NMAP_XML)

    port = result["hosts"][0]["ports"][0]

    assert port["port"] == 22
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "ssh"
    assert port["version"] == "OpenSSH 9.9"


def test_parser_extracts_mysql_service():
    parser = NmapParser()

    result = parser.parse(SAMPLE_NMAP_XML)

    port = result["hosts"][0]["ports"][1]

    assert port["port"] == 3306
    assert port["protocol"] == "tcp"
    assert port["state"] == "open"
    assert port["service"] == "mysql"
    assert port["version"] == "MySQL 8.0.36"


def test_parser_rejects_empty_xml():
    parser = NmapParser()

    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        parser.parse("")


def test_parser_rejects_invalid_xml():
    parser = NmapParser()

    with pytest.raises(
        ValueError,
        match="Invalid Nmap XML output",
    ):
        parser.parse("<nmaprun>")
