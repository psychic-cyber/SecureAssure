from typing import Any
import xml.etree.ElementTree as ET


class NmapParser:
    """
    Parser for Nmap XML output.

    Converts Nmap XML into a normalized Python structure
    that can later be consumed by the SecureAssure data layer.
    """

    def parse(self, xml_output: str) -> dict[str, Any]:
        """
        Parse Nmap XML output.

        Returns:
            {
                "hosts": [
                    {
                        "address": "...",
                        "hostname": "...",
                        "ports": [
                            {
                                "port": 22,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "ssh",
                                "version": "OpenSSH ..."
                            }
                        ]
                    }
                ]
            }
        """

        if not xml_output or not xml_output.strip():
            raise ValueError("Nmap XML output must not be empty.")

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as exc:
            raise ValueError("Invalid Nmap XML output.") from exc

        hosts = []

        for host_element in root.findall("host"):
            address = self._get_address(host_element)
            hostname = self._get_hostname(host_element)

            ports = []

            ports_element = host_element.find("ports")

            if ports_element is not None:
                for port_element in ports_element.findall("port"):
                    ports.append(
                        self._parse_port(port_element)
                    )

            hosts.append(
                {
                    "address": address,
                    "hostname": hostname,
                    "ports": ports,
                }
            )

        return {
            "hosts": hosts,
        }

    @staticmethod
    def _get_address(host_element: ET.Element) -> str | None:
        address_element = host_element.find("address")

        if address_element is None:
            return None

        return address_element.get("addr")

    @staticmethod
    def _get_hostname(host_element: ET.Element) -> str | None:
        hostname_element = host_element.find(
            "./hostnames/hostname"
        )

        if hostname_element is None:
            return None

        return hostname_element.get("name")

    @staticmethod
    def _parse_port(port_element: ET.Element) -> dict[str, Any]:
        state_element = port_element.find("state")
        service_element = port_element.find("service")

        state = None
        if state_element is not None:
            state = state_element.get("state")

        service = None
        version = None

        if service_element is not None:
            service = service_element.get("name")

            product = service_element.get("product")
            service_version = service_element.get("version")

            if product and service_version:
                version = f"{product} {service_version}"
            elif product:
                version = product
            elif service_version:
                version = service_version

        return {
            "port": int(port_element.get("portid")),
            "protocol": port_element.get("protocol"),
            "state": state,
            "service": service,
            "version": version,
        }
