from typing import Any

from sqlalchemy.orm import Session

from backend.app.models import Asset, Scan, Service


def persist_nmap_results(
    db: Session,
    scan: Scan,
    parsed_results: dict[str, Any],
) -> list[Asset]:
    """
    Persist normalized Nmap results into the database.

    For every discovered host:
    - create or reuse an Asset
    - create or reuse Services for discovered ports
    - associate discovered services with the asset

    Returns:
        List of affected Asset objects.
    """

    if not isinstance(parsed_results, dict):
        raise ValueError("Parsed Nmap results must be a dictionary.")

    hosts = parsed_results.get("hosts")

    if not isinstance(hosts, list):
        raise ValueError("Parsed Nmap results must contain a hosts list.")

    persisted_assets: list[Asset] = []

    for host_data in hosts:
        if not isinstance(host_data, dict):
            continue

        address = host_data.get("address")
        hostname = host_data.get("hostname")
        ports = host_data.get("ports", [])

        if not address:
            continue

        asset = (
            db.query(Asset)
            .filter(Asset.ip_address == address)
            .first()
        )

        if asset is None:
            asset = Asset(
                ip_address=address,
                hostname=hostname,
                asset_type="HOST",
                criticality="MEDIUM",
                status="ACTIVE",
            )

            db.add(asset)
            db.flush()

        elif hostname and not asset.hostname:
            asset.hostname = hostname

        for port_data in ports:
            if not isinstance(port_data, dict):
                continue

            port = port_data.get("port")
            protocol = port_data.get("protocol")

            if port is None or not protocol:
                continue

            service = (
                db.query(Service)
                .filter(
                    Service.asset_id == asset.id,
                    Service.port == port,
                    Service.protocol == protocol,
                )
                .first()
            )

            if service is None:
                service = Service(
                    asset_id=asset.id,
                    port=port,
                    protocol=protocol,
                    service_name=port_data.get("service"),
                    service_version=port_data.get("version"),
                    state=port_data.get("state") or "unknown",
                )

                db.add(service)

            else:
                service.service_name = port_data.get(
                    "service"
                )
                service.service_version = port_data.get(
                    "version"
                )
                service.state = (
                    port_data.get("state") or service.state
                )

        persisted_assets.append(asset)

    db.commit()

    for asset in persisted_assets:
        db.refresh(asset)

    return persisted_assets
