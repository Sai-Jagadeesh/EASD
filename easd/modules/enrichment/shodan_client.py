"""
Shodan enrichment module.

Enriches discovered IPs with Shodan data including:
- Service information
- Banners
- Vulnerabilities
- Historical data
"""

import asyncio
from datetime import datetime
from typing import Optional

from easd.config import EASDConfig
from easd.core.models import (
    ModuleResult,
    IPAddress,
    Port,
    Service,
    PortState,
    GeoLocation,
    CloudProvider,
    Finding,
    Severity,
    ScanSession,
)


async def query_shodan(ip: str, api_key: str) -> Optional[dict]:
    """
    Query Shodan API for IP information.

    Args:
        ip: IP address to query
        api_key: Shodan API key

    Returns:
        Shodan host data or None
    """
    if not api_key:
        return None

    try:
        import shodan
        api = shodan.Shodan(api_key)

        # Run sync API call in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, api.host, ip)
        return result

    except Exception:
        return None


async def search_shodan_org(org_name: str, api_key: str) -> list[dict]:
    """
    Search Shodan for hosts belonging to an organization.

    Args:
        org_name: Organization name to search
        api_key: Shodan API key

    Returns:
        List of host data
    """
    if not api_key:
        return []

    try:
        import shodan
        api = shodan.Shodan(api_key)

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: api.search(f'org:"{org_name}"')
        )
        return result.get("matches", [])

    except Exception:
        return []


def parse_shodan_data(shodan_data: dict, ip: IPAddress) -> IPAddress:
    """Parse Shodan data and update IP address record."""
    # Basic info
    ip.asn = shodan_data.get("asn", "").replace("AS", "")
    if ip.asn:
        try:
            ip.asn = int(ip.asn)
        except ValueError:
            ip.asn = None

    ip.asn_org = shodan_data.get("org", "")

    # Geolocation
    ip.geolocation = GeoLocation(
        country=shodan_data.get("country_name", ""),
        country_code=shodan_data.get("country_code", ""),
        city=shodan_data.get("city", ""),
        latitude=shodan_data.get("latitude"),
        longitude=shodan_data.get("longitude"),
    )

    # Cloud provider detection
    cloud_keywords = {
        "amazon": CloudProvider.AWS,
        "aws": CloudProvider.AWS,
        "microsoft": CloudProvider.AZURE,
        "azure": CloudProvider.AZURE,
        "google": CloudProvider.GCP,
        "digitalocean": CloudProvider.DIGITALOCEAN,
    }

    org_lower = ip.asn_org.lower()
    for keyword, provider in cloud_keywords.items():
        if keyword in org_lower:
            ip.cloud_provider = provider
            break

    # Hostnames
    ip.hostnames = shodan_data.get("hostnames", [])
    ip.reverse_dns = shodan_data.get("hostnames", [])

    # OS fingerprint
    ip.os_fingerprint = shodan_data.get("os", "")

    # Ports and services
    for service_data in shodan_data.get("data", []):
        port_num = service_data.get("port")
        if port_num:
            # Check if we already have this port
            existing_port = next(
                (p for p in ip.ports if p.number == port_num),
                None
            )

            service = Service(
                name=service_data.get("_shodan", {}).get("module", "unknown"),
                product=service_data.get("product", ""),
                version=service_data.get("version", ""),
                banner=service_data.get("data", "")[:500],
                cpe=service_data.get("cpe", []),
            )

            if existing_port:
                # Update existing port with Shodan data
                if not existing_port.service.product:
                    existing_port.service = service
            else:
                # Add new port
                port = Port(
                    number=port_num,
                    protocol=service_data.get("transport", "tcp"),
                    state=PortState.OPEN,
                    service=service,
                )
                ip.ports.append(port)

    return ip


def extract_vulnerabilities(shodan_data: dict, ip: IPAddress) -> list[Finding]:
    """Extract vulnerability findings from Shodan data."""
    findings = []

    vulns = shodan_data.get("vulns", [])
    for vuln_id in vulns:
        finding = Finding(
            title=f"Potential vulnerability: {vuln_id}",
            description=f"Shodan detected potential vulnerability {vuln_id} on {ip.address}",
            severity=Severity.HIGH,
            category="vulnerability",
            affected_asset=ip.address,
            affected_asset_type="ip",
            cve=[vuln_id] if vuln_id.startswith("CVE-") else [],
            source="shodan",
        )
        findings.append(finding)

    # Check for specific dangerous configurations
    for service_data in shodan_data.get("data", []):
        # Check for MongoDB without auth
        if service_data.get("_shodan", {}).get("module") == "mongodb":
            if "totalSize" in service_data.get("data", ""):
                finding = Finding(
                    title=f"MongoDB without authentication on {ip.address}",
                    description="MongoDB instance appears to be accessible without authentication",
                    severity=Severity.CRITICAL,
                    category="misconfiguration",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=service_data.get("data", "")[:200],
                    source="shodan",
                )
                findings.append(finding)

        # Check for Elasticsearch without auth
        if service_data.get("_shodan", {}).get("module") == "elasticsearch":
            data = service_data.get("data", "")
            if "cluster_name" in data:
                finding = Finding(
                    title=f"Elasticsearch potentially without authentication on {ip.address}",
                    description="Elasticsearch instance may be accessible without authentication",
                    severity=Severity.HIGH,
                    category="misconfiguration",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=data[:200],
                    source="shodan",
                )
                findings.append(finding)

        # Check for Redis without auth
        if service_data.get("_shodan", {}).get("module") == "redis":
            data = service_data.get("data", "")
            if "redis_version" in data and "NOAUTH" not in data:
                finding = Finding(
                    title=f"Redis potentially without authentication on {ip.address}",
                    description="Redis instance may be accessible without authentication",
                    severity=Severity.CRITICAL,
                    category="misconfiguration",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=data[:200],
                    source="shodan",
                )
                findings.append(finding)

    return findings


async def run(
    session: ScanSession,
    config: EASDConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run Shodan enrichment on discovered IP addresses.

    Args:
        session: Current scan session
        config: EASD configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with enriched data
    """
    result = ModuleResult(
        module_name="shodan_enrichment",
        started_at=datetime.utcnow(),
    )

    if not config.api_keys.shodan:
        result.success = True
        result.error_message = "No Shodan API key configured"
        result.completed_at = datetime.utcnow()
        return result

    # Query Shodan for each IP
    enriched_count = 0

    for ip in session.ip_addresses:
        try:
            shodan_data = await query_shodan(ip.address, config.api_keys.shodan)

            if shodan_data:
                # Update IP with Shodan data
                ip = parse_shodan_data(shodan_data, ip)
                result.ip_addresses.append(ip)

                # Extract vulnerability findings
                findings = extract_vulnerabilities(shodan_data, ip)
                result.findings.extend(findings)

                enriched_count += 1

            # Rate limiting (Shodan has strict rate limits)
            await asyncio.sleep(1.0)

        except Exception:
            continue

    # Also search by organization name if provided
    if session.target_company:
        try:
            org_results = await search_shodan_org(
                session.target_company,
                config.api_keys.shodan
            )

            for host_data in org_results[:50]:  # Limit results
                ip_addr = host_data.get("ip_str")
                if ip_addr and ip_addr not in [ip.address for ip in session.ip_addresses]:
                    # New IP discovered through org search
                    ip = IPAddress(
                        address=ip_addr,
                        version=6 if ":" in ip_addr else 4,
                        source="shodan_org_search",
                    )
                    ip = parse_shodan_data({"data": [host_data]}, ip)
                    result.ip_addresses.append(ip)
                    enriched_count += 1

        except Exception:
            pass

    result.items_discovered = enriched_count
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
