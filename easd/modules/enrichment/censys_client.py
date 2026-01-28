"""
Censys enrichment module.

Enriches discovered assets with Censys data including:
- Host information
- Service details
- Certificate data
- Historical records
"""

import asyncio
from datetime import datetime
from typing import Optional
import base64

import httpx

from easd.config import EASDConfig
from easd.core.models import (
    ModuleResult,
    IPAddress,
    Port,
    Service,
    PortState,
    Certificate,
    GeoLocation,
    CloudProvider,
    Finding,
    Severity,
    ScanSession,
)


class CensysClient:
    """Async client for Censys API."""

    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str, api_secret: str):
        self.api_id = api_id
        self.api_secret = api_secret
        self._auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json_data: Optional[dict] = None,
        timeout: float = 30.0,
    ) -> Optional[dict]:
        """Make an authenticated request to Censys API."""
        url = f"{self.BASE_URL}/{endpoint}"
        headers = {
            "Authorization": f"Basic {self._auth}",
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    json=json_data,
                )

                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 429:
                    # Rate limited
                    await asyncio.sleep(5)
                    return None

        except Exception:
            pass

        return None

    async def get_host(self, ip: str) -> Optional[dict]:
        """Get host information for an IP address."""
        return await self._request("GET", f"hosts/{ip}")

    async def search_hosts(
        self,
        query: str,
        per_page: int = 50,
        cursor: Optional[str] = None,
    ) -> Optional[dict]:
        """Search for hosts matching a query."""
        params = {"q": query, "per_page": per_page}
        if cursor:
            params["cursor"] = cursor
        return await self._request("GET", "hosts/search", params=params)

    async def get_certificate(self, fingerprint: str) -> Optional[dict]:
        """Get certificate details by SHA256 fingerprint."""
        return await self._request("GET", f"certificates/{fingerprint}")

    async def search_certificates(
        self,
        query: str,
        per_page: int = 50,
    ) -> Optional[dict]:
        """Search for certificates."""
        params = {"q": query, "per_page": per_page}
        return await self._request("GET", "certificates/search", params=params)


def parse_censys_host(data: dict, ip: IPAddress) -> IPAddress:
    """Parse Censys host data and update IP address record."""
    result = data.get("result", {})

    # Autonomous System info
    autonomous_system = result.get("autonomous_system", {})
    if autonomous_system:
        ip.asn = autonomous_system.get("asn")
        ip.asn_org = autonomous_system.get("name", "")
        ip.asn_country = autonomous_system.get("country_code", "")

    # Location
    location = result.get("location", {})
    if location:
        ip.geolocation = GeoLocation(
            country=location.get("country", ""),
            country_code=location.get("country_code", ""),
            city=location.get("city", ""),
            latitude=location.get("coordinates", {}).get("latitude"),
            longitude=location.get("coordinates", {}).get("longitude"),
        )

    # Cloud provider detection
    cloud_info = result.get("cloud", {})
    if cloud_info:
        provider_map = {
            "AWS": CloudProvider.AWS,
            "AMAZON": CloudProvider.AWS,
            "AZURE": CloudProvider.AZURE,
            "MICROSOFT": CloudProvider.AZURE,
            "GOOGLE": CloudProvider.GCP,
            "GCP": CloudProvider.GCP,
            "DIGITALOCEAN": CloudProvider.DIGITALOCEAN,
        }
        provider_name = cloud_info.get("provider", "").upper()
        for key, provider in provider_map.items():
            if key in provider_name:
                ip.cloud_provider = provider
                ip.cloud_region = cloud_info.get("region", "")
                break

    # Services/Ports
    services = result.get("services", [])
    for svc in services:
        port_num = svc.get("port")
        if not port_num:
            continue

        # Check if we already have this port
        existing_port = next((p for p in ip.ports if p.number == port_num), None)

        service = Service(
            name=svc.get("service_name", "unknown"),
            product=svc.get("software", [{}])[0].get("product", "") if svc.get("software") else "",
            version=svc.get("software", [{}])[0].get("version", "") if svc.get("software") else "",
            banner=svc.get("banner", "")[:500] if svc.get("banner") else "",
        )

        if existing_port:
            if not existing_port.service.product:
                existing_port.service = service
        else:
            port = Port(
                number=port_num,
                protocol=svc.get("transport_protocol", "tcp").lower(),
                state=PortState.OPEN,
                service=service,
            )
            ip.ports.append(port)

    # DNS names
    dns = result.get("dns", {})
    if dns:
        names = dns.get("names", [])
        ip.hostnames = list(set(ip.hostnames + names))
        ip.reverse_dns = list(set(ip.reverse_dns + dns.get("reverse_dns", {}).get("names", [])))

    # Operating system
    os_info = result.get("operating_system", {})
    if os_info:
        os_parts = []
        if os_info.get("vendor"):
            os_parts.append(os_info["vendor"])
        if os_info.get("product"):
            os_parts.append(os_info["product"])
        if os_info.get("version"):
            os_parts.append(os_info["version"])
        ip.os_fingerprint = " ".join(os_parts)

    return ip


def parse_censys_certificate(data: dict) -> Optional[Certificate]:
    """Parse Censys certificate data."""
    result = data.get("result", {})
    if not result:
        return None

    parsed = result.get("parsed", {})
    if not parsed:
        return None

    cert = Certificate(
        serial_number=parsed.get("serial_number", ""),
        subject=parsed.get("subject_dn", ""),
        issuer=parsed.get("issuer_dn", ""),
        fingerprint_sha256=result.get("fingerprint_sha256", ""),
    )

    # Subject Alternative Names
    names = parsed.get("names", [])
    cert.san = names

    # Validity
    validity = parsed.get("validity", {})
    if validity:
        try:
            if validity.get("start"):
                cert.not_before = datetime.fromisoformat(
                    validity["start"].replace("Z", "+00:00")
                )
            if validity.get("end"):
                cert.not_after = datetime.fromisoformat(
                    validity["end"].replace("Z", "+00:00")
                )
                cert.is_expired = cert.not_after < datetime.utcnow()
        except Exception:
            pass

    # Self-signed check
    cert.is_self_signed = parsed.get("subject_dn") == parsed.get("issuer_dn")

    return cert


def extract_findings(data: dict, ip: IPAddress) -> list[Finding]:
    """Extract security findings from Censys data."""
    findings = []
    result = data.get("result", {})

    # Check for specific vulnerable services
    services = result.get("services", [])
    for svc in services:
        service_name = svc.get("service_name", "").lower()
        port = svc.get("port", 0)

        # Check for exposed databases
        if service_name in ["mongodb", "redis", "elasticsearch", "memcached"]:
            finding = Finding(
                title=f"{service_name.title()} exposed on {ip.address}:{port}",
                description=f"Censys detected {service_name} service accessible on the internet.",
                severity=Severity.HIGH if service_name in ["mongodb", "redis"] else Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                source="censys",
            )
            findings.append(finding)

        # Check for Telnet
        if service_name == "telnet":
            finding = Finding(
                title=f"Telnet service exposed on {ip.address}:{port}",
                description="Telnet transmits data in cleartext and should not be exposed to the internet.",
                severity=Severity.MEDIUM,
                category="exposed_service",
                affected_asset=ip.address,
                affected_asset_type="ip",
                source="censys",
            )
            findings.append(finding)

        # Check for FTP
        if service_name == "ftp":
            banner = svc.get("banner", "")
            if "anonymous" in banner.lower():
                finding = Finding(
                    title=f"FTP with anonymous access on {ip.address}:{port}",
                    description="FTP server allows anonymous access.",
                    severity=Severity.MEDIUM,
                    category="misconfiguration",
                    affected_asset=ip.address,
                    affected_asset_type="ip",
                    evidence=banner[:200],
                    source="censys",
                )
                findings.append(finding)

    # Check for expired certificates
    for svc in services:
        tls = svc.get("tls", {})
        if tls:
            cert = tls.get("certificates", {}).get("leaf", {})
            if cert:
                validity = cert.get("parsed", {}).get("validity", {})
                if validity.get("end"):
                    try:
                        end_date = datetime.fromisoformat(
                            validity["end"].replace("Z", "+00:00")
                        )
                        if end_date < datetime.utcnow():
                            finding = Finding(
                                title=f"Expired SSL certificate on {ip.address}:{svc.get('port')}",
                                description=f"SSL certificate expired on {end_date.strftime('%Y-%m-%d')}",
                                severity=Severity.LOW,
                                category="misconfiguration",
                                affected_asset=ip.address,
                                affected_asset_type="ip",
                                source="censys",
                            )
                            findings.append(finding)
                    except Exception:
                        pass

    return findings


async def run(
    session: ScanSession,
    config: EASDConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run Censys enrichment on discovered IP addresses.

    Args:
        session: Current scan session
        config: EASD configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with enriched data
    """
    result = ModuleResult(
        module_name="censys_enrichment",
        started_at=datetime.utcnow(),
    )

    if not config.api_keys.censys_id or not config.api_keys.censys_secret:
        result.success = True
        result.error_message = "No Censys API credentials configured"
        result.completed_at = datetime.utcnow()
        return result

    client = CensysClient(config.api_keys.censys_id, config.api_keys.censys_secret)
    enriched_count = 0

    # Enrich each IP
    for ip in session.ip_addresses:
        try:
            host_data = await client.get_host(ip.address)

            if host_data:
                ip = parse_censys_host(host_data, ip)
                result.ip_addresses.append(ip)

                # Extract findings
                findings = extract_findings(host_data, ip)
                result.findings.extend(findings)

                enriched_count += 1

            # Rate limiting
            await asyncio.sleep(0.5)

        except Exception:
            continue

    # Search for certificates by domain
    for domain in session.target_domains:
        try:
            cert_data = await client.search_certificates(f"names:{domain}")
            if cert_data and cert_data.get("result", {}).get("hits"):
                for hit in cert_data["result"]["hits"][:20]:  # Limit results
                    cert = parse_censys_certificate({"result": hit})
                    if cert:
                        result.certificates.append(cert)

            await asyncio.sleep(0.5)

        except Exception:
            continue

    # Search for hosts by organization name
    if session.target_company:
        try:
            search_data = await client.search_hosts(
                f'autonomous_system.name:"{session.target_company}"',
                per_page=50,
            )

            if search_data and search_data.get("result", {}).get("hits"):
                for hit in search_data["result"]["hits"]:
                    ip_addr = hit.get("ip")
                    if ip_addr and ip_addr not in [ip.address for ip in session.ip_addresses]:
                        new_ip = IPAddress(
                            address=ip_addr,
                            version=6 if ":" in ip_addr else 4,
                            source="censys_search",
                        )
                        new_ip = parse_censys_host({"result": hit}, new_ip)
                        result.ip_addresses.append(new_ip)
                        enriched_count += 1

        except Exception:
            pass

    result.items_discovered = enriched_count + len(result.certificates)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
