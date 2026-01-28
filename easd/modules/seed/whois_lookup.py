"""
WHOIS lookup module.

Performs WHOIS lookups to gather domain registration information
and discover related domains.
"""

import asyncio
from datetime import datetime
from typing import Optional
import re

from easd.config import EASDConfig
from easd.core.models import (
    ModuleResult,
    Domain,
    ScanSession,
)


async def whois_lookup(domain: str) -> Optional[dict]:
    """
    Perform WHOIS lookup for a domain.

    Args:
        domain: Domain to lookup

    Returns:
        Dictionary with WHOIS data or None
    """
    try:
        import whois
        # python-whois is synchronous, run in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, whois.whois, domain)

        if result:
            return {
                "domain_name": result.domain_name,
                "registrar": result.registrar,
                "whois_server": result.whois_server,
                "creation_date": result.creation_date,
                "expiration_date": result.expiration_date,
                "updated_date": result.updated_date,
                "name_servers": result.name_servers,
                "status": result.status,
                "emails": result.emails,
                "dnssec": result.dnssec,
                "name": result.name,
                "org": result.org,
                "address": result.address,
                "city": result.city,
                "state": result.state,
                "registrant_postal_code": result.registrant_postal_code,
                "country": result.country,
            }
    except Exception:
        pass

    return None


def normalize_date(date_value) -> Optional[datetime]:
    """Normalize various date formats to datetime."""
    if date_value is None:
        return None

    if isinstance(date_value, datetime):
        return date_value

    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None

    if isinstance(date_value, str):
        # Try common formats
        formats = [
            "%Y-%m-%d",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%d-%b-%Y",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(date_value, fmt)
            except ValueError:
                continue

    return None


def normalize_list(value) -> list[str]:
    """Normalize value to a list of strings."""
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, list):
        return [str(v) for v in value if v]

    return []


async def run(
    session: ScanSession,
    config: EASDConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run WHOIS lookups for target domains.

    Args:
        session: Current scan session
        config: EASD configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with domain information
    """
    result = ModuleResult(
        module_name="whois_lookup",
        started_at=datetime.utcnow(),
    )

    # Get domains to lookup
    domains_to_check = set(session.target_domains)

    # If we have a company name but no domains, try to guess common domains
    if session.target_company and not domains_to_check:
        company_slug = re.sub(r"[^a-z0-9]", "", session.target_company.lower())
        if company_slug:
            # Common TLDs to try
            tlds = ["com", "net", "org", "io", "co"]
            for tld in tlds:
                domains_to_check.add(f"{company_slug}.{tld}")

            # Also try with hyphens for multi-word companies
            company_hyphen = re.sub(r"\s+", "-", session.target_company.lower())
            company_hyphen = re.sub(r"[^a-z0-9-]", "", company_hyphen)
            if company_hyphen != company_slug:
                for tld in tlds[:3]:  # Just main TLDs
                    domains_to_check.add(f"{company_hyphen}.{tld}")

    # Perform WHOIS lookups
    for domain in domains_to_check:
        try:
            whois_data = await whois_lookup(domain)

            if whois_data:
                # Create Domain object
                domain_obj = Domain(
                    fqdn=domain,
                    registrar=whois_data.get("registrar") or "",
                    registrant_name=whois_data.get("name") or "",
                    registrant_org=whois_data.get("org") or "",
                    registrant_email=(
                        whois_data.get("emails")[0]
                        if isinstance(whois_data.get("emails"), list) and whois_data.get("emails")
                        else whois_data.get("emails") or ""
                    ),
                    creation_date=normalize_date(whois_data.get("creation_date")),
                    expiration_date=normalize_date(whois_data.get("expiration_date")),
                    updated_date=normalize_date(whois_data.get("updated_date")),
                    name_servers=normalize_list(whois_data.get("name_servers")),
                    source="whois",
                )

                result.domains.append(domain_obj)

                # Add domain to session targets if not already there
                if domain not in session.target_domains:
                    session.target_domains.append(domain)

            # Rate limiting
            await asyncio.sleep(1.0)  # WHOIS servers are sensitive to rate

        except Exception:
            continue

    result.items_discovered = len(result.domains)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
