"""
Employee discovery module.

Discovers employees and their information through:
- Email pattern generation
- Hunter.io API
- GitHub user discovery
- Public data sources
- Email verification
"""

import asyncio
import re
from datetime import datetime
from typing import Optional
from urllib.parse import quote

import httpx

from easd.config import EASDConfig
from easd.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


# Common email patterns used by organizations
EMAIL_PATTERNS = [
    "{first}.{last}",           # john.doe@company.com
    "{first}{last}",            # johndoe@company.com
    "{f}{last}",                # jdoe@company.com
    "{first}_{last}",           # john_doe@company.com
    "{first}-{last}",           # john-doe@company.com
    "{last}.{first}",           # doe.john@company.com
    "{last}{first}",            # doejohn@company.com
    "{last}{f}",                # doej@company.com
    "{first}",                  # john@company.com
    "{last}",                   # doe@company.com
    "{f}.{last}",               # j.doe@company.com
    "{first}.{l}",              # john.d@company.com
    "{f}{l}",                   # jd@company.com
]


async def query_hunter_domain(
    domain: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query Hunter.io for domain email information.
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.hunter.io/v2/domain-search",
                params={
                    "domain": domain,
                    "api_key": api_key,
                    "limit": 100,
                },
            )

            if response.status_code == 200:
                return response.json().get("data", {})

    except Exception:
        pass

    return {}


async def query_hunter_email_finder(
    domain: str,
    first_name: str,
    last_name: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Find specific email using Hunter.io.
    """
    if not api_key:
        return {}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.hunter.io/v2/email-finder",
                params={
                    "domain": domain,
                    "first_name": first_name,
                    "last_name": last_name,
                    "api_key": api_key,
                },
            )

            if response.status_code == 200:
                return response.json().get("data", {})

    except Exception:
        pass

    return {}


async def query_clearbit_company(
    domain: str,
    timeout: float = 30.0,
) -> dict:
    """
    Query Clearbit for company information (free tier).
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://company.clearbit.com/v2/companies/find",
                params={"domain": domain},
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def search_phonebook_cz(
    domain: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Search phonebook.cz for emails (IntelX service).
    Note: Requires API key for full access.
    """
    emails = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # This is a simplified version - full access requires API
            response = await client.get(
                f"https://phonebook.cz/api/v1/search",
                params={"term": domain, "type": "email"},
            )

            if response.status_code == 200:
                data = response.json()
                emails = data.get("emails", [])

    except Exception:
        pass

    return emails


async def search_emailrep(
    email: str,
    timeout: float = 30.0,
) -> dict:
    """
    Check email reputation and verify existence.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://emailrep.io/{quote(email)}",
                headers={"Accept": "application/json"},
            )

            if response.status_code == 200:
                return response.json()

    except Exception:
        pass

    return {}


async def discover_from_google_dorks(
    domain: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Discover employees using search engine patterns.
    Note: This is a placeholder - actual implementation would need
    to use a search API or scraping service.
    """
    # Common patterns that reveal employee info:
    # site:linkedin.com/in "works at {company}"
    # site:{domain} "@{domain}" filetype:pdf
    # site:github.com "{domain}" in:email

    # For now, return empty as this requires external APIs
    return []


async def discover_from_breach_data(
    domain: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Check for emails in known breach databases.
    Note: Uses Have I Been Pwned API if available.
    """
    # HIBP requires API key and doesn't support domain-wide searches
    # This would need to be implemented with a paid breach data service
    return []


def generate_email_permutations(
    first_name: str,
    last_name: str,
    domain: str,
) -> list[str]:
    """
    Generate possible email addresses for a person.
    """
    emails = []

    first = first_name.lower().strip()
    last = last_name.lower().strip()
    f = first[0] if first else ""
    l = last[0] if last else ""

    for pattern in EMAIL_PATTERNS:
        try:
            email = pattern.format(first=first, last=last, f=f, l=l)
            email = f"{email}@{domain}"
            emails.append(email)
        except Exception:
            continue

    return emails


def detect_email_pattern(emails: list[str], domain: str) -> Optional[str]:
    """
    Detect the email pattern used by an organization.
    """
    if not emails:
        return None

    pattern_scores = {}

    for email in emails:
        local_part = email.split('@')[0].lower()

        # Check various patterns
        if '.' in local_part:
            parts = local_part.split('.')
            if len(parts) == 2:
                if len(parts[0]) == 1:
                    pattern_scores["{f}.{last}"] = pattern_scores.get("{f}.{last}", 0) + 1
                elif len(parts[1]) == 1:
                    pattern_scores["{first}.{l}"] = pattern_scores.get("{first}.{l}", 0) + 1
                else:
                    pattern_scores["{first}.{last}"] = pattern_scores.get("{first}.{last}", 0) + 1
        elif '_' in local_part:
            pattern_scores["{first}_{last}"] = pattern_scores.get("{first}_{last}", 0) + 1
        elif '-' in local_part:
            pattern_scores["{first}-{last}"] = pattern_scores.get("{first}-{last}", 0) + 1
        else:
            # No separator
            if len(local_part) <= 3:
                pattern_scores["{f}{l}"] = pattern_scores.get("{f}{l}", 0) + 1
            else:
                pattern_scores["{first}{last}"] = pattern_scores.get("{first}{last}", 0) + 1

    if pattern_scores:
        return max(pattern_scores, key=pattern_scores.get)

    return None


async def run(
    session: ScanSession,
    config: EASDConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run employee discovery.
    """
    result = ModuleResult(
        module_name="employee_discovery",
        started_at=datetime.utcnow(),
    )

    discovered_employees = []
    discovered_emails = set()
    email_pattern = None
    items_discovered = 0

    # Get API keys
    hunter_key = config.api_keys.hunter if hasattr(config.api_keys, 'hunter') else None

    # Process each target domain
    for domain in session.target_domains:
        # Query Hunter.io for domain emails
        if hunter_key:
            hunter_data = await query_hunter_domain(domain, hunter_key, config.scan.timeout)

            if hunter_data:
                # Get email pattern
                pattern = hunter_data.get("pattern")
                if pattern:
                    email_pattern = pattern

                # Get discovered emails
                for email_data in hunter_data.get("emails", []):
                    email = email_data.get("value", "")
                    if email:
                        discovered_emails.add(email)

                        employee = {
                            "email": email,
                            "first_name": email_data.get("first_name", ""),
                            "last_name": email_data.get("last_name", ""),
                            "position": email_data.get("position", ""),
                            "department": email_data.get("department", ""),
                            "linkedin": email_data.get("linkedin", ""),
                            "twitter": email_data.get("twitter", ""),
                            "phone": email_data.get("phone_number", ""),
                            "confidence": email_data.get("confidence", 0),
                            "source": "hunter.io",
                        }
                        discovered_employees.append(employee)
                        items_discovered += 1

                await asyncio.sleep(1)

        # Also check for emails from GitHub (if github_recon already ran)
        if hasattr(session, 'github_data') and session.github_data:
            github_emails = session.github_data.get("emails", [])
            for email in github_emails:
                if domain.lower() in email.lower():
                    discovered_emails.add(email)

                    # Check if we already have this employee
                    if not any(e["email"] == email for e in discovered_employees):
                        employee = {
                            "email": email,
                            "first_name": "",
                            "last_name": "",
                            "position": "",
                            "department": "",
                            "linkedin": "",
                            "twitter": "",
                            "phone": "",
                            "confidence": 70,
                            "source": "github",
                        }
                        discovered_employees.append(employee)
                        items_discovered += 1

    # Detect email pattern if not found
    if not email_pattern and discovered_emails:
        email_pattern = detect_email_pattern(list(discovered_emails), session.target_domains[0])

    # Create findings
    if discovered_employees:
        # Summary finding
        finding = Finding(
            title=f"Discovered {len(discovered_employees)} employee(s) for target organization",
            description=f"Found {len(discovered_employees)} potential employees through OSINT sources. "
                       f"These can be used for social engineering, phishing, or credential attacks.",
            severity=Severity.MEDIUM,
            category="osint",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence=f"Sample emails: {', '.join(list(discovered_emails)[:10])}",
            source="employee_discovery",
        )
        result.findings.append(finding)

        # High-value targets (executives)
        executive_keywords = ["ceo", "cto", "cfo", "cio", "ciso", "vp", "vice president",
                            "director", "head of", "chief", "president", "founder"]

        executives = []
        for emp in discovered_employees:
            position = (emp.get("position") or "").lower()
            if any(kw in position for kw in executive_keywords):
                executives.append(emp)

        if executives:
            exec_list = ", ".join(
                f"{e.get('first_name', '')} {e.get('last_name', '')} ({e.get('position', '')})"
                for e in executives[:10]
            )
            finding = Finding(
                title=f"Identified {len(executives)} executive(s) / high-value targets",
                description=f"Found executive-level employees who may be high-value targets for spear phishing.",
                severity=Severity.HIGH,
                category="osint",
                affected_asset=session.target_company or session.target_domains[0],
                affected_asset_type="organization",
                evidence=exec_list,
                source="employee_discovery",
            )
            result.findings.append(finding)

    # Email pattern finding
    if email_pattern:
        finding = Finding(
            title=f"Email pattern detected: {email_pattern}@domain.com",
            description=f"The organization uses the email pattern '{email_pattern}' for employee emails. "
                       f"This can be used to generate valid email addresses from employee names.",
            severity=Severity.LOW,
            category="osint",
            affected_asset=session.target_domains[0] if session.target_domains else "",
            affected_asset_type="domain",
            evidence=f"Pattern: {email_pattern}",
            source="employee_discovery",
        )
        result.findings.append(finding)

    # Store employee data in session
    if not hasattr(session, 'employee_data'):
        session.employee_data = {}

    session.employee_data = {
        "employees": discovered_employees,
        "emails": list(discovered_emails),
        "email_pattern": email_pattern,
    }

    result.items_discovered = items_discovered
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
