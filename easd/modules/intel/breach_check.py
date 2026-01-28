"""
Breach and credential exposure checking module.

Integrates with:
- HaveIBeenPwned (HIBP)
- DeHashed
- Intelligence X (IntelX)
- LeakCheck
- BreachDirectory

Checks if employee emails appear in known data breaches.
"""

import asyncio
import hashlib
from datetime import datetime
from typing import Optional

import httpx

from easd.config import EASDConfig
from easd.core.models import (
    ModuleResult,
    Finding,
    Severity,
    ScanSession,
)


async def check_hibp_breaches(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Check HaveIBeenPwned for breaches containing this email.
    Requires API key ($3.50/month).
    """
    if not api_key:
        return []

    breaches = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "EASD-Scanner",
                },
                params={"truncateResponse": "false"},
            )

            if response.status_code == 200:
                breaches = response.json()

    except Exception:
        pass

    return breaches


async def check_hibp_pastes(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Check HaveIBeenPwned for pastes containing this email.
    """
    if not api_key:
        return []

    pastes = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "User-Agent": "EASD-Scanner",
                },
            )

            if response.status_code == 200:
                pastes = response.json()

    except Exception:
        pass

    return pastes


async def check_dehashed(
    query: str,
    api_key: str,
    email: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Search DeHashed for leaked credentials.
    Returns emails, passwords, hashes, usernames, etc.
    """
    if not api_key or not email:
        return []

    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                "https://api.dehashed.com/search",
                params={"query": f"email:{query}"},
                auth=(email, api_key),
                headers={"Accept": "application/json"},
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("entries", [])

    except Exception:
        pass

    return results


async def check_leakcheck(
    email: str,
    api_key: str,
    timeout: float = 30.0,
) -> list[dict]:
    """
    Check LeakCheck.io for breaches.
    """
    if not api_key:
        return []

    results = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://leakcheck.io/api/public",
                params={
                    "key": api_key,
                    "check": email,
                    "type": "email",
                },
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    results = data.get("sources", [])

    except Exception:
        pass

    return results


async def check_intelx(
    query: str,
    api_key: str,
    timeout: float = 30.0,
) -> dict:
    """
    Search Intelligence X for breaches, pastes, dark web.
    """
    if not api_key:
        return {}

    results = {"records": 0, "breaches": []}

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # Start search
            response = await client.post(
                "https://2.intelx.io/intelligent/search",
                headers={"x-key": api_key},
                json={
                    "term": query,
                    "maxresults": 100,
                    "media": 0,
                    "sort": 2,
                    "terminate": [],
                },
            )

            if response.status_code == 200:
                data = response.json()
                search_id = data.get("id")

                if search_id:
                    await asyncio.sleep(2)

                    # Get results
                    result_response = await client.get(
                        f"https://2.intelx.io/intelligent/search/result",
                        headers={"x-key": api_key},
                        params={"id": search_id},
                    )

                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        results["records"] = result_data.get("records", 0)
                        results["breaches"] = [
                            {
                                "name": r.get("name", ""),
                                "date": r.get("date", ""),
                                "bucket": r.get("bucket", ""),
                            }
                            for r in result_data.get("records", [])[:20]
                        ]

    except Exception:
        pass

    return results


async def check_breach_directory(
    email: str,
    timeout: float = 30.0,
) -> list[str]:
    """
    Check BreachDirectory (free, limited).
    """
    sources = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://breachdirectory.org/api/breach/email/{email}",
                headers={"User-Agent": "EASD-Scanner"},
            )

            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    sources = data.get("result", [])

    except Exception:
        pass

    return sources


async def run(
    session: ScanSession,
    config: EASDConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run breach checking for discovered emails.
    """
    result = ModuleResult(
        module_name="breach_check",
        started_at=datetime.utcnow(),
    )

    # Get API keys
    hibp_key = getattr(config.api_keys, 'hibp', None)
    dehashed_key = getattr(config.api_keys, 'dehashed', None)
    dehashed_email = getattr(config.api_keys, 'dehashed_email', None)
    leakcheck_key = getattr(config.api_keys, 'leakcheck', None)
    intelx_key = getattr(config.api_keys, 'intelx', None)

    # Collect emails to check
    emails_to_check = set()

    # From employee discovery
    if hasattr(session, 'employee_data') and session.employee_data:
        emails_to_check.update(session.employee_data.get('emails', []))

    # From GitHub
    if hasattr(session, 'github_data') and session.github_data:
        emails_to_check.update(session.github_data.get('emails', []))

    # Filter to target domain emails only
    target_domains = [d.lower() for d in session.target_domains]
    emails_to_check = [
        e for e in emails_to_check
        if any(d in e.lower() for d in target_domains)
    ]

    if not emails_to_check:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Track results
    breached_emails = []
    credential_exposures = []
    total_breaches = 0

    for email in list(emails_to_check)[:50]:  # Limit API calls
        email_breaches = []
        has_password_exposed = False

        # Check HIBP
        if hibp_key:
            breaches = await check_hibp_breaches(email, hibp_key, config.scan.timeout)
            if breaches:
                email_breaches.extend([b.get("Name", "Unknown") for b in breaches])

            pastes = await check_hibp_pastes(email, hibp_key, config.scan.timeout)
            if pastes:
                email_breaches.append(f"{len(pastes)} paste(s)")

            await asyncio.sleep(1.5)  # HIBP rate limit

        # Check DeHashed (includes passwords)
        if dehashed_key and dehashed_email:
            entries = await check_dehashed(email, dehashed_key, dehashed_email, config.scan.timeout)
            if entries:
                for entry in entries:
                    if entry.get("password") or entry.get("hashed_password"):
                        has_password_exposed = True
                        credential_exposures.append({
                            "email": email,
                            "source": entry.get("database_name", "Unknown"),
                            "has_password": bool(entry.get("password")),
                            "has_hash": bool(entry.get("hashed_password")),
                        })
                email_breaches.append(f"DeHashed: {len(entries)} entries")

            await asyncio.sleep(0.5)

        # Check LeakCheck
        if leakcheck_key:
            sources = await check_leakcheck(email, leakcheck_key, config.scan.timeout)
            if sources:
                email_breaches.extend(sources)

            await asyncio.sleep(0.5)

        # Check IntelX
        if intelx_key:
            intelx_results = await check_intelx(email, intelx_key, config.scan.timeout)
            if intelx_results.get("records", 0) > 0:
                email_breaches.append(f"IntelX: {intelx_results['records']} records")

            await asyncio.sleep(1)

        # Free check - BreachDirectory
        if not hibp_key and not dehashed_key:
            sources = await check_breach_directory(email, config.scan.timeout)
            if sources:
                email_breaches.extend(sources[:5])

            await asyncio.sleep(1)

        if email_breaches:
            breached_emails.append({
                "email": email,
                "breaches": list(set(email_breaches)),
                "breach_count": len(email_breaches),
                "password_exposed": has_password_exposed,
            })
            total_breaches += len(email_breaches)
            result.items_discovered += 1

    # Store results
    if not hasattr(session, 'breach_data'):
        session.breach_data = {}
    session.breach_data = {
        "breached_emails": breached_emails,
        "credential_exposures": credential_exposures,
        "total_breaches": total_breaches,
        "emails_checked": len(emails_to_check),
    }

    # Create findings
    if credential_exposures:
        finding = Finding(
            title=f"CRITICAL: {len(credential_exposures)} credential(s) exposed in breaches",
            description="Employee passwords or password hashes found in data breaches. "
                       "These credentials may still be valid or reused on other systems.",
            severity=Severity.CRITICAL,
            category="credential_exposure",
            affected_asset=session.target_company or session.target_domains[0],
            affected_asset_type="organization",
            evidence="\n".join([
                f"{c['email']} - {c['source']} (password: {c['has_password']}, hash: {c['has_hash']})"
                for c in credential_exposures[:10]
            ]),
            source="breach_check",
        )
        result.findings.append(finding)

    if breached_emails:
        # Separate by severity
        password_exposed = [b for b in breached_emails if b["password_exposed"]]
        email_only = [b for b in breached_emails if not b["password_exposed"]]

        if email_only:
            finding = Finding(
                title=f"{len(email_only)} employee email(s) found in data breaches",
                description="These employee emails appear in known data breaches. "
                           "Check if passwords were exposed and if they may have been reused.",
                severity=Severity.HIGH,
                category="credential_exposure",
                affected_asset=session.target_company or session.target_domains[0],
                affected_asset_type="organization",
                evidence="\n".join([
                    f"{b['email']}: {', '.join(b['breaches'][:3])}"
                    for b in email_only[:10]
                ]),
                source="breach_check",
            )
            result.findings.append(finding)

    result.success = True
    result.completed_at = datetime.utcnow()
    return result
