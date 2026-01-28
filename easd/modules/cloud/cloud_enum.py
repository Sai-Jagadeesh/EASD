"""
Cloud asset enumeration module.

Discovers cloud assets such as:
- AWS S3 buckets
- Azure Blob storage
- GCP Storage buckets
"""

import asyncio
import re
from datetime import datetime
from typing import Optional

import httpx

from easd.config import EASDConfig
from easd.core.models import (
    ModuleResult,
    CloudAsset,
    CloudProvider,
    AssetType,
    Finding,
    Severity,
    ScanSession,
)


# Common bucket name patterns/mutations
BUCKET_MUTATIONS = [
    "{name}",
    "{name}-backup",
    "{name}-backups",
    "{name}-bak",
    "{name}-data",
    "{name}-files",
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-uploads",
    "{name}-images",
    "{name}-docs",
    "{name}-documents",
    "{name}-public",
    "{name}-private",
    "{name}-dev",
    "{name}-development",
    "{name}-staging",
    "{name}-stage",
    "{name}-prod",
    "{name}-production",
    "{name}-test",
    "{name}-testing",
    "{name}-logs",
    "{name}-archive",
    "{name}-web",
    "{name}-cdn",
    "{name}-s3",
    "{name}-bucket",
    "backup-{name}",
    "backups-{name}",
    "data-{name}",
    "{name}backup",
    "{name}data",
]


def generate_bucket_names(base_names: list[str]) -> list[str]:
    """Generate bucket name mutations from base names."""
    buckets = set()

    for name in base_names:
        # Clean the name
        clean_name = re.sub(r"[^a-z0-9-]", "", name.lower())
        clean_name = re.sub(r"-+", "-", clean_name).strip("-")

        if not clean_name or len(clean_name) < 3:
            continue

        for pattern in BUCKET_MUTATIONS:
            bucket_name = pattern.format(name=clean_name)
            if 3 <= len(bucket_name) <= 63:
                buckets.add(bucket_name)

        # Also try with dots replaced by dashes
        if "." in name:
            dotless = name.replace(".", "-").lower()
            dotless = re.sub(r"[^a-z0-9-]", "", dotless)
            for pattern in BUCKET_MUTATIONS[:5]:  # Just main patterns
                bucket_name = pattern.format(name=dotless)
                if 3 <= len(bucket_name) <= 63:
                    buckets.add(bucket_name)

    return list(buckets)


async def check_s3_bucket(
    bucket_name: str,
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if an S3 bucket exists and is accessible.

    Returns:
        CloudAsset if bucket exists, None otherwise
    """
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for url in urls:
            try:
                response = await client.head(url)

                # Bucket exists
                if response.status_code in [200, 403, 301, 307]:
                    is_public = response.status_code == 200

                    # Try to list contents if public
                    permissions = []
                    if is_public:
                        try:
                            list_response = await client.get(url)
                            if "<Contents>" in list_response.text:
                                permissions.append("LIST")
                        except Exception:
                            pass

                    asset = CloudAsset(
                        provider=CloudProvider.AWS,
                        asset_type=AssetType.BUCKET,
                        name=bucket_name,
                        url=url,
                        is_public=is_public,
                        permissions=permissions,
                        source="cloud_enum",
                    )
                    return asset

            except httpx.ConnectTimeout:
                continue
            except httpx.ReadTimeout:
                continue
            except Exception:
                continue

    return None


async def check_azure_blob(
    container_name: str,
    account_name: str,
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if an Azure Blob container exists and is accessible.

    Returns:
        CloudAsset if container exists, None otherwise
    """
    url = f"https://{account_name}.blob.core.windows.net/{container_name}?restype=container&comp=list"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)

            if response.status_code == 200:
                asset = CloudAsset(
                    provider=CloudProvider.AZURE,
                    asset_type=AssetType.BLOB,
                    name=f"{account_name}/{container_name}",
                    url=f"https://{account_name}.blob.core.windows.net/{container_name}",
                    is_public=True,
                    permissions=["LIST"],
                    source="cloud_enum",
                )
                return asset
            elif response.status_code == 404:
                # Container doesn't exist
                return None
            elif response.status_code in [403, 409]:
                # Container exists but not public
                asset = CloudAsset(
                    provider=CloudProvider.AZURE,
                    asset_type=AssetType.BLOB,
                    name=f"{account_name}/{container_name}",
                    url=f"https://{account_name}.blob.core.windows.net/{container_name}",
                    is_public=False,
                    source="cloud_enum",
                )
                return asset

    except Exception:
        pass

    return None


async def check_gcp_bucket(
    bucket_name: str,
    timeout: float = 10.0,
) -> Optional[CloudAsset]:
    """
    Check if a GCP Storage bucket exists and is accessible.

    Returns:
        CloudAsset if bucket exists, None otherwise
    """
    url = f"https://storage.googleapis.com/{bucket_name}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)

            if response.status_code == 200:
                is_public = True
                permissions = []

                # Check if we can list
                if "<Contents>" in response.text or "ListBucketResult" in response.text:
                    permissions.append("LIST")

                asset = CloudAsset(
                    provider=CloudProvider.GCP,
                    asset_type=AssetType.BUCKET,
                    name=bucket_name,
                    url=url,
                    is_public=is_public,
                    permissions=permissions,
                    source="cloud_enum",
                )
                return asset
            elif response.status_code == 403:
                # Bucket exists but not public
                asset = CloudAsset(
                    provider=CloudProvider.GCP,
                    asset_type=AssetType.BUCKET,
                    name=bucket_name,
                    url=url,
                    is_public=False,
                    source="cloud_enum",
                )
                return asset

    except Exception:
        pass

    return None


def create_findings_for_public_assets(assets: list[CloudAsset]) -> list[Finding]:
    """Create findings for publicly accessible cloud assets."""
    findings = []

    for asset in assets:
        if asset.is_public:
            severity = Severity.HIGH if "LIST" in asset.permissions else Severity.MEDIUM

            finding = Finding(
                title=f"Public {asset.provider.value.upper()} {asset.asset_type.value} found: {asset.name}",
                description=f"A publicly accessible {asset.asset_type.value} was discovered. "
                           f"Public cloud storage can lead to data exposure.",
                severity=severity,
                category="cloud_exposure",
                affected_asset=asset.url,
                affected_asset_type="cloud_asset",
                evidence=f"Permissions: {', '.join(asset.permissions) if asset.permissions else 'READ'}",
                source="cloud_enum",
            )
            findings.append(finding)

    return findings


async def run(
    session: ScanSession,
    config: EASDConfig,
    orchestrator,
) -> ModuleResult:
    """
    Run cloud asset enumeration.

    Args:
        session: Current scan session
        config: EASD configuration
        orchestrator: Orchestrator instance

    Returns:
        ModuleResult with discovered cloud assets
    """
    result = ModuleResult(
        module_name="cloud_enum",
        started_at=datetime.utcnow(),
    )

    # Generate base names from company and domains
    base_names = []

    if session.target_company:
        # Clean company name for bucket names
        company_clean = re.sub(r"[^a-zA-Z0-9\s-]", "", session.target_company)
        base_names.append(company_clean)
        base_names.append(company_clean.replace(" ", "-"))
        base_names.append(company_clean.replace(" ", ""))

    for domain in session.target_domains:
        # Use domain without TLD
        parts = domain.split(".")
        if len(parts) >= 2:
            base_names.append(parts[0])
            base_names.append(".".join(parts[:-1]))

    # Generate bucket name mutations
    bucket_names = generate_bucket_names(base_names)

    if not bucket_names:
        result.success = True
        result.completed_at = datetime.utcnow()
        return result

    # Limit number of checks to avoid being blocked
    max_checks = 200
    bucket_names = bucket_names[:max_checks]

    discovered_assets: list[CloudAsset] = []
    semaphore = asyncio.Semaphore(20)  # Limit concurrent requests

    async def check_bucket(name: str, provider: str):
        async with semaphore:
            if provider == "aws":
                return await check_s3_bucket(name, config.scan.timeout)
            elif provider == "gcp":
                return await check_gcp_bucket(name, config.scan.timeout)
            return None

    # Check enabled providers
    providers = config.modules.cloud.providers

    tasks = []
    for bucket_name in bucket_names:
        if "aws" in providers:
            tasks.append(check_bucket(bucket_name, "aws"))
        if "gcp" in providers:
            tasks.append(check_bucket(bucket_name, "gcp"))

    # Azure requires account names, try with company name
    if "azure" in providers and session.target_company:
        account_name = re.sub(r"[^a-z0-9]", "", session.target_company.lower())[:24]
        if len(account_name) >= 3:
            for container in ["public", "data", "files", "backup", "assets", "web"]:
                tasks.append(check_azure_blob(container, account_name, config.scan.timeout))

    # Execute all checks
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for asset in results:
        if isinstance(asset, CloudAsset):
            discovered_assets.append(asset)

    # Create findings for public assets
    findings = create_findings_for_public_assets(discovered_assets)

    result.cloud_assets = discovered_assets
    result.findings = findings
    result.items_discovered = len(discovered_assets)
    result.success = True
    result.completed_at = datetime.utcnow()

    return result
