"""
Orchestrator for EASD discovery pipeline.

Coordinates the execution of discovery modules in the correct order,
manages data flow between modules, and handles the overall scan lifecycle.
"""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, Any
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskID

from easd.config import EASDConfig, get_config
from easd.core.models import (
    ScanSession,
    ScanStatus,
    Organization,
    ModuleResult,
)
from easd.core.database import Database


# Type alias for module functions
ModuleFunction = Callable[[ScanSession, EASDConfig, "Orchestrator"], ModuleResult]


class Orchestrator:
    """
    Orchestrates the attack surface discovery pipeline.

    Manages module execution order, data persistence, and progress reporting.
    """

    # Module execution order
    MODULE_ORDER = [
        "seed",           # Initial discovery (WHOIS, crt.sh, ASN)
        "domain",         # Domain/subdomain enumeration
        "dns",            # DNS resolution
        "infrastructure", # Port scanning, service detection
        "enrichment",     # Shodan, Censys enrichment
        "osint",          # GitHub recon, employee discovery
        "web",            # Web application discovery
        "cloud",          # Cloud asset enumeration
        "correlation",    # Data correlation and risk scoring
    ]

    def __init__(
        self,
        config: Optional[EASDConfig] = None,
        db_path: Optional[Path] = None,
        console: Optional[Console] = None,
    ):
        """
        Initialize the orchestrator.

        Args:
            config: EASD configuration. If None, loads from default locations.
            db_path: Path to database file. If None, creates in output directory.
            console: Rich console for output. If None, creates a new one.
        """
        self.config = config or get_config()
        self.console = console or Console()
        self.db: Optional[Database] = None
        self.db_path = db_path
        self.session: Optional[ScanSession] = None

        # Registered modules
        self._modules: dict[str, ModuleFunction] = {}

        # Event callbacks
        self._on_module_start: list[Callable[[str], None]] = []
        self._on_module_complete: list[Callable[[str, ModuleResult], None]] = []
        self._on_finding: list[Callable[[Any], None]] = []

        # Progress tracking
        self._progress: Optional[Progress] = None
        self._task_ids: dict[str, TaskID] = {}

    def register_module(self, name: str, func: ModuleFunction) -> None:
        """Register a discovery module."""
        self._modules[name] = func

    def on_module_start(self, callback: Callable[[str], None]) -> None:
        """Register a callback for module start events."""
        self._on_module_start.append(callback)

    def on_module_complete(self, callback: Callable[[str, ModuleResult], None]) -> None:
        """Register a callback for module completion events."""
        self._on_module_complete.append(callback)

    def on_finding(self, callback: Callable[[Any], None]) -> None:
        """Register a callback for new findings."""
        self._on_finding.append(callback)

    def _init_database(self, session_id: str) -> None:
        """Initialize the database for a session."""
        if self.db_path:
            db_file = self.db_path
        else:
            output_dir = self.config.get_output_dir(session_id)
            db_file = output_dir / "easd.db"

        self.db = Database(db_file)

    def create_session(
        self,
        company: str = "",
        domains: Optional[list[str]] = None,
        ip_ranges: Optional[list[str]] = None,
        modules: Optional[list[str]] = None,
        passive_only: bool = False,
        intensity: str = "normal",
    ) -> ScanSession:
        """
        Create a new scan session.

        Args:
            company: Target company name
            domains: List of known root domains
            ip_ranges: List of known IP ranges (CIDR notation)
            modules: List of modules to run. If None, runs all.
            passive_only: If True, only runs passive discovery modules
            intensity: Scan intensity (passive, normal, aggressive)

        Returns:
            Created ScanSession object
        """
        self.session = ScanSession(
            target_company=company,
            target_domains=domains or [],
            target_ip_ranges=ip_ranges or [],
            modules_enabled=modules or self.MODULE_ORDER.copy(),
            passive_only=passive_only,
            intensity=intensity,
            status=ScanStatus.PENDING,
        )

        # Initialize organization
        if company:
            self.session.organization = Organization(
                name=company,
                source="user_input",
            )

        # Initialize database
        self._init_database(self.session.id)
        self.db.create_session(self.session)

        return self.session

    def load_session(self, session_id: str) -> Optional[ScanSession]:
        """Load an existing session."""
        self._init_database(session_id)
        self.session = self.db.get_session(session_id)
        return self.session

    async def run(self) -> ScanSession:
        """
        Run the discovery pipeline.

        Executes all enabled modules in order, collecting and correlating results.

        Returns:
            Completed ScanSession with all discovered data
        """
        if not self.session:
            raise ValueError("No session created. Call create_session first.")

        if not self.db:
            raise ValueError("Database not initialized.")

        # Update session status
        self.session.status = ScanStatus.RUNNING
        self.db.update_session(self.session)

        try:
            # Filter modules based on passive_only mode
            modules_to_run = self._get_modules_to_run()

            # Run each module in order
            for module_name in modules_to_run:
                if module_name not in self._modules:
                    self.console.print(
                        f"[yellow]Warning: Module '{module_name}' not registered, skipping[/yellow]"
                    )
                    continue

                # Notify module start
                for callback in self._on_module_start:
                    callback(module_name)

                # Execute module
                try:
                    result = await self._run_module(module_name)
                    self.session.module_results.append(result)

                    # Merge results into session
                    self._merge_module_result(result)

                    # Notify module complete
                    for callback in self._on_module_complete:
                        callback(module_name, result)

                except Exception as e:
                    self.console.print(f"[red]Error in module '{module_name}': {e}[/red]")
                    result = ModuleResult(
                        module_name=module_name,
                        success=False,
                        error_message=str(e),
                        completed_at=datetime.utcnow(),
                    )
                    self.session.module_results.append(result)

            # Update final statistics
            self.session.update_statistics()
            self.session.status = ScanStatus.COMPLETED
            self.db.update_session(self.session)

        except Exception as e:
            self.session.status = ScanStatus.FAILED
            self.db.update_session(self.session)
            raise

        return self.session

    def _get_modules_to_run(self) -> list[str]:
        """Get the list of modules to run based on configuration."""
        passive_modules = {"seed", "domain", "dns", "enrichment", "correlation"}

        modules = []
        for module in self.MODULE_ORDER:
            if module not in self.session.modules_enabled:
                continue

            if self.session.passive_only and module not in passive_modules:
                continue

            modules.append(module)

        return modules

    async def _run_module(self, module_name: str) -> ModuleResult:
        """Run a single module."""
        module_func = self._modules[module_name]
        result = ModuleResult(
            module_name=module_name,
            started_at=datetime.utcnow(),
        )

        try:
            # Run the module (supports both sync and async)
            if asyncio.iscoroutinefunction(module_func):
                module_result = await module_func(self.session, self.config, self)
            else:
                module_result = module_func(self.session, self.config, self)

            if module_result:
                result = module_result

            result.success = True
            result.completed_at = datetime.utcnow()

        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.completed_at = datetime.utcnow()
            raise

        return result

    def _merge_module_result(self, result: ModuleResult) -> None:
        """Merge module results into the session."""
        # Merge domains
        for domain in result.domains:
            if domain.fqdn not in [d.fqdn for d in self.session.domains]:
                self.session.domains.append(domain)
                self.db.add_domain(self.session.id, domain)

        # Merge subdomains
        for subdomain in result.subdomains:
            if not self.db.subdomain_exists(self.session.id, subdomain.fqdn):
                self.session.subdomains.append(subdomain)
                self.db.add_subdomain(self.session.id, subdomain)

        # Merge IP addresses
        for ip in result.ip_addresses:
            if not self.db.ip_exists(self.session.id, ip.address):
                self.session.ip_addresses.append(ip)
                self.db.add_ip_address(self.session.id, ip)

        # Merge web applications
        for webapp in result.web_applications:
            self.session.web_applications.append(webapp)
            self.db.add_web_application(self.session.id, webapp)

        # Merge cloud assets
        for asset in result.cloud_assets:
            self.session.cloud_assets.append(asset)
            self.db.add_cloud_asset(self.session.id, asset)

        # Merge findings
        for finding in result.findings:
            self.session.findings.append(finding)
            self.db.add_finding(self.session.id, finding)
            # Notify finding callbacks
            for callback in self._on_finding:
                callback(finding)

        # Merge certificates
        for cert in result.certificates:
            self.session.certificates.append(cert)
            self.db.add_certificate(self.session.id, cert)

        # Update session in database
        self.db.update_session(self.session)

    def add_domain(self, fqdn: str, source: str = "manual") -> None:
        """Add a domain to the current session."""
        if not self.session or not self.db:
            return

        from easd.core.models import Domain
        domain = Domain(fqdn=fqdn, source=source)

        if fqdn not in [d.fqdn for d in self.session.domains]:
            self.session.domains.append(domain)
            self.db.add_domain(self.session.id, domain)
            self.session.target_domains.append(fqdn)
            self.db.update_session(self.session)

    def add_subdomain(self, fqdn: str, parent_domain: str, source: str = "manual") -> None:
        """Add a subdomain to the current session."""
        if not self.session or not self.db:
            return

        from easd.core.models import Subdomain
        subdomain = Subdomain(fqdn=fqdn, parent_domain=parent_domain, source=source)

        if not self.db.subdomain_exists(self.session.id, fqdn):
            self.session.subdomains.append(subdomain)
            self.db.add_subdomain(self.session.id, subdomain)

    def add_ip(self, address: str, source: str = "manual") -> None:
        """Add an IP address to the current session."""
        if not self.session or not self.db:
            return

        from easd.core.models import IPAddress
        ip = IPAddress(address=address, source=source)

        if not self.db.ip_exists(self.session.id, address):
            self.session.ip_addresses.append(ip)
            self.db.add_ip_address(self.session.id, ip)

    def get_statistics(self) -> dict:
        """Get current session statistics."""
        if not self.session:
            return {}

        self.session.update_statistics()
        return {
            "domains": self.session.total_domains,
            "subdomains": self.session.total_subdomains,
            "ip_addresses": self.session.total_ips,
            "open_ports": self.session.total_ports,
            "web_applications": self.session.total_web_apps,
            "cloud_assets": self.session.total_cloud_assets,
            "findings": {
                "total": self.session.total_findings,
                "critical": self.session.critical_findings,
                "high": self.session.high_findings,
                "medium": self.session.medium_findings,
                "low": self.session.low_findings,
            },
        }

    def cancel(self) -> None:
        """Cancel the current scan."""
        if self.session:
            self.session.status = ScanStatus.CANCELLED
            if self.db:
                self.db.update_session(self.session)

    def cleanup(self) -> None:
        """Clean up resources."""
        if self.db:
            self.db.close()
            self.db = None
