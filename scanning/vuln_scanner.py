"""
Vulnerability Scanner Orchestrator - FULL INTEGRATION v2.0
Coordinates ALL 39 scanning modules for 100% coverage.
Updated: Janeiro 2026
"""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable

from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

# Scope Guard for legal safety
try:
    from utils.scope_guard import ScopeGuard, ScopeDefinition, ScopeMode
    SCOPE_GUARD_AVAILABLE = True
except ImportError:
    SCOPE_GUARD_AVAILABLE = False

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class ModuleCategory(Enum):
    """Categories of scanning modules."""
    PASSIVE = auto()      # No direct interaction (headers, ssl, cors)
    ACTIVE = auto()       # Active probing (sqli, xss, cmdi)
    INFRASTRUCTURE = auto()  # Cloud, K8s, network
    AUTHENTICATION = auto()  # Auth, OAuth, SAML, MFA
    API = auto()          # REST, GraphQL, gRPC, WebSocket
    ADVANCED = auto()     # SSTI, Deser, Smuggling, etc.


@dataclass
class Finding:
    """Vulnerability finding structure."""
    
    id: str = ""
    type: str = ""
    name: str = ""
    severity: str = "INFO"
    description: str = ""
    host: str = ""
    matched_at: str = ""
    evidence: list[str] | None = None
    cvss_score: float = 0.0
    cwe: str = ""
    remediation: str = ""
    references: list[str] | None = None
    metadata: dict[str, Any] | None = None
    confidence: float = 0.0  # NEW: Confidence score 0-100
    category: str = ""       # NEW: Module category
    
    def __post_init__(self):
        self.evidence = self.evidence or []
        self.references = self.references or []
        self.metadata = self.metadata or {}

        # Generate unique ID if not provided
        if not self.id:
            self.id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate a unique finding ID based on content hash."""
        # Create deterministic ID from key fields
        content = f"{self.type}:{self.name}:{self.host}:{self.matched_at}"
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"FIND-{content_hash}-{timestamp}"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "host": self.host,
            "matched_at": self.matched_at,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
            "confidence": self.confidence,
            "category": self.category,
        }


@dataclass 
class ModuleConfig:
    """Configuration for a scanning module."""
    name: str
    cls: type
    category: ModuleCategory
    enabled: bool = True
    requires_urls: bool = False      # Needs crawled URLs
    requires_forms: bool = False     # Needs form data
    requires_auth: bool = False      # Needs authentication
    requires_websocket: bool = False # Needs WebSocket endpoints
    requires_graphql: bool = False   # Needs GraphQL endpoint
    requires_grpc: bool = False      # Needs gRPC endpoint
    min_safety_level: str = "safe"   # Minimum SafetyLevel required


class ScanModule(ABC):
    """Base class for scanning modules."""

    name: str = "base"

    # Class-level flag: set by FullScanner when target is localhost
    _target_is_local: bool = False

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._scope_guard: Any = None

        # Initialize scope guard if available and scope is defined
        if SCOPE_GUARD_AVAILABLE:
            try:
                # Get scope from settings if available
                scope_config = getattr(settings, 'scope', None)
                if scope_config:
                    # Allow localhost if scan target IS localhost
                    is_local = ScanModule._target_is_local
                    scope_def = ScopeDefinition(
                        allowed_domains=getattr(scope_config, 'allowed_domains', []),
                        allowed_ips=getattr(scope_config, 'allowed_ips', []),
                        block_internal_ips=not is_local,
                        block_cloud_metadata=True,
                        block_localhost=not is_local,
                    )
                    self._scope_guard = ScopeGuard(scope=scope_def, mode=ScopeMode.STRICT)
                    logger.debug(f"ScopeGuard initialized for {self.name} (localhost_allowed={is_local})")
            except Exception as e:
                logger.debug(f"ScopeGuard initialization skipped: {e}")

    @classmethod
    def set_target_is_local(cls, target: str) -> None:
        """Set class-level flag if scan target is localhost/internal."""
        from urllib.parse import urlparse
        host = urlparse(target).hostname or ""
        cls._target_is_local = host.lower() in (
            "localhost", "127.0.0.1", "::1", "0.0.0.0",
        ) or host.startswith("192.168.") or host.startswith("10.")

    def is_url_in_scope(self, url: str) -> tuple[bool, str]:
        """
        Check if a URL is within the allowed scope.

        SECURITY: Use this before making requests to prevent
        testing unauthorized targets.

        Args:
            url: URL to check

        Returns:
            Tuple of (allowed, reason)
        """
        if self._scope_guard is None:
            return True, "No scope restrictions"

        allowed, violation = self._scope_guard.is_allowed(url)
        if not allowed and violation:
            return False, violation.reason
        return True, "URL is in scope"

    def filter_urls_by_scope(self, urls: list[str]) -> list[str]:
        """
        Filter a list of URLs to only include those in scope.

        Args:
            urls: List of URLs to filter

        Returns:
            Filtered list of in-scope URLs
        """
        if self._scope_guard is None:
            return urls

        safe_urls = []
        for url in urls:
            allowed, _ = self.is_url_in_scope(url)
            if allowed:
                safe_urls.append(url)

        if len(safe_urls) < len(urls):
            logger.info(
                f"🛡️ {self.name}: Filtered {len(urls) - len(safe_urls)} out-of-scope URLs"
            )

        return safe_urls

    @abstractmethod
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Execute scan on a host.

        Args:
            host: Target hostname
            asset_data: Reconnaissance data
            rate_limiter: Rate limiter instance

        Returns:
            Dict with 'vulns' and 'info' lists
        """
        pass


class VulnerabilityScanner:
    """
    Orchestrates vulnerability scanning across ALL 39 modules.
    
    FULL INTEGRATION v2.0 - Janeiro 2026
    
    Module Categories:
    - PASSIVE: Headers, SSL, CORS (non-intrusive)
    - ACTIVE: SQLi, XSS, CMDi, XXE, SSRF, LFI, etc.
    - INFRASTRUCTURE: Cloud, Kubernetes, DNS
    - AUTHENTICATION: Auth, OAuth, SAML, MFA, Rate Limit
    - API: REST, GraphQL Advanced, gRPC, WebSocket, SSE
    - ADVANCED: SSTI, Deserialization, Smuggling, Cache Poison, etc.
    """
    
    # Version for tracking
    VERSION = "2.0.0"
    
    def __init__(self, settings: Settings, safety_level: str = "safe") -> None:
        """
        Initialize scanner with ALL modules.
        
        Args:
            settings: Application settings
            safety_level: Safety level (passive/safe/cautious/standard/aggressive)
        """
        self.settings = settings
        self.safety_level = safety_level
        self.modules: dict[str, ScanModule] = {}
        self.module_configs: dict[str, ModuleConfig] = {}
        self._load_all_modules()
        
        logger.info(f"VulnerabilityScanner v{self.VERSION} initialized with {len(self.modules)} modules")
    
    def _load_all_modules(self) -> None:
        """Load ALL 39 scanning modules."""
        # Import all modules
        from scanning.modules.nuclei_runner import NucleiRunner
        from scanning.modules.header_security import HeaderSecurityChecker
        from scanning.modules.ssl_checker import SSLChecker
        from scanning.modules.cors_checker import CORSChecker
        from scanning.modules.sqli_scanner import SQLiScanner
        from scanning.modules.xss_scanner import XSSScanner
        from scanning.modules.cmdi_scanner import CommandInjectionScanner
        from scanning.modules.xxe_scanner import XXEScanner
        from scanning.modules.ssrf_scanner import SSRFScanner
        from scanning.modules.lfi_scanner import LFIScanner
        from scanning.modules.auth_scanner import AuthScanner
        from scanning.modules.api_scanner import APIScanner
        from scanning.modules.dir_scanner import DirectoryScanner
        from scanning.modules.cms_scanner import CMSScanner
        from scanning.modules.cloud_scanner import CloudScanner
        from scanning.modules.business_logic_scanner import BusinessLogicScanner
        from scanning.modules.authorization_engine import AuthorizationEngine
        from scanning.modules.post_exploitation import PostExploitationModule
        # Advanced Phase 1
        from scanning.modules.oauth_scanner import OAuthScanner
        from scanning.modules.ssti_scanner import SSTIScanner
        from scanning.modules.deserialization_scanner import DeserializationScanner
        from scanning.modules.websocket_scanner import WebSocketScanner
        from scanning.modules.mfa_bypass_scanner import MFABypassScanner
        from scanning.modules.nosql_scanner import NoSQLScanner
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner
        from scanning.modules.prototype_pollution_scanner import PrototypePollutionScanner
        from scanning.modules.crlf_scanner import CRLFScanner
        from scanning.modules.mobile_api_scanner import MobileAPIScanner
        from scanning.modules.saml_scanner import SAMLScanner
        # 100% Coverage Phase 2
        from scanning.modules.cache_poisoning_scanner import CachePoisoningScanner
        from scanning.modules.graphql_advanced_scanner import GraphQLAdvancedScanner
        from scanning.modules.ldap_xpath_scanner import LDAPXPathScanner
        from scanning.modules.kubernetes_scanner import KubernetesContainerScanner
        from scanning.modules.grpc_scanner import GRPCScanner
        from scanning.modules.dns_rebinding_scanner import DNSRebindingScanner
        from scanning.modules.email_security_scanner import EmailSecurityScanner
        from scanning.modules.sse_scanner import SSEScanner
        from scanning.modules.rate_limit_scanner import RateLimitScanner
        
        # Define ALL module configurations
        all_modules: list[ModuleConfig] = [
            # === PASSIVE MODULES (Always safe) ===
            ModuleConfig("nuclei", NucleiRunner, ModuleCategory.PASSIVE),
            ModuleConfig("headers", HeaderSecurityChecker, ModuleCategory.PASSIVE),
            ModuleConfig("ssl", SSLChecker, ModuleCategory.PASSIVE),
            ModuleConfig("cors", CORSChecker, ModuleCategory.PASSIVE),
            ModuleConfig("email_security", EmailSecurityScanner, ModuleCategory.PASSIVE),
            
            # === ACTIVE INJECTION MODULES ===
            ModuleConfig("sqli", SQLiScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("xss", XSSScanner, ModuleCategory.ACTIVE, requires_urls=True, requires_forms=True),
            ModuleConfig("cmdi", CommandInjectionScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("xxe", XXEScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("ssrf", SSRFScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("lfi", LFIScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("nosql", NoSQLScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("crlf", CRLFScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("ldap_xpath", LDAPXPathScanner, ModuleCategory.ACTIVE, requires_urls=True),
            
            # === ADVANCED INJECTION MODULES ===
            ModuleConfig("ssti", SSTIScanner, ModuleCategory.ADVANCED, requires_urls=True),
            ModuleConfig("deserialization", DeserializationScanner, ModuleCategory.ADVANCED, requires_urls=True),
            ModuleConfig("smuggling", HTTPSmugglingScanner, ModuleCategory.ADVANCED, min_safety_level="aggressive"),
            ModuleConfig("prototype_pollution", PrototypePollutionScanner, ModuleCategory.ADVANCED, requires_urls=True),
            ModuleConfig("cache_poisoning", CachePoisoningScanner, ModuleCategory.ADVANCED, min_safety_level="aggressive"),
            
            # === AUTHENTICATION MODULES ===
            ModuleConfig("auth", AuthScanner, ModuleCategory.AUTHENTICATION),
            ModuleConfig("oauth", OAuthScanner, ModuleCategory.AUTHENTICATION, requires_auth=True),
            ModuleConfig("saml", SAMLScanner, ModuleCategory.AUTHENTICATION),
            ModuleConfig("mfa_bypass", MFABypassScanner, ModuleCategory.AUTHENTICATION, requires_auth=True, min_safety_level="cautious"),
            ModuleConfig("rate_limit", RateLimitScanner, ModuleCategory.AUTHENTICATION, min_safety_level="cautious"),
            
            # === API MODULES ===
            ModuleConfig("api", APIScanner, ModuleCategory.API, requires_urls=True),
            ModuleConfig("graphql", GraphQLAdvancedScanner, ModuleCategory.API, requires_graphql=True),
            ModuleConfig("grpc", GRPCScanner, ModuleCategory.API, requires_grpc=True),
            ModuleConfig("websocket", WebSocketScanner, ModuleCategory.API, requires_websocket=True),
            ModuleConfig("sse", SSEScanner, ModuleCategory.API, requires_urls=True),
            ModuleConfig("mobile_api", MobileAPIScanner, ModuleCategory.API, requires_urls=True),
            
            # === INFRASTRUCTURE MODULES ===
            ModuleConfig("cloud", CloudScanner, ModuleCategory.INFRASTRUCTURE),
            ModuleConfig("kubernetes", KubernetesContainerScanner, ModuleCategory.INFRASTRUCTURE),
            ModuleConfig("dns_rebinding", DNSRebindingScanner, ModuleCategory.INFRASTRUCTURE, min_safety_level="standard"),
            ModuleConfig("dir_scanner", DirectoryScanner, ModuleCategory.INFRASTRUCTURE, requires_urls=True),
            ModuleConfig("cms", CMSScanner, ModuleCategory.INFRASTRUCTURE),
            
            # === ENTERPRISE MODULES ===
            ModuleConfig("business_logic", BusinessLogicScanner, ModuleCategory.ADVANCED, requires_urls=True, requires_auth=True),
            ModuleConfig("authorization", AuthorizationEngine, ModuleCategory.AUTHENTICATION, requires_auth=True),
            ModuleConfig("post_exploitation", PostExploitationModule, ModuleCategory.ADVANCED, min_safety_level="standard"),
        ]
        
        # Register modules
        loaded = 0
        skipped = 0
        
        for config in all_modules:
            try:
                # Check safety level compatibility
                if not self._is_safe_for_level(config.min_safety_level):
                    logger.debug(f"Skipping {config.name}: requires {config.min_safety_level} mode")
                    skipped += 1
                    continue
                
                self.modules[config.name] = config.cls(self.settings)
                self.module_configs[config.name] = config
                loaded += 1
                logger.debug(f"Loaded module: {config.name} ({config.category.name})")
                
            except Exception as e:
                logger.warning(f"Failed to load module {config.name}: {e}")
        
        logger.info(f"Modules loaded: {loaded}, skipped by safety level: {skipped}")
    
    def _is_safe_for_level(self, required_level: str) -> bool:
        """Check if current safety level allows the module."""
        levels = ["passive", "safe", "cautious", "standard", "aggressive"]
        
        current_idx = levels.index(self.safety_level) if self.safety_level in levels else 1
        required_idx = levels.index(required_level) if required_level in levels else 1
        
        return current_idx >= required_idx
    
    def _should_run_module(
        self,
        config: ModuleConfig,
        asset_data: dict[str, Any],
    ) -> bool:
        """Determine if a module should run based on asset data."""
        if not config.enabled:
            return False
        
        # Check requirements
        if config.requires_urls and not asset_data.get("urls"):
            return False
        if config.requires_forms and not asset_data.get("forms"):
            return False
        if config.requires_websocket and not asset_data.get("websocket_endpoints"):
            return False
        if config.requires_graphql and not asset_data.get("graphql_endpoint"):
            return False
        if config.requires_grpc and not asset_data.get("grpc_endpoints"):
            return False
        
        return True
    
    async def scan_host(
        self,
        host: str,
        asset_data: dict[str, Any],
        modules: str = "all",
        categories: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Scan a host for vulnerabilities using ALL relevant modules.
        
        Args:
            host: Target hostname
            asset_data: Reconnaissance data (urls, forms, tech, etc.)
            modules: Comma-separated list, 'all', or category names
            categories: List of categories to run (PASSIVE, ACTIVE, etc.)
            
        Returns:
            Dict with vulnerabilities and info
        """
        logger.info(f"Starting full vulnerability scan on {host} with {len(self.modules)} modules available")
        
        result = {
            "host": host,
            "vulnerabilities": [],
            "info": [],
            "modules_run": [],
            "modules_skipped": [],
        }
        
        # Select modules
        selected = self._select_modules(modules, categories, asset_data)
        
        if not selected:
            logger.warning(f"No valid modules selected for {host}")
            return result
        
        logger.info(f"Running {len(selected)} modules on {host}")
        
        # Create rate limiter
        rate_limiter = RateLimiter(
            settings=self.settings,
            default_rate=getattr(self.settings.rate_limit, 'requests_per_second', 10.0),
            default_burst=getattr(self.settings.rate_limit, 'concurrent_scans', 20),
        )
        
        # Group modules by category for phased execution
        passive_modules = []
        active_modules = []
        
        for name, module in selected.items():
            config = self.module_configs.get(name)
            if config and config.category == ModuleCategory.PASSIVE:
                passive_modules.append((name, module))
            else:
                active_modules.append((name, module))
        
        # Phase 1: Run passive modules first (parallel)
        if passive_modules:
            logger.info(f"Phase 1: Running {len(passive_modules)} passive modules")
            passive_results = await self._run_modules_parallel(
                passive_modules, host, asset_data, rate_limiter
            )
            self._aggregate_results(result, passive_results)
        
        # Phase 2: Run active modules (with rate limiting)
        if active_modules:
            logger.info(f"Phase 2: Running {len(active_modules)} active modules")
            active_results = await self._run_modules_parallel(
                active_modules, host, asset_data, rate_limiter, max_concurrent=5
            )
            self._aggregate_results(result, active_results)
        
        # Deduplicate and sort findings
        result["vulnerabilities"] = self._deduplicate_findings(result["vulnerabilities"])
        result["vulnerabilities"].sort(
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                x.get("severity", "INFO").upper(), 5
            )
        )
        
        logger.info(
            f"Scan complete for {host}: "
            f"{len(result['vulnerabilities'])} unique vulnerabilities, "
            f"{len(result['modules_run'])} modules executed"
        )
        return result
    
    def _select_modules(
        self,
        modules: str,
        categories: list[str] | None,
        asset_data: dict[str, Any],
    ) -> dict[str, ScanModule]:
        """Select modules to run based on criteria."""
        selected = {}
        
        if modules == "all":
            # Filter by category if specified
            if categories:
                cat_enums = [ModuleCategory[c.upper()] for c in categories if c.upper() in ModuleCategory.__members__]
                for name, module in self.modules.items():
                    config = self.module_configs.get(name)
                    if config and config.category in cat_enums:
                        if self._should_run_module(config, asset_data):
                            selected[name] = module
            else:
                # Run all applicable modules
                for name, module in self.modules.items():
                    config = self.module_configs.get(name)
                    if config and self._should_run_module(config, asset_data):
                        selected[name] = module
        else:
            # Parse comma-separated list
            module_names = [m.strip() for m in modules.split(",")]
            for name in module_names:
                if name in self.modules:
                    config = self.module_configs.get(name)
                    if config and self._should_run_module(config, asset_data):
                        selected[name] = self.modules[name]
        
        return selected
    
    async def _run_modules_parallel(
        self,
        modules: list[tuple[str, ScanModule]],
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
        max_concurrent: int = 10,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Run modules in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_with_semaphore(name: str, module: ScanModule):
            async with semaphore:
                try:
                    result = await module.scan(host, asset_data, rate_limiter)
                    return (name, result, None)
                except Exception as e:
                    logger.error(f"Module {name} failed on {host}: {e}")
                    return (name, {"vulns": [], "info": []}, str(e))
        
        tasks = [run_with_semaphore(name, module) for name, module in modules]
        return await asyncio.gather(*tasks)
    
    def _aggregate_results(
        self,
        result: dict[str, Any],
        module_results: list[tuple[str, dict[str, Any], str | None]],
    ) -> None:
        """Aggregate results from multiple modules."""
        for name, mod_result, error in module_results:
            if error:
                result["modules_skipped"].append({"name": name, "error": error})
            else:
                result["modules_run"].append(name)
                result["vulnerabilities"].extend(mod_result.get("vulns", []))
                result["info"].extend(mod_result.get("info", []))
    
    def _deduplicate_findings(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings based on key fields."""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create unique key
            key = (
                finding.get("type", ""),
                finding.get("name", ""),
                finding.get("matched_at", ""),
                finding.get("host", ""),
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    async def _run_module(
        self,
        module: ScanModule,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Run a single scanning module."""
        try:
            logger.debug(f"Running module {module.name} on {host}")
            return await module.scan(host, asset_data, rate_limiter)
        except Exception as e:
            logger.error(f"Module {module.name} failed on {host}: {e}")
            return {"vulns": [], "info": []}
    
    def get_available_modules(self) -> list[str]:
        """Get list of available modules."""
        return list(self.modules.keys())
    
    def get_modules_by_category(self) -> dict[str, list[str]]:
        """Get modules grouped by category."""
        by_category: dict[str, list[str]] = {}
        
        for name, config in self.module_configs.items():
            cat_name = config.category.name
            if cat_name not in by_category:
                by_category[cat_name] = []
            by_category[cat_name].append(name)
        
        return by_category
    
    def get_statistics(self) -> dict[str, Any]:
        """Get scanner statistics."""
        by_category = self.get_modules_by_category()
        
        return {
            "version": self.VERSION,
            "total_modules": len(self.modules),
            "safety_level": self.safety_level,
            "modules_by_category": {k: len(v) for k, v in by_category.items()},
            "module_list": list(self.modules.keys()),
        }
