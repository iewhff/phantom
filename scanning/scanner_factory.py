"""
Scanner Factory - Factory for creating scanner modules with dependency injection.

This module provides a factory pattern for instantiating scanner modules
with their dependencies automatically injected from the DI container.

Part of Phase 8: Dependency Inversion (2026-02-26)

Usage:
    from scanning.scanner_factory import ScannerFactory

    factory = ScannerFactory()

    # Create a scanner with injected dependencies
    sqli_scanner = factory.create("sqli")

    # Create with custom scope (for per-scan state)
    async with factory.create_scoped_scanner("xss") as scanner:
        findings = await scanner.scan(context)
"""

from __future__ import annotations

import importlib
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Type,
    TypeVar,
)

from utils.logger import get_logger
from scanning.container import (
    ScanContainer,
    ScanScope,
    Lifetime,
    get_container,
)

if TYPE_CHECKING:
    from scanning.protocols import ScannerModuleProtocol

logger = get_logger(__name__)

T = TypeVar("T")


# =============================================================================
# SCANNER REGISTRY
# =============================================================================


@dataclass
class ScannerInfo:
    """Information about a registered scanner."""

    name: str
    module_path: str
    class_name: str
    category: str
    description: str = ""
    requires_auth: bool = False
    is_destructive: bool = False
    dependencies: List[str] = field(default_factory=list)


# Scanner registry - maps short names to module paths
SCANNER_REGISTRY: Dict[str, ScannerInfo] = {
    # Injection scanners
    "sqli": ScannerInfo(
        name="sqli",
        module_path="scanning.modules.sqli_scanner",
        class_name="SQLiScanner",
        category="injection",
        description="SQL Injection scanner",
        dependencies=["http_client", "rate_limiter", "payload_library", "waf_bypass"],
    ),
    "xss": ScannerInfo(
        name="xss",
        module_path="scanning.modules.xss_scanner",
        class_name="XSSScanner",
        category="injection",
        description="Cross-Site Scripting scanner",
        dependencies=["http_client", "rate_limiter", "payload_library"],
    ),
    "cmdi": ScannerInfo(
        name="cmdi",
        module_path="scanning.modules.cmdi_scanner",
        class_name="CommandInjectionScanner",  # Fixed: was CMDiScanner
        category="injection",
        description="Command Injection scanner",
        dependencies=["http_client", "rate_limiter", "oob_engine"],
    ),
    "lfi": ScannerInfo(
        name="lfi",
        module_path="scanning.modules.lfi_scanner",
        class_name="LFIScanner",
        category="injection",
        description="Local File Inclusion scanner",
    ),
    "ssti": ScannerInfo(
        name="ssti",
        module_path="scanning.modules.ssti_scanner",
        class_name="SSTIScanner",
        category="injection",
        description="Server-Side Template Injection scanner",
    ),
    "xxe": ScannerInfo(
        name="xxe",
        module_path="scanning.modules.xxe_scanner",
        class_name="XXEScanner",
        category="injection",
        description="XML External Entity scanner",
        dependencies=["http_client", "oob_engine"],
    ),
    "nosql": ScannerInfo(
        name="nosql",
        module_path="scanning.modules.nosql_scanner",
        class_name="NoSQLScanner",
        category="injection",
        description="NoSQL Injection scanner",
    ),

    # Business logic scanners
    "business_logic": ScannerInfo(
        name="business_logic",
        module_path="scanning.modules.business_logic_scanner",
        class_name="BusinessLogicScanner",
        category="business",
        description="Business Logic vulnerability scanner",
        requires_auth=True,
    ),
    "race_condition": ScannerInfo(
        name="race_condition",
        module_path="scanning.modules.race_condition_scanner",
        class_name="RaceConditionScanner",
        category="business",
        description="Race Condition scanner",
        is_destructive=True,
    ),

    # Auth scanners
    "auth": ScannerInfo(
        name="auth",
        module_path="scanning.modules.auth_scanner",
        class_name="AuthScanner",
        category="auth",
        description="Authentication vulnerability scanner",
    ),
    "jwt": ScannerInfo(
        name="jwt",
        module_path="scanning.modules.jwt_scanner",
        class_name="JWTScanner",
        category="auth",
        description="JWT vulnerability scanner",
    ),
    "oauth": ScannerInfo(
        name="oauth",
        module_path="scanning.modules.oauth_scanner",
        class_name="OAuthScanner",
        category="auth",
        description="OAuth vulnerability scanner",
    ),

    # Network scanners
    "ssrf": ScannerInfo(
        name="ssrf",
        module_path="scanning.modules.ssrf_scanner",
        class_name="SSRFScanner",
        category="network",
        description="Server-Side Request Forgery scanner",
        dependencies=["http_client", "oob_engine"],
    ),
    "cors": ScannerInfo(
        name="cors",
        module_path="scanning.modules.cors_checker",
        class_name="CORSChecker",
        category="network",
        description="CORS misconfiguration scanner",
    ),

    # API scanners
    "graphql": ScannerInfo(
        name="graphql",
        module_path="scanning.modules.graphql_advanced_scanner",
        class_name="GraphQLAdvancedScanner",
        category="api",
        description="GraphQL vulnerability scanner",
    ),
    "api": ScannerInfo(
        name="api",
        module_path="scanning.modules.api_scanner",
        class_name="APIScanner",
        category="api",
        description="API vulnerability scanner",
    ),
}


# =============================================================================
# SCANNER FACTORY
# =============================================================================


class ScannerFactory:
    """Factory for creating scanner modules with dependency injection.

    This factory creates scanner instances with their dependencies
    automatically resolved from the DI container.

    Example:
        factory = ScannerFactory()

        # Simple creation
        scanner = factory.create("sqli")

        # With custom settings
        scanner = factory.create("sqli", settings={"max_payloads": 100})

        # Scoped creation (for per-scan dependencies)
        async with factory.create_scoped("xss") as scanner:
            findings = await scanner.scan(context)
    """

    def __init__(
        self,
        container: Optional[ScanContainer] = None,
        settings: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize factory.

        Args:
            container: DI container (uses global if not provided)
            settings: Default settings for all scanners
        """
        self._container = container or get_container()
        self._default_settings = settings or {}
        self._scanner_cache: Dict[str, Type[Any]] = {}

    def create(
        self,
        scanner_name: str,
        settings: Optional[Dict[str, Any]] = None,
        scope: Optional[ScanScope] = None,
    ) -> Any:
        """Create a scanner instance.

        Args:
            scanner_name: Short name of scanner (e.g., "sqli", "xss")
            settings: Scanner-specific settings
            scope: DI scope for scoped dependencies

        Returns:
            Scanner instance with injected dependencies
        """
        info = self._get_scanner_info(scanner_name)
        scanner_class = self._load_scanner_class(info)

        # Merge settings
        merged_settings = {**self._default_settings, **(settings or {})}

        # Resolve dependencies
        dependencies = self._resolve_dependencies(info, scope)

        # Create scanner instance
        try:
            scanner = scanner_class(merged_settings, **dependencies)
            logger.debug(f"Created {scanner_name} scanner with {len(dependencies)} dependencies")
            return scanner
        except TypeError as e:
            # Fallback for scanners not yet updated for DI
            logger.debug(f"Fallback creation for {scanner_name}: {e}")
            return scanner_class(merged_settings)

    @asynccontextmanager
    async def create_scoped(
        self,
        scanner_name: str,
        settings: Optional[Dict[str, Any]] = None,
    ):
        """Create a scanner with scoped dependencies.

        This creates a new scope for the scanner, ensuring scoped
        dependencies (like HTTP clients) are properly isolated.

        Args:
            scanner_name: Short name of scanner
            settings: Scanner-specific settings

        Yields:
            Scanner instance
        """
        async with self._container.create_scope() as scope:
            scanner = self.create(scanner_name, settings, scope)
            yield scanner

    def create_all(
        self,
        category: Optional[str] = None,
        settings: Optional[Dict[str, Any]] = None,
        scope: Optional[ScanScope] = None,
    ) -> List[Any]:
        """Create all registered scanners.

        Args:
            category: Optional filter by category
            settings: Scanner-specific settings
            scope: DI scope

        Returns:
            List of scanner instances
        """
        scanners = []

        for name, info in SCANNER_REGISTRY.items():
            if category and info.category != category:
                continue

            try:
                scanner = self.create(name, settings, scope)
                scanners.append(scanner)
            except Exception as e:
                logger.warning(f"Failed to create {name} scanner: {e}")

        return scanners

    def _get_scanner_info(self, scanner_name: str) -> ScannerInfo:
        """Get scanner info from registry."""
        if scanner_name not in SCANNER_REGISTRY:
            raise ValueError(
                f"Unknown scanner: {scanner_name}. "
                f"Available: {list(SCANNER_REGISTRY.keys())}"
            )
        return SCANNER_REGISTRY[scanner_name]

    def _load_scanner_class(self, info: ScannerInfo) -> Type[Any]:
        """Load scanner class from module path."""
        cache_key = f"{info.module_path}.{info.class_name}"

        if cache_key in self._scanner_cache:
            return self._scanner_cache[cache_key]

        try:
            module = importlib.import_module(info.module_path)
            scanner_class = getattr(module, info.class_name)
            self._scanner_cache[cache_key] = scanner_class
            return scanner_class
        except (ImportError, AttributeError) as e:
            raise ImportError(
                f"Failed to load {info.class_name} from {info.module_path}: {e}"
            ) from e

    def _resolve_dependencies(
        self,
        info: ScannerInfo,
        scope: Optional[ScanScope],
    ) -> Dict[str, Any]:
        """Resolve dependencies for a scanner."""
        dependencies = {}

        # Map dependency names to protocol types
        from scanning.protocols import (
            RateLimiterProtocol,
            PayloadLibraryProtocol,
            OOBEngineProtocol,
            WAFBypassEngineProtocol,
            FindingsStoreProtocol,
        )

        DEPENDENCY_MAP = {
            "rate_limiter": RateLimiterProtocol,
            "payload_library": PayloadLibraryProtocol,
            "oob_engine": OOBEngineProtocol,
            "waf_bypass": WAFBypassEngineProtocol,
            "findings_store": FindingsStoreProtocol,
        }

        for dep_name in info.dependencies:
            if dep_name == "http_client":
                # HTTP client is handled specially (context manager)
                continue

            if dep_name in DEPENDENCY_MAP:
                protocol = DEPENDENCY_MAP[dep_name]
                if self._container.is_registered(protocol):
                    if scope:
                        dependencies[dep_name] = scope.resolve(protocol)
                    else:
                        # Create temporary scope for resolution
                        temp_scope = self._container.create_scope_sync()
                        dependencies[dep_name] = temp_scope.resolve(protocol)

        return dependencies

    def get_scanner_info(self, scanner_name: str) -> ScannerInfo:
        """Get information about a scanner."""
        return self._get_scanner_info(scanner_name)

    def list_scanners(self, category: Optional[str] = None) -> List[str]:
        """List available scanner names."""
        if category:
            return [
                name for name, info in SCANNER_REGISTRY.items()
                if info.category == category
            ]
        return list(SCANNER_REGISTRY.keys())

    def list_categories(self) -> List[str]:
        """List scanner categories."""
        return list(set(info.category for info in SCANNER_REGISTRY.values()))


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


_global_factory: Optional[ScannerFactory] = None


def get_scanner_factory() -> ScannerFactory:
    """Get the global scanner factory."""
    global _global_factory
    if _global_factory is None:
        _global_factory = ScannerFactory()
    return _global_factory


def create_scanner(
    scanner_name: str,
    settings: Optional[Dict[str, Any]] = None,
) -> Any:
    """Create a scanner using the global factory.

    Convenience function for quick scanner creation.

    Args:
        scanner_name: Short name of scanner
        settings: Scanner-specific settings

    Returns:
        Scanner instance
    """
    return get_scanner_factory().create(scanner_name, settings)


@asynccontextmanager
async def create_scoped_scanner(
    scanner_name: str,
    settings: Optional[Dict[str, Any]] = None,
):
    """Create a scanner with scoped dependencies using the global factory.

    Convenience function for scoped scanner creation.

    Args:
        scanner_name: Short name of scanner
        settings: Scanner-specific settings

    Yields:
        Scanner instance
    """
    async with get_scanner_factory().create_scoped(scanner_name, settings) as scanner:
        yield scanner


__all__ = [
    # Core classes
    "ScannerFactory",
    "ScannerInfo",
    "SCANNER_REGISTRY",
    # Convenience functions
    "get_scanner_factory",
    "create_scanner",
    "create_scoped_scanner",
]
