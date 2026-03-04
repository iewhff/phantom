"""
Scanning Container - Dependency Injection Container for Scanner Modules.

This module provides a lightweight DI container that manages dependencies
for scanner modules. It supports:
1. Singleton registrations (shared instances)
2. Transient registrations (new instance per resolve)
3. Scoped registrations (new instance per scan)
4. Factory-based resolution
5. Type-safe dependency injection

Part of Phase 8: Dependency Inversion (2026-02-26)

Usage:
    from scanning.container import ScanContainer, Lifetime

    # Create container
    container = ScanContainer()

    # Register dependencies
    container.register(HttpClientProtocol, create_http_client, Lifetime.SCOPED)
    container.register(RateLimiterProtocol, create_rate_limiter, Lifetime.SINGLETON)

    # Create scope for a scan
    async with container.create_scope() as scope:
        client = scope.resolve(HttpClientProtocol)
        limiter = scope.resolve(RateLimiterProtocol)
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generic,
    Optional,
    Type,
    TypeVar,
    Union,
    overload,
)

from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.protocols import (
        HttpClientProtocol,
        RateLimiterProtocol,
        PayloadLibraryProtocol,
        OOBEngineProtocol,
        WAFBypassEngineProtocol,
        LoggerProtocol,
        FindingsStoreProtocol,
    )

logger = get_logger(__name__)

T = TypeVar("T")


# =============================================================================
# LIFETIME ENUM
# =============================================================================


class Lifetime(Enum):
    """Dependency lifetime options."""

    SINGLETON = auto()
    """Single instance for entire application lifetime."""

    TRANSIENT = auto()
    """New instance every time resolved."""

    SCOPED = auto()
    """Single instance per scope (e.g., per scan)."""


# =============================================================================
# REGISTRATION DATACLASS
# =============================================================================


@dataclass
class Registration:
    """A dependency registration."""

    interface: Type[Any]
    factory: Callable[..., Any]
    lifetime: Lifetime
    instance: Optional[Any] = None

    def is_singleton_resolved(self) -> bool:
        """Check if singleton has been resolved."""
        return self.lifetime == Lifetime.SINGLETON and self.instance is not None


# =============================================================================
# SCAN SCOPE
# =============================================================================


class ScanScope:
    """A scope for scan-specific dependencies.

    Scoped dependencies are shared within a scope but not across scopes.
    This is useful for per-scan state like HTTP clients and rate limiters.
    """

    def __init__(self, container: "ScanContainer") -> None:
        self._container = container
        self._scoped_instances: Dict[Type[Any], Any] = {}
        self._disposed = False

    def resolve(self, interface: Type[T]) -> T:
        """Resolve a dependency within this scope."""
        if self._disposed:
            raise RuntimeError("Cannot resolve from disposed scope")

        registration = self._container._get_registration(interface)

        if registration.lifetime == Lifetime.SINGLETON:
            return self._container._resolve_singleton(registration)
        elif registration.lifetime == Lifetime.SCOPED:
            return self._resolve_scoped(registration)
        else:
            return self._container._resolve_transient(registration)

    def _resolve_scoped(self, registration: Registration) -> Any:
        """Resolve a scoped dependency."""
        if registration.interface in self._scoped_instances:
            return self._scoped_instances[registration.interface]

        instance = registration.factory(self)
        self._scoped_instances[registration.interface] = instance
        return instance

    async def dispose(self) -> None:
        """Dispose all scoped instances."""
        self._disposed = True

        for instance in self._scoped_instances.values():
            if hasattr(instance, "aclose"):
                try:
                    await instance.aclose()
                except Exception as e:
                    logger.warning(f"Error closing scoped instance: {e}")
            elif hasattr(instance, "close"):
                try:
                    instance.close()
                except Exception as e:
                    logger.warning(f"Error closing scoped instance: {e}")

        self._scoped_instances.clear()


# =============================================================================
# MAIN CONTAINER
# =============================================================================


class ScanContainer:
    """Dependency injection container for scanner modules.

    Manages dependency registration and resolution with support for
    different lifetimes (singleton, transient, scoped).

    Example:
        container = ScanContainer()

        # Register with factory
        container.register(
            HttpClientProtocol,
            lambda scope: create_http_client(scope.resolve(RateLimiterProtocol)),
            Lifetime.SCOPED,
        )

        # Use in scan
        async with container.create_scope() as scope:
            client = scope.resolve(HttpClientProtocol)
    """

    def __init__(self) -> None:
        self._registrations: Dict[Type[Any], Registration] = {}
        self._singleton_lock = asyncio.Lock()

    def register(
        self,
        interface: Type[T],
        factory: Callable[[ScanScope], T],
        lifetime: Lifetime = Lifetime.TRANSIENT,
    ) -> None:
        """Register a dependency.

        Args:
            interface: The Protocol or ABC to register
            factory: Factory function that takes a ScanScope and returns instance
            lifetime: Lifetime of the dependency

        Example:
            container.register(
                RateLimiterProtocol,
                lambda scope: RateLimiter(default_rate=10.0),
                Lifetime.SINGLETON,
            )
        """
        self._registrations[interface] = Registration(
            interface=interface,
            factory=factory,
            lifetime=lifetime,
        )
        logger.debug(f"Registered {interface.__name__} with {lifetime.name} lifetime")

    def register_instance(self, interface: Type[T], instance: T) -> None:
        """Register an existing instance as a singleton.

        Args:
            interface: The Protocol or ABC to register
            instance: The instance to use

        Example:
            rate_limiter = RateLimiter(default_rate=10.0)
            container.register_instance(RateLimiterProtocol, rate_limiter)
        """
        self._registrations[interface] = Registration(
            interface=interface,
            factory=lambda _: instance,
            lifetime=Lifetime.SINGLETON,
            instance=instance,
        )
        logger.debug(f"Registered {interface.__name__} instance as singleton")

    def is_registered(self, interface: Type[Any]) -> bool:
        """Check if an interface is registered."""
        return interface in self._registrations

    def _get_registration(self, interface: Type[Any]) -> Registration:
        """Get registration for an interface."""
        if interface not in self._registrations:
            raise KeyError(
                f"No registration found for {interface.__name__}. "
                f"Did you forget to call container.register()?"
            )
        return self._registrations[interface]

    def _resolve_singleton(self, registration: Registration) -> Any:
        """Resolve a singleton dependency."""
        if registration.instance is not None:
            return registration.instance

        # Create instance (thread-safe for sync context)
        instance = registration.factory(None)  # Singletons don't use scope
        registration.instance = instance
        return instance

    def _resolve_transient(self, registration: Registration) -> Any:
        """Resolve a transient dependency."""
        return registration.factory(None)

    @asynccontextmanager
    async def create_scope(self):
        """Create a new scope for scan-specific dependencies.

        Example:
            async with container.create_scope() as scope:
                client = scope.resolve(HttpClientProtocol)
                # client is scoped to this scan
        """
        scope = ScanScope(self)
        try:
            yield scope
        finally:
            await scope.dispose()

    def create_scope_sync(self) -> ScanScope:
        """Create a scope without async context manager.

        WARNING: You must call scope.dispose() manually!

        Example:
            scope = container.create_scope_sync()
            try:
                client = scope.resolve(HttpClientProtocol)
            finally:
                await scope.dispose()
        """
        return ScanScope(self)


# =============================================================================
# DEFAULT CONTAINER CONFIGURATION
# =============================================================================


def create_default_container() -> ScanContainer:
    """Create a container with default registrations.

    This sets up the standard dependencies used by scanner modules.
    Import actual implementations here to avoid circular imports.
    """
    container = ScanContainer()

    # HTTP Client (scoped - one per scan)
    def create_http_client(scope: ScanScope):
        from utils.scan_client import get_scan_client
        return get_scan_client()

    # Rate Limiter (singleton - shared across scans)
    def create_rate_limiter(scope: ScanScope):
        from utils.rate_limiter import RateLimiter
        return RateLimiter(default_rate=10.0, default_burst=20)

    # Payload Library (singleton - immutable)
    def create_payload_library(scope: ScanScope):
        from utils.payload_library import PayloadLibrary
        return PayloadLibrary.get_instance()

    # OOB Engine (singleton - manages global state)
    def create_oob_engine(scope: ScanScope):
        from utils.oob_engine import OOBEngine
        return OOBEngine.get_instance()

    # WAF Bypass Engine (singleton - caches detection results)
    def create_waf_bypass_engine(scope: ScanScope):
        from phantom.waf_bypass_engine import get_waf_bypass_engine
        return get_waf_bypass_engine()

    # Shared Findings Store (scoped - per scan)
    def create_findings_store(scope: ScanScope):
        from utils.shared_findings_store import SharedFindingsStore
        return SharedFindingsStore()

    # Register with appropriate lifetimes
    # Note: We import protocols here to avoid module-level circular imports
    from scanning.protocols import (
        RateLimiterProtocol,
        PayloadLibraryProtocol,
        OOBEngineProtocol,
        WAFBypassEngineProtocol,
        FindingsStoreProtocol,
    )

    container.register(RateLimiterProtocol, create_rate_limiter, Lifetime.SINGLETON)
    container.register(PayloadLibraryProtocol, create_payload_library, Lifetime.SINGLETON)
    container.register(OOBEngineProtocol, create_oob_engine, Lifetime.SINGLETON)
    container.register(WAFBypassEngineProtocol, create_waf_bypass_engine, Lifetime.SINGLETON)
    container.register(FindingsStoreProtocol, create_findings_store, Lifetime.SCOPED)

    logger.info("Default container configured with 5 dependencies")
    return container


# =============================================================================
# GLOBAL CONTAINER INSTANCE
# =============================================================================

_global_container: Optional[ScanContainer] = None


def get_container() -> ScanContainer:
    """Get the global container instance.

    Creates a default container if none exists.
    """
    global _global_container
    if _global_container is None:
        _global_container = create_default_container()
    return _global_container


def set_container(container: ScanContainer) -> None:
    """Set the global container instance.

    Use this for testing or custom configurations.
    """
    global _global_container
    _global_container = container


def reset_container() -> None:
    """Reset the global container.

    Use this to force re-creation of default container.
    """
    global _global_container
    _global_container = None


__all__ = [
    # Core classes
    "ScanContainer",
    "ScanScope",
    "Registration",
    "Lifetime",
    # Factory function
    "create_default_container",
    # Global container management
    "get_container",
    "set_container",
    "reset_container",
]
