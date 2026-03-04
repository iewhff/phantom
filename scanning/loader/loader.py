"""
Module Loader - Dynamic Scanner Module Loading.

Handles dynamic loading of scanner modules with:
- ModuleRegistry as primary source
- ALL_MODULES fallback for backwards compatibility
- Safety level enforcement
- Instance caching
- Cleanup management
- **Phase 8: Dependency Injection support** (2026-02-26)

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Type, TYPE_CHECKING

from scanning.config import (
    ALL_MODULES,
    SHORT_TO_REGISTRY_NAME,
    SAFETY_HIERARCHY,
    MODULE_SAFETY_LEVELS,
    get_module_safety_level,
    is_safe_for_mode,
)
from scanning.module_registry import get_module_registry, ModuleInfo

if TYPE_CHECKING:
    from core.config_manager import Settings
    from scanning.container import ScanContainer, ScanScope
    from scanning.protocols import (
        RateLimiterProtocol,
        OOBEngineProtocol,
        WAFBypassEngineProtocol,
        PayloadLibraryProtocol,
        FindingsStoreProtocol,
    )

logger = logging.getLogger("phantom")


# =============================================================================
# DEPENDENCY INJECTION SUPPORT (Phase 8)
# =============================================================================

# Map of parameter names to protocol types for DI resolution
DI_PARAMETER_MAP: dict[str, str] = {
    "rate_limiter": "RateLimiterProtocol",
    "oob_engine": "OOBEngineProtocol",
    "waf_bypass_engine": "WAFBypassEngineProtocol",
    "payload_library": "PayloadLibraryProtocol",
    "findings_store": "FindingsStoreProtocol",
}


def get_di_parameters(cls: Type[Any]) -> set[str]:
    """
    Inspect a class's __init__ to find DI-compatible parameters.

    Returns parameter names that match known DI dependencies.
    This allows scanners to opt-in to DI by adding parameters
    without requiring base class changes.

    Args:
        cls: The scanner class to inspect

    Returns:
        Set of parameter names that can be injected
    """
    try:
        sig = inspect.signature(cls.__init__)
        di_params = set()
        for param_name in sig.parameters:
            if param_name in DI_PARAMETER_MAP:
                di_params.add(param_name)
        return di_params
    except (ValueError, TypeError):
        return set()


class LoadStatus(Enum):
    """Status of a module load attempt."""
    SUCCESS = "success"
    CACHED = "cached"
    SAFETY_BLOCKED = "safety_blocked"
    NOT_FOUND = "not_found"
    IMPORT_ERROR = "import_error"
    INSTANTIATION_ERROR = "instantiation_error"


@dataclass
class ModuleLoadResult:
    """Result of a module load attempt.

    Attributes:
        status: The load status
        module: The loaded module instance (if successful)
        name: The module name that was requested
        error: Error message (if failed)
        source: Where the module was loaded from (registry/all_modules/cache)
    """
    status: LoadStatus
    module: Optional[Any] = None
    name: str = ""
    error: Optional[str] = None
    source: str = ""

    @property
    def success(self) -> bool:
        """Check if the load was successful."""
        return self.status in (LoadStatus.SUCCESS, LoadStatus.CACHED)


class ModuleLoader:
    """Dynamic scanner module loader with safety enforcement.

    Loads scanner modules dynamically using ModuleRegistry as the primary
    source, with fallback to ALL_MODULES for backwards compatibility.
    Enforces safety level requirements and caches loaded instances.

    Phase 8 (2026-02-26): Supports optional dependency injection.
    When a DI container and scope are provided, the loader will:
    1. Inspect each scanner's __init__ for DI-compatible parameters
    2. Resolve those dependencies from the container
    3. Pass them to the scanner during instantiation

    This maintains full backward compatibility - scanners without DI
    parameters work exactly as before.
    """

    def __init__(
        self,
        settings: "Settings",
        safe_mode: str = "safe",
        container: Optional["ScanContainer"] = None,
        scope: Optional["ScanScope"] = None,
    ):
        """Initialize the module loader.

        Args:
            settings: Application settings for module instantiation
            safe_mode: Current safety mode for level checking
            container: Optional DI container for dependency resolution (Phase 8)
            scope: Optional DI scope for scoped dependencies (Phase 8)
        """
        self.settings = settings
        self.safe_mode = safe_mode
        self._loaded_modules: dict[str, Any] = {}
        self._load_history: list[ModuleLoadResult] = []

        # Phase 8: DI support
        self._container = container
        self._scope = scope
        self._di_stats: dict[str, int] = {"injected": 0, "legacy": 0}

    @property
    def loaded_modules(self) -> dict[str, Any]:
        """Get the dictionary of loaded module instances."""
        return self._loaded_modules

    @property
    def load_count(self) -> int:
        """Get the number of loaded modules."""
        return len(self._loaded_modules)

    def is_loaded(self, name: str) -> bool:
        """Check if a module is already loaded.

        Args:
            name: Module name to check

        Returns:
            True if module is loaded
        """
        return name in self._loaded_modules

    def get_cached(self, name: str) -> Optional[Any]:
        """Get a cached module instance.

        Args:
            name: Module name

        Returns:
            Cached module instance or None
        """
        return self._loaded_modules.get(name)

    @property
    def di_stats(self) -> dict[str, int]:
        """Get DI injection statistics.

        Returns:
            Dictionary with 'injected' and 'legacy' counts
        """
        return self._di_stats.copy()

    def set_di_scope(self, scope: "ScanScope") -> None:
        """Set or update the DI scope for dependency resolution.

        Args:
            scope: DI scope for scoped dependencies
        """
        self._scope = scope

    def _resolve_di_dependencies(
        self,
        cls: Type[Any],
        module_name: str,
    ) -> dict[str, Any]:
        """
        Resolve DI dependencies for a scanner class.

        Inspects the class's __init__ to find DI-compatible parameters
        and resolves them from the container.

        Args:
            cls: Scanner class to inspect
            module_name: Module name for logging

        Returns:
            Dictionary of parameter name -> resolved instance
        """
        if not self._container:
            return {}

        di_params = get_di_parameters(cls)
        if not di_params:
            return {}

        resolved: dict[str, Any] = {}

        for param_name in di_params:
            protocol_name = DI_PARAMETER_MAP.get(param_name)
            if not protocol_name:
                continue

            try:
                # Import protocol dynamically
                from scanning import protocols
                protocol_type = getattr(protocols, protocol_name, None)
                if not protocol_type:
                    continue

                # Check if registered
                if not self._container.is_registered(protocol_type):
                    logger.debug(
                        f"[DI] {module_name}: {param_name} not registered, skipping"
                    )
                    continue

                # Resolve from scope (scoped deps) or container (singletons)
                if self._scope:
                    instance = self._scope.resolve(protocol_type)
                else:
                    # Create temp scope for resolution
                    temp_scope = self._container.create_scope_sync()
                    instance = temp_scope.resolve(protocol_type)

                resolved[param_name] = instance
                logger.debug(
                    f"[DI] {module_name}: Resolved {param_name} = {type(instance).__name__}"
                )

            except Exception as e:
                logger.debug(
                    f"[DI] {module_name}: Failed to resolve {param_name}: {e}"
                )

        return resolved

    def _instantiate_with_di(
        self,
        cls: Type[Any],
        module_name: str,
    ) -> Any:
        """
        Instantiate a scanner class with DI dependencies.

        Falls back to legacy instantiation (settings only) if DI resolution fails.

        Args:
            cls: Scanner class to instantiate
            module_name: Module name for logging

        Returns:
            Scanner instance
        """
        # Try to resolve DI dependencies
        di_kwargs = self._resolve_di_dependencies(cls, module_name)

        if di_kwargs:
            # Try DI-aware instantiation
            try:
                instance = cls(self.settings, **di_kwargs)
                self._di_stats["injected"] += 1
                logger.debug(
                    f"[DI] {module_name}: Instantiated with {len(di_kwargs)} dependencies"
                )
                return instance
            except TypeError as e:
                # Signature mismatch - fall back to legacy
                logger.debug(
                    f"[DI] {module_name}: DI instantiation failed ({e}), using legacy"
                )

        # Legacy instantiation (backward compatible)
        self._di_stats["legacy"] += 1
        return cls(self.settings)

    def _check_safety(self, name: str, module_info: Optional[ModuleInfo] = None) -> tuple[bool, str]:
        """Check if a module can be loaded under current safety mode.

        Args:
            name: Module name
            module_info: Optional ModuleInfo from registry

        Returns:
            Tuple of (allowed, reason)
        """
        # Get required safety level
        required_level = MODULE_SAFETY_LEVELS.get(name, "passive")

        # Calculate indices
        try:
            current_idx = SAFETY_HIERARCHY.index(self.safe_mode)
        except ValueError:
            current_idx = 1  # Default to "safe"

        try:
            required_idx = SAFETY_HIERARCHY.index(required_level)
        except ValueError:
            required_idx = 0  # Default to "passive"

        # Check destructive flag from registry
        if module_info and module_info.is_destructive:
            standard_idx = SAFETY_HIERARCHY.index("standard")
            if current_idx < standard_idx:
                return False, (
                    f"Module '{name}' is destructive and requires 'standard' mode, "
                    f"current mode is '{self.safe_mode}'"
                )

        # Check required level
        if current_idx < required_idx:
            return False, (
                f"Module '{name}' requires '{required_level}' mode, "
                f"current mode is '{self.safe_mode}'"
            )

        return True, "OK"

    def load(self, name: str) -> ModuleLoadResult:
        """Load a scanner module by name.

        Uses ModuleRegistry as the primary source of module metadata,
        with fallback to ALL_MODULES for backwards compatibility.

        Args:
            name: Short module name (e.g., "sqli") or registry name (e.g., "sqli_scanner")

        Returns:
            ModuleLoadResult with status and module instance
        """
        # Check cache first
        if name in self._loaded_modules:
            result = ModuleLoadResult(
                status=LoadStatus.CACHED,
                module=self._loaded_modules[name],
                name=name,
                source="cache",
            )
            self._load_history.append(result)
            return result

        # Try to resolve module info from registry
        registry = get_module_registry()
        module_info: Optional[ModuleInfo] = None

        # Check if this is a short name that maps to registry
        registry_name = SHORT_TO_REGISTRY_NAME.get(name)
        if registry_name:
            module_info = registry.get(registry_name)
        else:
            # Maybe it's already a registry name
            module_info = registry.get(name)

        # If found in registry, use registry metadata
        if module_info:
            return self._load_from_registry(name, module_info)

        # Fallback to ALL_MODULES
        return self._load_from_all_modules(name)

    def _load_from_registry(self, name: str, module_info: ModuleInfo) -> ModuleLoadResult:
        """Load a module using registry metadata.

        Args:
            name: Module name
            module_info: Module metadata from registry

        Returns:
            ModuleLoadResult
        """
        # Safety check
        allowed, reason = self._check_safety(name, module_info)
        if not allowed:
            logger.warning(f"SAFETY BLOCK (load): {reason}")
            result = ModuleLoadResult(
                status=LoadStatus.SAFETY_BLOCKED,
                name=name,
                error=reason,
                source="registry",
            )
            self._load_history.append(result)
            return result

        try:
            mod = importlib.import_module(module_info.module_path)
            cls = getattr(mod, module_info.class_name)

            # Phase 8: Use DI-aware instantiation
            instance = self._instantiate_with_di(cls, name)
            self._loaded_modules[name] = instance

            logger.debug(f"Loaded module from registry: {name} ({module_info.name})")

            result = ModuleLoadResult(
                status=LoadStatus.SUCCESS,
                module=instance,
                name=name,
                source="registry",
            )
            self._load_history.append(result)
            return result

        except ImportError as e:
            logger.exception(f"Failed to import module {name} from registry: {e}")
            result = ModuleLoadResult(
                status=LoadStatus.IMPORT_ERROR,
                name=name,
                error=str(e),
                source="registry",
            )
            self._load_history.append(result)
            return result

        except Exception as e:
            logger.exception(f"Failed to instantiate module {name} from registry: {e}")
            result = ModuleLoadResult(
                status=LoadStatus.INSTANTIATION_ERROR,
                name=name,
                error=str(e),
                source="registry",
            )
            self._load_history.append(result)
            return result

    def _load_from_all_modules(self, name: str) -> ModuleLoadResult:
        """Load a module using ALL_MODULES fallback.

        Args:
            name: Module name

        Returns:
            ModuleLoadResult
        """
        if name not in ALL_MODULES:
            logger.warning(f"Unknown module: {name}")
            result = ModuleLoadResult(
                status=LoadStatus.NOT_FOUND,
                name=name,
                error=f"Unknown module: {name}",
                source="all_modules",
            )
            self._load_history.append(result)
            return result

        # Safety check
        allowed, reason = self._check_safety(name)
        if not allowed:
            logger.warning(f"SAFETY BLOCK (load): {reason}")
            result = ModuleLoadResult(
                status=LoadStatus.SAFETY_BLOCKED,
                name=name,
                error=reason,
                source="all_modules",
            )
            self._load_history.append(result)
            return result

        module_path = ALL_MODULES[name]

        try:
            parts = module_path.rsplit(".", 1)
            if len(parts) != 2:
                error = f"Invalid module path format '{module_path}' for module '{name}'"
                logger.warning(error)
                result = ModuleLoadResult(
                    status=LoadStatus.IMPORT_ERROR,
                    name=name,
                    error=error,
                    source="all_modules",
                )
                self._load_history.append(result)
                return result

            module_name, class_name = parts

            mod = importlib.import_module(module_name)
            cls = getattr(mod, class_name)

            # Phase 8: Use DI-aware instantiation
            instance = self._instantiate_with_di(cls, name)
            self._loaded_modules[name] = instance

            logger.debug(f"Loaded module from ALL_MODULES: {name}")

            result = ModuleLoadResult(
                status=LoadStatus.SUCCESS,
                module=instance,
                name=name,
                source="all_modules",
            )
            self._load_history.append(result)
            return result

        except ImportError as e:
            logger.exception(f"Failed to import module {name}: {e}")
            result = ModuleLoadResult(
                status=LoadStatus.IMPORT_ERROR,
                name=name,
                error=str(e),
                source="all_modules",
            )
            self._load_history.append(result)
            return result

        except Exception as e:
            logger.exception(f"Failed to instantiate module {name}: {e}")
            result = ModuleLoadResult(
                status=LoadStatus.INSTANTIATION_ERROR,
                name=name,
                error=str(e),
                source="all_modules",
            )
            self._load_history.append(result)
            return result

    def load_multiple(self, names: list[str]) -> dict[str, ModuleLoadResult]:
        """Load multiple modules.

        Args:
            names: List of module names to load

        Returns:
            Dictionary mapping names to load results
        """
        results = {}
        for name in names:
            results[name] = self.load(name)
        return results

    def get_load_stats(self) -> dict[str, int]:
        """Get statistics about load attempts.

        Returns:
            Dictionary with counts by status
        """
        stats: dict[str, int] = {status.value: 0 for status in LoadStatus}
        for result in self._load_history:
            stats[result.status.value] += 1
        return stats

    async def cleanup(self) -> int:
        """Clean up loaded module instances.

        Calls cleanup() on modules that support it and clears the cache.

        Returns:
            Number of modules cleaned up
        """
        count = 0
        for name, module in self._loaded_modules.items():
            try:
                if hasattr(module, 'cleanup') and callable(module.cleanup):
                    if asyncio.iscoroutinefunction(module.cleanup):
                        await module.cleanup()
                    else:
                        module.cleanup()
                count += 1
            except Exception as e:
                logger.debug(f"[Cleanup] Module {name} cleanup error: {e}")

        module_count = len(self._loaded_modules)
        self._loaded_modules.clear()
        self._load_history.clear()

        logger.debug(f"[Cleanup] Cleared {module_count} module instances")
        return module_count

    def clear_cache(self) -> int:
        """Clear the module cache without calling cleanup methods.

        Returns:
            Number of modules cleared
        """
        count = len(self._loaded_modules)
        self._loaded_modules.clear()
        return count

    def update_safe_mode(self, new_mode: str) -> None:
        """Update the safety mode for future loads.

        Note: This does not affect already-loaded modules.

        Args:
            new_mode: New safety mode
        """
        self.safe_mode = new_mode
