"""
Module Runner - Single Module Execution Logic.

Handles execution of individual scanner modules:
- Safe mode checks
- Rate limiter creation
- Asset data building
- Module interface dispatch
- Result normalization

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, Union

from scanning.module_executor.interfaces import (
    ModuleInterface,
    get_module_interface,
    is_signature_mismatch,
    OLD_3ARG_MODULES,
    STRING_ENDPOINTS_MODULES,
    TYPED_ENDPOINTS_MODULES,
    TWO_ARG_MODULES,
    PORT_PARAMS_MODULES,
    SIMPLE_INTERFACE_MODULES,
)

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════════════


class SafeScannerProtocol(Protocol):
    """Protocol for safe scanner operations."""

    def is_operation_allowed(self, operation: str) -> bool:
        """Check if operation is allowed in current safe mode."""
        ...


class ModuleProtocol(Protocol):
    """Protocol for scanner module."""

    async def scan(self, *args: Any, **kwargs: Any) -> Any:
        """Run the scan."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class RunnerConfig:
    """Configuration for module runner."""

    # Rate limiter defaults
    default_rate: float = 10.0
    default_burst: int = 20

    # Safe mode
    safe_mode: bool = False

    # Whether to inject specific attributes
    inject_rate_limiter: bool = True
    inject_auth_context: bool = True


@dataclass
class RunContext:
    """Context for a single module run."""

    # Target info
    target: str

    # Module info
    module_name: str
    module_instance: Any

    # Asset data
    asset_data: dict = field(default_factory=dict)

    # Rate limiter
    rate_limiter: Optional[Any] = None

    # Auth context
    auth_context: Optional[Any] = None

    # Results
    result: Optional[dict] = None
    error: Optional[Exception] = None


# ═══════════════════════════════════════════════════════════════════════════════
# Module Runner
# ═══════════════════════════════════════════════════════════════════════════════


class ModuleRunner:
    """
    Runs individual scanner modules.

    Handles the complexity of different module signatures,
    safe mode checks, and result normalization.
    """

    def __init__(
        self,
        config: Optional[RunnerConfig] = None,
        safe_scanner: Optional[SafeScannerProtocol] = None,
        settings: Optional[Any] = None,
    ):
        """
        Initialize module runner.

        Args:
            config: Runner configuration
            safe_scanner: Safe scanner for operation checks
            settings: Scanner settings
        """
        self.config = config or RunnerConfig()
        self.safe_scanner = safe_scanner
        self.settings = settings

    def create_rate_limiter(self) -> Any:
        """
        Create a rate limiter for module execution.

        Returns:
            RateLimiter instance
        """
        from utils.rate_limiter import RateLimiter

        try:
            return RateLimiter(
                settings=self.settings,
                default_rate=getattr(
                    getattr(self.settings, "rate_limit", None),
                    "requests_per_second",
                    self.config.default_rate,
                )
                if self.settings
                else self.config.default_rate,
                default_burst=getattr(
                    getattr(self.settings, "rate_limit", None),
                    "concurrent_scans",
                    self.config.default_burst,
                )
                if self.settings
                else self.config.default_burst,
            )
        except Exception:
            # Fallback simple rate limiter
            return RateLimiter(
                default_rate=self.config.default_rate,
                default_burst=self.config.default_burst,
            )

    def check_safe_mode(self, module_name: str) -> tuple[bool, Optional[dict]]:
        """
        Check if module can run in current safe mode.

        Args:
            module_name: Name of the module

        Returns:
            Tuple of (can_run, skip_result_if_not)
        """
        if not self.safe_scanner:
            return True, None

        if not self.safe_scanner.is_operation_allowed(f"scan_{module_name}"):
            logger.info(f"Module {module_name} skipped due to safe mode restrictions")
            return False, {
                "findings": [],
                "info": [{"module": module_name, "skipped": "safe_mode"}],
            }

        return True, None

    def set_module_safe_mode(self, module: Any) -> None:
        """Set safe mode on module if supported."""
        if hasattr(module, "set_safe_mode"):
            module.set_safe_mode(self.config.safe_mode)

    def inject_module_attributes(
        self,
        module: Any,
        module_name: str,
        rate_limiter: Any,
        auth_context: Optional[Any] = None,
    ) -> None:
        """
        Inject attributes into module instance.

        Args:
            module: Module instance
            module_name: Module name
            rate_limiter: Rate limiter to inject
            auth_context: Auth context to inject
        """
        # Set rate_limiter attribute on module if it uses one
        if self.config.inject_rate_limiter:
            if hasattr(module, "rate_limiter") or module_name in {
                "jwt",
                "race",
                "host_header",
                "clickjacking",
                "file_upload",
            }:
                try:
                    module.rate_limiter = rate_limiter
                except AttributeError:
                    pass  # Read-only or no such attribute

        # Inject auth context for race condition scanner
        if self.config.inject_auth_context and auth_context:
            if module_name == "race":
                try:
                    module._auth_context = auth_context
                except AttributeError:
                    pass

    async def execute_module(
        self,
        module: Any,
        module_name: str,
        target: str,
        asset_data: dict,
        rate_limiter: Any,
    ) -> dict:
        """
        Execute a module with the appropriate signature.

        Args:
            module: Module instance
            module_name: Module name
            target: Target URL
            asset_data: Asset data dictionary
            rate_limiter: Rate limiter instance

        Returns:
            Module result dictionary
        """
        if not hasattr(module, "scan"):
            if hasattr(module, "run"):
                return await module.run(target)
            logger.warning(f"Module {module_name} has no scan/run method")
            return {"findings": [], "info": []}

        # Extract endpoints list for modules that expect List[str]
        endpoints_list = asset_data.get("endpoints", [target])

        interface = get_module_interface(module_name)

        # OLD_3ARG_MODULES MUST be called with all 3 args - no fallback
        if interface == ModuleInterface.OLD_3ARG:
            return await module.scan(target, asset_data, rate_limiter)

        # Try different signatures with fallbacks for other modules
        try:
            if interface == ModuleInterface.STRING_ENDPOINTS:
                return await module.scan(target, endpoints=endpoints_list)
            elif interface == ModuleInterface.TYPED_ENDPOINTS:
                return await module.scan(target)
            elif interface == ModuleInterface.SIMPLE:
                return await module.scan(target)
            elif interface == ModuleInterface.PORT_PARAMS:
                extra_params = {
                    "auth_context": asset_data.get("auth_context"),
                    "rate_limiter": rate_limiter,
                    "endpoints": asset_data.get("endpoints", []),
                    "verify_ssl": asset_data.get("verify_ssl", False),
                }
                return await module.scan(target, port=None, extra_params=extra_params)
            elif interface == ModuleInterface.TWO_ARG:
                return await module.scan(target, asset_data)
            elif rate_limiter:
                # Default: try with rate_limiter
                return await module.scan(target, asset_data, rate_limiter)
            else:
                return await module.scan(target, asset_data)

        except TypeError as e:
            # Only catch signature mismatches, re-raise other TypeErrors
            if not is_signature_mismatch(e):
                raise

            # Try without rate_limiter (old interface fallback)
            try:
                return await module.scan(target, asset_data)
            except TypeError as e2:
                if not is_signature_mismatch(e2):
                    raise
                # Try new interface with endpoints
                try:
                    return await module.scan(target, endpoints=endpoints_list)
                except TypeError as e3:
                    if not is_signature_mismatch(e3):
                        raise
                    # Final fallback: just target
                    return await module.scan(target)

    def normalize_result(
        self, result: Any, module_name: str, safe_mode: bool = False
    ) -> dict:
        """
        Normalize module result to standard format.

        Args:
            result: Raw module result
            module_name: Module name for metadata
            safe_mode: Whether safe mode is enabled

        Returns:
            Normalized result dictionary
        """
        findings = []

        if isinstance(result, dict):
            findings = result.get(
                "findings", result.get("vulns", result.get("vulnerabilities", []))
            )
        elif isinstance(result, list):
            findings = result

        # Add module info to findings
        for f in findings:
            if isinstance(f, dict):
                f["module"] = module_name
                f["safe_mode"] = safe_mode

        return {
            "findings": findings,
            "info": result.get("info", []) if isinstance(result, dict) else [],
        }

    async def run(
        self,
        module: Any,
        module_name: str,
        target: str,
        asset_data: dict,
        rate_limiter: Optional[Any] = None,
        auth_context: Optional[Any] = None,
    ) -> dict:
        """
        Run a single module with full setup.

        Args:
            module: Module instance
            module_name: Module name
            target: Target URL
            asset_data: Asset data dictionary
            rate_limiter: Optional rate limiter (created if not provided)
            auth_context: Optional auth context

        Returns:
            Module result dictionary
        """
        if not module:
            return {"findings": [], "info": []}

        # Check safe mode
        can_run, skip_result = self.check_safe_mode(module_name)
        if not can_run:
            return skip_result

        # Set safe mode on module
        self.set_module_safe_mode(module)

        # Create rate limiter if needed
        if rate_limiter is None:
            rate_limiter = self.create_rate_limiter()

        # Inject attributes
        self.inject_module_attributes(
            module, module_name, rate_limiter, auth_context
        )

        # Execute module
        raw_result = await self.execute_module(
            module, module_name, target, asset_data, rate_limiter
        )

        # Normalize result
        return self.normalize_result(raw_result, module_name, self.config.safe_mode)


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════


async def run_module(
    module: Any,
    module_name: str,
    target: str,
    asset_data: dict,
    rate_limiter: Optional[Any] = None,
    safe_mode: bool = False,
) -> dict:
    """
    Run a single module with minimal setup.

    Args:
        module: Module instance
        module_name: Module name
        target: Target URL
        asset_data: Asset data dictionary
        rate_limiter: Optional rate limiter
        safe_mode: Whether safe mode is enabled

    Returns:
        Module result dictionary
    """
    config = RunnerConfig(safe_mode=safe_mode)
    runner = ModuleRunner(config=config)
    return await runner.run(
        module=module,
        module_name=module_name,
        target=target,
        asset_data=asset_data,
        rate_limiter=rate_limiter,
    )
