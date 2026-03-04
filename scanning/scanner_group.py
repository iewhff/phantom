"""
Scanner Group Abstraction.

Provides a way to group related scanners and execute them together with:
- Shared state management
- Group-level timeout and error handling
- Parallel or sequential execution
- Finding aggregation
- Progress tracking

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional, Type

from scanning.module_registry import ModuleCategory, ModuleInfo, ModulePriority, get_module_registry
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class GroupExecutionMode(Enum):
    """How to execute scanners in a group."""
    PARALLEL = auto()      # Run all scanners concurrently
    SEQUENTIAL = auto()    # Run scanners one by one
    PRIORITY = auto()      # Run by priority (CRITICAL first)


class GroupStatus(Enum):
    """Status of a scanner group execution."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    PARTIAL = auto()  # Some scanners completed, some failed


# =============================================================================
# RESULTS
# =============================================================================

@dataclass
class ScannerResult:
    """Result from a single scanner execution."""
    scanner_name: str
    success: bool
    duration_seconds: float = 0.0
    findings: list[dict] = field(default_factory=list)
    error_message: str = ""
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class GroupResult:
    """Result from a scanner group execution."""
    group_name: str
    status: GroupStatus
    duration_seconds: float = 0.0
    scanners_completed: int = 0
    scanners_failed: int = 0
    scanners_skipped: int = 0
    total_findings: int = 0
    scanner_results: list[ScannerResult] = field(default_factory=list)
    error_message: str = ""

    @property
    def success(self) -> bool:
        """Check if group completed successfully."""
        return self.status == GroupStatus.COMPLETED and self.scanners_failed == 0

    @property
    def findings(self) -> list[dict]:
        """Get all findings from all scanners."""
        all_findings = []
        for sr in self.scanner_results:
            all_findings.extend(sr.findings)
        return all_findings

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "group_name": self.group_name,
            "status": self.status.name,
            "duration_seconds": self.duration_seconds,
            "scanners_completed": self.scanners_completed,
            "scanners_failed": self.scanners_failed,
            "scanners_skipped": self.scanners_skipped,
            "total_findings": self.total_findings,
            "error_message": self.error_message,
        }


# =============================================================================
# SCANNER GROUP BASE CLASS
# =============================================================================

class ScannerGroup(ABC):
    """
    Abstract base class for scanner groups.

    A scanner group manages a collection of related scanners and executes them
    together with shared state and configuration.

    Usage:
        group = InjectionScannerGroup()
        result = await group.execute(target, context)
    """

    def __init__(
        self,
        name: str = "",
        execution_mode: GroupExecutionMode = GroupExecutionMode.PARALLEL,
        max_concurrent: int = 5,
        timeout_seconds: float = 600.0,
        stop_on_first_finding: bool = False,
    ):
        self.name = name or self.__class__.__name__
        self.execution_mode = execution_mode
        self.max_concurrent = max_concurrent
        self.timeout_seconds = timeout_seconds
        self.stop_on_first_finding = stop_on_first_finding

        self._scanners: list[ScanModule] = []
        self._scanner_infos: list[ModuleInfo] = []
        self._status = GroupStatus.PENDING
        self._start_time: float = 0.0
        self._should_stop = False

    @abstractmethod
    def get_scanner_names(self) -> list[str]:
        """Get list of scanner names in this group."""
        pass

    def _load_scanners(self) -> None:
        """Load scanner modules."""
        registry = get_module_registry()

        for name in self.get_scanner_names():
            try:
                # Get module info from registry
                info = None
                for m in registry.get_all():
                    if m.name == name or m.name == f"{name}_scanner":
                        info = m
                        break

                if not info:
                    logger.warning(f"[{self.name}] Scanner '{name}' not found in registry")
                    continue

                # Import and instantiate scanner
                module = __import__(info.module_path, fromlist=[info.class_name])
                scanner_class = getattr(module, info.class_name)
                scanner = scanner_class()

                self._scanners.append(scanner)
                self._scanner_infos.append(info)

                logger.debug(f"[{self.name}] Loaded scanner: {info.name}")

            except Exception as e:
                logger.error(f"[{self.name}] Failed to load scanner '{name}': {e}")

    async def execute(
        self,
        target: str,
        context: Optional[dict[str, Any]] = None,
        rate_limiter: Optional[Any] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> GroupResult:
        """
        Execute all scanners in the group.

        Args:
            target: Target URL/host
            context: Shared context (auth headers, tech stack, etc.)
            rate_limiter: Rate limiter instance
            on_finding: Callback for each finding

        Returns:
            GroupResult with all scanner results
        """
        self._start_time = time.time()
        self._status = GroupStatus.RUNNING
        self._should_stop = False

        # Load scanners if not already loaded
        if not self._scanners:
            self._load_scanners()

        logger.info(f"[{self.name}] Starting execution with {len(self._scanners)} scanners")

        result = GroupResult(
            group_name=self.name,
            status=GroupStatus.RUNNING,
        )

        try:
            if self.execution_mode == GroupExecutionMode.PARALLEL:
                await self._execute_parallel(target, context, rate_limiter, result, on_finding)
            elif self.execution_mode == GroupExecutionMode.SEQUENTIAL:
                await self._execute_sequential(target, context, rate_limiter, result, on_finding)
            elif self.execution_mode == GroupExecutionMode.PRIORITY:
                await self._execute_by_priority(target, context, rate_limiter, result, on_finding)

            # Determine final status
            if result.scanners_failed == 0:
                result.status = GroupStatus.COMPLETED
            elif result.scanners_completed > 0:
                result.status = GroupStatus.PARTIAL
            else:
                result.status = GroupStatus.FAILED

        except asyncio.CancelledError:
            result.status = GroupStatus.CANCELLED
            result.error_message = "Group execution cancelled"
        except Exception as e:
            result.status = GroupStatus.FAILED
            result.error_message = str(e)
            logger.error(f"[{self.name}] Group execution failed: {e}")

        result.duration_seconds = time.time() - self._start_time
        result.total_findings = len(result.findings)

        self._status = result.status
        logger.info(
            f"[{self.name}] Execution complete: {result.scanners_completed} completed, "
            f"{result.scanners_failed} failed, {result.total_findings} findings"
        )

        return result

    async def _execute_parallel(
        self,
        target: str,
        context: Optional[dict],
        rate_limiter: Any,
        result: GroupResult,
        on_finding: Optional[Callable],
    ) -> None:
        """Execute scanners in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def run_scanner(scanner: ScanModule, info: ModuleInfo) -> ScannerResult:
            async with semaphore:
                return await self._run_single_scanner(
                    scanner, info, target, context, rate_limiter, on_finding
                )

        # Create tasks for all scanners
        tasks = [
            run_scanner(scanner, info)
            for scanner, info in zip(self._scanners, self._scanner_infos)
        ]

        # Execute with timeout
        try:
            scanner_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] Group timeout after {self.timeout_seconds}s")
            scanner_results = []

        # Process results
        for sr in scanner_results:
            if isinstance(sr, Exception):
                result.scanners_failed += 1
                result.scanner_results.append(ScannerResult(
                    scanner_name="unknown",
                    success=False,
                    error_message=str(sr),
                ))
            elif isinstance(sr, ScannerResult):
                result.scanner_results.append(sr)
                if sr.success:
                    result.scanners_completed += 1
                elif sr.skipped:
                    result.scanners_skipped += 1
                else:
                    result.scanners_failed += 1

    async def _execute_sequential(
        self,
        target: str,
        context: Optional[dict],
        rate_limiter: Any,
        result: GroupResult,
        on_finding: Optional[Callable],
    ) -> None:
        """Execute scanners one by one."""
        for scanner, info in zip(self._scanners, self._scanner_infos):
            if self._should_stop:
                break

            sr = await self._run_single_scanner(
                scanner, info, target, context, rate_limiter, on_finding
            )
            result.scanner_results.append(sr)

            if sr.success:
                result.scanners_completed += 1
                if self.stop_on_first_finding and sr.findings:
                    logger.info(f"[{self.name}] Stopping after first finding")
                    break
            elif sr.skipped:
                result.scanners_skipped += 1
            else:
                result.scanners_failed += 1

    async def _execute_by_priority(
        self,
        target: str,
        context: Optional[dict],
        rate_limiter: Any,
        result: GroupResult,
        on_finding: Optional[Callable],
    ) -> None:
        """Execute scanners grouped by priority."""
        # Group by priority
        priority_groups: dict[ModulePriority, list[tuple[ScanModule, ModuleInfo]]] = {}
        for scanner, info in zip(self._scanners, self._scanner_infos):
            if info.priority not in priority_groups:
                priority_groups[info.priority] = []
            priority_groups[info.priority].append((scanner, info))

        # Execute by priority order
        for priority in sorted(priority_groups.keys(), key=lambda p: p.value):
            if self._should_stop:
                break

            group = priority_groups[priority]
            logger.debug(f"[{self.name}] Executing {len(group)} {priority.name} priority scanners")

            # Run this priority group in parallel
            semaphore = asyncio.Semaphore(self.max_concurrent)

            async def run_scanner(scanner: ScanModule, info: ModuleInfo) -> ScannerResult:
                async with semaphore:
                    return await self._run_single_scanner(
                        scanner, info, target, context, rate_limiter, on_finding
                    )

            tasks = [run_scanner(s, i) for s, i in group]
            scanner_results = await asyncio.gather(*tasks, return_exceptions=True)

            for sr in scanner_results:
                if isinstance(sr, Exception):
                    result.scanners_failed += 1
                elif isinstance(sr, ScannerResult):
                    result.scanner_results.append(sr)
                    if sr.success:
                        result.scanners_completed += 1
                    elif sr.skipped:
                        result.scanners_skipped += 1
                    else:
                        result.scanners_failed += 1

    async def _run_single_scanner(
        self,
        scanner: ScanModule,
        info: ModuleInfo,
        target: str,
        context: Optional[dict],
        rate_limiter: Any,
        on_finding: Optional[Callable],
    ) -> ScannerResult:
        """Run a single scanner and return result."""
        start_time = time.time()

        try:
            # Prepare asset data
            asset_data = context or {}
            if "endpoints" not in asset_data:
                asset_data["endpoints"] = [target]

            # Calculate timeout
            timeout = self.timeout_seconds * info.timeout_multiplier / len(self._scanners)
            timeout = max(timeout, 30.0)  # Minimum 30 seconds

            logger.debug(f"[{self.name}] Running scanner: {info.name}")

            # Execute scanner
            scan_result = await asyncio.wait_for(
                scanner.scan(target, asset_data, rate_limiter),
                timeout=timeout,
            )

            # Extract findings
            findings = []
            if isinstance(scan_result, dict):
                findings = scan_result.get("vulns", []) + scan_result.get("findings", [])
            elif isinstance(scan_result, list):
                findings = scan_result

            # Convert findings to dicts
            finding_dicts = []
            for f in findings:
                if isinstance(f, dict):
                    finding_dicts.append(f)
                elif hasattr(f, 'to_dict'):
                    finding_dicts.append(f.to_dict())

            # Call finding callback
            if on_finding:
                for f in finding_dicts:
                    on_finding(f)

            duration = time.time() - start_time
            return ScannerResult(
                scanner_name=info.name,
                success=True,
                duration_seconds=duration,
                findings=finding_dicts,
            )

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            logger.warning(f"[{self.name}] Scanner {info.name} timed out after {duration:.1f}s")
            return ScannerResult(
                scanner_name=info.name,
                success=False,
                duration_seconds=duration,
                error_message="Timeout",
            )

        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"[{self.name}] Scanner {info.name} failed: {e}")
            return ScannerResult(
                scanner_name=info.name,
                success=False,
                duration_seconds=duration,
                error_message=str(e),
            )

    def stop(self) -> None:
        """Stop group execution."""
        self._should_stop = True


# =============================================================================
# CONCRETE SCANNER GROUPS
# =============================================================================

class InjectionScannerGroup(ScannerGroup):
    """Group of injection vulnerability scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="InjectionScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "sqli_scanner",
            "xss_scanner",
            "cmdi_scanner",
            "ssti_scanner",
            "nosql_scanner",
            "xxe_scanner",
            "crlf_scanner",
            "ldap_xpath_scanner",
        ]


class AuthScannerGroup(ScannerGroup):
    """Group of authentication scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="AuthScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "auth_scanner",
            "jwt_scanner",
            "oauth_scanner",
            "saml_scanner",
            "mfa_bypass_scanner",
            "session_abuse_scanner",
            "csrf_scanner",
            "cookie_security_scanner",
        ]


class APIScannerGroup(ScannerGroup):
    """Group of API security scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="APIScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "api_scanner",
            "api_logic_profiler",
            "graphql_advanced_scanner",
            "grpc_scanner",
            "websocket_scanner",
            "sse_scanner",
        ]


class AccessControlScannerGroup(ScannerGroup):
    """Group of access control scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="AccessControlScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "authorization_engine",
            "mass_assignment_scanner",
            "permission_matrix_scanner",
            "abac_context_tester",
        ]


class InfrastructureScannerGroup(ScannerGroup):
    """Group of infrastructure scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="InfrastructureScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "ssl_checker",
            "header_security",
            "cors_checker",
            "cloud_scanner",
            "kubernetes_scanner",
            "subdomain_takeover_scanner",
        ]


class BusinessLogicScannerGroup(ScannerGroup):
    """Group of business logic scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="BusinessLogicScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "business_logic_scanner",
            "race_condition_scanner",
            "rate_limit_scanner",
            "logic_chain_scanner",
            "stateful_flow_scanner",
            "workflow_inference_engine",
        ]


class AdvancedScannerGroup(ScannerGroup):
    """Group of advanced exploitation scanners."""

    def __init__(self, **kwargs):
        super().__init__(name="AdvancedScanners", **kwargs)

    def get_scanner_names(self) -> list[str]:
        return [
            "deserialization_scanner",
            "smuggling_scanner",
            "prototype_pollution_scanner",
            "cache_poisoning_scanner",
            "dns_rebinding_scanner",
        ]


# =============================================================================
# GROUP FACTORY
# =============================================================================

def get_scanner_group(category: ModuleCategory) -> ScannerGroup:
    """
    Get a scanner group for a module category.

    Args:
        category: The module category

    Returns:
        ScannerGroup instance for the category
    """
    group_map = {
        ModuleCategory.INJECTION: InjectionScannerGroup,
        ModuleCategory.AUTH: AuthScannerGroup,
        ModuleCategory.API: APIScannerGroup,
        ModuleCategory.ACCESS_CONTROL: AccessControlScannerGroup,
        ModuleCategory.INFRASTRUCTURE: InfrastructureScannerGroup,
        ModuleCategory.BUSINESS_LOGIC: BusinessLogicScannerGroup,
        ModuleCategory.ADVANCED: AdvancedScannerGroup,
    }

    group_class = group_map.get(category)
    if group_class:
        return group_class()

    # Default group using registry
    return CategoryBasedGroup(category)


class CategoryBasedGroup(ScannerGroup):
    """Scanner group based on module registry category."""

    def __init__(self, category: ModuleCategory, **kwargs):
        super().__init__(name=f"{category.value.title()}Scanners", **kwargs)
        self._category = category

    def get_scanner_names(self) -> list[str]:
        registry = get_module_registry()
        modules = registry.get_by_category(self._category)
        return [m.name for m in modules]


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "GroupExecutionMode",
    "GroupStatus",
    # Results
    "ScannerResult",
    "GroupResult",
    # Base class
    "ScannerGroup",
    # Concrete groups
    "InjectionScannerGroup",
    "AuthScannerGroup",
    "APIScannerGroup",
    "AccessControlScannerGroup",
    "InfrastructureScannerGroup",
    "BusinessLogicScannerGroup",
    "AdvancedScannerGroup",
    "CategoryBasedGroup",
    # Factory
    "get_scanner_group",
]
