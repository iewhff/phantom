"""
PHANTOM AI - Module Executor Framework
=======================================

Enterprise unified scanner execution framework for managing 75+ security modules.

Features:
- Parallel module execution with configurable concurrency
- Dependency resolution and execution ordering
- Progress tracking and real-time status updates
- Graceful error handling and recovery
- Result aggregation and deduplication
- Resource management and rate limiting
- Module lifecycle management (init, run, cleanup)

Author: PHANTOM AI Team
Version: 3.0.0
"""

import asyncio
import logging
import time
import hashlib
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import (
    Dict, List, Optional, Set, Any, Callable, TypeVar,
    Coroutine, Union, Type
)
from collections import defaultdict
from abc import ABC, abstractmethod
import traceback

logger = logging.getLogger("phantom.module_executor")


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class ModuleCategory(Enum):
    """Categories of security testing modules."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    API = "api"
    INFRASTRUCTURE = "infrastructure"
    ADVANCED = "advanced"
    DISCOVERY = "discovery"
    BAAS = "baas"
    RECONNAISSANCE = "reconnaissance"
    VALIDATION = "validation"


class ModulePriority(Enum):
    """Module execution priority levels."""
    CRITICAL = 1      # Must run first (recon, fingerprinting)
    HIGH = 2          # High priority (common vulns)
    MEDIUM = 3        # Standard priority
    LOW = 4           # Low priority (rare vulns)
    BACKGROUND = 5    # Run in background if time permits


class ModuleState(Enum):
    """Module execution states."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ExecutionMode(Enum):
    """Module execution modes."""
    SEQUENTIAL = "sequential"     # One at a time
    PARALLEL = "parallel"         # All at once (limited by concurrency)
    WAVE = "wave"                 # In priority waves
    DEPENDENCY = "dependency"     # Based on dependency graph


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ModuleConfig:
    """Configuration for a single module."""
    name: str
    enabled: bool = True
    priority: ModulePriority = ModulePriority.MEDIUM
    timeout: float = 60.0
    retries: int = 1
    dependencies: List[str] = field(default_factory=list)
    category: ModuleCategory = ModuleCategory.INJECTION
    parallel_safe: bool = True
    requires_auth: bool = False
    requires_oob: bool = False
    custom_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "priority": self.priority.name,
            "timeout": self.timeout,
            "retries": self.retries,
            "dependencies": self.dependencies,
            "category": self.category.name,
            "parallel_safe": self.parallel_safe,
            "requires_auth": self.requires_auth,
            "requires_oob": self.requires_oob,
        }


@dataclass
class ModuleResult:
    """Result from a module execution."""
    module_name: str
    state: ModuleState
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    requests_made: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "module_name": self.module_name,
            "state": self.state.name,
            "findings_count": len(self.findings),
            "errors_count": len(self.errors),
            "warnings_count": len(self.warnings),
            "execution_time_ms": round(self.execution_time_ms, 2),
            "requests_made": self.requests_made,
            "findings": self.findings,
            "errors": self.errors,
            "warnings": self.warnings,
        }


@dataclass
class ExecutionProgress:
    """Progress tracking for module execution."""
    total_modules: int = 0
    pending: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    cancelled: int = 0

    current_modules: List[str] = field(default_factory=list)
    total_findings: int = 0
    total_requests: int = 0
    elapsed_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        completed_percentage = (
            (self.completed + self.failed + self.skipped) / self.total_modules * 100
            if self.total_modules > 0 else 0
        )
        return {
            "total_modules": self.total_modules,
            "pending": self.pending,
            "running": self.running,
            "completed": self.completed,
            "failed": self.failed,
            "skipped": self.skipped,
            "cancelled": self.cancelled,
            "current_modules": self.current_modules,
            "total_findings": self.total_findings,
            "total_requests": self.total_requests,
            "elapsed_time_ms": round(self.elapsed_time_ms, 2),
            "completed_percentage": round(completed_percentage, 1),
        }


@dataclass
class ExecutorConfig:
    """Configuration for the module executor."""
    # Concurrency settings
    max_concurrency: int = 10
    max_concurrent_per_category: int = 3

    # Timeout settings
    global_timeout: float = 3600.0  # 1 hour
    module_timeout: float = 120.0   # 2 minutes per module

    # Retry settings
    max_retries: int = 2
    retry_delay: float = 1.0

    # Execution settings
    mode: ExecutionMode = ExecutionMode.WAVE
    stop_on_critical_error: bool = False
    skip_failed_dependencies: bool = True

    # Progress settings
    progress_callback: Optional[Callable[[ExecutionProgress], None]] = None
    progress_interval: float = 1.0

    # Resource settings
    respect_rate_limits: bool = True
    max_requests_per_second: float = 10.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "max_concurrency": self.max_concurrency,
            "max_concurrent_per_category": self.max_concurrent_per_category,
            "global_timeout": self.global_timeout,
            "module_timeout": self.module_timeout,
            "max_retries": self.max_retries,
            "mode": self.mode.name,
            "stop_on_critical_error": self.stop_on_critical_error,
            "skip_failed_dependencies": self.skip_failed_dependencies,
        }


# =============================================================================
# BASE MODULE CLASS
# =============================================================================

class BaseSecurityModule(ABC):
    """
    Abstract base class for all security testing modules.

    All modules must inherit from this class and implement:
    - run(): Main execution method
    - get_config(): Return module configuration
    """

    def __init__(self, target_url: str, **kwargs):
        """
        Initialize the module.

        Args:
            target_url: Target URL to test
            **kwargs: Additional configuration
        """
        self.target_url = target_url
        self.kwargs = kwargs
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.requests_made: int = 0
        self._cancelled: bool = False

    @abstractmethod
    async def run(self) -> List[Dict[str, Any]]:
        """
        Execute the security module.

        Returns:
            List of findings (vulnerabilities discovered)
        """
        pass

    @classmethod
    @abstractmethod
    def get_config(cls) -> ModuleConfig:
        """
        Get module configuration.

        Returns:
            ModuleConfig with module settings
        """
        pass

    async def initialize(self) -> bool:
        """
        Initialize module before execution.
        Override to add custom initialization logic.

        Returns:
            True if initialization successful
        """
        return True

    async def cleanup(self) -> None:
        """
        Cleanup after module execution.
        Override to add custom cleanup logic.
        """
        pass

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the module results."""
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)

    def cancel(self) -> None:
        """Request cancellation of the module."""
        self._cancelled = True

    def is_cancelled(self) -> bool:
        """Check if module has been cancelled."""
        return self._cancelled


# =============================================================================
# MODULE REGISTRY
# =============================================================================

class ModuleRegistry:
    """
    Registry for security testing modules.

    Provides module registration, lookup, and dependency management.
    """

    _instance: Optional["ModuleRegistry"] = None

    @classmethod
    def get_instance(cls) -> "ModuleRegistry":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing)."""
        cls._instance = None

    def __init__(self):
        """Initialize the registry."""
        self._modules: Dict[str, Type[BaseSecurityModule]] = {}
        self._configs: Dict[str, ModuleConfig] = {}
        self._by_category: Dict[ModuleCategory, List[str]] = defaultdict(list)
        self._by_priority: Dict[ModulePriority, List[str]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def register(self, module_class: Type[BaseSecurityModule]) -> None:
        """
        Register a security module.

        Args:
            module_class: Module class to register
        """
        config = module_class.get_config()
        name = config.name.lower()

        self._modules[name] = module_class
        self._configs[name] = config
        self._by_category[config.category].append(name)
        self._by_priority[config.priority].append(name)

        logger.debug(f"Registered module: {name} (category: {config.category.name})")

    def unregister(self, name: str) -> bool:
        """
        Unregister a module.

        Args:
            name: Module name to unregister

        Returns:
            True if module was unregistered
        """
        name = name.lower()
        if name not in self._modules:
            return False

        config = self._configs[name]
        self._by_category[config.category].remove(name)
        self._by_priority[config.priority].remove(name)
        del self._modules[name]
        del self._configs[name]

        logger.debug(f"Unregistered module: {name}")
        return True

    def get_module(self, name: str) -> Optional[Type[BaseSecurityModule]]:
        """Get a module class by name."""
        return self._modules.get(name.lower())

    def get_config(self, name: str) -> Optional[ModuleConfig]:
        """Get module configuration by name."""
        return self._configs.get(name.lower())

    def get_all_modules(self) -> List[str]:
        """Get all registered module names."""
        return list(self._modules.keys())

    def get_by_category(self, category: ModuleCategory) -> List[str]:
        """Get module names by category."""
        return self._by_category.get(category, [])

    def get_by_priority(self, priority: ModulePriority) -> List[str]:
        """Get module names by priority."""
        return self._by_priority.get(priority, [])

    def get_execution_order(
        self,
        modules: Optional[List[str]] = None,
        mode: ExecutionMode = ExecutionMode.WAVE,
    ) -> List[List[str]]:
        """
        Get module execution order based on mode.

        Args:
            modules: Specific modules to order (None for all)
            mode: Execution mode

        Returns:
            List of module batches to execute
        """
        if modules is None:
            modules = list(self._modules.keys())

        modules = [m.lower() for m in modules]

        if mode == ExecutionMode.SEQUENTIAL:
            return [[m] for m in modules]

        elif mode == ExecutionMode.PARALLEL:
            return [modules]

        elif mode == ExecutionMode.WAVE:
            # Group by priority
            waves: Dict[ModulePriority, List[str]] = defaultdict(list)
            for module in modules:
                config = self._configs.get(module)
                if config:
                    waves[config.priority].append(module)

            # Return in priority order
            ordered = []
            for priority in ModulePriority:
                if waves[priority]:
                    ordered.append(waves[priority])
            return ordered

        elif mode == ExecutionMode.DEPENDENCY:
            return self._resolve_dependencies(modules)

        return [modules]

    def _resolve_dependencies(self, modules: List[str]) -> List[List[str]]:
        """
        Resolve module dependencies and return execution waves.

        Args:
            modules: Modules to resolve

        Returns:
            List of execution waves
        """
        # Build dependency graph
        dependencies: Dict[str, Set[str]] = {}
        for module in modules:
            config = self._configs.get(module)
            if config:
                dependencies[module] = set(d.lower() for d in config.dependencies if d.lower() in modules)
            else:
                dependencies[module] = set()

        # Topological sort with waves
        waves: List[List[str]] = []
        remaining = set(modules)
        completed: Set[str] = set()

        while remaining:
            # Find modules with no pending dependencies
            ready = [
                m for m in remaining
                if dependencies[m].issubset(completed)
            ]

            if not ready:
                # Circular dependency - add remaining to last wave
                logger.warning(f"Circular dependency detected in: {remaining}")
                waves.append(list(remaining))
                break

            waves.append(ready)
            completed.update(ready)
            remaining -= set(ready)

        return waves

    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics."""
        return {
            "total_modules": len(self._modules),
            "by_category": {
                cat.name: len(modules)
                for cat, modules in self._by_category.items()
            },
            "by_priority": {
                pri.name: len(modules)
                for pri, modules in self._by_priority.items()
            },
        }


# =============================================================================
# MODULE EXECUTOR
# =============================================================================

class ModuleExecutor:
    """
    Enterprise Module Executor for PHANTOM AI.

    Manages parallel execution of security testing modules with:
    - Dependency resolution
    - Progress tracking
    - Error handling and recovery
    - Rate limiting
    - Result aggregation
    """

    VERSION = "3.0.0"

    def __init__(self, config: Optional[ExecutorConfig] = None):
        """
        Initialize the module executor.

        Args:
            config: Executor configuration
        """
        self.config = config or ExecutorConfig()
        self.registry = ModuleRegistry.get_instance()

        # Execution state
        self._results: Dict[str, ModuleResult] = {}
        self._states: Dict[str, ModuleState] = {}
        self._running_modules: Dict[str, asyncio.Task] = {}

        # Progress tracking
        self._progress = ExecutionProgress()
        self._start_time: Optional[float] = None
        self._cancelled: bool = False

        # Concurrency control
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._category_semaphores: Dict[ModuleCategory, asyncio.Semaphore] = {}

        # Lock for thread safety
        self._lock = asyncio.Lock()

        logger.info(f"ModuleExecutor v{self.VERSION} initialized")

    async def execute(
        self,
        target_url: str,
        modules: Optional[List[str]] = None,
        mode: Optional[ExecutionMode] = None,
        **kwargs,
    ) -> Dict[str, ModuleResult]:
        """
        Execute security modules against a target.

        Args:
            target_url: Target URL to test
            modules: Specific modules to run (None for all)
            mode: Execution mode override
            **kwargs: Additional parameters passed to modules

        Returns:
            Dictionary of module_name -> ModuleResult
        """
        self._start_time = time.time()
        self._cancelled = False

        # Initialize semaphores
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        for category in ModuleCategory:
            self._category_semaphores[category] = asyncio.Semaphore(
                self.config.max_concurrent_per_category
            )

        # Get modules to execute
        if modules is None:
            modules = self.registry.get_all_modules()

        # Filter enabled modules
        enabled_modules = []
        for module in modules:
            config = self.registry.get_config(module)
            if config and config.enabled:
                enabled_modules.append(module)
            else:
                self._states[module] = ModuleState.SKIPPED
                self._results[module] = ModuleResult(
                    module_name=module,
                    state=ModuleState.SKIPPED,
                    warnings=["Module disabled or not found"],
                )

        # Initialize progress
        self._progress = ExecutionProgress(
            total_modules=len(enabled_modules),
            pending=len(enabled_modules),
        )

        # Get execution order
        execution_mode = mode or self.config.mode
        waves = self.registry.get_execution_order(enabled_modules, execution_mode)

        logger.info(
            f"Executing {len(enabled_modules)} modules in {len(waves)} waves "
            f"(mode: {execution_mode.name})"
        )

        # Execute waves
        try:
            for wave_index, wave in enumerate(waves, 1):
                if self._cancelled:
                    break

                logger.info(f"Starting wave {wave_index}/{len(waves)} with {len(wave)} modules")

                # Check dependencies
                ready_modules = []
                for module in wave:
                    if self._check_dependencies(module):
                        ready_modules.append(module)
                    else:
                        self._states[module] = ModuleState.SKIPPED
                        self._results[module] = ModuleResult(
                            module_name=module,
                            state=ModuleState.SKIPPED,
                            warnings=["Dependencies failed"],
                        )
                        self._progress.skipped += 1
                        self._progress.pending -= 1

                # Execute wave modules in parallel
                if ready_modules:
                    tasks = [
                        self._execute_module(target_url, module, **kwargs)
                        for module in ready_modules
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)

        except asyncio.CancelledError:
            logger.warning("Execution cancelled")
            self._cancelled = True
        except Exception as e:
            logger.error(f"Execution error: {e}")
            if self.config.stop_on_critical_error:
                raise

        # Update final progress
        self._progress.elapsed_time_ms = (time.time() - self._start_time) * 1000

        logger.info(
            f"Execution complete: {self._progress.completed} completed, "
            f"{self._progress.failed} failed, {self._progress.skipped} skipped, "
            f"found {self._progress.total_findings} findings in "
            f"{self._progress.elapsed_time_ms:.0f}ms"
        )

        return self._results

    async def _execute_module(
        self,
        target_url: str,
        module_name: str,
        **kwargs,
    ) -> None:
        """Execute a single module with proper handling."""
        config = self.registry.get_config(module_name)
        module_class = self.registry.get_module(module_name)

        if not config or not module_class:
            logger.error(f"Module not found: {module_name}")
            return

        # Update state
        async with self._lock:
            self._states[module_name] = ModuleState.QUEUED
            self._progress.pending -= 1

        # Acquire semaphores
        async with self._semaphore:
            category_sem = self._category_semaphores.get(config.category)
            if category_sem:
                await category_sem.acquire()

            try:
                # Update state to running
                async with self._lock:
                    self._states[module_name] = ModuleState.RUNNING
                    self._progress.running += 1
                    self._progress.current_modules.append(module_name)

                # Call progress callback
                if self.config.progress_callback:
                    try:
                        self.config.progress_callback(self._progress)
                    except Exception:
                        pass

                # Execute with retries
                result = await self._execute_with_retry(
                    target_url, module_name, module_class, config, **kwargs
                )

                # Store result
                async with self._lock:
                    self._results[module_name] = result
                    self._states[module_name] = result.state
                    self._progress.running -= 1
                    self._progress.current_modules.remove(module_name)

                    if result.state == ModuleState.COMPLETED:
                        self._progress.completed += 1
                        self._progress.total_findings += len(result.findings)
                    elif result.state == ModuleState.FAILED:
                        self._progress.failed += 1
                    elif result.state == ModuleState.TIMEOUT:
                        self._progress.failed += 1

                    self._progress.total_requests += result.requests_made

            finally:
                if category_sem:
                    category_sem.release()

    async def _execute_with_retry(
        self,
        target_url: str,
        module_name: str,
        module_class: Type[BaseSecurityModule],
        config: ModuleConfig,
        **kwargs,
    ) -> ModuleResult:
        """Execute module with retry logic."""
        start_time = time.time()
        last_error: Optional[str] = None
        attempts = 0

        timeout = config.timeout or self.config.module_timeout
        max_retries = config.retries or self.config.max_retries

        while attempts <= max_retries:
            attempts += 1

            try:
                # Create module instance
                module = module_class(target_url, **kwargs)

                # Initialize
                if not await module.initialize():
                    return ModuleResult(
                        module_name=module_name,
                        state=ModuleState.FAILED,
                        errors=["Module initialization failed"],
                        start_time=start_time,
                        end_time=time.time(),
                        execution_time_ms=(time.time() - start_time) * 1000,
                    )

                # Execute with timeout
                try:
                    findings = await asyncio.wait_for(
                        module.run(),
                        timeout=timeout,
                    )

                    # Cleanup
                    await module.cleanup()

                    end_time = time.time()
                    return ModuleResult(
                        module_name=module_name,
                        state=ModuleState.COMPLETED,
                        findings=findings or [],
                        errors=module.errors,
                        warnings=module.warnings,
                        requests_made=module.requests_made,
                        start_time=start_time,
                        end_time=end_time,
                        execution_time_ms=(end_time - start_time) * 1000,
                    )

                except asyncio.TimeoutError:
                    await module.cleanup()
                    return ModuleResult(
                        module_name=module_name,
                        state=ModuleState.TIMEOUT,
                        errors=[f"Module timed out after {timeout}s"],
                        start_time=start_time,
                        end_time=time.time(),
                        execution_time_ms=(time.time() - start_time) * 1000,
                    )

            except Exception as e:
                last_error = f"{type(e).__name__}: {str(e)}"
                logger.warning(
                    f"Module {module_name} failed (attempt {attempts}): {last_error}"
                )

                if attempts <= max_retries:
                    await asyncio.sleep(self.config.retry_delay)

        # All retries exhausted
        return ModuleResult(
            module_name=module_name,
            state=ModuleState.FAILED,
            errors=[last_error or "Unknown error"],
            start_time=start_time,
            end_time=time.time(),
            execution_time_ms=(time.time() - start_time) * 1000,
        )

    def _check_dependencies(self, module_name: str) -> bool:
        """Check if module dependencies are satisfied."""
        config = self.registry.get_config(module_name)
        if not config or not config.dependencies:
            return True

        for dep in config.dependencies:
            dep_lower = dep.lower()
            dep_state = self._states.get(dep_lower)

            if dep_state is None:
                logger.warning(f"Module {module_name}: dependency {dep} not found")
                if self.config.skip_failed_dependencies:
                    return False

            elif dep_state not in [ModuleState.COMPLETED]:
                logger.warning(f"Module {module_name}: dependency {dep} not completed")
                if self.config.skip_failed_dependencies:
                    return False

        return True

    async def cancel(self) -> None:
        """Cancel all running modules."""
        self._cancelled = True

        async with self._lock:
            for module_name, task in list(self._running_modules.items()):
                if not task.done():
                    task.cancel()
                    self._states[module_name] = ModuleState.CANCELLED
                    self._progress.cancelled += 1

        logger.info("Execution cancelled")

    def get_progress(self) -> ExecutionProgress:
        """Get current execution progress."""
        if self._start_time:
            self._progress.elapsed_time_ms = (time.time() - self._start_time) * 1000
        return self._progress

    def get_result(self, module_name: str) -> Optional[ModuleResult]:
        """Get result for a specific module."""
        return self._results.get(module_name.lower())

    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings from all modules."""
        findings = []
        for result in self._results.values():
            if result.findings:
                for finding in result.findings:
                    finding["_source_module"] = result.module_name
                    findings.append(finding)
        return findings

    def get_statistics(self) -> Dict[str, Any]:
        """Get executor statistics."""
        return {
            "version": self.VERSION,
            "config": self.config.to_dict(),
            "registry": self.registry.get_statistics(),
            "last_execution": {
                "progress": self._progress.to_dict() if self._progress else None,
                "results_count": len(self._results),
            },
        }


# =============================================================================
# DECORATOR FOR MODULE REGISTRATION
# =============================================================================

def register_module(
    name: str,
    category: ModuleCategory = ModuleCategory.INJECTION,
    priority: ModulePriority = ModulePriority.MEDIUM,
    timeout: float = 60.0,
    dependencies: Optional[List[str]] = None,
    requires_auth: bool = False,
    requires_oob: bool = False,
):
    """
    Decorator to register a security module.

    Usage:
        @register_module(
            name="sqli",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.HIGH,
        )
        class SQLiScanner(BaseSecurityModule):
            ...
    """
    def decorator(cls: Type[BaseSecurityModule]):
        # Create get_config method
        config = ModuleConfig(
            name=name,
            category=category,
            priority=priority,
            timeout=timeout,
            dependencies=dependencies or [],
            requires_auth=requires_auth,
            requires_oob=requires_oob,
        )

        @classmethod
        def get_config(cls) -> ModuleConfig:
            return config

        cls.get_config = get_config

        # Register with registry
        ModuleRegistry.get_instance().register(cls)

        return cls

    return decorator


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_module_executor(config: Optional[ExecutorConfig] = None) -> ModuleExecutor:
    """Get a module executor instance."""
    return ModuleExecutor(config)


def get_registry() -> ModuleRegistry:
    """Get the module registry."""
    return ModuleRegistry.get_instance()


async def execute_modules(
    target_url: str,
    modules: Optional[List[str]] = None,
    config: Optional[ExecutorConfig] = None,
    **kwargs,
) -> Dict[str, ModuleResult]:
    """
    Convenience function to execute modules.

    Args:
        target_url: Target URL
        modules: Modules to run (None for all)
        config: Executor configuration
        **kwargs: Additional module parameters

    Returns:
        Dictionary of module results
    """
    executor = ModuleExecutor(config)
    return await executor.execute(target_url, modules, **kwargs)


# =============================================================================
# EXAMPLE MODULES FOR TESTING
# =============================================================================

class ExampleScannerModule(BaseSecurityModule):
    """Example scanner module for testing."""

    @classmethod
    def get_config(cls) -> ModuleConfig:
        return ModuleConfig(
            name="example",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.LOW,
            timeout=30.0,
        )

    async def run(self) -> List[Dict[str, Any]]:
        """Run the example scanner."""
        await asyncio.sleep(0.1)  # Simulate work
        return [
            {
                "type": "example",
                "severity": "info",
                "description": "Example finding",
                "url": self.target_url,
            }
        ]


# Register example module
ModuleRegistry.get_instance().register(ExampleScannerModule)


# =============================================================================
# MODULE TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_executor():
        """Test the module executor."""
        print("=" * 60)
        print("PHANTOM AI - Module Executor Test")
        print("=" * 60)

        # Get registry
        registry = ModuleRegistry.get_instance()
        print(f"\n📦 Registry Statistics:")
        stats = registry.get_statistics()
        print(f"   Total modules: {stats['total_modules']}")
        for cat, count in stats['by_category'].items():
            if count > 0:
                print(f"   {cat}: {count}")

        # Create executor
        def progress_callback(progress: ExecutionProgress):
            print(
                f"   Progress: {progress.completed}/{progress.total_modules} "
                f"({progress.total_findings} findings)"
            )

        config = ExecutorConfig(
            max_concurrency=5,
            progress_callback=progress_callback,
        )
        executor = ModuleExecutor(config)

        # Execute modules
        print(f"\n🚀 Executing modules...")
        results = await executor.execute(
            target_url="https://example.com",
            modules=["example"],
        )

        # Print results
        print(f"\n📊 Execution Results:")
        for module_name, result in results.items():
            print(f"   {module_name}: {result.state.name}")
            print(f"      Time: {result.execution_time_ms:.2f}ms")
            print(f"      Findings: {len(result.findings)}")

        # Print statistics
        print(f"\n📈 Executor Statistics:")
        exec_stats = executor.get_statistics()
        print(f"   Version: {exec_stats['version']}")
        print(f"   Mode: {exec_stats['config']['mode']}")

        print("\n" + "=" * 60)
        print("✅ Module Executor test complete!")
        print("=" * 60)

    asyncio.run(test_executor())
