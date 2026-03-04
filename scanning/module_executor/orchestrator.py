"""
Module Orchestrator - Concurrent Module Execution.

Handles orchestration of scanner module execution:
- Concurrency control via semaphore
- Circuit breaker integration
- Timeout management (fixed and adaptive)
- Jitter delays for OPSEC
- Coverage tracking
- Finding sharing
- Error recovery

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, Union

from scanning.module_executor.interfaces import HEAVY_MODULES, is_heavy_module

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════════════


class CoverageTrackerProtocol(Protocol):
    """Protocol for coverage tracker."""

    def record_skip(self, **kwargs: Any) -> None:
        """Record a skip event."""
        ...

    def start_module(self, module_name: str) -> None:
        """Start tracking module."""
        ...

    def finish_module(self, module_name: str, duration_ms: int) -> None:
        """Finish tracking module."""
        ...

    def record_module_test(self, **kwargs: Any) -> None:
        """Record module test metrics."""
        ...

    def record_module_skip(self, **kwargs: Any) -> None:
        """Record module skip."""
        ...


class TimeoutManagerProtocol(Protocol):
    """Protocol for timeout manager."""

    def get_timeout_for_module(self, module_name: str) -> float:
        """Get timeout for a module."""
        ...

    def record_module_duration(self, module_name: str, duration: float) -> None:
        """Record actual module duration."""
        ...


class SharedFindingsStoreProtocol(Protocol):
    """Protocol for shared findings store."""

    async def add_finding(self, finding: dict) -> None:
        """Add a finding to the store."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class OrchestratorConfig:
    """Configuration for module orchestrator."""

    # Concurrency
    concurrent: int = 5
    waf_concurrent_reduction: bool = False

    # Timeouts (fallback when adaptive not available)
    timeout_heavy: float = 900.0
    timeout_normal: float = 600.0
    use_adaptive_timeout: bool = True

    # Circuit breaker
    cb_max_consecutive: int = 3
    cb_pause_duration: float = 30.0
    cb_max_backoff: int = 8

    # Jitter (OPSEC)
    jitter_min: float = 0.1
    jitter_max: float = 0.5
    jitter_sigma: float = 0.2

    # Finding sharing
    share_findings_threshold: float = 50.0


@dataclass
class CircuitBreakerState:
    """State for circuit breaker."""

    consecutive_blocks: int = 0
    max_consecutive: int = 3
    pause_duration: float = 30.0
    is_paused: bool = False
    total_pauses: int = 0


@dataclass
class ModuleResult:
    """Result from module execution."""

    module_name: str
    findings: list = field(default_factory=list)
    info: list = field(default_factory=list)
    error: Optional[str] = None
    elapsed: float = 0.0
    rate_limited: bool = False
    blocked: bool = False
    partial: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "findings": self.findings,
            "info": self.info,
        }
        if self.error:
            result["error"] = self.error
        if self.rate_limited:
            result["rate_limited"] = True
        if self.blocked:
            result["blocked"] = True
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════════


class CircuitBreaker:
    """Circuit breaker for rate limiting protection."""

    def __init__(self, config: OrchestratorConfig):
        """Initialize circuit breaker."""
        self.config = config
        self.state = CircuitBreakerState(
            max_consecutive=config.cb_max_consecutive,
            pause_duration=config.cb_pause_duration,
        )
        self._lock = asyncio.Lock()

    async def check(self) -> None:
        """Check if we should pause due to rate limiting."""
        max_backoff_exp = (
            int(self.config.cb_max_backoff).bit_length() - 1
            if self.config.cb_max_backoff > 0
            else 3
        )

        async with self._lock:
            if self.state.consecutive_blocks >= self.state.max_consecutive:
                if not self.state.is_paused:
                    self.state.is_paused = True
                    self.state.total_pauses += 1
                    pause_time = self.state.pause_duration * (
                        2 ** min(self.state.total_pauses - 1, max_backoff_exp)
                    )
                    logger.warning(
                        f"Circuit breaker triggered - pausing for {pause_time:.0f}s "
                        f"(attempt {self.state.total_pauses})"
                    )

        if self.state.is_paused:
            pause_time = self.state.pause_duration * (
                2 ** min(self.state.total_pauses - 1, max_backoff_exp)
            )
            await asyncio.sleep(pause_time)
            async with self._lock:
                self.state.consecutive_blocks = 0
                self.state.is_paused = False

    async def record_block(self) -> None:
        """Record a blocked request."""
        async with self._lock:
            self.state.consecutive_blocks += 1

    async def record_success(self) -> None:
        """Record a successful request - resets consecutive counter."""
        async with self._lock:
            self.state.consecutive_blocks = 0


# ═══════════════════════════════════════════════════════════════════════════════
# Module Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════


class ModuleOrchestrator:
    """
    Orchestrates concurrent module execution.

    Handles:
    - Concurrency control via semaphore
    - Circuit breaker for rate limiting
    - Adaptive or fixed timeouts
    - Jitter delays between module starts
    - Coverage tracking
    - Finding sharing between modules
    """

    def __init__(
        self,
        config: Optional[OrchestratorConfig] = None,
        module_loader: Optional[Callable[[str], Any]] = None,
        module_runner: Optional[Callable[..., Any]] = None,
        timeout_manager: Optional[TimeoutManagerProtocol] = None,
        coverage_tracker: Optional[CoverageTrackerProtocol] = None,
        shared_store: Optional[SharedFindingsStoreProtocol] = None,
        auth_refresher: Optional[Callable[[], Any]] = None,
    ):
        """
        Initialize orchestrator.

        Args:
            config: Orchestrator configuration
            module_loader: Function to load modules by name
            module_runner: Function to run a single module
            timeout_manager: Adaptive timeout manager
            coverage_tracker: Coverage tracker instance
            shared_store: Shared findings store
            auth_refresher: Function to refresh auth if needed
        """
        self.config = config or OrchestratorConfig()
        self._module_loader = module_loader
        self._module_runner = module_runner
        self.timeout_manager = timeout_manager
        self.coverage_tracker = coverage_tracker
        self.shared_store = shared_store
        self._auth_refresher = auth_refresher

        # State
        self._circuit_breaker = CircuitBreaker(self.config)
        self._module_instances: dict[str, Any] = {}
        self._checkpoints: dict[str, list[dict]] = {}

    @property
    def module_instances(self) -> dict[str, Any]:
        """Get module instances created during execution."""
        return self._module_instances

    def checkpoint_finding(self, module_name: str, finding: dict) -> None:
        """
        Checkpoint a finding during execution for recovery on timeout.

        Args:
            module_name: Module name
            finding: Finding to checkpoint
        """
        if module_name not in self._checkpoints:
            self._checkpoints[module_name] = []
        self._checkpoints[module_name].append(finding)

    def get_timeout(self, module_name: str) -> float:
        """
        Get timeout for a module.

        Args:
            module_name: Module name

        Returns:
            Timeout in seconds
        """
        if self.config.use_adaptive_timeout and self.timeout_manager:
            return self.timeout_manager.get_timeout_for_module(module_name)
        return (
            self.config.timeout_heavy
            if is_heavy_module(module_name)
            else self.config.timeout_normal
        )

    def calculate_jitter(self) -> float:
        """Calculate jitter delay for OPSEC."""
        base_delay = random.uniform(self.config.jitter_min, self.config.jitter_max)
        jitter = random.gauss(0, base_delay * self.config.jitter_sigma)
        return max(0.05, base_delay + jitter)

    async def _maybe_refresh_auth(self) -> None:
        """Refresh auth if needed."""
        if self._auth_refresher:
            try:
                await self._auth_refresher()
            except Exception as e:
                logger.debug(f"Auth refresh error: {e}")

    def _recover_partial_findings(self, module_name: str) -> list[dict]:
        """
        Recover partial findings from timeout.

        Args:
            module_name: Module name

        Returns:
            List of recovered findings
        """
        partial_findings = []

        # Check checkpoint store
        if module_name in self._checkpoints:
            partial_findings = self._checkpoints[module_name]
            if partial_findings:
                logger.info(
                    f"Recovered {len(partial_findings)} checkpointed findings "
                    f"from {module_name}"
                )

        # Try module's get_partial_findings()
        if module_name in self._module_instances:
            instance = self._module_instances[module_name]

            if hasattr(instance, "get_partial_findings"):
                try:
                    module_partials = instance.get_partial_findings()
                    if module_partials:
                        existing_ids = {
                            f.get("id") for f in partial_findings if f.get("id")
                        }
                        for f in module_partials:
                            if f.get("id") not in existing_ids:
                                partial_findings.append(f)
                        logger.info(
                            f"Merged {len(module_partials)} module partial findings "
                            f"from {module_name}"
                        )
                except Exception as e:
                    logger.warning(f"Failed to get partial findings from {module_name}: {e}")

            # Check _progressive_findings attribute
            if hasattr(instance, "_progressive_findings"):
                try:
                    progressive = instance._progressive_findings
                    if progressive:
                        existing_urls = {
                            (
                                f.get("matched_at"),
                                f.get("metadata", {}).get("param"),
                            )
                            for f in partial_findings
                        }
                        new_count = 0
                        for f in progressive:
                            key = (
                                f.get("matched_at"),
                                f.get("metadata", {}).get("param"),
                            )
                            if key not in existing_urls:
                                partial_findings.append(f)
                                existing_urls.add(key)
                                new_count += 1
                        if new_count > 0:
                            logger.info(
                                f"Recovered {new_count} progressive findings "
                                f"from {module_name}"
                            )
                except Exception as e:
                    logger.debug(
                        f"Could not access progressive findings from {module_name}: {e}"
                    )

        return partial_findings

    async def _share_findings(self, findings: list[dict], module_name: str) -> None:
        """
        Share findings immediately after module completes.

        Args:
            findings: Findings to share
            module_name: Source module name
        """
        if not self.shared_store or not findings:
            return

        try:
            for finding in findings:
                if isinstance(finding, dict):
                    conf = finding.get("confidence_score", finding.get("confidence", 0))
                    if (
                        isinstance(conf, (int, float))
                        and conf >= self.config.share_findings_threshold
                    ):
                        await self.shared_store.add_finding(finding)
                        logger.debug(
                            f"Shared finding from {module_name}: "
                            f"{finding.get('vuln_type', finding.get('type', 'unknown'))}"
                        )
        except Exception as e:
            logger.debug(f"Error sharing finding from {module_name}: {e}")

    async def _run_single_module(
        self,
        module_name: str,
        target: str,
        semaphore: asyncio.Semaphore,
        total: int,
        completed: list[int],  # Mutable counter
    ) -> ModuleResult:
        """
        Run a single module with full orchestration.

        Args:
            module_name: Module name
            target: Target URL
            semaphore: Concurrency semaphore
            total: Total modules count
            completed: Mutable completed counter

        Returns:
            ModuleResult
        """
        async with semaphore:
            # Check circuit breaker
            await self._circuit_breaker.check()

            # Refresh auth if needed
            await self._maybe_refresh_auth()

            # Add jitter delay
            delay = self.calculate_jitter()
            await asyncio.sleep(delay)

            # Load module
            module = None
            if self._module_loader:
                module = self._module_loader(module_name)

            if not module:
                completed[0] += 1
                logger.warning(
                    f"[{completed[0]}/{total}] {module_name}: SKIPPED (failed to load)"
                )
                self._record_skip(
                    module_name, "MODULE_ERROR", "Module failed to load"
                )
                return ModuleResult(
                    module_name=module_name,
                    error=f"module {module_name} failed to load",
                )

            self._module_instances[module_name] = module
            timeout = self.get_timeout(module_name)
            t0 = time.monotonic()

            logger.info(
                f"[{completed[0] + 1}/{total}] {module_name}: STARTING "
                f"(timeout={timeout}s)..."
            )

            try:
                # Run the module
                if self._module_runner:
                    raw_result = await asyncio.wait_for(
                        self._module_runner(module_name, target, module),
                        timeout=timeout,
                    )
                else:
                    raw_result = {"findings": [], "info": []}

                elapsed = time.monotonic() - t0

                # Record duration for adaptive learning
                if self.timeout_manager:
                    self.timeout_manager.record_module_duration(module_name, elapsed)

                # Extract result data
                findings = raw_result.get("findings", [])
                rate_limited = raw_result.get("rate_limited", False)
                blocked = raw_result.get("blocked", False)

                # Update circuit breaker
                if rate_limited or blocked:
                    await self._circuit_breaker.record_block()
                else:
                    await self._circuit_breaker.record_success()

                # Share findings
                await self._share_findings(findings, module_name)

                # Track coverage
                self._record_module_test(module_name, raw_result, elapsed)

                completed[0] += 1
                n_findings = len(findings)

                if n_findings > 0:
                    logger.info(
                        f"[{completed[0]}/{total}] {module_name}: DONE in "
                        f"{elapsed:.1f}s - {n_findings} finding(s)"
                    )
                else:
                    logger.info(
                        f"[{completed[0]}/{total}] {module_name}: DONE in "
                        f"{elapsed:.1f}s - clean"
                    )

                return ModuleResult(
                    module_name=module_name,
                    findings=findings,
                    info=raw_result.get("info", []),
                    elapsed=elapsed,
                    rate_limited=rate_limited,
                    blocked=blocked,
                )

            except asyncio.TimeoutError:
                completed[0] += 1
                logger.warning(
                    f"[{completed[0]}/{total}] {module_name}: TIMEOUT after {timeout}s"
                )
                self._record_skip(
                    module_name, "TIMEOUT", f"Module timed out after {timeout}s"
                )

                # Recover partial findings
                partial = self._recover_partial_findings(module_name)

                return ModuleResult(
                    module_name=module_name,
                    findings=partial,
                    error=f"timeout after {timeout}s (recovered {len(partial)} findings)",
                    elapsed=timeout,
                    partial=True,
                )

            except Exception as e:
                elapsed = time.monotonic() - t0
                completed[0] += 1
                logger.warning(
                    f"[{completed[0]}/{total}] {module_name}: ERROR in "
                    f"{elapsed:.1f}s - {e}"
                )
                self._record_skip(
                    module_name, "MODULE_ERROR", f"Module crashed: {str(e)[:100]}"
                )

                return ModuleResult(
                    module_name=module_name,
                    error=str(e),
                    elapsed=elapsed,
                )

    def _record_skip(self, module_name: str, reason: str, detail: str) -> None:
        """Record a module skip in coverage tracker."""
        if not self.coverage_tracker:
            return

        try:
            from scanning.coverage_tracker import SkipReason

            self.coverage_tracker.record_skip(
                surface_type="module",
                identifier=module_name,
                reason=getattr(SkipReason, reason, SkipReason.MODULE_ERROR),
                reason_detail=detail,
                potential_impact=f"Vulnerabilities testable by {module_name} were not checked",
                module_name=module_name,
            )
        except Exception as e:
            logger.debug(f"Error recording skip: {e}")

    def _record_module_test(
        self, module_name: str, result: dict, elapsed: float
    ) -> None:
        """Record module test metrics in coverage tracker."""
        if not self.coverage_tracker:
            return

        try:
            self.coverage_tracker.start_module(module_name)
            self.coverage_tracker.record_module_test(
                module_name=module_name,
                endpoints_tested=result.get("endpoints_tested", 1),
                params_tested=result.get("params_tested", 0),
                payloads_sent=result.get("payloads_sent", 0),
                findings=len(result.get("findings", [])),
            )
            self.coverage_tracker.finish_module(module_name, int(elapsed * 1000))
        except Exception as e:
            logger.debug(f"Error recording module test: {e}")

    async def execute(
        self,
        target: str,
        module_names: list[str],
    ) -> list[ModuleResult]:
        """
        Execute modules concurrently.

        Args:
            target: Target URL
            module_names: List of module names to execute

        Returns:
            List of ModuleResult
        """
        # Apply WAF concurrent reduction if needed
        concurrent = self.config.concurrent
        if self.config.waf_concurrent_reduction:
            concurrent = max(2, concurrent // 2)
            logger.info(f"WAF detected - reducing concurrency to {concurrent}")

        semaphore = asyncio.Semaphore(concurrent)

        # Reset state
        self._module_instances = {}
        self._checkpoints = {}

        # Track progress
        total = len(module_names)
        completed = [0]  # Mutable counter

        # Create tasks
        tasks = [
            self._run_single_module(name, target, semaphore, total, completed)
            for name in module_names
        ]

        # Execute
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to ModuleResult
        converted = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                converted.append(
                    ModuleResult(
                        module_name=module_names[i],
                        error=str(result),
                    )
                )
            else:
                converted.append(result)

        return converted


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════


async def execute_modules(
    target: str,
    module_names: list[str],
    concurrent: int = 5,
    module_loader: Optional[Callable[[str], Any]] = None,
    module_runner: Optional[Callable[..., Any]] = None,
) -> list[ModuleResult]:
    """
    Execute modules with minimal setup.

    Args:
        target: Target URL
        module_names: List of module names
        concurrent: Concurrency level
        module_loader: Function to load modules
        module_runner: Function to run modules

    Returns:
        List of ModuleResult
    """
    config = OrchestratorConfig(concurrent=concurrent)
    orchestrator = ModuleOrchestrator(
        config=config,
        module_loader=module_loader,
        module_runner=module_runner,
    )
    return await orchestrator.execute(target, module_names)
