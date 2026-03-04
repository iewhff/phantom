"""
Module Execution Phase - Scanner Module Orchestration.

This phase handles:
- Phase 3: Execute scanner modules (parallel or sequential)
- Phase 3.5: Smart retry for failed modules

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

from scanning.pipeline.base import Phase, PhaseResult, PhaseStatus, ScanContext
from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.modules import ScanModule

logger = get_logger(__name__)


@dataclass
class ExecutionConfig:
    """Configuration for module execution phase."""

    concurrent: int = 10
    enable_smart_retry: bool = True
    retry_threshold: float = 0.3  # Retry modules with >30% error rate
    max_retries: int = 2
    timeout_per_module: float = 300.0


class ModuleExecutionPhase(Phase):
    """
    Module execution phase.

    Orchestrates the execution of scanner modules with:
    - Parallel execution with concurrency control
    - Smart retry for failed modules
    - Result aggregation
    """

    def __init__(
        self,
        scanners: list["ScanModule"],
        config: Optional[ExecutionConfig] = None,
    ):
        super().__init__("ModuleExecutionPhase")
        self.scanners = scanners
        self.config = config or ExecutionConfig()
        self._module_results: dict[str, Any] = {}
        self._module_errors: dict[str, dict] = {}

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute scanner modules."""
        findings_count = 0
        modules_run = 0
        modules_failed = 0

        try:
            module_names = [s.name for s in self.scanners]
            logger.info(f"[Execution] Starting {len(module_names)} modules on {context.target_url}")

            # Phase 3: Execute modules
            results = await self._execute_modules(context, module_names)
            modules_run = len(results)

            # Aggregate findings
            for name, result in results.items():
                self._module_results[name] = result
                if result.get("success"):
                    findings = result.get("findings", [])
                    context.add_findings(findings)
                    findings_count += len(findings)
                else:
                    modules_failed += 1
                    self._module_errors[name] = result.get("error", {})

            # Phase 3.5: Smart Retry
            if self.config.enable_smart_retry:
                retry_findings = await self._smart_retry(context, results)
                context.add_findings(retry_findings)
                findings_count += len(retry_findings)

            logger.info(
                f"[Execution] Complete: {modules_run} modules, "
                f"{findings_count} findings, {modules_failed} failures"
            )

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.COMPLETED,
                findings_count=findings_count,
                data={
                    "modules_run": modules_run,
                    "modules_failed": modules_failed,
                    "findings": findings_count,
                    "module_results": self._get_module_summary(),
                },
            )

        except Exception as e:
            logger.error(f"[Execution] Failed: {e}")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message=str(e),
                findings_count=findings_count,
            )

    async def _execute_modules(
        self,
        context: ScanContext,
        module_names: list[str],
    ) -> dict[str, Any]:
        """Execute modules with concurrency control."""
        results = {}
        semaphore = asyncio.Semaphore(self.config.concurrent)

        async def run_module(scanner: "ScanModule") -> tuple[str, dict]:
            async with semaphore:
                try:
                    # Build module context
                    module_ctx = self._build_module_context(context, scanner)

                    # Execute with timeout
                    result = await asyncio.wait_for(
                        scanner.scan(context.target_url, module_ctx),
                        timeout=self.config.timeout_per_module,
                    )

                    return scanner.name, {
                        "success": True,
                        "findings": result.findings if hasattr(result, "findings") else [],
                        "info": result.info if hasattr(result, "info") else [],
                    }

                except asyncio.TimeoutError:
                    return scanner.name, {
                        "success": False,
                        "error": {"type": "timeout", "timeout": self.config.timeout_per_module},
                    }
                except Exception as e:
                    return scanner.name, {
                        "success": False,
                        "error": {"type": "exception", "message": str(e)},
                    }

        # Execute all modules
        tasks = [run_module(s) for s in self.scanners if s.name in module_names]
        completed = await asyncio.gather(*tasks, return_exceptions=True)

        for item in completed:
            if isinstance(item, Exception):
                logger.error(f"[Execution] Module task failed: {item}")
            elif isinstance(item, tuple) and len(item) == 2:
                name, result = item
                results[name] = result

        return results

    def _build_module_context(self, context: ScanContext, scanner: "ScanModule") -> dict[str, Any]:
        """Build context dict for a scanner module."""
        return {
            "target_url": context.target_url,
            "target_host": context.target_host,
            "endpoints": context.endpoints,
            "auth_headers": context.auth_headers,
            "auth_cookies": context.auth_cookies,
            "is_authenticated": context.is_authenticated,
            "tech_stack": context.tech_stack,
            "server": context.server,
            "framework": context.framework,
            "waf_detected": context.waf_detected,
            "waf_type": context.waf_type,
            "metadata": context.metadata,
        }

    async def _smart_retry(
        self,
        context: ScanContext,
        results: dict[str, Any],
    ) -> list[Any]:
        """Retry modules that had high error rates."""
        retry_findings = []

        # Identify modules to retry
        modules_to_retry = []
        for name, result in results.items():
            if not result.get("success"):
                error = result.get("error", {})
                error_type = error.get("type", "unknown")

                # Retry timeout and rate-limit errors
                if error_type in ("timeout", "rate_limited"):
                    modules_to_retry.append(name)

        if not modules_to_retry:
            return []

        logger.info(f"[SmartRetry] Retrying {len(modules_to_retry)} modules")

        # Get scanners to retry
        retry_scanners = [s for s in self.scanners if s.name in modules_to_retry]

        # Retry with backoff
        for attempt in range(self.config.max_retries):
            if not retry_scanners:
                break

            # Exponential backoff
            backoff = 5 * (2 ** attempt)
            await asyncio.sleep(backoff)

            retry_results = await self._execute_modules(
                context,
                [s.name for s in retry_scanners],
            )

            # Collect successful results
            still_failing = []
            for scanner in retry_scanners:
                result = retry_results.get(scanner.name, {})
                if result.get("success"):
                    findings = result.get("findings", [])
                    retry_findings.extend(findings)
                    logger.info(f"[SmartRetry] {scanner.name} succeeded with {len(findings)} findings")
                else:
                    still_failing.append(scanner)

            retry_scanners = still_failing

        return retry_findings

    def _get_module_summary(self) -> dict[str, dict]:
        """Get summary of module results."""
        summary = {}
        for name, result in self._module_results.items():
            summary[name] = {
                "success": result.get("success", False),
                "findings_count": len(result.get("findings", [])),
            }
            if not result.get("success"):
                summary[name]["error_type"] = result.get("error", {}).get("type", "unknown")
        return summary
