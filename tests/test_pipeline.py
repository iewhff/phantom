"""
Tests for the Pipeline Architecture.

Tests the core pipeline infrastructure:
- ScanContext
- Phase execution
- ScanPipeline orchestration
- Phase utilities (Conditional, Parallel, Retry)

Author: PHANTOM AI
Version: 2.0.0
"""

import asyncio
import pytest
from dataclasses import dataclass
from typing import Any

from scanning.pipeline.base import (
    Phase,
    PhaseResult,
    PhaseStatus,
    PipelineStatus,
    ScanContext,
    ScanPipeline,
    ConditionalPhase,
    ParallelPhase,
    RetryPhase,
)


# ═══════════════════════════════════════════════════════════════════════════════
# TEST FIXTURES
# ═══════════════════════════════════════════════════════════════════════════════


class MockPhase(Phase):
    """Mock phase for testing."""

    def __init__(self, name: str = "MockPhase", should_fail: bool = False):
        super().__init__(name)
        self.should_fail = should_fail
        self.executed = False
        self.execution_count = 0

    async def execute(self, context: ScanContext) -> PhaseResult:
        self.executed = True
        self.execution_count += 1

        if self.should_fail:
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message="Mock failure",
            )

        # Add a finding to context
        context.add_findings([{"type": "mock", "severity": "LOW"}])

        return PhaseResult(
            phase_name=self.name,
            status=PhaseStatus.COMPLETED,
            findings_count=1,
            data={"mock_data": True},
        )


class SlowPhase(Phase):
    """Slow phase for testing timeouts and parallelism."""

    def __init__(self, name: str = "SlowPhase", delay: float = 0.1):
        super().__init__(name)
        self.delay = delay
        self.executed = False

    async def execute(self, context: ScanContext) -> PhaseResult:
        await asyncio.sleep(self.delay)
        self.executed = True
        return PhaseResult(
            phase_name=self.name,
            status=PhaseStatus.COMPLETED,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN CONTEXT TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanContext:
    """Tests for ScanContext."""

    def test_create_context(self):
        """Test basic context creation."""
        ctx = ScanContext(
            target_url="https://example.com",
            scan_mode="full",
        )

        assert ctx.target_url == "https://example.com"
        assert ctx.scan_mode == "full"
        assert ctx.scan_id is not None
        assert len(ctx.scan_id) > 0

    def test_context_defaults(self):
        """Test default values."""
        ctx = ScanContext(target_url="https://example.com")

        assert ctx.findings == []
        assert ctx.endpoints == []
        assert ctx.is_authenticated == False
        assert ctx.auth_headers == {}
        assert ctx.auth_cookies == {}
        assert ctx.tech_stack == {}
        assert ctx.waf_detected == False

    def test_add_endpoints(self):
        """Test adding endpoints."""
        ctx = ScanContext(target_url="https://example.com")

        ctx.add_endpoints(["/api/v1", "/api/v2"])
        assert len(ctx.endpoints) == 2
        assert "/api/v1" in ctx.endpoints

        # Add duplicate - should not duplicate
        ctx.add_endpoints(["/api/v1", "/api/v3"])
        assert len(ctx.endpoints) == 3

    def test_add_findings(self):
        """Test adding findings."""
        ctx = ScanContext(target_url="https://example.com")

        finding = {"type": "sqli", "severity": "HIGH"}
        ctx.add_findings([finding])

        assert len(ctx.findings) == 1
        assert ctx.findings[0]["type"] == "sqli"

    def test_phase_completion_tracking(self):
        """Test completed phases tracking."""
        ctx = ScanContext(target_url="https://example.com")

        assert "discovery" not in ctx.completed_phases

        ctx.completed_phases.append("discovery")
        ctx.completed_phases.append("auth")

        assert "discovery" in ctx.completed_phases
        assert "auth" in ctx.completed_phases
        assert len(ctx.completed_phases) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestPhase:
    """Tests for Phase execution."""

    @pytest.mark.asyncio
    async def test_phase_execution(self):
        """Test basic phase execution."""
        phase = MockPhase("TestPhase")
        ctx = ScanContext(target_url="https://example.com")

        result = await phase.execute(ctx)

        assert phase.executed
        assert result.status == PhaseStatus.COMPLETED
        assert result.phase_name == "TestPhase"
        assert len(ctx.findings) == 1

    @pytest.mark.asyncio
    async def test_phase_failure(self):
        """Test phase failure handling."""
        phase = MockPhase("FailingPhase", should_fail=True)
        ctx = ScanContext(target_url="https://example.com")

        result = await phase.execute(ctx)

        assert phase.executed
        assert result.status == PhaseStatus.FAILED
        assert result.error_message == "Mock failure"

    @pytest.mark.asyncio
    async def test_phase_result_data(self):
        """Test phase result data."""
        phase = MockPhase("DataPhase")
        ctx = ScanContext(target_url="https://example.com")

        result = await phase.execute(ctx)

        assert result.data.get("mock_data") == True
        assert result.findings_count == 1


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestScanPipeline:
    """Tests for ScanPipeline."""

    @pytest.mark.asyncio
    async def test_empty_pipeline(self):
        """Test executing empty pipeline."""
        pipeline = ScanPipeline()
        ctx = ScanContext(target_url="https://example.com")

        result = await pipeline.execute(ctx)

        assert result.status == PipelineStatus.COMPLETED
        assert len(result.phase_results) == 0

    @pytest.mark.asyncio
    async def test_single_phase_pipeline(self):
        """Test pipeline with single phase."""
        phase = MockPhase("SinglePhase")
        pipeline = ScanPipeline().add_phase(phase)
        ctx = ScanContext(target_url="https://example.com")

        result = await pipeline.execute(ctx)

        assert result.status == PipelineStatus.COMPLETED
        assert len(result.phase_results) == 1
        assert "SinglePhase" in ctx.completed_phases

    @pytest.mark.asyncio
    async def test_multi_phase_pipeline(self):
        """Test pipeline with multiple phases."""
        phase1 = MockPhase("Phase1")
        phase2 = MockPhase("Phase2")
        phase3 = MockPhase("Phase3")

        pipeline = (
            ScanPipeline()
            .add_phase(phase1)
            .add_phase(phase2)
            .add_phase(phase3)
        )
        ctx = ScanContext(target_url="https://example.com")

        result = await pipeline.execute(ctx)

        assert result.status == PipelineStatus.COMPLETED
        assert len(result.phase_results) == 3
        assert phase1.executed
        assert phase2.executed
        assert phase3.executed

        # Verify execution order
        assert ctx.completed_phases == ["Phase1", "Phase2", "Phase3"]

    @pytest.mark.asyncio
    async def test_pipeline_continues_on_failure(self):
        """Test that pipeline continues executing after a phase fails."""
        phase1 = MockPhase("Phase1")
        phase2 = MockPhase("Phase2", should_fail=True)
        phase3 = MockPhase("Phase3")

        pipeline = (
            ScanPipeline()
            .add_phase(phase1)
            .add_phase(phase2)
            .add_phase(phase3)
        )
        ctx = ScanContext(target_url="https://example.com")

        result = await pipeline.execute(ctx)

        # Pipeline continues despite failure (collects partial results)
        assert phase1.executed
        assert phase2.executed
        assert phase3.executed  # Should still execute

    @pytest.mark.asyncio
    async def test_pipeline_findings_accumulation(self):
        """Test that findings accumulate across phases."""
        phase1 = MockPhase("Phase1")
        phase2 = MockPhase("Phase2")

        pipeline = ScanPipeline().add_phase(phase1).add_phase(phase2)
        ctx = ScanContext(target_url="https://example.com")

        await pipeline.execute(ctx)

        # Each MockPhase adds one finding
        assert len(ctx.findings) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# CONDITIONAL PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestConditionalPhase:
    """Tests for ConditionalPhase."""

    @pytest.mark.asyncio
    async def test_condition_true(self):
        """Test phase executes when condition is true."""
        inner_phase = MockPhase("InnerPhase")
        conditional = ConditionalPhase(
            inner_phase=inner_phase,
            condition=lambda ctx: True,
        )
        ctx = ScanContext(target_url="https://example.com")

        result = await conditional.execute(ctx)

        assert inner_phase.executed
        assert result.status == PhaseStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_condition_false(self):
        """Test phase is skipped when condition is false."""
        inner_phase = MockPhase("InnerPhase")
        conditional = ConditionalPhase(
            inner_phase=inner_phase,
            condition=lambda ctx: False,
        )
        ctx = ScanContext(target_url="https://example.com")

        result = await conditional.execute(ctx)

        assert not inner_phase.executed
        assert result.status == PhaseStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_condition_based_on_context(self):
        """Test condition that checks context state."""
        inner_phase = MockPhase("AuthPhase")
        conditional = ConditionalPhase(
            inner_phase=inner_phase,
            condition=lambda ctx: ctx.is_authenticated,
        )

        # Not authenticated - should skip
        ctx1 = ScanContext(target_url="https://example.com")
        result1 = await conditional.execute(ctx1)
        assert not inner_phase.executed
        assert result1.status == PhaseStatus.SKIPPED

        # Authenticated - should execute
        ctx2 = ScanContext(target_url="https://example.com")
        ctx2.is_authenticated = True
        inner_phase.executed = False  # Reset
        result2 = await conditional.execute(ctx2)
        assert inner_phase.executed
        assert result2.status == PhaseStatus.COMPLETED


# ═══════════════════════════════════════════════════════════════════════════════
# PARALLEL PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestParallelPhase:
    """Tests for ParallelPhase."""

    @pytest.mark.asyncio
    async def test_parallel_execution(self):
        """Test phases execute in parallel."""
        phase1 = SlowPhase("Slow1", delay=0.1)
        phase2 = SlowPhase("Slow2", delay=0.1)
        phase3 = SlowPhase("Slow3", delay=0.1)

        parallel = ParallelPhase(phases=[phase1, phase2, phase3])
        ctx = ScanContext(target_url="https://example.com")

        import time
        start = time.time()
        result = await parallel.execute(ctx)
        elapsed = time.time() - start

        # If parallel, should take ~0.1s, not 0.3s
        assert elapsed < 0.25  # Allow some overhead
        assert phase1.executed
        assert phase2.executed
        assert phase3.executed
        assert result.status == PhaseStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_parallel_with_failure(self):
        """Test parallel execution with one failing phase."""
        phase1 = MockPhase("Phase1")
        phase2 = MockPhase("Phase2", should_fail=True)
        phase3 = MockPhase("Phase3")

        parallel = ParallelPhase(phases=[phase1, phase2, phase3])
        ctx = ScanContext(target_url="https://example.com")

        result = await parallel.execute(ctx)

        # All phases should execute even if one fails
        assert phase1.executed
        assert phase2.executed
        assert phase3.executed
        # Result indicates failure if any phase failed
        assert result.status == PhaseStatus.FAILED
        # But data shows partial success
        assert result.data.get("successful") == 2
        assert result.data.get("failed") == 1


# ═══════════════════════════════════════════════════════════════════════════════
# RETRY PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestRetryPhase:
    """Tests for RetryPhase."""

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Test phase is retried on failure."""
        # Phase that fails first 2 times, then succeeds
        class FlakyPhase(Phase):
            def __init__(self):
                super().__init__("FlakyPhase")
                self.attempts = 0

            async def execute(self, context: ScanContext) -> PhaseResult:
                self.attempts += 1
                if self.attempts < 3:
                    return PhaseResult(
                        phase_name=self.name,
                        status=PhaseStatus.FAILED,
                        error_message=f"Attempt {self.attempts} failed",
                    )
                return PhaseResult(
                    phase_name=self.name,
                    status=PhaseStatus.COMPLETED,
                )

        flaky = FlakyPhase()
        retry = RetryPhase(inner_phase=flaky, max_retries=3)
        ctx = ScanContext(target_url="https://example.com")

        result = await retry.execute(ctx)

        assert flaky.attempts == 3
        assert result.status == PhaseStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        """Test retry gives up after max attempts."""
        always_fail = MockPhase("AlwaysFail", should_fail=True)
        retry = RetryPhase(inner_phase=always_fail, max_retries=3)
        ctx = ScanContext(target_url="https://example.com")

        result = await retry.execute(ctx)

        # 1 initial + 3 retries = 4 total attempts
        assert always_fail.execution_count == 4
        assert result.status == PhaseStatus.FAILED

    @pytest.mark.asyncio
    async def test_no_retry_on_success(self):
        """Test successful phase is not retried."""
        success_phase = MockPhase("SuccessPhase")
        retry = RetryPhase(inner_phase=success_phase, max_retries=3)
        ctx = ScanContext(target_url="https://example.com")

        result = await retry.execute(ctx)

        assert success_phase.execution_count == 1
        assert result.status == PhaseStatus.COMPLETED


# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════


class TestPipelineIntegration:
    """Integration tests for complete pipeline scenarios."""

    @pytest.mark.asyncio
    async def test_realistic_pipeline(self):
        """Test a realistic pipeline configuration."""
        # Create phases
        discovery = MockPhase("Discovery")
        auth = MockPhase("Auth")
        execution = MockPhase("Execution")
        validation = MockPhase("Validation")

        # Build pipeline
        pipeline = (
            ScanPipeline()
            .add_phase(discovery)
            .add_phase(
                ConditionalPhase(
                    inner_phase=auth,
                    condition=lambda ctx: len(ctx.findings) > 0,
                )
            )
            .add_phase(execution)
            .add_phase(validation)
        )

        ctx = ScanContext(
            target_url="https://example.com",
            scan_mode="full",
        )

        result = await pipeline.execute(ctx)

        assert result.status == PipelineStatus.COMPLETED
        assert discovery.executed
        assert auth.executed  # Condition met (discovery added findings)
        assert execution.executed
        assert validation.executed

    @pytest.mark.asyncio
    async def test_pipeline_with_parallel_scanners(self):
        """Test pipeline with parallel scanner execution."""
        # Discovery phase
        discovery = MockPhase("Discovery")

        # Parallel scanner execution
        scanner1 = MockPhase("Scanner1")
        scanner2 = MockPhase("Scanner2")
        scanner3 = MockPhase("Scanner3")
        parallel_scanners = ParallelPhase(phases=[scanner1, scanner2, scanner3])

        # Validation phase
        validation = MockPhase("Validation")

        pipeline = (
            ScanPipeline()
            .add_phase(discovery)
            .add_phase(parallel_scanners)
            .add_phase(validation)
        )

        ctx = ScanContext(target_url="https://example.com")
        result = await pipeline.execute(ctx)

        assert result.status == PipelineStatus.COMPLETED
        assert scanner1.executed
        assert scanner2.executed
        assert scanner3.executed
        # 1 from discovery + 3 from parallel (1 each) + 1 from validation = 5
        assert len(ctx.findings) == 5
