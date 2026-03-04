"""
Tests for scanning/module_executor/ module.

Tests ModuleRunner, ModuleOrchestrator, and interface categorization.
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from dataclasses import dataclass

from scanning.module_executor import (
    # Interfaces
    ModuleInterface,
    OLD_3ARG_MODULES,
    STRING_ENDPOINTS_MODULES,
    TYPED_ENDPOINTS_MODULES,
    TWO_ARG_MODULES,
    PORT_PARAMS_MODULES,
    SIMPLE_INTERFACE_MODULES,
    HEAVY_MODULES,
    get_module_interface,
    is_heavy_module,
    is_signature_mismatch,
    # Runner
    RunnerConfig,
    RunContext,
    ModuleRunner,
    run_module,
    # Orchestrator
    OrchestratorConfig,
    CircuitBreakerState,
    ModuleResult,
    CircuitBreaker,
    ModuleOrchestrator,
    execute_modules,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Interface Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestModuleInterface:
    """Tests for ModuleInterface enum."""

    def test_interface_values(self):
        """Test that all interface types exist."""
        assert ModuleInterface.OLD_3ARG
        assert ModuleInterface.STRING_ENDPOINTS
        assert ModuleInterface.TYPED_ENDPOINTS
        assert ModuleInterface.TWO_ARG
        assert ModuleInterface.PORT_PARAMS
        assert ModuleInterface.SIMPLE


class TestModuleSets:
    """Tests for module categorization sets."""

    def test_old_3arg_modules_not_empty(self):
        """Test OLD_3ARG_MODULES contains modules."""
        assert len(OLD_3ARG_MODULES) > 0
        assert "sqli" in OLD_3ARG_MODULES
        assert "xss" in OLD_3ARG_MODULES
        assert "auth" in OLD_3ARG_MODULES

    def test_string_endpoints_modules(self):
        """Test STRING_ENDPOINTS_MODULES."""
        assert "jwt" in STRING_ENDPOINTS_MODULES
        assert "cookie" in STRING_ENDPOINTS_MODULES

    def test_typed_endpoints_modules(self):
        """Test TYPED_ENDPOINTS_MODULES."""
        assert "race" in TYPED_ENDPOINTS_MODULES

    def test_two_arg_modules(self):
        """Test TWO_ARG_MODULES."""
        assert "firebase" in TWO_ARG_MODULES
        assert "backend" in TWO_ARG_MODULES

    def test_port_params_modules(self):
        """Test PORT_PARAMS_MODULES."""
        assert "client_hardening" in PORT_PARAMS_MODULES
        assert "token_binding" in PORT_PARAMS_MODULES

    def test_heavy_modules(self):
        """Test HEAVY_MODULES."""
        assert "sqli" in HEAVY_MODULES
        assert "xss" in HEAVY_MODULES
        assert "graphql" in HEAVY_MODULES

    def test_no_overlap_between_categories(self):
        """Test that module categories don't overlap."""
        all_categorized = (
            STRING_ENDPOINTS_MODULES
            | TYPED_ENDPOINTS_MODULES
            | TWO_ARG_MODULES
            | PORT_PARAMS_MODULES
            | SIMPLE_INTERFACE_MODULES
        )
        # OLD_3ARG is the default, so it can overlap with empty categories
        # But the specialized categories should not overlap
        assert not (STRING_ENDPOINTS_MODULES & TYPED_ENDPOINTS_MODULES)
        assert not (STRING_ENDPOINTS_MODULES & TWO_ARG_MODULES)
        assert not (TYPED_ENDPOINTS_MODULES & PORT_PARAMS_MODULES)


class TestGetModuleInterface:
    """Tests for get_module_interface function."""

    def test_get_old_3arg_interface(self):
        """Test getting OLD_3ARG interface."""
        assert get_module_interface("sqli") == ModuleInterface.OLD_3ARG
        assert get_module_interface("xss") == ModuleInterface.OLD_3ARG

    def test_get_string_endpoints_interface(self):
        """Test getting STRING_ENDPOINTS interface."""
        assert get_module_interface("jwt") == ModuleInterface.STRING_ENDPOINTS
        assert get_module_interface("cookie") == ModuleInterface.STRING_ENDPOINTS

    def test_get_typed_endpoints_interface(self):
        """Test getting TYPED_ENDPOINTS interface."""
        assert get_module_interface("race") == ModuleInterface.TYPED_ENDPOINTS

    def test_get_two_arg_interface(self):
        """Test getting TWO_ARG interface."""
        assert get_module_interface("firebase") == ModuleInterface.TWO_ARG

    def test_get_port_params_interface(self):
        """Test getting PORT_PARAMS interface."""
        assert get_module_interface("client_hardening") == ModuleInterface.PORT_PARAMS

    def test_unknown_defaults_to_old_3arg(self):
        """Test that unknown modules default to OLD_3ARG."""
        assert get_module_interface("unknown_module") == ModuleInterface.OLD_3ARG


class TestIsHeavyModule:
    """Tests for is_heavy_module function."""

    def test_heavy_modules_return_true(self):
        """Test heavy modules return True."""
        assert is_heavy_module("sqli") is True
        assert is_heavy_module("xss") is True
        assert is_heavy_module("graphql") is True

    def test_non_heavy_modules_return_false(self):
        """Test non-heavy modules return False."""
        assert is_heavy_module("cors") is False
        assert is_heavy_module("headers") is False
        assert is_heavy_module("unknown") is False


class TestIsSignatureMismatch:
    """Tests for is_signature_mismatch function."""

    def test_positional_argument_error(self):
        """Test detection of positional argument errors."""
        err = TypeError("scan() takes 2 positional arguments but 3 were given")
        assert is_signature_mismatch(err) is True

    def test_required_argument_error(self):
        """Test detection of required argument errors."""
        err = TypeError("scan() missing 1 required argument: 'target'")
        assert is_signature_mismatch(err) is True

    def test_unexpected_keyword_error(self):
        """Test detection of unexpected keyword errors."""
        err = TypeError("scan() got an unexpected keyword argument 'foo'")
        assert is_signature_mismatch(err) is True

    def test_non_signature_error(self):
        """Test that non-signature errors return False."""
        err = TypeError("'NoneType' object is not subscriptable")
        assert is_signature_mismatch(err) is False

    def test_other_type_error(self):
        """Test other TypeErrors return False."""
        err = TypeError("unsupported operand type(s)")
        assert is_signature_mismatch(err) is False


# ═══════════════════════════════════════════════════════════════════════════════
# Runner Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunnerConfig:
    """Tests for RunnerConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RunnerConfig()
        assert config.default_rate == 10.0
        assert config.default_burst == 20
        assert config.safe_mode is False
        assert config.inject_rate_limiter is True
        assert config.inject_auth_context is True

    def test_custom_config(self):
        """Test custom configuration values."""
        config = RunnerConfig(
            default_rate=5.0,
            default_burst=10,
            safe_mode=True,
        )
        assert config.default_rate == 5.0
        assert config.default_burst == 10
        assert config.safe_mode is True


class TestRunContext:
    """Tests for RunContext."""

    def test_basic_context(self):
        """Test basic context creation."""
        ctx = RunContext(
            target="http://example.com",
            module_name="sqli",
            module_instance=Mock(),
        )
        assert ctx.target == "http://example.com"
        assert ctx.module_name == "sqli"
        assert ctx.result is None
        assert ctx.error is None


class TestModuleRunner:
    """Tests for ModuleRunner class."""

    def test_init_default(self):
        """Test default initialization."""
        runner = ModuleRunner()
        assert runner.config.default_rate == 10.0
        assert runner.safe_scanner is None

    def test_init_with_config(self):
        """Test initialization with config."""
        config = RunnerConfig(safe_mode=True)
        runner = ModuleRunner(config=config)
        assert runner.config.safe_mode is True

    def test_check_safe_mode_no_scanner(self):
        """Test safe mode check without scanner."""
        runner = ModuleRunner()
        can_run, skip = runner.check_safe_mode("sqli")
        assert can_run is True
        assert skip is None

    def test_check_safe_mode_allowed(self):
        """Test safe mode check when allowed."""
        safe_scanner = Mock()
        safe_scanner.is_operation_allowed.return_value = True
        runner = ModuleRunner(safe_scanner=safe_scanner)

        can_run, skip = runner.check_safe_mode("sqli")
        assert can_run is True
        assert skip is None

    def test_check_safe_mode_blocked(self):
        """Test safe mode check when blocked."""
        safe_scanner = Mock()
        safe_scanner.is_operation_allowed.return_value = False
        runner = ModuleRunner(safe_scanner=safe_scanner)

        can_run, skip = runner.check_safe_mode("sqli")
        assert can_run is False
        assert skip is not None
        assert skip["findings"] == []

    def test_set_module_safe_mode(self):
        """Test setting safe mode on module."""
        module = Mock()
        runner = ModuleRunner(config=RunnerConfig(safe_mode=True))

        runner.set_module_safe_mode(module)
        module.set_safe_mode.assert_called_once_with(True)

    def test_set_module_safe_mode_no_method(self):
        """Test setting safe mode on module without method."""
        module = Mock(spec=[])  # No set_safe_mode method
        runner = ModuleRunner()

        # Should not raise
        runner.set_module_safe_mode(module)

    def test_inject_rate_limiter(self):
        """Test injecting rate limiter."""
        module = Mock()
        rate_limiter = Mock()
        runner = ModuleRunner()

        runner.inject_module_attributes(module, "jwt", rate_limiter)
        assert module.rate_limiter == rate_limiter

    def test_inject_auth_context_race(self):
        """Test injecting auth context for race module."""
        module = Mock()
        auth_context = Mock()
        runner = ModuleRunner()

        runner.inject_module_attributes(module, "race", Mock(), auth_context)
        assert module._auth_context == auth_context

    def test_normalize_result_dict(self):
        """Test normalizing dict result."""
        runner = ModuleRunner()
        raw = {"findings": [{"type": "sqli"}], "info": [{"msg": "test"}]}

        result = runner.normalize_result(raw, "sqli", safe_mode=True)

        assert len(result["findings"]) == 1
        assert result["findings"][0]["module"] == "sqli"
        assert result["findings"][0]["safe_mode"] is True

    def test_normalize_result_list(self):
        """Test normalizing list result."""
        runner = ModuleRunner()
        raw = [{"type": "xss"}]

        result = runner.normalize_result(raw, "xss")

        assert len(result["findings"]) == 1
        assert result["findings"][0]["module"] == "xss"

    @pytest.mark.asyncio
    async def test_execute_module_old_3arg(self):
        """Test executing OLD_3ARG module."""
        module = Mock()
        module.scan = AsyncMock(return_value={"findings": []})
        runner = ModuleRunner()

        result = await runner.execute_module(
            module, "sqli", "http://x.com", {"endpoints": []}, Mock()
        )

        module.scan.assert_called_once()
        # Should be called with 3 args
        assert len(module.scan.call_args[0]) == 3

    @pytest.mark.asyncio
    async def test_execute_module_string_endpoints(self):
        """Test executing STRING_ENDPOINTS module."""
        module = Mock()
        module.scan = AsyncMock(return_value={"findings": []})
        runner = ModuleRunner()

        result = await runner.execute_module(
            module, "jwt", "http://x.com", {"endpoints": ["a", "b"]}, Mock()
        )

        module.scan.assert_called_once()
        # Should be called with endpoints kwarg
        assert "endpoints" in module.scan.call_args[1]

    @pytest.mark.asyncio
    async def test_execute_module_typed_endpoints(self):
        """Test executing TYPED_ENDPOINTS module."""
        module = Mock()
        module.scan = AsyncMock(return_value={"findings": []})
        runner = ModuleRunner()

        result = await runner.execute_module(
            module, "race", "http://x.com", {}, Mock()
        )

        module.scan.assert_called_once()
        # Should be called with just target
        assert len(module.scan.call_args[0]) == 1

    @pytest.mark.asyncio
    async def test_execute_module_no_scan_method(self):
        """Test executing module without scan method."""
        module = Mock(spec=["run"])
        module.run = AsyncMock(return_value={"findings": []})
        runner = ModuleRunner()

        result = await runner.execute_module(
            module, "custom", "http://x.com", {}, Mock()
        )

        module.run.assert_called_once_with("http://x.com")

    @pytest.mark.asyncio
    async def test_run_full(self):
        """Test full run method."""
        module = Mock()
        module.scan = AsyncMock(return_value={"findings": [{"type": "sqli"}]})
        runner = ModuleRunner()

        result = await runner.run(
            module=module,
            module_name="sqli",
            target="http://x.com",
            asset_data={"endpoints": ["http://x.com"]},
        )

        assert len(result["findings"]) == 1
        assert result["findings"][0]["module"] == "sqli"

    @pytest.mark.asyncio
    async def test_run_null_module(self):
        """Test running with null module."""
        runner = ModuleRunner()

        result = await runner.run(
            module=None,
            module_name="test",
            target="http://x.com",
            asset_data={},
        )

        assert result == {"findings": [], "info": []}


class TestRunModuleFunction:
    """Tests for run_module convenience function."""

    @pytest.mark.asyncio
    async def test_run_module_simple(self):
        """Test run_module function."""
        module = Mock()
        module.scan = AsyncMock(return_value={"findings": []})

        result = await run_module(
            module=module,
            module_name="sqli",
            target="http://x.com",
            asset_data={},
        )

        assert result["findings"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Orchestrator Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestOrchestratorConfig:
    """Tests for OrchestratorConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = OrchestratorConfig()
        assert config.concurrent == 5
        assert config.timeout_heavy == 900.0
        assert config.timeout_normal == 600.0
        assert config.cb_max_consecutive == 3

    def test_custom_config(self):
        """Test custom configuration."""
        config = OrchestratorConfig(
            concurrent=10,
            timeout_heavy=600.0,
            waf_concurrent_reduction=True,
        )
        assert config.concurrent == 10
        assert config.timeout_heavy == 600.0
        assert config.waf_concurrent_reduction is True


class TestCircuitBreakerState:
    """Tests for CircuitBreakerState."""

    def test_default_state(self):
        """Test default state."""
        state = CircuitBreakerState()
        assert state.consecutive_blocks == 0
        assert state.is_paused is False
        assert state.total_pauses == 0


class TestModuleResult:
    """Tests for ModuleResult."""

    def test_basic_result(self):
        """Test basic result creation."""
        result = ModuleResult(
            module_name="sqli",
            findings=[{"type": "sqli"}],
            elapsed=5.0,
        )
        assert result.module_name == "sqli"
        assert len(result.findings) == 1
        assert result.elapsed == 5.0
        assert result.error is None

    def test_result_with_error(self):
        """Test result with error."""
        result = ModuleResult(
            module_name="test",
            error="timeout",
            partial=True,
        )
        assert result.error == "timeout"
        assert result.partial is True

    def test_to_dict(self):
        """Test to_dict conversion."""
        result = ModuleResult(
            module_name="sqli",
            findings=[{"type": "sqli"}],
            rate_limited=True,
        )
        d = result.to_dict()
        assert d["findings"] == [{"type": "sqli"}]
        assert d["rate_limited"] is True


class TestCircuitBreaker:
    """Tests for CircuitBreaker class."""

    def test_init(self):
        """Test initialization."""
        config = OrchestratorConfig()
        cb = CircuitBreaker(config)
        assert cb.state.consecutive_blocks == 0

    @pytest.mark.asyncio
    async def test_record_block(self):
        """Test recording a block."""
        config = OrchestratorConfig()
        cb = CircuitBreaker(config)

        await cb.record_block()
        assert cb.state.consecutive_blocks == 1

        await cb.record_block()
        assert cb.state.consecutive_blocks == 2

    @pytest.mark.asyncio
    async def test_record_success_resets(self):
        """Test that success resets counter."""
        config = OrchestratorConfig()
        cb = CircuitBreaker(config)

        await cb.record_block()
        await cb.record_block()
        assert cb.state.consecutive_blocks == 2

        await cb.record_success()
        assert cb.state.consecutive_blocks == 0

    @pytest.mark.asyncio
    async def test_check_no_pause(self):
        """Test check when not paused."""
        config = OrchestratorConfig(cb_max_consecutive=5)
        cb = CircuitBreaker(config)

        await cb.record_block()
        await cb.check()  # Should not pause

        assert cb.state.is_paused is False


class TestModuleOrchestrator:
    """Tests for ModuleOrchestrator class."""

    def test_init_default(self):
        """Test default initialization."""
        orch = ModuleOrchestrator()
        assert orch.config.concurrent == 5
        assert orch.module_instances == {}

    def test_init_with_config(self):
        """Test initialization with config."""
        config = OrchestratorConfig(concurrent=10)
        orch = ModuleOrchestrator(config=config)
        assert orch.config.concurrent == 10

    def test_checkpoint_finding(self):
        """Test checkpointing a finding."""
        orch = ModuleOrchestrator()

        orch.checkpoint_finding("sqli", {"type": "sqli"})
        orch.checkpoint_finding("sqli", {"type": "sqli2"})

        assert len(orch._checkpoints["sqli"]) == 2

    def test_get_timeout_adaptive(self):
        """Test getting timeout with adaptive manager."""
        timeout_manager = Mock()
        timeout_manager.get_timeout_for_module.return_value = 450.0

        orch = ModuleOrchestrator(timeout_manager=timeout_manager)

        timeout = orch.get_timeout("sqli")
        assert timeout == 450.0

    def test_get_timeout_fixed_heavy(self):
        """Test getting fixed timeout for heavy module."""
        config = OrchestratorConfig(
            use_adaptive_timeout=False,
            timeout_heavy=900.0,
            timeout_normal=600.0,
        )
        orch = ModuleOrchestrator(config=config)

        timeout = orch.get_timeout("sqli")  # Heavy module
        assert timeout == 900.0

    def test_get_timeout_fixed_normal(self):
        """Test getting fixed timeout for normal module."""
        config = OrchestratorConfig(
            use_adaptive_timeout=False,
            timeout_heavy=900.0,
            timeout_normal=600.0,
        )
        orch = ModuleOrchestrator(config=config)

        timeout = orch.get_timeout("cors")  # Normal module
        assert timeout == 600.0

    def test_calculate_jitter(self):
        """Test jitter calculation."""
        config = OrchestratorConfig(jitter_min=0.1, jitter_max=0.5)
        orch = ModuleOrchestrator(config=config)

        jitter = orch.calculate_jitter()
        assert jitter >= 0.05  # Minimum after max(0.05, ...)

    @pytest.mark.asyncio
    async def test_execute_empty_modules(self):
        """Test executing with empty module list."""
        orch = ModuleOrchestrator()

        results = await orch.execute("http://x.com", [])
        assert results == []

    @pytest.mark.asyncio
    async def test_execute_with_loader_failure(self):
        """Test executing when loader returns None."""
        orch = ModuleOrchestrator(
            module_loader=lambda name: None,
        )

        results = await orch.execute("http://x.com", ["sqli"])

        assert len(results) == 1
        assert results[0].error is not None
        assert "failed to load" in results[0].error

    @pytest.mark.asyncio
    async def test_execute_with_runner(self):
        """Test executing with runner."""
        module = Mock()

        async def mock_runner(name, target, mod):
            return {"findings": [{"type": name}], "info": []}

        orch = ModuleOrchestrator(
            module_loader=lambda name: module,
            module_runner=mock_runner,
        )

        results = await orch.execute("http://x.com", ["sqli"])

        assert len(results) == 1
        assert len(results[0].findings) == 1

    @pytest.mark.asyncio
    async def test_execute_concurrent_reduction(self):
        """Test concurrent reduction for WAF."""
        config = OrchestratorConfig(
            concurrent=10,
            waf_concurrent_reduction=True,
        )
        orch = ModuleOrchestrator(
            config=config,
            module_loader=lambda name: None,
        )

        # The reduced concurrency will be 5 (10 // 2)
        await orch.execute("http://x.com", [])
        # No assertion needed - just verify no errors


class TestExecuteModulesFunction:
    """Tests for execute_modules convenience function."""

    @pytest.mark.asyncio
    async def test_execute_modules_empty(self):
        """Test execute_modules with empty list."""
        results = await execute_modules("http://x.com", [])
        assert results == []

    @pytest.mark.asyncio
    async def test_execute_modules_with_loader(self):
        """Test execute_modules with loader."""
        module = Mock()

        async def mock_runner(name, target, mod):
            return {"findings": [], "info": []}

        results = await execute_modules(
            "http://x.com",
            ["sqli"],
            module_loader=lambda name: module,
            module_runner=mock_runner,
        )

        assert len(results) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Integration Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestModuleExecutorIntegration:
    """Integration tests for module executor."""

    @pytest.mark.asyncio
    async def test_full_execution_flow(self):
        """Test full execution flow with runner and orchestrator."""
        # Create mock module
        module = Mock()
        module.scan = AsyncMock(
            return_value={"findings": [{"type": "sqli", "severity": "HIGH"}], "info": []}
        )

        # Create shared store mock
        shared_store = Mock()
        shared_store.add_finding = AsyncMock()

        # Create orchestrator
        config = OrchestratorConfig(
            concurrent=2,
            use_adaptive_timeout=False,
            timeout_normal=5.0,
            jitter_min=0.01,
            jitter_max=0.02,
        )

        async def run_module_async(name, target, mod):
            runner = ModuleRunner()
            return await runner.run(
                module=mod,
                module_name=name,
                target=target,
                asset_data={"endpoints": [target]},
            )

        orch = ModuleOrchestrator(
            config=config,
            module_loader=lambda name: module,
            module_runner=run_module_async,
            shared_store=shared_store,
        )

        results = await orch.execute("http://example.com", ["sqli", "xss"])

        assert len(results) == 2
        # Both should have findings since same module is reused
        for result in results:
            assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_timeout_recovery(self):
        """Test that timeout recovery works."""
        # Create module that will timeout
        module = Mock()

        async def slow_scan(*args, **kwargs):
            await asyncio.sleep(10)  # Will timeout
            return {"findings": [], "info": []}

        module.scan = slow_scan

        # Set short timeout
        config = OrchestratorConfig(
            use_adaptive_timeout=False,
            timeout_normal=0.1,  # Very short
            jitter_min=0.01,
            jitter_max=0.02,
        )

        async def run_module_async(name, target, mod):
            return await mod.scan(target, {}, Mock())

        orch = ModuleOrchestrator(
            config=config,
            module_loader=lambda name: module,
            module_runner=run_module_async,
        )

        results = await orch.execute("http://x.com", ["slow"])

        assert len(results) == 1
        assert "timeout" in results[0].error.lower()

    @pytest.mark.asyncio
    async def test_error_recovery(self):
        """Test that errors are caught and reported."""
        # Create module that raises
        module = Mock()
        module.scan = AsyncMock(side_effect=ValueError("test error"))

        config = OrchestratorConfig(
            use_adaptive_timeout=False,
            timeout_normal=5.0,
            jitter_min=0.01,
            jitter_max=0.02,
        )

        async def run_module_async(name, target, mod):
            return await mod.scan(target, {}, Mock())

        orch = ModuleOrchestrator(
            config=config,
            module_loader=lambda name: module,
            module_runner=run_module_async,
        )

        results = await orch.execute("http://x.com", ["error"])

        assert len(results) == 1
        assert "test error" in results[0].error
