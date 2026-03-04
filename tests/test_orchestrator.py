"""
Tests for the scanning/orchestrator/ module.

Tests CircuitBreaker, ExecutionConfig, and related components.
"""

import pytest
import asyncio
from unittest.mock import Mock, MagicMock

from scanning.orchestrator import (
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitBreakerManager,
    get_circuit_breaker_manager,
    reset_circuit_breaker_manager,
    TimeoutConfig,
    JitterConfig,
    ConcurrencyConfig,
    ExecutionConfig,
    HEAVY_MODULES,
    BROWSER_MODULES,
    STATEFUL_MODULES,
    EXTERNAL_MODULES,
    is_heavy_module,
    is_browser_module,
    is_stateful_module,
    is_external_module,
)


class TestCircuitBreakerConfig:
    """Tests for CircuitBreakerConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CircuitBreakerConfig()
        assert config.max_consecutive_blocks == 3
        assert config.pause_duration == 30.0
        assert config.max_backoff_multiplier == 8

    def test_custom_values(self):
        """Test custom configuration values."""
        config = CircuitBreakerConfig(
            max_consecutive_blocks=5,
            pause_duration=60.0,
            max_backoff_multiplier=16,
        )
        assert config.max_consecutive_blocks == 5
        assert config.pause_duration == 60.0
        assert config.max_backoff_multiplier == 16

    def test_from_settings_with_valid_settings(self):
        """Test creating config from settings object."""
        settings = Mock()
        settings.scan_execution = Mock()
        settings.scan_execution.circuit_breaker = Mock()
        settings.scan_execution.circuit_breaker.max_consecutive_blocks = 10
        settings.scan_execution.circuit_breaker.pause_duration = 45
        settings.scan_execution.circuit_breaker.max_backoff_multiplier = 4

        config = CircuitBreakerConfig.from_settings(settings)
        assert config.max_consecutive_blocks == 10
        assert config.pause_duration == 45
        assert config.max_backoff_multiplier == 4

    def test_from_settings_with_dict(self):
        """Test creating config from dict-based settings."""
        settings = Mock()
        settings.scan_execution = {
            'circuit_breaker': {
                'max_consecutive_blocks': 7,
                'pause_duration': 20,
                'max_backoff_multiplier': 6,
            }
        }

        config = CircuitBreakerConfig.from_settings(settings)
        assert config.max_consecutive_blocks == 7
        assert config.pause_duration == 20
        assert config.max_backoff_multiplier == 6

    def test_from_settings_fallback_to_defaults(self):
        """Test config falls back to defaults on missing settings."""
        settings = Mock()
        settings.scan_execution = None

        config = CircuitBreakerConfig.from_settings(settings)
        assert config.max_consecutive_blocks == 3
        assert config.pause_duration == 30.0


class TestCircuitBreakerState:
    """Tests for CircuitBreakerState."""

    def test_default_state(self):
        """Test default state values."""
        state = CircuitBreakerState()
        assert state.consecutive_blocks == 0
        assert state.is_paused is False
        assert state.total_pauses == 0
        assert state.max_consecutive == 3
        assert state.pause_duration == 30.0

    def test_custom_state(self):
        """Test custom state values."""
        state = CircuitBreakerState(
            consecutive_blocks=2,
            is_paused=True,
            total_pauses=1,
            max_consecutive=5,
            pause_duration=60.0,
        )
        assert state.consecutive_blocks == 2
        assert state.is_paused is True
        assert state.total_pauses == 1


class TestCircuitBreakerManager:
    """Tests for CircuitBreakerManager."""

    def setup_method(self):
        """Reset manager before each test."""
        reset_circuit_breaker_manager()

    def teardown_method(self):
        """Reset manager after each test."""
        reset_circuit_breaker_manager()

    @pytest.mark.asyncio
    async def test_get_state_creates_new(self):
        """Test get_state creates new state for unknown target."""
        manager = CircuitBreakerManager()
        state = await manager.get_state("https://example.com")

        assert state.consecutive_blocks == 0
        assert state.is_paused is False

    @pytest.mark.asyncio
    async def test_get_state_returns_existing(self):
        """Test get_state returns existing state for known target."""
        manager = CircuitBreakerManager()
        state1 = await manager.get_state("https://example.com")
        state1.consecutive_blocks = 5

        state2 = await manager.get_state("https://example.com")
        assert state2.consecutive_blocks == 5

    @pytest.mark.asyncio
    async def test_cleanup_removes_state(self):
        """Test cleanup removes state for target."""
        manager = CircuitBreakerManager()
        await manager.get_state("https://example.com")
        await manager.cleanup("https://example.com")

        # Should create new state (not find existing)
        state = await manager.get_state("https://example.com")
        assert state.consecutive_blocks == 0

    @pytest.mark.asyncio
    async def test_record_block_increments_counter(self):
        """Test record_block increments consecutive_blocks."""
        manager = CircuitBreakerManager()
        await manager.get_state("https://example.com")

        await manager.record_block("https://example.com")
        await manager.record_block("https://example.com")

        state = await manager.get_state("https://example.com")
        assert state.consecutive_blocks == 2

    @pytest.mark.asyncio
    async def test_record_success_resets_counter(self):
        """Test record_success resets consecutive_blocks."""
        manager = CircuitBreakerManager()
        state = await manager.get_state("https://example.com")
        state.consecutive_blocks = 5

        await manager.record_success("https://example.com")

        state = await manager.get_state("https://example.com")
        assert state.consecutive_blocks == 0

    def test_get_stats_unknown_target(self):
        """Test get_stats returns defaults for unknown target."""
        manager = CircuitBreakerManager()
        stats = manager.get_stats("https://unknown.com")

        assert stats["consecutive_blocks"] == 0
        assert stats["is_paused"] is False
        assert stats["total_pauses"] == 0

    @pytest.mark.asyncio
    async def test_get_stats_known_target(self):
        """Test get_stats returns correct values for known target."""
        manager = CircuitBreakerManager()
        state = await manager.get_state("https://example.com")
        state.consecutive_blocks = 3
        state.total_pauses = 2

        stats = manager.get_stats("https://example.com")
        assert stats["consecutive_blocks"] == 3
        assert stats["total_pauses"] == 2


class TestCircuitBreakerManagerGlobal:
    """Tests for global circuit breaker manager."""

    def setup_method(self):
        """Reset manager before each test."""
        reset_circuit_breaker_manager()

    def teardown_method(self):
        """Reset manager after each test."""
        reset_circuit_breaker_manager()

    def test_get_circuit_breaker_manager_singleton(self):
        """Test get_circuit_breaker_manager returns singleton."""
        manager1 = get_circuit_breaker_manager()
        manager2 = get_circuit_breaker_manager()

        assert manager1 is manager2

    def test_reset_circuit_breaker_manager(self):
        """Test reset clears the singleton."""
        manager1 = get_circuit_breaker_manager()
        reset_circuit_breaker_manager()
        manager2 = get_circuit_breaker_manager()

        assert manager1 is not manager2


class TestTimeoutConfig:
    """Tests for TimeoutConfig."""

    def test_default_values(self):
        """Test default timeout values."""
        config = TimeoutConfig()
        assert config.heavy_timeout == 900.0
        assert config.normal_timeout == 600.0

    def test_get_timeout_for_heavy_module(self):
        """Test heavy modules get longer timeout."""
        config = TimeoutConfig(heavy_timeout=1000, normal_timeout=500)

        assert config.get_timeout_for_module("sqli") == 1000
        assert config.get_timeout_for_module("xss") == 1000

    def test_get_timeout_for_normal_module(self):
        """Test normal modules get standard timeout."""
        config = TimeoutConfig(heavy_timeout=1000, normal_timeout=500)

        assert config.get_timeout_for_module("headers") == 500
        assert config.get_timeout_for_module("ssl") == 500


class TestJitterConfig:
    """Tests for JitterConfig."""

    def test_default_values(self):
        """Test default jitter values."""
        config = JitterConfig()
        assert config.min_delay == 0.1
        assert config.max_delay == 0.5
        assert config.gaussian_sigma == 0.2

    def test_get_delay_returns_positive(self):
        """Test get_delay returns positive value."""
        config = JitterConfig()

        for _ in range(100):
            delay = config.get_delay()
            assert delay >= 0.05  # Minimum enforced delay

    def test_get_delay_respects_bounds(self):
        """Test get_delay stays roughly within bounds."""
        config = JitterConfig(min_delay=0.1, max_delay=0.2, gaussian_sigma=0.1)

        delays = [config.get_delay() for _ in range(100)]
        avg = sum(delays) / len(delays)

        # Average should be roughly between min and max
        assert 0.05 <= avg <= 0.5


class TestConcurrencyConfig:
    """Tests for ConcurrencyConfig."""

    def test_default_values(self):
        """Test default concurrency values."""
        config = ConcurrencyConfig()
        assert config.default_concurrency == 10
        assert config.waf_reduced_concurrency == 2
        assert config.rate_limited_concurrency == 3

    def test_get_effective_concurrency_normal(self):
        """Test normal concurrency without WAF/rate limiting."""
        config = ConcurrencyConfig()
        result = config.get_effective_concurrency(10)
        assert result == 10

    def test_get_effective_concurrency_waf_detected(self):
        """Test reduced concurrency when WAF detected."""
        config = ConcurrencyConfig(waf_reduced_concurrency=2)
        result = config.get_effective_concurrency(10, waf_detected=True)
        assert result == 5  # max(2, 10 // 2)

    def test_get_effective_concurrency_rate_limited(self):
        """Test reduced concurrency when rate limited."""
        config = ConcurrencyConfig(rate_limited_concurrency=3)
        result = config.get_effective_concurrency(10, rate_limited=True)
        assert result == 3  # max(3, 10 // 3)


class TestExecutionConfig:
    """Tests for ExecutionConfig."""

    def test_default_values(self):
        """Test default combined config."""
        config = ExecutionConfig()

        assert isinstance(config.timeout, TimeoutConfig)
        assert isinstance(config.jitter, JitterConfig)
        assert isinstance(config.concurrency, ConcurrencyConfig)

    def test_from_settings(self):
        """Test creating from settings."""
        settings = Mock()
        settings.timeouts = Mock()
        settings.timeouts.module_heavy = 1200
        settings.timeouts.module_normal = 800
        settings.scan_execution = {}

        config = ExecutionConfig.from_settings(settings)

        assert config.timeout.heavy_timeout == 1200
        assert config.timeout.normal_timeout == 800


class TestModuleCategories:
    """Tests for module categorization."""

    def test_heavy_modules(self):
        """Test HEAVY_MODULES contains expected modules."""
        assert "sqli" in HEAVY_MODULES
        assert "xss" in HEAVY_MODULES
        assert "cmdi" in HEAVY_MODULES

    def test_browser_modules(self):
        """Test BROWSER_MODULES contains expected modules."""
        assert "dom_xss" in BROWSER_MODULES

    def test_stateful_modules(self):
        """Test STATEFUL_MODULES contains expected modules."""
        assert "business_logic" in STATEFUL_MODULES
        assert "session_abuse" in STATEFUL_MODULES

    def test_external_modules(self):
        """Test EXTERNAL_MODULES contains expected modules."""
        assert "nuclei" in EXTERNAL_MODULES
        assert "linux_tools" in EXTERNAL_MODULES

    def test_is_heavy_module(self):
        """Test is_heavy_module function."""
        assert is_heavy_module("sqli") is True
        assert is_heavy_module("headers") is False

    def test_is_browser_module(self):
        """Test is_browser_module function."""
        assert is_browser_module("dom_xss") is True
        assert is_browser_module("sqli") is False

    def test_is_stateful_module(self):
        """Test is_stateful_module function."""
        assert is_stateful_module("business_logic") is True
        assert is_stateful_module("sqli") is False

    def test_is_external_module(self):
        """Test is_external_module function."""
        assert is_external_module("nuclei") is True
        assert is_external_module("xss") is False


class TestOrchestratorIntegration:
    """Integration tests for orchestrator with FullScanner."""

    def test_fullscanner_uses_circuit_breaker(self):
        """Test that FullScanner uses circuit breaker from orchestrator."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        # Verify the _get_cb_manager method exists
        assert hasattr(scanner, '_get_cb_manager')
        assert callable(scanner._get_cb_manager)

    @pytest.mark.asyncio
    async def test_fullscanner_circuit_breaker_state(self):
        """Test that FullScanner circuit breaker returns state dict."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        reset_circuit_breaker_manager()

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        state = await scanner._get_circuit_breaker("https://test.com")

        assert isinstance(state, dict)
        assert "consecutive_blocks" in state
        assert "is_paused" in state
        assert "total_pauses" in state

    @pytest.mark.asyncio
    async def test_fullscanner_circuit_breaker_cleanup(self):
        """Test that FullScanner can cleanup circuit breaker."""
        from scanning.full_scanner import FullScanner
        from core.config_manager import Settings

        reset_circuit_breaker_manager()

        settings = Settings()
        scanner = FullScanner(settings, safe_mode="safe")

        await scanner._get_circuit_breaker("https://test.com")
        await scanner._cleanup_circuit_breaker("https://test.com")

        # No error should occur
