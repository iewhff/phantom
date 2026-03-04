"""
Tests for SQLi scanner strategies.

Tests cover:
- Strategy base classes (StrategyResult, StrategyContext, BaseStrategy)
- ErrorBasedStrategy
- BooleanBlindStrategy
- TimeBlindStrategy
- UnionBasedStrategy
- StackedQueriesStrategy
- OutOfBandStrategy
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

from scanning.modules.sqli.strategies.base import (
    StrategyResult,
    StrategyContext,
    BaseStrategy,
    InjectionStrategy,
)
from scanning.modules.sqli.sqli_base import (
    DatabaseType,
    DetectionMethod,
    InjectionContext,
    ResponseCluster,
    ResponseFingerprint,
    SQLiEvidence,
    WAFType,
)


class TestStrategyResult:
    """Tests for StrategyResult dataclass."""

    def test_not_found_factory(self):
        """Test StrategyResult.not_found factory method."""
        result = StrategyResult.not_found()

        assert result.found is False
        assert result.evidence is None
        assert result.attempts == 0
        assert result.errors == []

    def test_not_found_with_attempts(self):
        """Test StrategyResult.not_found with attempts count."""
        result = StrategyResult.not_found(attempts=15)

        assert result.found is False
        assert result.attempts == 15

    def test_not_found_with_errors(self):
        """Test StrategyResult.not_found with error list."""
        errors = ["Connection timeout", "Rate limited"]
        result = StrategyResult.not_found(attempts=5, errors=errors)

        assert result.found is False
        assert result.attempts == 5
        assert result.errors == errors

    def test_vulnerable_factory(self):
        """Test StrategyResult.vulnerable factory method."""
        evidence = SQLiEvidence(
            detection_method=DetectionMethod.ERROR_BASED,
            payload="' OR '1'='1",
            original_value="test",
            response_status=200,
            response_length=5000,
            response_time=0.15,
        )
        result = StrategyResult.vulnerable(evidence, attempts=10)

        assert result.found is True
        assert result.evidence is evidence
        assert result.attempts == 10
        assert result.errors == []


class TestStrategyContext:
    """Tests for StrategyContext dataclass."""

    def test_basic_creation(self):
        """Test basic StrategyContext creation."""
        injection_ctx = InjectionContext(
            url="https://example.com/search",
            method="GET",
            param_name="q",
            param_value="test",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/search",
            param_name="q",
            params={"q": ["test"]},
            injection_ctx=injection_ctx,
        )

        assert ctx.base_url == "https://example.com/search"
        assert ctx.param_name == "q"
        assert ctx.params == {"q": ["test"]}

    def test_default_values(self):
        """Test StrategyContext default values."""
        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
        )

        assert ctx.timeout == 30.0
        assert ctx.time_delay == 5
        assert ctx.max_mutations == 5
        assert ctx.max_payloads == 15
        assert ctx.detected_waf is None
        assert ctx.detected_db is None
        assert ctx.auth_headers == {}
        assert ctx.asset_data == {}

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_with_callback(self):
        """Test rate limit acquisition with callback."""
        async_mock = AsyncMock()

        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
            host="example.com",
            rate_limiter_acquire=async_mock,
        )

        await ctx.acquire_rate_limit()

        async_mock.assert_called_once_with("example.com")

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_without_callback(self):
        """Test rate limit acquisition without callback does nothing."""
        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
        )

        # Should not raise
        await ctx.acquire_rate_limit()

    def test_check_false_positive_with_callback(self):
        """Test false positive check with callback."""
        fp_mock = MagicMock(return_value=True)

        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
            is_false_positive=fp_mock,
        )

        result = ctx.check_false_positive("<html>404 Not Found</html>", 404)

        assert result is True
        fp_mock.assert_called_once_with("<html>404 Not Found</html>", 404)

    def test_check_false_positive_without_callback(self):
        """Test false positive check without callback returns False."""
        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
        )

        result = ctx.check_false_positive("content", 200)

        assert result is False


class TestBaseStrategy:
    """Tests for BaseStrategy abstract base class."""

    def test_build_test_url_append(self):
        """Test _build_test_url with append mode."""

        class ConcreteStrategy(BaseStrategy):
            @property
            def name(self):
                return "test"

            @property
            def detection_method(self):
                return DetectionMethod.ERROR_BASED

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        injection_ctx = InjectionContext(
            url="https://example.com/search",
            method="GET",
            param_name="q",
            param_value="test",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/search",
            param_name="q",
            params={"q": ["test"]},
            injection_ctx=injection_ctx,
        )

        url = strategy._build_test_url(ctx, "' OR '1'='1", append=True)

        # URL should contain original value + payload
        assert "q=test" in url or "q=test%27" in url or "test'" in url

    def test_build_test_url_replace(self):
        """Test _build_test_url with replace mode."""

        class ConcreteStrategy(BaseStrategy):
            @property
            def name(self):
                return "test"

            @property
            def detection_method(self):
                return DetectionMethod.ERROR_BASED

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        injection_ctx = InjectionContext(
            url="https://example.com/search",
            method="GET",
            param_name="q",
            param_value="test",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/search",
            param_name="q",
            params={"q": ["test"]},
            injection_ctx=injection_ctx,
        )

        url = strategy._build_test_url(ctx, "INJECTED", append=False)

        # URL should contain only payload, not original
        assert "INJECTED" in url
        assert "testINJECTED" not in url

    def test_get_mutations_with_callback(self):
        """Test _get_mutations with callback."""

        class ConcreteStrategy(BaseStrategy):
            @property
            def name(self):
                return "test"

            @property
            def detection_method(self):
                return DetectionMethod.ERROR_BASED

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        mutation_mock = MagicMock(return_value=["payload1", "payload2", "payload3"])

        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
            detected_waf=WAFType.CLOUDFLARE,
            get_payload_mutations=mutation_mock,
        )

        mutations = strategy._get_mutations(ctx, "test_payload")

        assert mutations == ["payload1", "payload2", "payload3"]
        mutation_mock.assert_called_once_with("test_payload", WAFType.CLOUDFLARE)

    def test_get_mutations_without_callback(self):
        """Test _get_mutations without callback returns original."""

        class ConcreteStrategy(BaseStrategy):
            @property
            def name(self):
                return "test"

            @property
            def detection_method(self):
                return DetectionMethod.ERROR_BASED

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        injection_ctx = InjectionContext(
            url="https://example.com/",
            method="GET",
            param_name="id",
            param_value="1",
            param_type="query",
        )
        ctx = StrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            injection_ctx=injection_ctx,
        )

        mutations = strategy._get_mutations(ctx, "test_payload")

        assert mutations == ["test_payload"]


class TestInjectionStrategyProtocol:
    """Tests for InjectionStrategy protocol."""

    def test_protocol_compliance(self):
        """Test that concrete strategies comply with protocol."""
        from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy

        strategy = ErrorBasedStrategy()

        # Check protocol requirements
        assert hasattr(strategy, 'name')
        assert hasattr(strategy, 'detection_method')
        assert hasattr(strategy, 'test')
        assert isinstance(strategy, InjectionStrategy)

    def test_all_strategies_implement_protocol(self):
        """Test all strategies implement the protocol correctly."""
        from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy
        from scanning.modules.sqli.strategies.time_blind import TimeBlindStrategy
        from scanning.modules.sqli.strategies.union_based import UnionBasedStrategy
        from scanning.modules.sqli.strategies.stacked_queries import StackedQueriesStrategy
        from scanning.modules.sqli.strategies.out_of_band import OutOfBandStrategy

        strategies = [
            ErrorBasedStrategy(),
            BooleanBlindStrategy(),
            TimeBlindStrategy(),
            UnionBasedStrategy(),
            StackedQueriesStrategy(),
            OutOfBandStrategy(),
        ]

        for strategy in strategies:
            assert isinstance(strategy, InjectionStrategy)
            assert isinstance(strategy.name, str)
            assert isinstance(strategy.detection_method, DetectionMethod)


class TestErrorBasedStrategy:
    """Tests for ErrorBasedStrategy."""

    def test_strategy_properties(self):
        """Test ErrorBasedStrategy properties."""
        from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy

        strategy = ErrorBasedStrategy()

        assert strategy.name == "error_based"
        assert strategy.detection_method == DetectionMethod.ERROR_BASED

    def test_filter_payloads_by_db_mysql(self):
        """Test payload filtering for MySQL."""
        from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy

        strategy = ErrorBasedStrategy()
        payloads = [
            ("' AND SLEEP(5)--", 80),
            ("' AND pg_sleep(5)--", 80),
            ("'; WAITFOR DELAY '0:0:5'--", 80),
            ("' AND BENCHMARK(1000,SHA1('test'))--", 80),
        ]

        filtered = strategy._filter_payloads_by_db(payloads, "mysql")

        # MySQL payloads (sleep, benchmark) should come first
        mysql_payloads = [p for p, _ in filtered if "sleep" in p.lower() or "benchmark" in p.lower()]
        assert len(mysql_payloads) >= 2


class TestBooleanBlindStrategy:
    """Tests for BooleanBlindStrategy."""

    def test_strategy_properties(self):
        """Test BooleanBlindStrategy properties."""
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy

        strategy = BooleanBlindStrategy()

        assert strategy.name == "boolean_blind"
        assert strategy.detection_method == DetectionMethod.BOOLEAN_BLIND

    def test_build_numeric_payloads_and(self):
        """Test numeric payload building for AND conditions."""
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy

        strategy = BooleanBlindStrategy()

        true_value, false_value = strategy._build_numeric_payloads(
            "123",
            "1 AND 1=1",
            "1 AND 1=2"
        )

        assert "123" in true_value
        assert "1=1" in true_value
        assert "123" in false_value
        assert "1=2" in false_value

    def test_build_numeric_payloads_or(self):
        """Test numeric payload building for OR conditions."""
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy

        strategy = BooleanBlindStrategy()

        true_value, false_value = strategy._build_numeric_payloads(
            "123",
            "-1 OR 1=1",
            "-1 OR 1=2"
        )

        assert "123" in true_value
        assert "1=1" in true_value

    def test_check_detection_criteria_similarity_based(self):
        """Test similarity-based detection criteria."""
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy

        strategy = BooleanBlindStrategy()

        # Create mock fingerprints
        baseline_fp = MagicMock()
        baseline_fp.content_length = 5000

        true_fp = MagicMock()
        true_fp.content_length = 5000

        false_fp = MagicMock()
        false_fp.content_length = 1000

        # Similarity-based: true similar to baseline, false differs
        result = strategy._check_detection_criteria(
            true_to_baseline=85,
            false_to_baseline=50,
            true_to_false=40,
            length_diff_tf=4000,
            length_ratio_tf=0.2,
            true_fp=true_fp,
            false_fp=false_fp,
            baseline_fp=baseline_fp,
        )

        assert result is True

    def test_check_detection_criteria_length_based(self):
        """Test length-based detection criteria."""
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy

        strategy = BooleanBlindStrategy()

        baseline_fp = MagicMock()
        baseline_fp.content_length = 5000

        true_fp = MagicMock()
        true_fp.content_length = 4900  # Close to baseline

        false_fp = MagicMock()
        false_fp.content_length = 1000  # Far from baseline

        result = strategy._check_detection_criteria(
            true_to_baseline=70,  # Not similarity-based
            false_to_baseline=70,  # Not similarity-based
            true_to_false=70,
            length_diff_tf=3900,  # > 150
            length_ratio_tf=0.2,  # < 0.9
            true_fp=true_fp,
            false_fp=false_fp,
            baseline_fp=baseline_fp,
        )

        assert result is True

    def test_check_detection_criteria_inverse_boolean(self):
        """Test inverse boolean detection for LIKE contexts."""
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy

        strategy = BooleanBlindStrategy()

        baseline_fp = MagicMock()
        baseline_fp.content_length = 1000

        true_fp = MagicMock()
        true_fp.content_length = 5000  # True returns MORE data (OR 1=1 in LIKE)

        false_fp = MagicMock()
        false_fp.content_length = 1000  # False returns baseline

        result = strategy._check_detection_criteria(
            true_to_baseline=40,  # True is DIFFERENT from baseline
            false_to_baseline=85,  # False is SIMILAR to baseline
            true_to_false=30,  # True and false very different
            length_diff_tf=4000,
            length_ratio_tf=0.2,
            true_fp=true_fp,
            false_fp=false_fp,
            baseline_fp=baseline_fp,
        )

        assert result is True


class TestTimeBlindStrategy:
    """Tests for TimeBlindStrategy."""

    def test_strategy_properties(self):
        """Test TimeBlindStrategy properties."""
        from scanning.modules.sqli.strategies.time_blind import TimeBlindStrategy

        strategy = TimeBlindStrategy()

        assert strategy.name == "time_blind"
        assert strategy.detection_method == DetectionMethod.TIME_BLIND


class TestUnionBasedStrategy:
    """Tests for UnionBasedStrategy."""

    def test_strategy_properties(self):
        """Test UnionBasedStrategy properties."""
        from scanning.modules.sqli.strategies.union_based import UnionBasedStrategy

        strategy = UnionBasedStrategy()

        assert strategy.name == "union_based"
        assert strategy.detection_method == DetectionMethod.UNION_BASED


class TestStackedQueriesStrategy:
    """Tests for StackedQueriesStrategy."""

    def test_strategy_properties(self):
        """Test StackedQueriesStrategy properties."""
        from scanning.modules.sqli.strategies.stacked_queries import StackedQueriesStrategy

        strategy = StackedQueriesStrategy()

        assert strategy.name == "stacked_queries"
        assert strategy.detection_method == DetectionMethod.STACKED_QUERIES


class TestOutOfBandStrategy:
    """Tests for OutOfBandStrategy."""

    def test_strategy_properties(self):
        """Test OutOfBandStrategy properties."""
        from scanning.modules.sqli.strategies.out_of_band import OutOfBandStrategy

        strategy = OutOfBandStrategy()

        assert strategy.name == "out_of_band"
        assert strategy.detection_method == DetectionMethod.OUT_OF_BAND


class TestStrategyDetectionMethodMapping:
    """Tests to ensure strategies use correct detection methods."""

    def test_all_strategies_have_unique_methods(self):
        """Test that each strategy uses a distinct detection method."""
        from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy
        from scanning.modules.sqli.strategies.time_blind import TimeBlindStrategy
        from scanning.modules.sqli.strategies.union_based import UnionBasedStrategy
        from scanning.modules.sqli.strategies.stacked_queries import StackedQueriesStrategy
        from scanning.modules.sqli.strategies.out_of_band import OutOfBandStrategy

        strategies = [
            ErrorBasedStrategy(),
            BooleanBlindStrategy(),
            TimeBlindStrategy(),
            UnionBasedStrategy(),
            StackedQueriesStrategy(),
            OutOfBandStrategy(),
        ]

        methods = [s.detection_method for s in strategies]
        assert len(methods) == len(set(methods)), "Strategies should have unique detection methods"

    def test_strategy_method_name_consistency(self):
        """Test that strategy names match their detection methods."""
        from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy
        from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy
        from scanning.modules.sqli.strategies.time_blind import TimeBlindStrategy

        # Name should match detection method (case-insensitive)
        assert "error" in ErrorBasedStrategy().name.lower()
        assert "boolean" in BooleanBlindStrategy().name.lower()
        assert "time" in TimeBlindStrategy().name.lower()
