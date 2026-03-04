"""
Tests for XSS scanner strategies.

Tests cover:
- Strategy base classes (XSSStrategyResult, XSSStrategyContext, BaseXSSStrategy)
- URLParamStrategy
- FormTestStrategy
- HeaderTestStrategy
- JSONBodyStrategy
- TemplateInjectionStrategy
- StoredXSSStrategy
- SecondOrderStrategy
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from scanning.modules.xss.strategies.base import (
    XSSStrategyResult,
    XSSStrategyContext,
    BaseXSSStrategy,
    XSSStrategy,
)
from scanning.modules.xss.xss_base import (
    XSSContext,
    XSSEvidence,
    WAFType,
)


class TestXSSStrategyResult:
    """Tests for XSSStrategyResult dataclass."""

    def test_not_found_factory(self):
        """Test XSSStrategyResult.not_found factory method."""
        result = XSSStrategyResult.not_found()

        assert result.found is False
        assert result.evidence == []
        assert result.attempts == 0
        assert result.errors == []

    def test_not_found_with_attempts(self):
        """Test XSSStrategyResult.not_found with attempts count."""
        result = XSSStrategyResult.not_found(attempts=10)

        assert result.found is False
        assert result.attempts == 10

    def test_not_found_with_errors(self):
        """Test XSSStrategyResult.not_found with error list."""
        errors = ["Timeout", "WAF blocked"]
        result = XSSStrategyResult.not_found(attempts=5, errors=errors)

        assert result.found is False
        assert result.errors == errors

    def test_vulnerable_factory(self):
        """Test XSSStrategyResult.vulnerable factory method."""
        evidence = [
            XSSEvidence(
                payload="<script>alert(1)</script>",
                context=XSSContext.HTML_TEXT,
                reflected_in="body",
                encoding_used="none",
                waf_bypassed=False,
                response_snippet="<div><script>alert(1)</script></div>",
            )
        ]
        result = XSSStrategyResult.vulnerable(evidence, attempts=15)

        assert result.found is True
        assert len(result.evidence) == 1
        assert result.attempts == 15


class TestXSSStrategyContext:
    """Tests for XSSStrategyContext dataclass."""

    def test_basic_creation(self):
        """Test basic XSSStrategyContext creation."""
        ctx = XSSStrategyContext(
            base_url="https://example.com/search",
            param_name="q",
            params={"q": ["test"]},
        )

        assert ctx.base_url == "https://example.com/search"
        assert ctx.param_name == "q"
        assert ctx.params == {"q": ["test"]}

    def test_default_values(self):
        """Test XSSStrategyContext default values."""
        ctx = XSSStrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
        )

        assert ctx.method == "GET"
        assert ctx.timeout == 30.0
        assert ctx.mutation_level == 3
        assert ctx.max_payloads == 20
        assert ctx.detected_waf is None
        assert ctx.detected_context is None
        assert ctx.auth_headers == {}
        assert ctx.forms == []

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_with_callback(self):
        """Test rate limit acquisition with callback."""
        async_mock = AsyncMock()

        ctx = XSSStrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            host="example.com",
            rate_limiter_acquire=async_mock,
        )

        await ctx.acquire_rate_limit()

        async_mock.assert_called_once_with("example.com")

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_without_callback(self):
        """Test rate limit acquisition without callback does nothing."""
        ctx = XSSStrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
        )

        # Should not raise
        await ctx.acquire_rate_limit()


class TestBaseXSSStrategy:
    """Tests for BaseXSSStrategy abstract base class."""

    def test_build_test_url_append(self):
        """Test _build_test_url with append mode."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        ctx = XSSStrategyContext(
            base_url="https://example.com/search",
            param_name="q",
            params={"q": ["test"]},
        )

        url = strategy._build_test_url(ctx, "<script>alert(1)</script>", append=True)

        # URL should contain original value + payload
        assert "example.com/search" in url
        assert "q=" in url

    def test_build_test_url_replace(self):
        """Test _build_test_url with replace mode."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        ctx = XSSStrategyContext(
            base_url="https://example.com/search",
            param_name="q",
            params={"q": ["original"]},
        )

        url = strategy._build_test_url(ctx, "PAYLOAD", append=False)

        # URL should contain only payload
        assert "PAYLOAD" in url

    def test_get_mutations_with_callback(self):
        """Test _get_mutations with callback."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        mutation_mock = MagicMock(return_value=["p1", "p2", "p3"])

        ctx = XSSStrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
            mutation_level=3,
            get_payload_mutations=mutation_mock,
        )

        mutations = strategy._get_mutations(ctx, "test_payload")

        assert mutations == ["p1", "p2", "p3"]
        mutation_mock.assert_called_once_with("test_payload", 3)

    def test_get_mutations_without_callback(self):
        """Test _get_mutations without callback returns original."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        ctx = XSSStrategyContext(
            base_url="https://example.com/",
            param_name="id",
            params={"id": ["1"]},
        )

        mutations = strategy._get_mutations(ctx, "test_payload")

        assert mutations == ["test_payload"]

    def test_check_reflection_direct(self):
        """Test _check_reflection with direct match."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()

        assert strategy._check_reflection("<script>", "<div><script>alert(1)</script></div>") is True
        assert strategy._check_reflection("notfound", "<div>content</div>") is False

    def test_check_reflection_case_insensitive(self):
        """Test _check_reflection with case-insensitive match."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()

        assert strategy._check_reflection("<SCRIPT>", "<div><script>alert(1)</script></div>") is True
        assert strategy._check_reflection("ALERT", "alert(1)") is True

    def test_extract_snippet(self):
        """Test _extract_snippet extracts correct context."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()
        content = "A" * 200 + "<script>alert(1)</script>" + "B" * 200

        snippet = strategy._extract_snippet("<script>", content, context_size=50)

        assert "<script>" in snippet
        assert len(snippet) <= 50 * 2 + len("<script>") + 50

    def test_extract_snippet_not_found(self):
        """Test _extract_snippet when payload not found."""

        class ConcreteStrategy(BaseXSSStrategy):
            @property
            def name(self):
                return "test"

            async def test(self, ctx):
                pass

        strategy = ConcreteStrategy()

        snippet = strategy._extract_snippet("notfound", "some content")

        assert snippet == ""


class TestXSSStrategyProtocol:
    """Tests for XSSStrategy protocol compliance."""

    def test_protocol_compliance(self):
        """Test that concrete strategies comply with protocol."""
        from scanning.modules.xss.strategies.url_param import URLParamStrategy

        strategy = URLParamStrategy()

        assert hasattr(strategy, 'name')
        assert hasattr(strategy, 'test')
        assert isinstance(strategy, XSSStrategy)

    def test_all_strategies_implement_protocol(self):
        """Test all strategies implement the protocol correctly."""
        from scanning.modules.xss.strategies.url_param import URLParamStrategy
        from scanning.modules.xss.strategies.form_test import FormTestStrategy
        from scanning.modules.xss.strategies.header_test import HeaderTestStrategy
        from scanning.modules.xss.strategies.json_body import JSONBodyStrategy
        from scanning.modules.xss.strategies.template_injection import TemplateInjectionStrategy
        from scanning.modules.xss.strategies.stored_xss import StoredXSSStrategy
        from scanning.modules.xss.strategies.second_order import SecondOrderStrategy

        strategies = [
            URLParamStrategy(),
            FormTestStrategy(),
            HeaderTestStrategy(),
            JSONBodyStrategy(),
            TemplateInjectionStrategy(),
            StoredXSSStrategy(),
            SecondOrderStrategy(),
        ]

        for strategy in strategies:
            assert isinstance(strategy, XSSStrategy)
            assert isinstance(strategy.name, str)


class TestURLParamStrategy:
    """Tests for URLParamStrategy."""

    def test_strategy_name(self):
        """Test URLParamStrategy name."""
        from scanning.modules.xss.strategies.url_param import URLParamStrategy

        strategy = URLParamStrategy()
        assert strategy.name == "url_param"


class TestFormTestStrategy:
    """Tests for FormTestStrategy."""

    def test_strategy_name(self):
        """Test FormTestStrategy name."""
        from scanning.modules.xss.strategies.form_test import FormTestStrategy

        strategy = FormTestStrategy()
        assert strategy.name == "form_test"


class TestHeaderTestStrategy:
    """Tests for HeaderTestStrategy."""

    def test_strategy_name(self):
        """Test HeaderTestStrategy name."""
        from scanning.modules.xss.strategies.header_test import HeaderTestStrategy

        strategy = HeaderTestStrategy()
        assert strategy.name == "header_test"


class TestJSONBodyStrategy:
    """Tests for JSONBodyStrategy."""

    def test_strategy_name(self):
        """Test JSONBodyStrategy name."""
        from scanning.modules.xss.strategies.json_body import JSONBodyStrategy

        strategy = JSONBodyStrategy()
        assert strategy.name == "json_body"


class TestTemplateInjectionStrategy:
    """Tests for TemplateInjectionStrategy."""

    def test_strategy_name(self):
        """Test TemplateInjectionStrategy name."""
        from scanning.modules.xss.strategies.template_injection import TemplateInjectionStrategy

        strategy = TemplateInjectionStrategy()
        assert strategy.name == "template_injection"


class TestStoredXSSStrategy:
    """Tests for StoredXSSStrategy."""

    def test_strategy_name(self):
        """Test StoredXSSStrategy name."""
        from scanning.modules.xss.strategies.stored_xss import StoredXSSStrategy

        strategy = StoredXSSStrategy()
        assert strategy.name == "stored_xss"


class TestSecondOrderStrategy:
    """Tests for SecondOrderStrategy."""

    def test_strategy_name(self):
        """Test SecondOrderStrategy name."""
        from scanning.modules.xss.strategies.second_order import SecondOrderStrategy

        strategy = SecondOrderStrategy()
        assert strategy.name == "second_order"


class TestStrategyNamesUnique:
    """Tests to ensure strategy names are unique."""

    def test_all_strategies_have_unique_names(self):
        """Test that each strategy has a unique name."""
        from scanning.modules.xss.strategies.url_param import URLParamStrategy
        from scanning.modules.xss.strategies.form_test import FormTestStrategy
        from scanning.modules.xss.strategies.header_test import HeaderTestStrategy
        from scanning.modules.xss.strategies.json_body import JSONBodyStrategy
        from scanning.modules.xss.strategies.template_injection import TemplateInjectionStrategy
        from scanning.modules.xss.strategies.stored_xss import StoredXSSStrategy
        from scanning.modules.xss.strategies.second_order import SecondOrderStrategy

        strategies = [
            URLParamStrategy(),
            FormTestStrategy(),
            HeaderTestStrategy(),
            JSONBodyStrategy(),
            TemplateInjectionStrategy(),
            StoredXSSStrategy(),
            SecondOrderStrategy(),
        ]

        names = [s.name for s in strategies]
        assert len(names) == len(set(names)), "Strategies should have unique names"
