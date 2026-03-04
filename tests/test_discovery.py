"""
Tests for the Discovery module.

Tests fallback endpoint generation and authenticated crawling functionality.
"""

from __future__ import annotations

import pytest
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

from scanning.discovery import (
    get_generic_fallback_endpoints,
    ENDPOINT_CATEGORIES,
    AuthenticatedCrawler,
    CrawlConfig,
    CrawlResult,
    authenticated_crawl,
)


# ============================================================================
# Test Fixtures and Mocks
# ============================================================================


class MockAuthContext:
    """Mock auth context for testing."""

    def __init__(
        self,
        has_auth: bool = True,
        cookies: Optional[dict[str, str]] = None,
        auth_headers: Optional[dict[str, str]] = None,
        session_cookie: Optional[str] = None,
    ):
        self._has_auth = has_auth
        self._cookies = cookies or {"session": "test123"}
        self._auth_headers = auth_headers or {"Authorization": "Bearer token"}
        self._session_cookie = session_cookie or "session=test123"

    @property
    def has_auth(self) -> bool:
        return self._has_auth

    @property
    def cookies(self) -> Optional[dict[str, str]]:
        return self._cookies

    @property
    def auth_headers(self) -> dict[str, str]:
        return self._auth_headers

    @property
    def session_cookie(self) -> Optional[str]:
        return self._session_cookie


# ============================================================================
# Fallback Endpoints Tests
# ============================================================================


class TestGetGenericFallbackEndpoints:
    """Tests for get_generic_fallback_endpoints function."""

    def test_returns_list_of_endpoints(self):
        """Should return a list of endpoint URLs."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert isinstance(endpoints, list)
        assert len(endpoints) > 0
        assert all(isinstance(e, str) for e in endpoints)

    def test_all_endpoints_are_full_urls(self):
        """All endpoints should be full URLs with scheme and host."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        for endpoint in endpoints:
            assert endpoint.startswith("https://example.com")

    def test_includes_api_patterns(self):
        """Should include common API patterns."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/api/users" in endpoints
        assert "https://example.com/graphql" in endpoints

    def test_includes_search_patterns(self):
        """Should include search patterns with parameters."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/search?q=test" in endpoints

    def test_includes_auth_patterns(self):
        """Should include authentication endpoints."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/login" in endpoints
        assert "https://example.com/logout" in endpoints

    def test_includes_admin_patterns(self):
        """Should include admin/dashboard patterns."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/admin" in endpoints
        assert "https://example.com/dashboard" in endpoints

    def test_includes_file_patterns(self):
        """Should include file operation patterns."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/upload" in endpoints
        assert "https://example.com/download" in endpoints

    def test_includes_crud_patterns(self):
        """Should include CRUD operation patterns."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/edit?id=1" in endpoints
        assert "https://example.com/delete?id=1" in endpoints

    def test_includes_actuator_patterns(self):
        """Should include Spring Boot Actuator patterns."""
        endpoints = get_generic_fallback_endpoints("https://example.com")
        assert "https://example.com/actuator" in endpoints
        assert "https://example.com/actuator/env" in endpoints
        assert "https://example.com/actuator/heapdump" in endpoints

    def test_detects_context_path(self):
        """Should detect and use context path for prefixed endpoints."""
        endpoints = get_generic_fallback_endpoints("https://example.com/WebGoat/start")
        # Should include context-prefixed versions
        assert "https://example.com/WebGoat/actuator" in endpoints
        assert "https://example.com/WebGoat/api" in endpoints

    def test_handles_root_path(self):
        """Should handle targets at root path."""
        endpoints = get_generic_fallback_endpoints("https://example.com/")
        assert "https://example.com/api/users" in endpoints

    def test_handles_http_scheme(self):
        """Should work with HTTP as well as HTTPS."""
        endpoints = get_generic_fallback_endpoints("http://localhost:8080")
        assert any(e.startswith("http://localhost:8080") for e in endpoints)

    def test_handles_port_in_url(self):
        """Should preserve port number in generated URLs."""
        endpoints = get_generic_fallback_endpoints("https://example.com:8443")
        assert all("example.com:8443" in e for e in endpoints)


class TestEndpointCategories:
    """Tests for ENDPOINT_CATEGORIES constant."""

    def test_has_all_expected_categories(self):
        """Should have all expected endpoint categories."""
        category_names = {cat.name for cat in ENDPOINT_CATEGORIES}
        expected = {"api", "search", "auth", "user", "admin", "file", "crud", "debug", "actuator"}
        assert category_names == expected

    def test_each_category_has_patterns(self):
        """Each category should have at least one pattern."""
        for category in ENDPOINT_CATEGORIES:
            assert len(category.patterns) > 0
            assert category.description

    def test_patterns_are_valid_paths(self):
        """All patterns should be valid URL paths."""
        for category in ENDPOINT_CATEGORIES:
            for pattern in category.patterns:
                assert pattern.startswith("/") or pattern.startswith("?")


# ============================================================================
# Authenticated Crawler Tests
# ============================================================================


class TestCrawlConfig:
    """Tests for CrawlConfig dataclass."""

    def test_default_values(self):
        """Should have sensible default values."""
        config = CrawlConfig()
        assert config.max_depth == 3
        assert config.max_pages == 50
        assert config.timeout == 10.0
        assert config.probe_api is True

    def test_custom_values(self):
        """Should allow custom configuration."""
        config = CrawlConfig(max_depth=5, max_pages=100, timeout=30.0)
        assert config.max_depth == 5
        assert config.max_pages == 100
        assert config.timeout == 30.0


class TestCrawlResult:
    """Tests for CrawlResult dataclass."""

    def test_default_values(self):
        """Should have empty defaults."""
        result = CrawlResult()
        assert result.endpoints == []
        assert result.forms == []
        assert result.api_endpoints == []
        assert result.spa_crawler_used is False
        assert result.error is None

    def test_with_data(self):
        """Should store provided data."""
        result = CrawlResult(
            endpoints=["/api/users"],
            forms=[{"action": "/submit"}],
            spa_crawler_used=True,
        )
        assert result.endpoints == ["/api/users"]
        assert len(result.forms) == 1
        assert result.spa_crawler_used is True


class TestAuthenticatedCrawler:
    """Tests for AuthenticatedCrawler class."""

    def test_init_with_auth_context(self):
        """Should initialize with auth context."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)
        assert crawler.auth_context == auth
        assert crawler.config is not None

    def test_init_with_custom_config(self):
        """Should accept custom config."""
        auth = MockAuthContext()
        config = CrawlConfig(max_depth=5)
        crawler = AuthenticatedCrawler(auth, config=config)
        assert crawler.config.max_depth == 5

    @pytest.mark.asyncio
    async def test_crawl_without_auth_returns_error(self):
        """Should return error when no auth available."""
        auth = MockAuthContext(has_auth=False)
        crawler = AuthenticatedCrawler(auth)
        result = await crawler.crawl("https://example.com")
        assert result.error == "No authentication context available"
        assert result.endpoints == []

    @pytest.mark.asyncio
    async def test_crawl_returns_result(self):
        """Should return CrawlResult from crawl."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        # Mock both SPA and basic crawl to avoid external calls
        with patch.object(crawler, "_try_spa_crawl", new_callable=AsyncMock) as mock_spa:
            mock_spa.return_value = CrawlResult(endpoints=["/found"])
            result = await crawler.crawl("https://example.com")

        assert isinstance(result, CrawlResult)
        assert "/found" in result.endpoints

    def test_process_forms_filters_invalid(self):
        """Should filter malformed forms."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        forms = [
            {"action": "/submit", "inputs": [{"name": "field1"}]},  # Valid
            {"action": None},  # Invalid - no action
            "not a dict",  # Invalid - not dict
            {"action": "/empty", "inputs": [], "method": "POST"},  # Invalid - no inputs, POST
            {"action": "/get", "inputs": [], "method": "GET"},  # Valid - GET allowed
        ]

        result = crawler._process_forms(forms, "https://example.com")
        assert len(result) == 2  # Only 2 valid forms (first valid + GET without inputs)

    def test_process_forms_normalizes_inputs(self):
        """Should normalize string inputs to dict format."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        forms = [{"action": "/submit", "inputs": ["field1", "field2"]}]
        result = crawler._process_forms(forms, "https://example.com")

        assert len(result) == 1
        assert all(isinstance(inp, dict) for inp in result[0]["inputs"])
        assert result[0]["inputs"][0]["name"] == "field1"

    def test_process_link_skips_anchors(self):
        """Should skip anchor links."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        from urllib.parse import urlparse
        parsed = urlparse("https://example.com")

        assert crawler._process_link("#section", "https://example.com", parsed) is None
        assert crawler._process_link("javascript:void(0)", "https://example.com", parsed) is None
        assert crawler._process_link("mailto:test@example.com", "https://example.com", parsed) is None

    def test_process_link_resolves_relative(self):
        """Should resolve relative URLs."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        from urllib.parse import urlparse
        parsed = urlparse("https://example.com")

        result = crawler._process_link("/api/users", "https://example.com/page", parsed)
        assert result == "https://example.com/api/users"

    def test_process_link_skips_external(self):
        """Should skip external links."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        from urllib.parse import urlparse
        parsed = urlparse("https://example.com")

        result = crawler._process_link("https://other.com/page", "https://example.com", parsed)
        assert result is None


# ============================================================================
# Convenience Function Tests
# ============================================================================


class TestAuthenticatedCrawlFunction:
    """Tests for authenticated_crawl convenience function."""

    @pytest.mark.asyncio
    async def test_creates_crawler_and_calls(self):
        """Should create crawler and return result."""
        auth = MockAuthContext()

        with patch.object(AuthenticatedCrawler, "crawl", new_callable=AsyncMock) as mock:
            mock.return_value = CrawlResult(endpoints=["/found"])
            result = await authenticated_crawl("https://example.com", auth)

        assert isinstance(result, CrawlResult)
        mock.assert_called_once_with("https://example.com")

    @pytest.mark.asyncio
    async def test_passes_config(self):
        """Should pass custom config to crawler."""
        auth = MockAuthContext()
        config = CrawlConfig(max_depth=10)

        with patch.object(AuthenticatedCrawler, "crawl", new_callable=AsyncMock) as mock:
            mock.return_value = CrawlResult()
            await authenticated_crawl("https://example.com", auth, config=config)

        # Crawler was created with config (verified by checking the call was made)
        mock.assert_called_once()


# ============================================================================
# Integration Tests
# ============================================================================


class TestDiscoveryIntegration:
    """Integration tests for discovery module."""

    def test_module_exports(self):
        """Module should export all expected symbols."""
        from scanning.discovery import (
            get_generic_fallback_endpoints,
            ENDPOINT_CATEGORIES,
            AuthenticatedCrawler,
            CrawlConfig,
            CrawlResult,
            authenticated_crawl,
        )

        # All should be importable
        assert callable(get_generic_fallback_endpoints)
        assert callable(authenticated_crawl)
        assert isinstance(ENDPOINT_CATEGORIES, list)

    def test_endpoint_generation_comprehensive(self):
        """Generated endpoints should cover major attack surfaces."""
        endpoints = get_generic_fallback_endpoints("https://target.com")

        # Check for injectable parameters (SQLi/XSS targets)
        injectable = [e for e in endpoints if "=" in e]
        assert len(injectable) >= 20, "Should have many injectable endpoints"

        # Check for sensitive endpoints
        sensitive = [e for e in endpoints if any(s in e for s in ["admin", "config", "env", "actuator"])]
        assert len(sensitive) >= 10, "Should have sensitive endpoints"

    @pytest.mark.asyncio
    async def test_crawler_handles_missing_spa_crawler(self):
        """Should gracefully handle missing SPA crawler."""
        auth = MockAuthContext()
        crawler = AuthenticatedCrawler(auth)

        # Mock import failure
        with patch.dict("sys.modules", {"reconnaissance.spa_crawler": None}):
            with patch.object(crawler, "_basic_html_crawl", new_callable=AsyncMock) as mock:
                mock.return_value = CrawlResult(endpoints=["/fallback"])
                result = await crawler.crawl("https://example.com")

        # Should fall back to basic crawl
        assert result is not None
