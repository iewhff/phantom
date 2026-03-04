"""
Tests for utils/endpoint_validator.py - Endpoint Validation Utilities.

Covers:
- EndpointValidator class
- EXISTS_CODES and SKIP_CODES constants
- Singleton pattern (get_instance, reset)
- endpoint_exists() method
- filter_existing_endpoints() method
- mark_as_nonexistent() method
- get_stats() method
- endpoint_exists() convenience function
"""

import pytest
from unittest.mock import AsyncMock, Mock, patch
import httpx

from utils.endpoint_validator import (
    EndpointValidator,
    endpoint_exists,
)


# =============================================================================
# SETUP AND FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
def reset_validator():
    """Reset validator cache before each test."""
    EndpointValidator.reset()
    yield
    EndpointValidator.reset()


@pytest.fixture
def validator():
    """Get validator instance."""
    return EndpointValidator.get_instance()


# =============================================================================
# CONSTANT TESTS
# =============================================================================

class TestEndpointValidatorConstants:
    """Tests for EndpointValidator constants."""

    def test_exists_codes_not_empty(self):
        """Test EXISTS_CODES is not empty."""
        assert len(EndpointValidator.EXISTS_CODES) > 0

    def test_exists_codes_include_success(self):
        """Test EXISTS_CODES includes success codes."""
        assert 200 in EndpointValidator.EXISTS_CODES
        assert 201 in EndpointValidator.EXISTS_CODES
        assert 204 in EndpointValidator.EXISTS_CODES

    def test_exists_codes_include_redirects(self):
        """Test EXISTS_CODES includes redirect codes."""
        assert 301 in EndpointValidator.EXISTS_CODES
        assert 302 in EndpointValidator.EXISTS_CODES
        assert 307 in EndpointValidator.EXISTS_CODES
        assert 308 in EndpointValidator.EXISTS_CODES

    def test_exists_codes_include_auth_errors(self):
        """Test EXISTS_CODES includes auth error codes."""
        assert 401 in EndpointValidator.EXISTS_CODES
        assert 403 in EndpointValidator.EXISTS_CODES

    def test_exists_codes_include_server_errors(self):
        """Test EXISTS_CODES includes server error codes."""
        assert 500 in EndpointValidator.EXISTS_CODES
        assert 502 in EndpointValidator.EXISTS_CODES
        assert 503 in EndpointValidator.EXISTS_CODES

    def test_skip_codes_contains_404(self):
        """Test SKIP_CODES contains 404."""
        assert 404 in EndpointValidator.SKIP_CODES

    def test_skip_codes_not_empty(self):
        """Test SKIP_CODES is not empty."""
        assert len(EndpointValidator.SKIP_CODES) > 0


# =============================================================================
# SINGLETON PATTERN TESTS
# =============================================================================

class TestEndpointValidatorSingleton:
    """Tests for singleton pattern."""

    def test_get_instance_returns_validator(self):
        """Test get_instance returns EndpointValidator."""
        instance = EndpointValidator.get_instance()
        assert isinstance(instance, EndpointValidator)

    def test_get_instance_returns_same_instance(self):
        """Test get_instance returns same instance."""
        instance1 = EndpointValidator.get_instance()
        instance2 = EndpointValidator.get_instance()
        assert instance1 is instance2

    def test_reset_clears_cache(self):
        """Test reset clears the cache."""
        validator = EndpointValidator.get_instance()
        # Manually add to cache
        EndpointValidator._cache = {"example.com": {"/test": True}}
        assert len(EndpointValidator._cache) > 0

        EndpointValidator.reset()
        assert len(EndpointValidator._cache) == 0


# =============================================================================
# ENDPOINT_EXISTS METHOD TESTS
# =============================================================================

class TestEndpointExists:
    """Tests for endpoint_exists() method."""

    @pytest.mark.asyncio
    async def test_cached_result_returned(self, validator):
        """Test cached results are returned without making request."""
        base_url = "https://example.com"
        path = "/api/users"

        # Pre-populate cache
        EndpointValidator._cache["example.com"] = {"/api/users": True}

        result = await validator.endpoint_exists(base_url, path)
        assert result is True

    @pytest.mark.asyncio
    async def test_cached_false_returned(self, validator):
        """Test cached false is returned."""
        base_url = "https://example.com"
        path = "/nonexistent"

        # Pre-populate cache with False
        EndpointValidator._cache["example.com"] = {"/nonexistent": False}

        result = await validator.endpoint_exists(base_url, path)
        assert result is False

    @pytest.mark.asyncio
    async def test_full_url_path_handled(self, validator):
        """Test full URL as path is handled."""
        # Pre-populate cache
        EndpointValidator._cache["api.example.com"] = {"/v1/data": True}

        result = await validator.endpoint_exists(
            "https://example.com",
            "https://api.example.com/v1/data"
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_rate_limiter_called(self, validator):
        """Test rate limiter is called when provided."""
        rate_limiter = AsyncMock()
        rate_limiter.acquire = AsyncMock()

        # Pre-populate cache to avoid actual HTTP request
        EndpointValidator._cache["example.com"] = {"/test": True}

        # Not cached path - would call rate limiter
        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_head.return_value = mock_response

            await validator.endpoint_exists(
                "https://example.com",
                "/new-endpoint",
                rate_limiter=rate_limiter
            )
            rate_limiter.acquire.assert_called_once()


class TestEndpointExistsStatusCodes:
    """Tests for status code handling in endpoint_exists()."""

    @pytest.mark.asyncio
    async def test_200_means_exists(self, validator):
        """Test 200 response means endpoint exists."""
        mock_response = Mock()
        mock_response.status_code = 200

        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_response
            result = await validator.endpoint_exists(
                "https://example.com",
                "/exists"
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_404_means_not_exists(self, validator):
        """Test 404 response means endpoint doesn't exist."""
        mock_response = Mock()
        mock_response.status_code = 404

        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_response
            result = await validator.endpoint_exists(
                "https://example.com",
                "/notfound"
            )
            assert result is False

    @pytest.mark.asyncio
    async def test_401_means_exists(self, validator):
        """Test 401 response means endpoint exists (auth required)."""
        mock_response = Mock()
        mock_response.status_code = 401

        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_response
            result = await validator.endpoint_exists(
                "https://example.com",
                "/protected"
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_403_means_exists(self, validator):
        """Test 403 response means endpoint exists (forbidden)."""
        mock_response = Mock()
        mock_response.status_code = 403

        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_response
            result = await validator.endpoint_exists(
                "https://example.com",
                "/forbidden"
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_500_means_exists(self, validator):
        """Test 500 response means endpoint exists (server error)."""
        mock_response = Mock()
        mock_response.status_code = 500

        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_response
            result = await validator.endpoint_exists(
                "https://example.com",
                "/error"
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_exception_assumes_exists(self, validator):
        """Test exception assumes endpoint exists (don't skip)."""
        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.side_effect = Exception("Network error")
            result = await validator.endpoint_exists(
                "https://example.com",
                "/error-endpoint"
            )
            assert result is True


# =============================================================================
# MARK_AS_NONEXISTENT METHOD TESTS
# =============================================================================

class TestMarkAsNonexistent:
    """Tests for mark_as_nonexistent() method."""

    def test_marks_endpoint_false(self, validator):
        """Test endpoint is marked as non-existent."""
        validator.mark_as_nonexistent("https://example.com", "/deleted")

        assert "example.com" in EndpointValidator._cache
        assert EndpointValidator._cache["example.com"]["/deleted"] is False

    def test_creates_host_entry(self, validator):
        """Test host entry is created if not exists."""
        assert "newhost.com" not in EndpointValidator._cache

        validator.mark_as_nonexistent("https://newhost.com", "/path")

        assert "newhost.com" in EndpointValidator._cache

    def test_multiple_paths_same_host(self, validator):
        """Test multiple paths can be marked for same host."""
        validator.mark_as_nonexistent("https://example.com", "/path1")
        validator.mark_as_nonexistent("https://example.com", "/path2")

        assert EndpointValidator._cache["example.com"]["/path1"] is False
        assert EndpointValidator._cache["example.com"]["/path2"] is False


# =============================================================================
# GET_STATS METHOD TESTS
# =============================================================================

class TestGetStats:
    """Tests for get_stats() method."""

    def test_empty_stats(self, validator):
        """Test stats when cache is empty."""
        stats = validator.get_stats()
        assert stats["hosts"] == 0
        assert stats["total_endpoints"] == 0
        assert stats["existing"] == 0
        assert stats["non_existent"] == 0

    def test_stats_with_data(self, validator):
        """Test stats with cached data."""
        EndpointValidator._cache = {
            "example.com": {
                "/api/users": True,
                "/api/orders": True,
                "/deleted": False,
            },
            "other.com": {
                "/test": True,
            }
        }

        stats = validator.get_stats()
        assert stats["hosts"] == 2
        assert stats["total_endpoints"] == 4
        assert stats["existing"] == 3
        assert stats["non_existent"] == 1

    def test_stats_all_existing(self, validator):
        """Test stats when all endpoints exist."""
        EndpointValidator._cache = {
            "example.com": {
                "/path1": True,
                "/path2": True,
            }
        }

        stats = validator.get_stats()
        assert stats["existing"] == 2
        assert stats["non_existent"] == 0

    def test_stats_all_nonexistent(self, validator):
        """Test stats when all endpoints don't exist."""
        EndpointValidator._cache = {
            "example.com": {
                "/gone1": False,
                "/gone2": False,
            }
        }

        stats = validator.get_stats()
        assert stats["existing"] == 0
        assert stats["non_existent"] == 2


# =============================================================================
# FILTER_EXISTING_ENDPOINTS METHOD TESTS
# =============================================================================

class TestFilterExistingEndpoints:
    """Tests for filter_existing_endpoints() method."""

    @pytest.mark.asyncio
    async def test_filters_nonexistent(self, validator):
        """Test non-existent endpoints are filtered out."""
        # Pre-populate cache
        EndpointValidator._cache["example.com"] = {
            "/exists1": True,
            "/exists2": True,
            "/gone": False,
        }

        paths = ["/exists1", "/exists2", "/gone"]
        result = await validator.filter_existing_endpoints(
            "https://example.com",
            paths
        )

        assert "/exists1" in result
        assert "/exists2" in result
        assert "/gone" not in result

    @pytest.mark.asyncio
    async def test_empty_list(self, validator):
        """Test empty list returns empty."""
        result = await validator.filter_existing_endpoints(
            "https://example.com",
            []
        )
        assert result == []

    @pytest.mark.asyncio
    async def test_all_existing(self, validator):
        """Test all existing returns all."""
        EndpointValidator._cache["example.com"] = {
            "/a": True,
            "/b": True,
            "/c": True,
        }

        paths = ["/a", "/b", "/c"]
        result = await validator.filter_existing_endpoints(
            "https://example.com",
            paths
        )

        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_all_nonexistent(self, validator):
        """Test all non-existent returns empty."""
        EndpointValidator._cache["example.com"] = {
            "/x": False,
            "/y": False,
            "/z": False,
        }

        paths = ["/x", "/y", "/z"]
        result = await validator.filter_existing_endpoints(
            "https://example.com",
            paths
        )

        assert len(result) == 0


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================

class TestEndpointExistsFunction:
    """Tests for endpoint_exists() convenience function."""

    @pytest.mark.asyncio
    async def test_uses_singleton(self):
        """Test convenience function uses singleton validator."""
        # Pre-populate cache
        EndpointValidator._cache["example.com"] = {"/cached": True}

        result = await endpoint_exists("https://example.com", "/cached")
        assert result is True

    @pytest.mark.asyncio
    async def test_with_rate_limiter(self):
        """Test convenience function with rate limiter."""
        rate_limiter = AsyncMock()
        rate_limiter.acquire = AsyncMock()

        # Pre-populate cache
        EndpointValidator._cache["example.com"] = {"/test": True}

        result = await endpoint_exists(
            "https://example.com",
            "/test",
            rate_limiter=rate_limiter
        )
        assert result is True


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestEndpointValidatorIntegration:
    """Integration tests for endpoint validator."""

    @pytest.mark.asyncio
    async def test_cache_persists_across_calls(self, validator):
        """Test cache persists across multiple calls."""
        # First call - simulate HTTP response
        mock_response = Mock()
        mock_response.status_code = 200

        with patch.object(httpx.AsyncClient, 'head', new_callable=AsyncMock) as mock_head:
            mock_head.return_value = mock_response

            result1 = await validator.endpoint_exists(
                "https://example.com",
                "/api"
            )
            assert result1 is True

        # Second call - should use cache (not make HTTP request)
        result2 = await validator.endpoint_exists(
            "https://example.com",
            "/api"
        )
        assert result2 is True

    @pytest.mark.asyncio
    async def test_different_hosts_separate_cache(self, validator):
        """Test different hosts have separate cache entries."""
        EndpointValidator._cache["host1.com"] = {"/path": True}
        EndpointValidator._cache["host2.com"] = {"/path": False}

        result1 = await validator.endpoint_exists("https://host1.com", "/path")
        result2 = await validator.endpoint_exists("https://host2.com", "/path")

        assert result1 is True
        assert result2 is False

    def test_workflow(self, validator):
        """Test typical workflow."""
        # Check stats initially
        stats = validator.get_stats()
        assert stats["hosts"] == 0

        # Mark some endpoints
        validator.mark_as_nonexistent("https://example.com", "/deleted1")
        validator.mark_as_nonexistent("https://example.com", "/deleted2")

        # Check stats
        stats = validator.get_stats()
        assert stats["hosts"] == 1
        assert stats["non_existent"] == 2

        # Reset
        EndpointValidator.reset()
        stats = validator.get_stats()
        assert stats["hosts"] == 0
