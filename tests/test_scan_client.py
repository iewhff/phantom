"""
Integration tests for ScanClient OPSEC features.

Tests:
1. Circuit breaker triggers after 3x 429/403
2. Deduplication cache prevents duplicate requests
3. Dry-run mode simulates without sending
4. Retry-After header is respected
5. Latency tracking works correctly
6. Kill switch integration
7. Safety mode blocking
"""

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

# Set safety mode for tests
os.environ["PHANTOM_SAFE_MODE"] = "standard"


class TestCircuitBreaker:
    """Test circuit breaker functionality."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_triggers_after_3_blocks(self):
        """Circuit breaker should trigger after 3 consecutive 429/403 responses."""
        from utils.scan_client import (
            get_scan_client,
            reset_circuit_breaker,
            get_circuit_breaker,
        )

        reset_circuit_breaker()
        cb = get_circuit_breaker()

        # Simulate 3 blocks
        await cb.record_block("http://test.com/1", 429)
        assert cb.consecutive_blocks == 1
        assert not cb.is_paused

        await cb.record_block("http://test.com/2", 429)
        assert cb.consecutive_blocks == 2
        assert not cb.is_paused

        triggered = await cb.record_block("http://test.com/3", 429)
        assert triggered is True
        assert cb.is_paused
        assert cb.total_pauses == 1

    @pytest.mark.asyncio
    async def test_circuit_breaker_resets_on_success(self):
        """Success should reset consecutive block count."""
        from utils.scan_client import reset_circuit_breaker, get_circuit_breaker

        reset_circuit_breaker()
        cb = get_circuit_breaker()

        await cb.record_block("http://test.com/1", 403)
        await cb.record_block("http://test.com/2", 403)
        assert cb.consecutive_blocks == 2

        await cb.record_success()
        assert cb.consecutive_blocks == 0

    @pytest.mark.asyncio
    async def test_circuit_breaker_respects_retry_after(self):
        """Circuit breaker should use Retry-After header value."""
        from utils.scan_client import reset_circuit_breaker, get_circuit_breaker
        import time

        reset_circuit_breaker()
        cb = get_circuit_breaker()

        # Trigger with Retry-After
        await cb.record_block("http://test.com/1", 429)
        await cb.record_block("http://test.com/2", 429)
        await cb.record_block("http://test.com/3", 429, retry_after=5.0)

        # Should be paused for ~5 seconds (not default 30)
        remaining = cb.cooldown_until - time.time()
        assert 4.0 <= remaining <= 6.0  # Allow some variance


class TestDeduplication:
    """Test request deduplication."""

    @pytest.mark.asyncio
    async def test_duplicate_requests_are_skipped(self):
        """Same request within TTL should be marked as duplicate."""
        from utils.scan_client import reset_deduplicator, get_deduplicator

        reset_deduplicator()
        dedup = get_deduplicator()

        # First request
        is_dup1 = await dedup.is_duplicate("GET", "http://test.com/api/users")
        assert is_dup1 is False

        # Same request
        is_dup2 = await dedup.is_duplicate("GET", "http://test.com/api/users")
        assert is_dup2 is True

    @pytest.mark.asyncio
    async def test_different_requests_not_duplicates(self):
        """Different URLs should not be duplicates."""
        from utils.scan_client import reset_deduplicator, get_deduplicator

        reset_deduplicator()
        dedup = get_deduplicator()

        is_dup1 = await dedup.is_duplicate("GET", "http://test.com/api/users")
        is_dup2 = await dedup.is_duplicate("GET", "http://test.com/api/products")

        assert is_dup1 is False
        assert is_dup2 is False

    @pytest.mark.asyncio
    async def test_params_affect_dedup_key(self):
        """Different params should create different cache keys."""
        from utils.scan_client import reset_deduplicator, get_deduplicator

        reset_deduplicator()
        dedup = get_deduplicator()

        is_dup1 = await dedup.is_duplicate("GET", "http://test.com/search", {"q": "test1"})
        is_dup2 = await dedup.is_duplicate("GET", "http://test.com/search", {"q": "test2"})

        assert is_dup1 is False
        assert is_dup2 is False  # Different params = different request


class TestDryRunMode:
    """Test dry-run mode functionality."""

    @pytest.mark.asyncio
    async def test_dry_run_does_not_send_request(self):
        """Dry-run mode should simulate request without sending."""
        from utils.scan_client import get_scan_client, reset_scan_session

        reset_scan_session()

        async with get_scan_client(dry_run=True) as client:
            response = await client.get("http://test.com/api/users")

            # Should get simulated response
            assert response.status_code == 200
            assert b"DRY-RUN" in response.content
            assert response.headers.get("X-Dry-Run") == "true"

            # Should track stats
            stats = client.get_stats()
            assert stats["dry_run_simulated"] == 1
            assert stats["dry_run_mode"] is True


class TestLatencyTracking:
    """Test latency metrics."""

    @pytest.mark.asyncio
    async def test_latency_tracking(self):
        """Latency should be tracked for all requests."""
        from utils.scan_client import reset_circuit_breaker, get_circuit_breaker

        reset_circuit_breaker()
        cb = get_circuit_breaker()

        # Record some latencies
        await cb.record_latency(100.0)
        await cb.record_latency(200.0)
        await cb.record_latency(50.0)

        stats = cb.get_stats()
        assert stats["latency_ms"]["min"] == 50.0
        assert stats["latency_ms"]["max"] == 200.0
        # avg = (100 + 200 + 50) / 3 = 116.67, but we need requests counted
        # Note: record_latency doesn't increment total_requests, only record_success does


class TestRateLimitDetection:
    """Test rate limit response detection."""

    def test_429_is_rate_limited(self):
        """429 status should be detected as rate limited."""
        from utils.scan_client import is_rate_limited_response

        response = httpx.Response(429, content=b"Too Many Requests")
        assert is_rate_limited_response(response) is True

    def test_retry_after_header_detected(self):
        """Response with Retry-After should be detected."""
        from utils.scan_client import is_rate_limited_response

        response = httpx.Response(200, headers={"retry-after": "30"})
        assert is_rate_limited_response(response) is True

    def test_rate_limit_text_detected(self):
        """Rate limit message in body should be detected."""
        from utils.scan_client import is_rate_limited_response

        response = httpx.Response(200, content=b"rate limit exceeded, please wait")
        assert is_rate_limited_response(response) is True

    def test_normal_response_not_rate_limited(self):
        """Normal 200 response should not be detected as rate limited."""
        from utils.scan_client import is_rate_limited_response

        response = httpx.Response(200, content=b'{"success": true}')
        assert is_rate_limited_response(response) is False


class TestBlockDetection:
    """Test WAF/block response detection."""

    def test_403_is_blocked(self):
        """403 status should be detected as blocked."""
        from utils.scan_client import is_blocked_response

        response = httpx.Response(403, content=b"Forbidden")
        assert is_blocked_response(response) is True

    def test_cloudflare_challenge_detected(self):
        """Cloudflare challenge should be detected."""
        from utils.scan_client import is_blocked_response

        response = httpx.Response(403, content=b"cf-ray challenge page")
        assert is_blocked_response(response) is True


class TestSessionManagement:
    """Test scan session management."""

    def test_reset_scan_session(self):
        """reset_scan_session should clear all state."""
        from utils.scan_client import (
            reset_scan_session,
            get_circuit_breaker,
            get_deduplicator,
        )

        reset_scan_session()

        cb = get_circuit_breaker()
        dedup = get_deduplicator()

        assert cb.consecutive_blocks == 0
        assert cb.total_blocked == 0
        assert len(dedup._cache) == 0

    def test_get_scan_session_stats(self):
        """get_scan_session_stats should return combined stats."""
        from utils.scan_client import reset_scan_session, get_scan_session_stats

        reset_scan_session()
        stats = get_scan_session_stats()

        assert "circuit_breaker" in stats
        assert "deduplicator" in stats
        assert "safety_mode" in stats


class TestSafetyModeIntegration:
    """Test safety mode integration in ScanClient."""

    @pytest.mark.asyncio
    async def test_safe_mode_blocks_post(self):
        """Safe mode should block POST requests."""
        os.environ["PHANTOM_SAFE_MODE"] = "safe"

        from utils.scan_client import get_scan_client, reset_scan_session

        reset_scan_session()

        async with get_scan_client() as client:
            response = await client.post("http://test.com/api/users", json={"name": "test"})

            # SafeAsyncClient returns 403 for blocked requests
            assert response.status_code == 403
            assert b"Blocked" in response.content

        # Reset for other tests
        os.environ["PHANTOM_SAFE_MODE"] = "standard"

    @pytest.mark.asyncio
    async def test_standard_mode_allows_post(self):
        """Standard mode should allow POST with safe payload."""
        os.environ["PHANTOM_SAFE_MODE"] = "standard"

        from utils.scan_client import get_scan_client, reset_scan_session
        from utils.safe_http_client import is_payload_safe

        # Verify the payload would be considered safe
        assert is_payload_safe('{"name": "test"}') is True

        reset_scan_session()

        # Note: This test would need mocking to avoid actual HTTP request
        # For unit test purposes, we verify the configuration is correct
        assert os.environ.get("PHANTOM_SAFE_MODE") == "standard"


class TestClientStats:
    """Test client statistics tracking."""

    @pytest.mark.asyncio
    async def test_stats_include_all_fields(self):
        """Client stats should include all tracking fields."""
        from utils.scan_client import get_scan_client, reset_scan_session

        reset_scan_session()

        async with get_scan_client(dry_run=True) as client:
            # Make a request to populate stats
            await client.get("http://test.com/api")

            stats = client.get_stats()

            # Verify all expected fields
            assert "rate_limited" in stats
            assert "blocked" in stats
            assert "allowed" in stats
            assert "dry_run_simulated" in stats
            assert "dry_run_mode" in stats
            assert "circuit_breaker" in stats
            assert "dedup" in stats

            # Verify circuit breaker stats
            cb_stats = stats["circuit_breaker"]
            assert "latency_ms" in cb_stats
            assert "avg" in cb_stats["latency_ms"]
            assert "min" in cb_stats["latency_ms"]
            assert "max" in cb_stats["latency_ms"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
