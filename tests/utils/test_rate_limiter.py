"""
Tests for utils/rate_limiter.py

Tests thread-safety and race condition fixes.
"""

import asyncio
import pytest
from unittest.mock import MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from utils.rate_limiter import TokenBucket, RateLimiter, AdaptiveRateLimiter


class TestTokenBucket:
    """Tests for TokenBucket class."""

    @pytest.mark.asyncio
    async def test_consume_reduces_tokens(self):
        """Test that consume reduces token count."""
        bucket = TokenBucket(capacity=10, rate=1.0)

        result = await bucket.consume(1.0)

        assert result is True
        # Tokens should be reduced (accounting for refill time)
        assert bucket.tokens < 10

    @pytest.mark.asyncio
    async def test_consume_rejects_when_empty(self):
        """Test that consume rejects when not enough tokens."""
        bucket = TokenBucket(capacity=1, rate=0.1)

        # First consume should succeed
        result1 = await bucket.consume(1.0)
        assert result1 is True

        # Second should fail (no time to refill)
        result2 = await bucket.consume(1.0)
        assert result2 is False

    @pytest.mark.asyncio
    async def test_wait_and_consume_waits_for_tokens(self):
        """Test that wait_and_consume waits until tokens available."""
        bucket = TokenBucket(capacity=1, rate=10.0)  # Fast refill

        # Consume all tokens
        await bucket.consume(1.0)

        # This should wait and then succeed
        await asyncio.wait_for(
            bucket.wait_and_consume(0.5),
            timeout=1.0
        )

    @pytest.mark.asyncio
    async def test_concurrent_consume_thread_safe(self):
        """Test that concurrent consume calls are thread-safe."""
        bucket = TokenBucket(capacity=100, rate=0)  # No refill

        # Run many concurrent consumers
        async def consumer():
            successes = 0
            for _ in range(10):
                if await bucket.consume(1.0):
                    successes += 1
            return successes

        # 20 concurrent consumers, each trying 10 times
        results = await asyncio.gather(*[consumer() for _ in range(20)])

        # Total successes should not exceed capacity
        total_successes = sum(results)
        assert total_successes <= 100


class TestRateLimiter:
    """Tests for RateLimiter class."""

    @pytest.mark.asyncio
    async def test_acquire_creates_bucket_for_domain(self):
        """Test that acquire creates bucket for new domain."""
        limiter = RateLimiter(default_rate=10.0, default_burst=5)

        await limiter.acquire("test-domain")

        assert "test-domain" in limiter._buckets

    @pytest.mark.asyncio
    async def test_try_acquire_thread_safe(self):
        """Test that try_acquire is thread-safe."""
        limiter = RateLimiter(default_rate=0, default_burst=50)

        # Run many concurrent acquires
        async def acquirer():
            successes = 0
            for _ in range(10):
                if await limiter.try_acquire("shared-domain"):
                    successes += 1
            return successes

        results = await asyncio.gather(*[acquirer() for _ in range(10)])

        # Total should not exceed burst
        assert sum(results) <= 50

    @pytest.mark.asyncio
    async def test_set_rate_thread_safe(self):
        """Test that set_rate is thread-safe with concurrent access."""
        limiter = RateLimiter(default_rate=10.0, default_burst=10)

        # Create bucket first
        await limiter.acquire("test")

        # Set rate concurrently
        async def setter(rate):
            await limiter.set_rate("test", rate)

        await asyncio.gather(*[setter(i) for i in range(1, 11)])

        # Should not raise any errors


class TestAdaptiveRateLimiter:
    """Tests for AdaptiveRateLimiter class."""

    @pytest.mark.asyncio
    async def test_report_rate_limit_decreases_rate(self):
        """Test that reporting rate limit decreases the rate."""
        limiter = AdaptiveRateLimiter(default_rate=10.0, default_burst=10)

        # Create bucket
        await limiter.acquire("test")
        initial_rate = limiter._buckets["test"].rate

        # Report rate limit
        await limiter.report_rate_limit("test")

        # Rate should decrease
        new_rate = limiter._buckets["test"].rate
        assert new_rate < initial_rate

    @pytest.mark.asyncio
    async def test_report_success_increases_rate_after_backoff(self):
        """Test that success reports gradually restore rate."""
        limiter = AdaptiveRateLimiter(default_rate=10.0, default_burst=10)

        # Create bucket and trigger backoff
        await limiter.acquire("test")
        await limiter.report_rate_limit("test")
        reduced_rate = limiter._buckets["test"].rate

        # Report success
        await limiter.report_success("test")

        # Rate should increase (but still be below initial)
        assert limiter._buckets["test"].rate > reduced_rate

    @pytest.mark.asyncio
    async def test_concurrent_rate_adjustments_thread_safe(self):
        """Test that concurrent rate adjustments are thread-safe."""
        limiter = AdaptiveRateLimiter(default_rate=10.0, default_burst=10)
        await limiter.acquire("test")

        # Concurrent rate limit reports and success reports
        async def reporter():
            for _ in range(5):
                await limiter.report_rate_limit("test")
                await limiter.report_success("test")

        await asyncio.gather(*[reporter() for _ in range(5)])

        # Should not raise any errors
        assert "test" in limiter._buckets
