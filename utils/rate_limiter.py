"""
Rate limiter with token bucket algorithm.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.config_manager import Settings

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.

    SECURITY: Thread-safe implementation using asyncio.Lock to prevent
    race conditions in concurrent access scenarios.
    """

    capacity: float
    rate: float  # tokens per second
    tokens: float = field(init=False)
    last_update: float = field(init=False)
    _lock: asyncio.Lock = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def consume(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens (thread-safe).

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False otherwise
        """
        async with self._lock:
            self._refill_unsafe()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def consume_sync(self, tokens: float = 1.0) -> bool:
        """
        Try to consume tokens (non-async, for backwards compatibility).

        WARNING: This method is not thread-safe. Use consume() in async contexts.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False otherwise
        """
        self._refill_unsafe()

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

    async def wait_and_consume(self, tokens: float = 1.0) -> None:
        """
        Wait until tokens available and consume (thread-safe).

        Args:
            tokens: Number of tokens to consume
        """
        while not await self.consume(tokens):
            # Calculate wait time under lock
            async with self._lock:
                needed = tokens - self.tokens
                wait_time = needed / self.rate if self.rate > 0 else 1.0
            await asyncio.sleep(min(wait_time, 1.0))

    def _refill_unsafe(self) -> None:
        """
        Refill tokens based on elapsed time.

        NOTE: Must be called while holding _lock.
        """
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now

        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate,
        )


class RateLimiter:
    """
    Rate limiter with per-domain limiting.

    Uses token bucket algorithm for smooth rate limiting.
    """

    # Class-level counter for all instances (for compliance reporting)
    _global_request_count: int = 0
    _global_lock: asyncio.Lock | None = None
    _global_sync_lock: threading.Lock = threading.Lock()  # Thread-safe for counter

    def __init__(
        self,
        settings: Settings | None = None,
        default_rate: float = 10.0,
        default_burst: int = 20,
    ) -> None:
        """
        Initialize rate limiter.

        Args:
            settings: Application settings
            default_rate: Default requests per second
            default_burst: Default burst size
        """
        if settings:
            self.default_rate = getattr(settings.rate_limit, 'requests_per_second', default_rate)
            self.default_burst = getattr(settings.rate_limit, 'concurrent_scans', default_burst)
        else:
            self.default_rate = default_rate
            self.default_burst = default_burst

        self._buckets: dict[str, TokenBucket] = {}
        self._domain_rates: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()  # For sync methods - prevents bucket race
        self._request_count: int = 0  # Instance-level counter
    
    async def acquire(self, domain: str = "default") -> None:
        """
        Acquire permission to make a request.

        Args:
            domain: Domain or identifier for rate limiting
        """
        bucket = await self._get_bucket(domain)
        await bucket.wait_and_consume()

        # Increment instance counter (protected by instance lock)
        async with self._lock:
            self._request_count += 1

        # Increment global counter (protected by class-level lock for cross-instance safety)
        with RateLimiter._global_sync_lock:
            RateLimiter._global_request_count += 1

    @property
    def request_count(self) -> int:
        """Get total requests made through this limiter."""
        return self._request_count

    @classmethod
    def get_global_request_count(cls) -> int:
        """Get total requests made across all RateLimiter instances."""
        return cls._global_request_count

    @classmethod
    def reset_global_count(cls) -> None:
        """Reset the global request counter."""
        cls._global_request_count = 0
    
    async def try_acquire(self, domain: str = "default") -> bool:
        """
        Try to acquire without waiting (thread-safe).

        Args:
            domain: Domain or identifier

        Returns:
            True if acquired, False otherwise
        """
        bucket = await self._get_bucket(domain)
        return await bucket.consume()

    def try_acquire_sync(self, domain: str = "default") -> bool:
        """
        Try to acquire without waiting (non-async, for backwards compatibility).

        Thread-safe: Uses sync lock to prevent race conditions during bucket creation.

        Args:
            domain: Domain or identifier

        Returns:
            True if acquired, False otherwise
        """
        with self._sync_lock:
            bucket = self._buckets.get(domain)
            if bucket is None:
                bucket = TokenBucket(
                    capacity=self.default_burst,
                    rate=self._domain_rates.get(domain, self.default_rate),
                )
                self._buckets[domain] = bucket

        return bucket.consume_sync()

    async def _get_bucket(self, domain: str) -> TokenBucket:
        """Get or create bucket for domain (thread-safe)."""
        async with self._lock:
            if domain not in self._buckets:
                rate = self._domain_rates.get(domain, self.default_rate)
                self._buckets[domain] = TokenBucket(
                    capacity=self.default_burst,
                    rate=rate,
                )
            return self._buckets[domain]

    async def set_rate(self, domain: str, rate: float) -> None:
        """
        Set rate limit for specific domain (thread-safe).

        Args:
            domain: Domain identifier
            rate: Requests per second
        """
        async with self._lock:
            self._domain_rates[domain] = rate

            if domain in self._buckets:
                self._buckets[domain].rate = rate

    # ═══════════════════════════════════════════════════════════════════════════
    # RATE-02 FIX: Adaptive rate on 429 responses
    # Implements exponential backoff when rate limited
    # ═══════════════════════════════════════════════════════════════════════════

    async def signal_rate_limited(self, domain: str = "default") -> float:
        """
        Signal that a 429 was received - reduce rate by 50%.

        RATE-02 FIX: Adaptive rate limiting based on server response.
        Implements exponential backoff when 429s are received.

        Args:
            domain: Domain that returned 429

        Returns:
            New rate after reduction
        """
        async with self._lock:
            current_rate = self._domain_rates.get(domain, self.default_rate)
            # Reduce rate by 50%, minimum 0.5 req/s
            new_rate = max(0.5, current_rate * 0.5)
            self._domain_rates[domain] = new_rate

            if domain in self._buckets:
                self._buckets[domain].rate = new_rate

            logger.warning(
                f"[RATE-02] 429 received for {domain}, "
                f"reducing rate: {current_rate:.1f} → {new_rate:.1f} req/s"
            )

            return new_rate

    async def signal_success(self, domain: str = "default") -> None:
        """
        Signal successful request - gradually recover rate.

        Call this after successful requests to slowly restore rate
        after a 429-triggered backoff.

        Args:
            domain: Domain that succeeded
        """
        async with self._lock:
            current_rate = self._domain_rates.get(domain, self.default_rate)
            # Only recover if we're below default rate
            if current_rate < self.default_rate:
                # Recover by 10%, capped at default
                new_rate = min(self.default_rate, current_rate * 1.1)
                self._domain_rates[domain] = new_rate

                if domain in self._buckets:
                    self._buckets[domain].rate = new_rate

                if new_rate >= self.default_rate * 0.9:
                    logger.debug(f"[RATE-02] Rate recovered to {new_rate:.1f} req/s for {domain}")

    async def get_wait_time_after_429(self, domain: str = "default") -> float:
        """
        Get recommended wait time after 429.

        Uses exponential backoff based on current rate reduction.

        Returns:
            Seconds to wait before retrying
        """
        async with self._lock:
            current_rate = self._domain_rates.get(domain, self.default_rate)
            # Lower rate = longer wait
            if current_rate <= 1.0:
                return 30.0  # Very slow, wait 30s
            elif current_rate <= 2.0:
                return 15.0  # Slow, wait 15s
            elif current_rate <= 5.0:
                return 5.0   # Moderate, wait 5s
            else:
                return 2.0   # Still okay, wait 2s


class ConcurrencyLimiter:
    """Limits concurrent operations."""
    
    def __init__(
        self,
        max_concurrent: int = 10,
        per_domain: bool = False,
    ) -> None:
        """
        Initialize limiter.
        
        Args:
            max_concurrent: Maximum concurrent operations
            per_domain: Whether to limit per domain
        """
        self.max_concurrent = max_concurrent
        self.per_domain = per_domain
        
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._domain_semaphores: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(max_concurrent)
        )
    
    async def __aenter__(self) -> None:
        """Acquire semaphore."""
        await self._semaphore.acquire()
    
    async def __aexit__(self, *args: object) -> None:
        """Release semaphore."""
        self._semaphore.release()
    
    async def acquire(self, domain: str | None = None) -> None:
        """
        Acquire concurrency slot.
        
        Args:
            domain: Optional domain for per-domain limiting
        """
        if self.per_domain and domain:
            await self._domain_semaphores[domain].acquire()
        else:
            await self._semaphore.acquire()
    
    def release(self, domain: str | None = None) -> None:
        """
        Release concurrency slot.
        
        Args:
            domain: Optional domain
        """
        if self.per_domain and domain:
            self._domain_semaphores[domain].release()
        else:
            self._semaphore.release()


class AdaptiveRateLimiter(RateLimiter):
    """
    Rate limiter that adapts based on response codes.
    
    Slows down on 429 (Too Many Requests) responses.
    """
    
    def __init__(
        self,
        settings: Settings | None = None,
        min_rate: float = 0.5,
        max_rate: float = 50.0,
        **kwargs: object,
    ) -> None:
        """
        Initialize adaptive limiter.
        
        Args:
            settings: Application settings
            min_rate: Minimum rate limit
            max_rate: Maximum rate limit
            **kwargs: Additional arguments
        """
        super().__init__(settings, **kwargs)  # type: ignore[arg-type]
        self.min_rate = min_rate
        self.max_rate = max_rate
        self._backoff_factors: dict[str, float] = defaultdict(lambda: 1.0)
    
    async def report_success(self, domain: str = "default") -> None:
        """
        Report successful request (thread-safe).

        Args:
            domain: Domain identifier
        """
        async with self._lock:
            # Gradually increase rate
            factor = self._backoff_factors[domain]
            if factor < 1.0:
                self._backoff_factors[domain] = min(1.0, factor * 1.1)
                await self._update_rate_unsafe(domain)

    async def report_rate_limit(self, domain: str = "default") -> None:
        """
        Report rate limit hit (429) (thread-safe).

        Args:
            domain: Domain identifier
        """
        async with self._lock:
            # Decrease rate
            factor = self._backoff_factors[domain]
            self._backoff_factors[domain] = max(0.1, factor * 0.5)
            await self._update_rate_unsafe(domain)

            logger.warning(
                f"Rate limit hit for {domain}, reducing rate",
                domain=domain,
                factor=self._backoff_factors[domain],
            )

    async def _update_rate_unsafe(self, domain: str) -> None:
        """
        Update rate based on backoff factor.

        NOTE: Must be called while holding _lock.
        """
        base_rate = self._domain_rates.get(domain, self.default_rate)
        new_rate = base_rate * self._backoff_factors[domain]
        new_rate = max(self.min_rate, min(self.max_rate, new_rate))

        if domain in self._buckets:
            self._buckets[domain].rate = new_rate


# =============================================================================
# PHANTOM AI RATE LIMITER ENHANCEMENTS
# =============================================================================

@dataclass
class DomainRateHistory:
    """
    Historical rate data for a domain.

    Used to calculate optimal rates based on past performance.
    """
    domain: str
    successful_requests: int = 0
    failed_requests: int = 0
    rate_limited_requests: int = 0
    total_response_time_ms: float = 0.0
    current_rate: float = 10.0
    last_optimal_rate: float = 10.0
    last_updated: float = field(default_factory=time.monotonic)

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        total = self.successful_requests + self.failed_requests
        if total == 0:
            return 100.0
        return (self.successful_requests / total) * 100

    @property
    def average_response_time_ms(self) -> float:
        """Calculate average response time."""
        total = self.successful_requests + self.failed_requests
        if total == 0:
            return 0.0
        return self.total_response_time_ms / total

    def record_success(self, response_time_ms: float) -> None:
        """Record a successful request."""
        self.successful_requests += 1
        self.total_response_time_ms += response_time_ms
        self.last_updated = time.monotonic()

    def record_failure(self, rate_limited: bool = False) -> None:
        """Record a failed request."""
        self.failed_requests += 1
        if rate_limited:
            self.rate_limited_requests += 1
        self.last_updated = time.monotonic()


@dataclass
class ScanRateCoordination:
    """
    Coordination data for parallel scans.

    Ensures multiple scans against the same domain don't
    exceed aggregate rate limits.
    """
    scan_id: str
    domains: set[str] = field(default_factory=set)
    allocated_rate: float = 0.0
    started_at: float = field(default_factory=time.monotonic)
    active: bool = True
    domain_allocations: dict[str, float] = field(default_factory=dict)  # Per-domain allocations


@dataclass
class RateStatistics:
    """
    Comprehensive rate limiting statistics.

    Used for monitoring, debugging, and optimization.
    """
    total_requests: int = 0
    total_waits: int = 0
    total_wait_time_ms: float = 0.0
    domains_tracked: int = 0
    active_scans: int = 0
    global_rate_limit: float = 0.0
    average_rate: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "total_waits": self.total_waits,
            "total_wait_time_ms": round(self.total_wait_time_ms, 2),
            "domains_tracked": self.domains_tracked,
            "active_scans": self.active_scans,
            "global_rate_limit": round(self.global_rate_limit, 2),
            "average_rate": round(self.average_rate, 2),
        }


class PhantomRateLimiter(AdaptiveRateLimiter):
    """
    PHANTOM AI Enhanced Rate Limiter.

    Extends AdaptiveRateLimiter with:
    - Optimal rate calculation based on domain history
    - Parallel scan coordination
    - Comprehensive statistics
    - Attack Surface Budget integration
    - Per-scan request tracking

    Thread Safety:
    - All public methods are thread-safe
    - Uses asyncio.Lock for async operations

    Usage:
        limiter = PhantomRateLimiter()

        # Get optimal rate for domain
        rate = await limiter.get_optimal_rate("example.com")

        # Coordinate parallel scan
        await limiter.register_scan("scan-123", ["example.com", "api.example.com"])

        # Acquire with tracking
        await limiter.acquire_tracked("example.com", scan_id="scan-123")

        # Get statistics
        stats = limiter.get_rate_statistics()
    """

    # Class-level coordination for all instances
    _global_scans: dict[str, ScanRateCoordination] = {}
    _global_domain_allocations: dict[str, float] = defaultdict(float)
    _coordination_lock: asyncio.Lock | None = None
    _init_lock: threading.Lock = threading.Lock()  # Protects _coordination_lock init

    def __init__(
        self,
        settings: "Settings | None" = None,
        min_rate: float = 0.5,
        max_rate: float = 50.0,
        global_rate_limit: float = 100.0,
        **kwargs: object,
    ) -> None:
        """
        Initialize PHANTOM rate limiter.

        Args:
            settings: Application settings
            min_rate: Minimum rate limit per domain
            max_rate: Maximum rate limit per domain
            global_rate_limit: Maximum total requests per second across all domains
            **kwargs: Additional arguments for parent class
        """
        super().__init__(settings, min_rate, max_rate, **kwargs)

        self.global_rate_limit = global_rate_limit

        # Domain history for optimal rate calculation
        self._domain_history: dict[str, DomainRateHistory] = {}

        # Request tracking per scan
        self._scan_requests: dict[str, int] = defaultdict(int)

        # Wait statistics
        self._total_waits: int = 0
        self._total_wait_time_ms: float = 0.0

        # Ensure coordination lock exists (thread-safe initialization)
        with PhantomRateLimiter._init_lock:
            if PhantomRateLimiter._coordination_lock is None:
                PhantomRateLimiter._coordination_lock = asyncio.Lock()

    async def get_optimal_rate(self, domain: str) -> float:
        """
        Calculate optimal rate for a domain based on historical performance.

        Uses a heuristic approach:
        - Start with default rate
        - Increase if success rate is high (>95%) and response times are low
        - Decrease if rate limiting is detected or errors are frequent
        - Consider parallel scan coordination

        Args:
            domain: Target domain

        Returns:
            Optimal rate in requests per second
        """
        async with self._lock:
            history = self._domain_history.get(domain)

            if not history:
                # No history, return default
                return self.default_rate

            # Base calculation on success rate
            success_rate = history.success_rate
            avg_response_time = history.average_response_time_ms

            # Calculate optimal rate
            optimal_rate = self.default_rate

            # Success rate factor
            if success_rate >= 99.0:
                # Very high success, can increase rate
                optimal_rate *= 1.5
            elif success_rate >= 95.0:
                # Good success rate
                optimal_rate *= 1.2
            elif success_rate >= 80.0:
                # Acceptable, keep default
                pass
            elif success_rate >= 50.0:
                # Some failures, reduce rate
                optimal_rate *= 0.7
            else:
                # High failure rate, significantly reduce
                optimal_rate *= 0.5

            # Response time factor
            if avg_response_time > 0:
                if avg_response_time < 100:
                    # Fast responses, can increase rate
                    optimal_rate *= 1.2
                elif avg_response_time < 500:
                    # Normal responses
                    pass
                elif avg_response_time < 1000:
                    # Slow responses, reduce rate
                    optimal_rate *= 0.8
                else:
                    # Very slow, significantly reduce
                    optimal_rate *= 0.5

            # Rate limiting penalty
            if history.rate_limited_requests > 0:
                # Reduce by 20% for each rate limit (up to 80% total reduction)
                penalty = min(0.8, history.rate_limited_requests * 0.2)
                optimal_rate *= (1 - penalty)

            # Apply limits
            optimal_rate = max(self.min_rate, min(self.max_rate, optimal_rate))

            # Check coordination (don't exceed allocated rate for parallel scans)
            allocated = PhantomRateLimiter._global_domain_allocations.get(domain, 0)
            if allocated > 0:
                optimal_rate = min(optimal_rate, allocated)

            # Update history
            history.last_optimal_rate = optimal_rate

            logger.debug(
                f"Optimal rate for {domain}: {optimal_rate:.2f} req/s "
                f"(success: {success_rate:.1f}%, response: {avg_response_time:.0f}ms)"
            )

            return optimal_rate

    async def register_scan(
        self,
        scan_id: str,
        domains: list[str],
        requested_rate: float | None = None,
    ) -> dict[str, float]:
        """
        Register a scan for rate coordination.

        Allocates rate budget across domains for the scan.
        Ensures parallel scans don't exceed aggregate limits.

        Args:
            scan_id: Unique scan identifier
            domains: List of domains to scan
            requested_rate: Requested rate per domain (None for optimal)

        Returns:
            Dict mapping domain -> allocated rate
        """
        assert PhantomRateLimiter._coordination_lock is not None

        async with PhantomRateLimiter._coordination_lock:
            # Calculate available rate budget
            total_allocated = sum(PhantomRateLimiter._global_domain_allocations.values())
            available_budget = self.global_rate_limit - total_allocated

            if available_budget <= 0:
                logger.warning(
                    f"Global rate limit reached, cannot register scan {scan_id}"
                )
                return {}

            # Allocate rate per domain
            allocations: dict[str, float] = {}
            rate_per_domain = min(
                requested_rate or self.default_rate,
                available_budget / len(domains),
            )

            for domain in domains:
                # Check if domain already has allocation from other scans
                existing = PhantomRateLimiter._global_domain_allocations.get(domain, 0)

                # Calculate allocation for this scan
                allocation = min(rate_per_domain, self.max_rate - existing)
                allocation = max(allocation, self.min_rate)

                allocations[domain] = allocation
                PhantomRateLimiter._global_domain_allocations[domain] = existing + allocation

            # Register scan coordination
            PhantomRateLimiter._global_scans[scan_id] = ScanRateCoordination(
                scan_id=scan_id,
                domains=set(domains),
                allocated_rate=sum(allocations.values()),
                domain_allocations=allocations.copy(),  # Track per-domain for cleanup
            )

            logger.info(
                f"Registered scan {scan_id} with {len(domains)} domains, "
                f"total rate: {sum(allocations.values()):.2f} req/s"
            )

            return allocations

    async def unregister_scan(self, scan_id: str) -> None:
        """
        Unregister a scan and release its rate allocation.

        Args:
            scan_id: Scan identifier to unregister
        """
        assert PhantomRateLimiter._coordination_lock is not None

        async with PhantomRateLimiter._coordination_lock:
            scan = PhantomRateLimiter._global_scans.pop(scan_id, None)
            if not scan:
                return

            # Release allocations using tracked per-domain values
            for domain, allocation in scan.domain_allocations.items():
                if domain in PhantomRateLimiter._global_domain_allocations:
                    PhantomRateLimiter._global_domain_allocations[domain] -= allocation
                    # Remove domain entry if allocation is zero or negative
                    if PhantomRateLimiter._global_domain_allocations[domain] <= 0:
                        del PhantomRateLimiter._global_domain_allocations[domain]

            scan.active = False
            logger.info(f"Unregistered scan {scan_id}, released {len(scan.domain_allocations)} domain allocations")

    async def coordinate_parallel_scans(self, scan_id: str) -> dict[str, float]:
        """
        Get current rate allocations for a parallel scan.

        This method is called during scanning to get the current
        rate limits that should be applied.

        Args:
            scan_id: Scan identifier

        Returns:
            Dict mapping domain -> current allocated rate
        """
        assert PhantomRateLimiter._coordination_lock is not None

        async with PhantomRateLimiter._coordination_lock:
            scan = PhantomRateLimiter._global_scans.get(scan_id)
            if not scan or not scan.active:
                return {}

            # Return current allocations for scan's domains
            return {
                domain: PhantomRateLimiter._global_domain_allocations.get(domain, self.default_rate)
                for domain in scan.domains
            }

    async def acquire_tracked(
        self,
        domain: str = "default",
        scan_id: str | None = None,
    ) -> float:
        """
        Acquire rate limit permission with tracking.

        Similar to acquire() but tracks wait times and per-scan requests.

        Args:
            domain: Domain or identifier
            scan_id: Optional scan ID for tracking

        Returns:
            Wait time in milliseconds (0 if no wait)
        """
        start = time.monotonic()

        await self.acquire(domain)

        wait_time_ms = (time.monotonic() - start) * 1000

        async with self._lock:
            if wait_time_ms > 10:  # Only count significant waits
                self._total_waits += 1
                self._total_wait_time_ms += wait_time_ms

            if scan_id:
                self._scan_requests[scan_id] += 1

        return wait_time_ms

    def record_request_result(
        self,
        domain: str,
        success: bool,
        response_time_ms: float = 0.0,
        rate_limited: bool = False,
    ) -> None:
        """
        Record the result of a request for history tracking.

        Called after each request to update domain history.

        Args:
            domain: Target domain
            success: Whether request was successful
            response_time_ms: Response time in milliseconds
            rate_limited: Whether request was rate limited (429)
        """
        # BUG-FIX 2026-02-08: Add lock protection to prevent race condition on _domain_history
        with self._global_sync_lock:
            if domain not in self._domain_history:
                self._domain_history[domain] = DomainRateHistory(domain=domain)

            history = self._domain_history[domain]

            if success:
                history.record_success(response_time_ms)
            else:
                history.record_failure(rate_limited=rate_limited)

    def get_rate_statistics(self) -> RateStatistics:
        """
        Get comprehensive rate limiting statistics.

        Returns:
            RateStatistics object with all metrics
        """
        # BUG-FIX 2026-02-08: Use lock to prevent dict modification during iteration
        # which would cause RuntimeError: dictionary changed size during iteration
        with self._global_sync_lock:
            # Calculate average rate across all domains
            total_rate = 0.0
            buckets_snapshot = list(self._buckets.values())

        for bucket in buckets_snapshot:
            total_rate += bucket.rate

        avg_rate = total_rate / len(buckets_snapshot) if buckets_snapshot else self.default_rate

        return RateStatistics(
            total_requests=self._request_count,
            total_waits=self._total_waits,
            total_wait_time_ms=self._total_wait_time_ms,
            domains_tracked=len(self._domain_history),
            active_scans=len([s for s in PhantomRateLimiter._global_scans.values() if s.active]),
            global_rate_limit=self.global_rate_limit,
            average_rate=avg_rate,
        )

    def get_domain_history(self, domain: str) -> DomainRateHistory | None:
        """
        Get historical data for a domain.

        Args:
            domain: Domain to get history for

        Returns:
            DomainRateHistory or None if no data
        """
        return self._domain_history.get(domain)

    def get_all_domain_histories(self) -> dict[str, DomainRateHistory]:
        """
        Get historical data for all tracked domains.

        Returns:
            Dict mapping domain -> DomainRateHistory
        """
        return self._domain_history.copy()

    def get_scan_request_count(self, scan_id: str) -> int:
        """
        Get the number of requests made for a specific scan.

        Args:
            scan_id: Scan identifier

        Returns:
            Number of requests made
        """
        return self._scan_requests.get(scan_id, 0)

    async def apply_optimal_rates(self) -> None:
        """
        Apply optimal rates to all tracked domains.

        Calculates and sets optimal rates based on historical data.
        Should be called periodically during long scans.
        """
        for domain in list(self._domain_history.keys()):
            optimal_rate = await self.get_optimal_rate(domain)
            await self.set_rate(domain, optimal_rate)

        logger.info(
            f"Applied optimal rates to {len(self._domain_history)} domains"
        )

    def print_statistics(self) -> None:
        """Print rate limiting statistics to console."""
        stats = self.get_rate_statistics()
        print(f"""
╔════════════════════════════════════════════════════════════════════╗
║  📊 PHANTOM Rate Limiter Statistics                                 ║
╠════════════════════════════════════════════════════════════════════╣
║  Total Requests:    {stats.total_requests:<15}                            ║
║  Total Waits:       {stats.total_waits:<15}                            ║
║  Total Wait Time:   {stats.total_wait_time_ms:.0f}ms                                          ║
║  Domains Tracked:   {stats.domains_tracked:<15}                            ║
║  Active Scans:      {stats.active_scans:<15}                            ║
║  Global Rate Limit: {stats.global_rate_limit:.1f} req/s                                    ║
║  Average Rate:      {stats.average_rate:.1f} req/s                                    ║
╚════════════════════════════════════════════════════════════════════╝
""")


# =============================================================================
# PHANTOM RATE LIMITER FACTORY
# =============================================================================

_phantom_limiter_instance: PhantomRateLimiter | None = None
_phantom_limiter_lock: asyncio.Lock | None = None
_phantom_limiter_init_lock = threading.Lock()  # Protects lazy asyncio.Lock init


async def get_phantom_rate_limiter(
    settings: "Settings | None" = None,
) -> PhantomRateLimiter:
    """
    Get the global PHANTOM rate limiter instance.

    Creates the instance on first call with provided settings.

    Args:
        settings: Optional settings for initialization

    Returns:
        PhantomRateLimiter singleton instance
    """
    global _phantom_limiter_instance, _phantom_limiter_lock

    # Lazy-init asyncio.Lock (can't create at module level outside event loop)
    if _phantom_limiter_lock is None:
        with _phantom_limiter_init_lock:
            if _phantom_limiter_lock is None:
                _phantom_limiter_lock = asyncio.Lock()

    async with _phantom_limiter_lock:
        if _phantom_limiter_instance is None:
            _phantom_limiter_instance = PhantomRateLimiter(settings=settings)
            logger.info("PHANTOM Rate Limiter initialized")

        return _phantom_limiter_instance


def get_phantom_rate_limiter_sync(
    settings: "Settings | None" = None,
) -> PhantomRateLimiter:
    """
    Get the global PHANTOM rate limiter instance (sync version).

    Creates the instance on first call.

    Args:
        settings: Optional settings for initialization

    Returns:
        PhantomRateLimiter singleton instance
    """
    global _phantom_limiter_instance

    if _phantom_limiter_instance is None:
        _phantom_limiter_instance = PhantomRateLimiter(settings=settings)
        logger.info("PHANTOM Rate Limiter initialized (sync)")

    return _phantom_limiter_instance
