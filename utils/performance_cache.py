"""
Performance Cache System for PHANTOM AI.

Provides cross-module caching to avoid redundant operations:
- Response fingerprints: Cache identical HTTP responses
- WAF signatures: Cache WAF detection per host
- Negative control baselines: Reuse baselines between modules
- Tech fingerprints: Already cached (OK)

Thread-safe implementation with TTL support.

Version: 1.0.0
"""

import asyncio
import hashlib
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable
from functools import wraps

from utils.logger import get_logger

logger = get_logger(__name__)

CACHE_VERSION = "1.0.0"


@dataclass
class CacheEntry:
    """Single cache entry with TTL support."""
    value: Any
    created_at: float
    ttl_seconds: float
    hits: int = 0

    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.ttl_seconds <= 0:
            return False  # No expiry
        return time.time() - self.created_at > self.ttl_seconds

    def hit(self) -> Any:
        """Record cache hit and return value."""
        self.hits += 1
        return self.value


class PerformanceCache:
    """
    Thread-safe performance cache with multiple namespaces.

    Namespaces:
    - response: HTTP response fingerprints
    - waf: WAF detection results per host
    - baseline: Negative control baselines
    - tech: Tech fingerprinting results
    """

    # Default TTLs (seconds)
    DEFAULT_TTL = 300  # 5 minutes
    RESPONSE_TTL = 120  # 2 minutes (responses can change)
    WAF_TTL = 600  # 10 minutes (WAF status rarely changes)
    BASELINE_TTL = 300  # 5 minutes
    TECH_TTL = 900  # 15 minutes (tech stack doesn't change)

    # Maximum cache sizes per namespace
    MAX_ENTRIES = {
        "response": 1000,
        "waf": 100,
        "baseline": 500,
        "tech": 100,
    }

    def __init__(self):
        self._caches: dict[str, dict[str, CacheEntry]] = {
            "response": {},
            "waf": {},
            "baseline": {},
            "tech": {},
        }
        self._locks: dict[str, threading.Lock] = {
            "response": threading.Lock(),
            "waf": threading.Lock(),
            "baseline": threading.Lock(),
            "tech": threading.Lock(),
        }
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "by_namespace": {ns: {"hits": 0, "misses": 0} for ns in self._caches},
        }
        self._stats_lock = threading.Lock()

    def get(self, namespace: str, key: str) -> tuple[bool, Any]:
        """
        Get value from cache.

        Args:
            namespace: Cache namespace
            key: Cache key

        Returns:
            Tuple of (hit, value) - hit is True if found and not expired
        """
        if namespace not in self._caches:
            return False, None

        with self._locks[namespace]:
            entry = self._caches[namespace].get(key)

            if entry is None:
                self._record_miss(namespace)
                return False, None

            if entry.is_expired():
                del self._caches[namespace][key]
                self._record_miss(namespace)
                return False, None

            self._record_hit(namespace)
            return True, entry.hit()

    def set(
        self,
        namespace: str,
        key: str,
        value: Any,
        ttl: float | None = None,
    ) -> None:
        """
        Set value in cache.

        Args:
            namespace: Cache namespace
            key: Cache key
            value: Value to cache
            ttl: Optional custom TTL in seconds
        """
        if namespace not in self._caches:
            return

        # Determine TTL
        if ttl is None:
            ttl = {
                "response": self.RESPONSE_TTL,
                "waf": self.WAF_TTL,
                "baseline": self.BASELINE_TTL,
                "tech": self.TECH_TTL,
            }.get(namespace, self.DEFAULT_TTL)

        with self._locks[namespace]:
            # Check size limit and evict if needed
            max_size = self.MAX_ENTRIES.get(namespace, 1000)
            if len(self._caches[namespace]) >= max_size:
                self._evict_oldest(namespace)

            self._caches[namespace][key] = CacheEntry(
                value=value,
                created_at=time.time(),
                ttl_seconds=ttl,
            )

    def invalidate(self, namespace: str, key: str | None = None) -> int:
        """
        Invalidate cache entries.

        Args:
            namespace: Cache namespace
            key: Specific key to invalidate, or None for entire namespace

        Returns:
            Number of entries invalidated
        """
        if namespace not in self._caches:
            return 0

        with self._locks[namespace]:
            if key is None:
                count = len(self._caches[namespace])
                self._caches[namespace].clear()
                return count
            elif key in self._caches[namespace]:
                del self._caches[namespace][key]
                return 1
            return 0

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with self._stats_lock:
            total_entries = sum(len(c) for c in self._caches.values())
            return {
                **self._stats,
                "total_entries": total_entries,
                "hit_rate": (
                    self._stats["hits"] / max(1, self._stats["hits"] + self._stats["misses"])
                ),
            }

    def _record_hit(self, namespace: str) -> None:
        """Record cache hit."""
        with self._stats_lock:
            self._stats["hits"] += 1
            self._stats["by_namespace"][namespace]["hits"] += 1

    def _record_miss(self, namespace: str) -> None:
        """Record cache miss."""
        with self._stats_lock:
            self._stats["misses"] += 1
            self._stats["by_namespace"][namespace]["misses"] += 1

    def _evict_oldest(self, namespace: str) -> None:
        """Evict oldest entry from namespace (must hold lock)."""
        if not self._caches[namespace]:
            return

        oldest_key = min(
            self._caches[namespace].keys(),
            key=lambda k: self._caches[namespace][k].created_at,
        )
        del self._caches[namespace][oldest_key]

        with self._stats_lock:
            self._stats["evictions"] += 1


# Global singleton
_cache_instance: PerformanceCache | None = None
_cache_lock = threading.Lock()


def get_performance_cache() -> PerformanceCache:
    """Get or create global cache instance."""
    global _cache_instance
    if _cache_instance is None:
        with _cache_lock:
            if _cache_instance is None:
                _cache_instance = PerformanceCache()
    return _cache_instance


# ============================================================
# Response Fingerprinting Cache
# ============================================================

def hash_response(
    url: str,
    status_code: int,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
) -> str:
    """
    Create fingerprint hash for HTTP response.

    Args:
        url: Request URL
        status_code: HTTP status code
        headers: Response headers
        body: Response body

    Returns:
        SHA256 fingerprint
    """
    # Normalize URL (remove query params for caching)
    base_url = url.split("?")[0] if url else ""

    # Create fingerprint components
    components = [
        base_url,
        str(status_code),
    ]

    # Add relevant headers
    if headers:
        for key in ("content-type", "content-length", "x-powered-by", "server"):
            if key in headers:
                components.append(f"{key}:{headers[key]}")

    # Add body hash (first 1KB)
    if body:
        if isinstance(body, str):
            body = body.encode("utf-8", errors="ignore")
        body_sample = body[:1024]
        components.append(hashlib.md5(body_sample).hexdigest())

    fingerprint = ":".join(components)
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


def cache_response(
    url: str,
    status_code: int,
    headers: dict[str, str] | None,
    body: bytes | str | None,
    metadata: dict | None = None,
) -> str:
    """
    Cache HTTP response and return fingerprint.

    Args:
        url: Request URL
        status_code: HTTP status code
        headers: Response headers
        body: Response body
        metadata: Additional metadata to cache

    Returns:
        Response fingerprint
    """
    cache = get_performance_cache()
    fingerprint = hash_response(url, status_code, headers, body)

    cache_data = {
        "url": url,
        "status_code": status_code,
        "headers": headers,
        "body_hash": hashlib.md5(
            (body if isinstance(body, bytes) else (body or "").encode())[:1024]
        ).hexdigest(),
        "body_length": len(body) if body else 0,
        "metadata": metadata or {},
    }

    cache.set("response", fingerprint, cache_data)
    return fingerprint


def get_cached_response(fingerprint: str) -> dict | None:
    """
    Get cached response by fingerprint.

    Returns:
        Cached response data or None
    """
    cache = get_performance_cache()
    hit, data = cache.get("response", fingerprint)
    return data if hit else None


def is_response_cached(
    url: str,
    status_code: int,
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
) -> bool:
    """Check if response is already cached."""
    fingerprint = hash_response(url, status_code, headers, body)
    cache = get_performance_cache()
    hit, _ = cache.get("response", fingerprint)
    return hit


# ============================================================
# WAF Detection Cache
# ============================================================

@dataclass
class WAFDetection:
    """WAF detection result."""
    detected: bool
    waf_type: str | None = None
    confidence: float = 0.0
    signatures: list[str] = field(default_factory=list)
    bypass_techniques: list[str] = field(default_factory=list)


def cache_waf_detection(host: str, detection: WAFDetection) -> None:
    """
    Cache WAF detection result for host.

    Args:
        host: Target hostname
        detection: WAF detection result
    """
    cache = get_performance_cache()
    cache.set("waf", host, {
        "detected": detection.detected,
        "waf_type": detection.waf_type,
        "confidence": detection.confidence,
        "signatures": detection.signatures,
        "bypass_techniques": detection.bypass_techniques,
    })
    logger.debug(f"[CACHE] WAF detection cached for {host}: {detection.waf_type or 'none'}")


def get_cached_waf_detection(host: str) -> WAFDetection | None:
    """
    Get cached WAF detection for host.

    Args:
        host: Target hostname

    Returns:
        WAFDetection or None if not cached
    """
    cache = get_performance_cache()
    hit, data = cache.get("waf", host)

    if not hit or not data:
        return None

    return WAFDetection(
        detected=data.get("detected", False),
        waf_type=data.get("waf_type"),
        confidence=data.get("confidence", 0.0),
        signatures=data.get("signatures", []),
        bypass_techniques=data.get("bypass_techniques", []),
    )


# ============================================================
# Negative Control Baseline Cache
# ============================================================

@dataclass
class BaselineResult:
    """Negative control baseline result."""
    endpoint: str
    method: str
    status_code: int
    response_length: int
    content_hash: str
    has_error_indicators: bool
    error_patterns: list[str] = field(default_factory=list)


def cache_baseline(
    endpoint: str,
    method: str,
    baseline: BaselineResult,
) -> None:
    """
    Cache negative control baseline.

    Args:
        endpoint: Tested endpoint
        method: HTTP method
        baseline: Baseline result
    """
    cache = get_performance_cache()
    key = f"{method}:{endpoint}"
    cache.set("baseline", key, {
        "endpoint": baseline.endpoint,
        "method": baseline.method,
        "status_code": baseline.status_code,
        "response_length": baseline.response_length,
        "content_hash": baseline.content_hash,
        "has_error_indicators": baseline.has_error_indicators,
        "error_patterns": baseline.error_patterns,
    })


def get_cached_baseline(endpoint: str, method: str = "GET") -> BaselineResult | None:
    """
    Get cached baseline for endpoint.

    Args:
        endpoint: Target endpoint
        method: HTTP method

    Returns:
        BaselineResult or None
    """
    cache = get_performance_cache()
    key = f"{method}:{endpoint}"
    hit, data = cache.get("baseline", key)

    if not hit or not data:
        return None

    return BaselineResult(
        endpoint=data.get("endpoint", endpoint),
        method=data.get("method", method),
        status_code=data.get("status_code", 0),
        response_length=data.get("response_length", 0),
        content_hash=data.get("content_hash", ""),
        has_error_indicators=data.get("has_error_indicators", False),
        error_patterns=data.get("error_patterns", []),
    )


# ============================================================
# Decorator for Cached Functions
# ============================================================

def cached(namespace: str, ttl: float | None = None, key_func: Callable | None = None):
    """
    Decorator for caching function results.

    Args:
        namespace: Cache namespace
        ttl: Optional TTL override
        key_func: Optional function to generate cache key from args

    Usage:
        @cached("response")
        async def fetch_url(url: str) -> dict:
            ...
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"

            cache = get_performance_cache()
            hit, value = cache.get(namespace, cache_key)

            if hit:
                logger.debug(f"[CACHE] Hit for {func.__name__}")
                return value

            # Call function
            result = await func(*args, **kwargs)

            # Cache result
            cache.set(namespace, cache_key, result, ttl)
            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"

            cache = get_performance_cache()
            hit, value = cache.get(namespace, cache_key)

            if hit:
                logger.debug(f"[CACHE] Hit for {func.__name__}")
                return value

            # Call function
            result = func(*args, **kwargs)

            # Cache result
            cache.set(namespace, cache_key, result, ttl)
            return result

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


# ============================================================
# Batch Processing Utilities
# ============================================================

async def batch_process(
    items: list,
    processor: Callable,
    batch_size: int = 10,
    max_concurrent: int = 5,
) -> list:
    """
    Process items in batches with concurrency control.

    Args:
        items: Items to process
        processor: Async function to process each item
        batch_size: Items per batch
        max_concurrent: Max concurrent batches

    Returns:
        List of results
    """
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def process_with_semaphore(item):
        async with semaphore:
            return await processor(item)

    # Process in batches
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        batch_tasks = [process_with_semaphore(item) for item in batch]
        batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

        for result in batch_results:
            if isinstance(result, Exception):
                logger.warning(f"[BATCH] Item failed: {result}")
                results.append(None)
            else:
                results.append(result)

    return results


async def parallel_map(
    items: list,
    processor: Callable,
    max_concurrent: int = 10,
) -> list:
    """
    Map function over items in parallel with concurrency limit.

    Args:
        items: Items to process
        processor: Async function to apply
        max_concurrent: Maximum concurrent tasks

    Returns:
        List of results in same order as items
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited_processor(item):
        async with semaphore:
            return await processor(item)

    tasks = [limited_processor(item) for item in items]
    return await asyncio.gather(*tasks, return_exceptions=True)
