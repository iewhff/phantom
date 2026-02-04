"""
Endpoint Validator - Avoids wasting requests on non-existent endpoints.

Provides a shared cache to track which endpoints exist (return 200/401/403)
vs don't exist (return 404). This prevents multiple scanners from making
redundant requests to endpoints that don't exist.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from utils.logger import get_logger

if TYPE_CHECKING:
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class EndpointValidator:
    """
    Singleton validator that caches endpoint existence status.

    Usage:
        validator = EndpointValidator.get_instance()

        # Check if endpoint exists before testing
        if await validator.endpoint_exists(base_url, "/api/users", rate_limiter):
            # Endpoint exists, proceed with testing
            ...
        else:
            # Endpoint returns 404, skip testing
            continue
    """

    _instance = None
    _lock = asyncio.Lock()

    # Cache: {host: {path: exists_bool}}
    _cache: dict[str, dict[str, bool]] = {}

    # Status codes that indicate endpoint exists (worth testing)
    EXISTS_CODES = {200, 201, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500, 502, 503}

    # Status codes that indicate endpoint doesn't exist (skip)
    SKIP_CODES = {404}

    @classmethod
    def get_instance(cls) -> "EndpointValidator":
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset cache (useful for testing)."""
        cls._cache = {}

    async def endpoint_exists(
        self,
        base_url: str,
        path: str,
        rate_limiter: "RateLimiter | None" = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> bool:
        """
        Check if endpoint exists (cached).

        Returns True if endpoint returns any status code except 404.
        Results are cached per host+path combination.
        """
        # Normalize URL
        if path.startswith("http"):
            full_url = path
            parsed = urlparse(path)
            host = parsed.netloc
            path = parsed.path
        else:
            parsed = urlparse(base_url)
            host = parsed.netloc
            full_url = urljoin(base_url, path)

        # Check cache
        if host in self._cache and path in self._cache[host]:
            return self._cache[host][path]

        # Not in cache, make request
        if rate_limiter:
            await rate_limiter.acquire()

        exists = False
        try:
            if client:
                response = await client.head(full_url)
            else:
                async with httpx.AsyncClient(timeout=timeout, verify=False) as c:
                    response = await c.head(full_url)

            exists = response.status_code not in self.SKIP_CODES

        except httpx.HTTPStatusError as e:
            exists = e.response.status_code not in self.SKIP_CODES
        except Exception:
            # On error, assume exists (don't skip)
            exists = True

        # Cache result
        if host not in self._cache:
            self._cache[host] = {}
        self._cache[host][path] = exists

        if not exists:
            logger.debug(f"[EndpointValidator] Skipping non-existent: {path}")

        return exists

    async def filter_existing_endpoints(
        self,
        base_url: str,
        paths: list[str],
        rate_limiter: "RateLimiter | None" = None,
        max_concurrent: int = 10,
    ) -> list[str]:
        """
        Filter a list of paths to only those that exist.

        Useful for batch-checking multiple endpoints before testing.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_one(path: str) -> tuple[str, bool]:
            async with semaphore:
                exists = await self.endpoint_exists(base_url, path, rate_limiter)
                return (path, exists)

        results = await asyncio.gather(*[check_one(p) for p in paths])

        existing = [path for path, exists in results if exists]
        skipped = len(paths) - len(existing)

        if skipped > 0:
            logger.info(f"[EndpointValidator] Filtered {skipped}/{len(paths)} non-existent endpoints")

        return existing

    def mark_as_nonexistent(self, base_url: str, path: str) -> None:
        """Manually mark an endpoint as non-existent (e.g., after getting 404)."""
        parsed = urlparse(base_url)
        host = parsed.netloc

        if host not in self._cache:
            self._cache[host] = {}
        self._cache[host][path] = False

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = sum(len(paths) for paths in self._cache.values())
        existing = sum(
            sum(1 for exists in paths.values() if exists)
            for paths in self._cache.values()
        )
        return {
            "hosts": len(self._cache),
            "total_endpoints": total,
            "existing": existing,
            "non_existent": total - existing,
        }


# Convenience function
async def endpoint_exists(
    base_url: str,
    path: str,
    rate_limiter: "RateLimiter | None" = None,
) -> bool:
    """Check if endpoint exists (uses singleton validator)."""
    return await EndpointValidator.get_instance().endpoint_exists(
        base_url, path, rate_limiter
    )
