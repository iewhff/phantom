"""
Discovery Module - Endpoint discovery and authenticated crawling.

This module provides:
- Generic fallback endpoint generation for when discovery fails
- Authenticated crawling to discover protected endpoints
- Context-aware endpoint patterns (API, auth, admin, files, etc.)

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from scanning.discovery.fallback_endpoints import (
    get_generic_fallback_endpoints,
    ENDPOINT_CATEGORIES,
)

from scanning.discovery.authenticated_crawler import (
    AuthenticatedCrawler,
    CrawlConfig,
    CrawlResult,
    authenticated_crawl,
)

__all__ = [
    # Fallback endpoints
    "get_generic_fallback_endpoints",
    "ENDPOINT_CATEGORIES",
    # Authenticated crawler
    "AuthenticatedCrawler",
    "CrawlConfig",
    "CrawlResult",
    "authenticated_crawl",
]
