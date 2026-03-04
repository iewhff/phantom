"""
Generic Fallback Endpoint Generation.

When discovery fails, test common patterns that exist on most real-world web apps:
- API endpoints (/api/*, /v1/*, /graphql)
- Search functionality (/search?q=, /s?query=)
- Authentication endpoints (/login, /auth, /oauth)
- User management (/users, /profile, /account)
- Admin panels (/admin, /dashboard, /manage)
- CRUD operations (/create, /update, /delete)
- File operations (/upload, /download, /export)
- Debug/Info disclosure endpoints
- Spring Boot Actuator endpoints

Returns injectable endpoints WITH parameters for SQLi/XSS testing.
"""

from __future__ import annotations

from typing import NamedTuple
from urllib.parse import urljoin, urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class EndpointCategory(NamedTuple):
    """Category of endpoints with patterns."""

    name: str
    description: str
    patterns: list[str]


# =====================================================
# ENDPOINT CATEGORIES - Universal patterns
# =====================================================

API_PATTERNS = [
    # REST API versions
    "/api/users",
    "/api/user",
    "/api/v1/users",
    "/api/v2/users",
    "/v1/users",
    "/v2/users",
    # With injectable parameters
    "/api/users?id=1",
    "/api/user?id=1",
    "/api/v1/user?id=1",
    "/api/search?q=test",
    "/api/search?query=test",
    "/api/products?id=1",
    "/api/products?search=test",
    "/api/items?id=1",
    "/api/data?id=1",
    "/api/data?filter=test",
    # GraphQL (common attack surface)
    "/graphql",
    "/graphql?query={__schema{types{name}}}",
    "/api/graphql",
]

SEARCH_PATTERNS = [
    "/search?q=test",
    "/search?query=test",
    "/search?s=test",
    "/search?term=test",
    "/search?keyword=test",
    "/s?q=test",
    "/find?q=test",
    "/lookup?q=test",
    # Common CMS patterns
    "/?s=test",  # WordPress
    "/?search=test",
    "/index.php?search=test",
    "/index.php?q=test",
]

AUTH_PATTERNS = [
    "/login",
    "/signin",
    "/auth/login",
    "/api/auth/login",
    "/api/login",
    "/api/auth",
    "/oauth/authorize",
    "/oauth/token",
    "/sso/login",
    "/session",
    "/logout",
    "/register",
    "/signup",
    "/api/register",
    "/forgot-password",
    "/reset-password",
    "/password-reset",
]

USER_PATTERNS = [
    "/user",
    "/users",
    "/users?id=1",
    "/user?id=1",
    "/profile",
    "/profile?id=1",
    "/account",
    "/account?id=1",
    "/me",
    "/api/me",
    "/api/profile",
    "/api/user/profile",
    "/settings",
    "/preferences",
]

ADMIN_PATTERNS = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/administrator",
    "/dashboard",
    "/panel",
    "/manage",
    "/management",
    "/console",
    "/config",
    "/settings",
    "/system",
    "/cms",
    "/wp-admin",
    "/phpmyadmin",
]

FILE_PATTERNS = [
    "/upload",
    "/upload?type=image",
    "/download",
    "/download?file=test",
    "/export",
    "/export?format=csv",
    "/import",
    "/file",
    "/file?name=test",
    "/files",
    "/files?path=/",
    "/documents",
    "/media",
    "/attachments",
    "/static",
]

CRUD_PATTERNS = [
    "/create",
    "/new",
    "/add",
    "/edit?id=1",
    "/update?id=1",
    "/delete?id=1",
    "/remove?id=1",
    "/view?id=1",
    "/detail?id=1",
    "/item?id=1",
    "/product?id=1",
    "/order?id=1",
    "/orders",
    "/cart",
    "/checkout",
]

DEBUG_PATTERNS = [
    "/debug",
    "/info",
    "/status",
    "/health",
    "/metrics",
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/docs",
    "/env",
    "/.env",
    "/config.json",
    "/version",
    "/phpinfo.php",
]

ACTUATOR_PATTERNS = [
    # Root actuator
    "/actuator",
    "/actuator/",
    # Sensitive endpoints (credential exposure)
    "/actuator/env",
    "/actuator/configprops",
    "/actuator/heapdump",  # Memory dump - CRITICAL
    # Endpoint enumeration
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/conditions",
    # Request/session exposure
    "/actuator/httptrace",
    "/actuator/trace",
    "/actuator/sessions",
    # Health/metrics (often public)
    "/actuator/health",
    "/actuator/health/liveness",
    "/actuator/health/readiness",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/prometheus",
    # Log manipulation
    "/actuator/loggers",
    "/actuator/logfile",
    # Database migration info
    "/actuator/flyway",
    "/actuator/liquibase",
    # DoS potential
    "/actuator/shutdown",
    # JMX/RCE potential
    "/actuator/jolokia",
    "/actuator/jolokia/list",
    # Spring Cloud Gateway (SSRF)
    "/actuator/gateway",
    "/actuator/gateway/routes",
]

# Export all categories for external use
ENDPOINT_CATEGORIES: list[EndpointCategory] = [
    EndpointCategory("api", "REST API endpoints", API_PATTERNS),
    EndpointCategory("search", "Search functionality (high SQLi/XSS risk)", SEARCH_PATTERNS),
    EndpointCategory("auth", "Authentication endpoints", AUTH_PATTERNS),
    EndpointCategory("user", "User/Profile management (IDOR targets)", USER_PATTERNS),
    EndpointCategory("admin", "Admin/Dashboard (priv escalation targets)", ADMIN_PATTERNS),
    EndpointCategory("file", "File operations (upload/LFI risks)", FILE_PATTERNS),
    EndpointCategory("crud", "CRUD operations (business logic targets)", CRUD_PATTERNS),
    EndpointCategory("debug", "Debug/Info disclosure endpoints", DEBUG_PATTERNS),
    EndpointCategory("actuator", "Spring Boot Actuator", ACTUATOR_PATTERNS),
]


def get_generic_fallback_endpoints(target: str) -> list[str]:
    """
    Generate generic fallback endpoints when discovery fails on ANY website.

    PHILOSOPHY: "Quando discovery falha, testa padrões comuns"
    This is NOT lab-specific — these patterns exist on most real-world web apps.

    Args:
        target: The target URL

    Returns:
        List of injectable endpoint URLs with parameters for SQLi/XSS testing.
    """
    endpoints = []
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Detect context path for apps like /WebGoat/
    # Many Java apps run at a context path, not the root
    context_path = ""
    path_parts = parsed.path.strip("/").split("/")
    if path_parts and path_parts[0]:
        # First path component is likely the context path
        context_path = f"/{path_parts[0]}"
        logger.debug(f"[GENERIC-FALLBACK] Detected context path: {context_path}")

    # Combine all patterns
    all_patterns: list[str] = []
    for category in ENDPOINT_CATEGORIES:
        all_patterns.extend(category.patterns)

    # Build full URLs
    for pattern in all_patterns:
        endpoints.append(urljoin(base, pattern))

    # Also add context-path prefixed versions
    # For apps at /WebGoat/, also probe /WebGoat/actuator, /WebGoat/api, etc.
    if context_path:
        context_patterns: list[str] = []
        # Only prefix critical patterns to avoid explosion
        critical_prefixes = list(ACTUATOR_PATTERNS) + [
            "/api",
            "/api/v1",
            "/api/v2",
            "/admin",
            "/dashboard",
            "/console",
            "/swagger",
            "/swagger-ui",
            "/api-docs",
            "/login",
            "/logout",
            "/register",
            "/graphql",
            "/health",
            "/metrics",
        ]
        for pattern in critical_prefixes:
            prefixed = f"{context_path}{pattern}"
            if prefixed not in all_patterns:
                context_patterns.append(prefixed)

        for pattern in context_patterns:
            endpoints.append(urljoin(base, pattern))

        logger.info(
            f"[GENERIC-FALLBACK] Generated {len(endpoints)} common endpoint patterns "
            f"for broad coverage (API, search, auth, admin, file, CRUD, debug, actuator) "
            f"including {len(context_patterns)} context-prefixed patterns at {context_path}"
        )
    else:
        logger.info(
            f"[GENERIC-FALLBACK] Generated {len(endpoints)} common endpoint patterns "
            f"for broad coverage (API, search, auth, admin, file, CRUD, debug, actuator)"
        )

    return endpoints
