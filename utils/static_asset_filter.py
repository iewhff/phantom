"""
Static Asset Filter Utility

Provides centralized filtering of static assets (JS, CSS, images, fonts)
that cannot have server-side vulnerabilities like SQLi, SSTI, SSRF, etc.

Usage:
    from utils.static_asset_filter import filter_static_assets, is_static_asset

    # Filter a list of endpoints
    dynamic_endpoints = filter_static_assets(endpoints)

    # Check single URL
    if is_static_asset(url):
        skip_testing()
"""

from typing import List, Set

# Extensions that are definitely static assets
STATIC_EXTENSIONS: Set[str] = frozenset({
    # JavaScript bundles (CANNOT have SQLi, SSTI, etc.)
    '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx',
    # Stylesheets
    '.css', '.scss', '.sass', '.less',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.avif',
    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    # Documents (static files)
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Media
    '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov', '.flv',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z',
    # Source maps
    '.map',
})

# Paths that indicate static asset directories
STATIC_PATH_PATTERNS: List[str] = [
    '/static/', '/assets/', '/dist/', '/build/', '/vendor/',
    '/node_modules/', '/_next/static/', '/__webpack/',
    '/public/images/', '/public/css/', '/public/js/',
    '/img/', '/images/', '/css/', '/js/', '/fonts/', '/media/',
]

# Paths that are dynamic even if they look static
DYNAMIC_PATH_INDICATORS: List[str] = [
    '/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/',
    '/auth/', '/login', '/register', '/admin/',
]


def is_static_asset(url: str) -> bool:
    """
    Check if a URL points to a static asset.

    Static assets cannot have server-side vulnerabilities.
    Testing them wastes time and can generate false positives.

    Args:
        url: The URL to check

    Returns:
        True if the URL is a static asset
    """
    if not url:
        return False

    url_lower = url.lower()

    # Check if it's a dynamic API endpoint (never static)
    if any(ind in url_lower for ind in DYNAMIC_PATH_INDICATORS):
        return False

    # Extract path without query string and fragment
    path = url_lower.split('?')[0].split('#')[0]

    # Check file extension
    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True

    # Check path patterns
    for pattern in STATIC_PATH_PATTERNS:
        if pattern in path:
            # But not if it's an API endpoint that happens to be under /assets/
            # e.g., /assets/api/v1/users is dynamic
            if '/api/' not in path and '/rest/' not in path:
                return True

    return False


def filter_static_assets(endpoints: List[str], log_count: bool = True) -> List[str]:
    """
    Filter out static assets from a list of endpoints.

    Args:
        endpoints: List of endpoint URLs
        log_count: Whether to return count info

    Returns:
        List of dynamic endpoints (static assets removed)
    """
    if not endpoints:
        return []

    dynamic = [ep for ep in endpoints if not is_static_asset(ep)]

    # Return both for logging purposes
    return dynamic


def get_static_asset_count(endpoints: List[str]) -> int:
    """Get count of static assets in endpoint list."""
    return sum(1 for ep in endpoints if is_static_asset(ep))


def categorize_endpoints(endpoints: List[str]) -> dict:
    """
    Categorize endpoints into static and dynamic.

    Returns:
        dict with 'static' and 'dynamic' lists
    """
    static = []
    dynamic = []

    for ep in endpoints:
        if is_static_asset(ep):
            static.append(ep)
        else:
            dynamic.append(ep)

    return {
        'static': static,
        'dynamic': dynamic,
        'static_count': len(static),
        'dynamic_count': len(dynamic),
    }
