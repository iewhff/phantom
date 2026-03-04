"""
Module Categories and Presets.

Contains:
- CATEGORIES: Predefined module groups for different scan types

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from typing import Optional

from .modules import ALL_MODULES


# Module categories for selective scanning
CATEGORIES: dict[str, list[str]] = {
    # Quick infrastructure scan
    "quick": ["headers", "ssl", "cors", "dir", "backend"],

    # Web application scan - includes API coverage
    "web": [
        "sqli", "xss", "dom_xss", "cmdi", "lfi", "xxe", "ssrf", "csrf",
        "headers", "ssl", "cors",
        "api", "graphql", "grpc", "websocket", "sse",  # API/GraphQL coverage
    ],

    # API-focused scan
    "api": [
        "api", "graphql", "grpc", "websocket", "sse",
        "auth", "oauth", "ratelimit", "idor", "mass_assign",
    ],

    # Injection vulnerabilities
    "injection": [
        "sqli", "xss", "dom_xss", "cmdi", "xxe",
        "nosql", "ssti", "ldap", "crlf",
    ],

    # Authentication & Authorization
    "auth": [
        "auth", "oauth", "saml", "mfa", "authz",
        "ratelimit", "idor", "csrf", "session_abuse",
    ],

    # Infrastructure scan
    "infra": [
        "ssl", "headers", "cors", "cloud", "k8s",
        "dns_rebind", "supabase", "firebase",
    ],

    # Advanced attacks
    "advanced": [
        "smuggling", "cache", "deser", "prototype",
        "dns_rebind", "rls_bypass",
    ],

    # Standard scan - comprehensive testing
    "standard": [
        # Critical Injections (MUST run)
        "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
        "nosql", "ssti", "ldap", "crlf",
        # Authentication & Authorization
        "auth", "oauth", "saml", "mfa", "jwt", "authz", "idor", "session_abuse",
        # API Security
        "api", "graphql", "grpc", "websocket", "sse",
        # Infrastructure
        "ssl", "headers", "cors", "cloud", "k8s", "dns_rebind",
        # Advanced Attacks
        "smuggling", "cache", "deser", "prototype", "cache_deception",
        # Business Logic
        "business", "race", "mass_assign", "ratelimit", "creative_exploiter",
        "stateful_flow",
        # Discovery
        "dir", "cms", "nuclei", "backend", "third_party",
        # BaaS
        "supabase", "firebase", "rls_bypass",
        # Specialized
        "mobile", "email", "host_header", "clickjacking",
        "info_disclosure", "open_redirect", "file_upload",
        "cookie", "subdomain_takeover", "csrf",
        # Configuration & Integration Security
        "config_exposure", "secrets_pattern", "webhook_security",
        # Cross-Surface Analysis
        "cross_surface",
        # Concurrency Testing
        "concurrency_stress", "concurrency_state",
        # Advanced Business Logic & Access Control
        "workflow_inference", "abac_context", "token_binding",
        # Client-Side Security
        "client_hardening",
        # Authorization & Permission Logic
        "permission_matrix",
        # Integration Exploitation & Defensive Testing
        "integration_exploiter", "defensive_evasion",
    ],

    # Smart scan - high-value modules with reasonable timeout
    "smart": [
        "sqli", "xss", "headers", "ssl", "cors",
        "dir", "auth", "api", "idor",
    ],

    # Bounty hunting - maximum bounty potential
    "bounty": [
        "idor",              # IDOR/BOLA detection - TOP VALUE $3k-$20k
        "sqli",              # SQL Injection - HIGH VALUE
        "xss",               # Reflected/Stored XSS
        "dom_xss",           # DOM-based XSS with browser execution
        "csrf",              # Cross-Site Request Forgery
        "authz",             # Authorization bypass
        "auth",              # Authentication vulnerabilities
        "jwt",               # JWT misconfigurations - HIGH VALUE
        "session_abuse",     # Session & token abuse
        "ssrf",              # Server-Side Request Forgery
        "business",          # Business logic flaws - HIGH VALUE
        "race",              # Race conditions - HIGH VALUE
        "stateful_flow",     # Multi-step workflow fuzzing
        "mass_assign",       # Mass assignment
        "api",               # API security issues
        "graphql",           # GraphQL introspection/injection
        "open_redirect",     # Open redirects (chain potential)
        "cache_deception",   # Web cache deception
        "host_header",       # Host header attacks
        "supabase",          # Supabase RLS bypass
        "firebase",          # Firebase misconfigurations
        "rls_bypass",        # Row Level Security bypass
        "mobile",            # Mobile API vulnerabilities
        "comms",             # Communications API
        "creative_exploiter",# Creative exploitation
        "config_exposure",   # Exposed configs - HIGH VALUE
        "secrets_pattern",   # API keys/tokens - HIGH VALUE
        "webhook_security",  # Webhook SSRF, signature bypass
        "cross_surface",     # Cross-surface attacks - HIGH VALUE
        "workflow_inference",# Workflow bypass - HIGH VALUE
        "concurrency_state", # Race conditions - HIGH VALUE
        "abac_context",      # ABAC bypass - HIGH VALUE
        "token_binding",     # Token binding issues
        "client_hardening",  # CSP bypass, client-side issues
        "permission_matrix", # Authorization logic flaws - HIGH VALUE
        "integration_exploiter",  # API key exploitation - HIGH VALUE
        "defensive_evasion", # WAF bypass
    ],

    # BaaS (Backend-as-a-Service) focused scan
    "baas": [
        "supabase", "firebase", "rls_bypass",
        "backend", "third_party", "api",
    ],

    # Client engagement - full professional pentest
    "client": [
        # Critical Injections
        "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
        "nosql", "ssti", "ldap", "crlf",
        # Authentication & Authorization
        "auth", "oauth", "saml", "mfa", "jwt", "authz", "idor", "session_abuse",
        # API Security
        "api", "graphql", "grpc", "websocket", "sse",
        # Infrastructure
        "ssl", "headers", "cors", "cloud", "k8s", "dns_rebind",
        # Advanced Attacks
        "smuggling", "cache", "deser", "prototype", "cache_deception",
        # Business Logic
        "business", "race", "mass_assign", "ratelimit", "creative_exploiter",
        "stateful_flow",
        # Discovery
        "dir", "cms", "nuclei", "backend", "third_party",
        # BaaS
        "supabase", "firebase", "rls_bypass",
        # Specialized
        "mobile", "email", "host_header", "clickjacking",
        "info_disclosure", "open_redirect", "file_upload",
        "cookie", "subdomain_takeover", "csrf",
        # Configuration & Integration Security
        "config_exposure", "secrets_pattern", "webhook_security",
        # Cross-Surface Analysis
        "cross_surface",
        # Concurrency Testing
        "concurrency_stress", "concurrency_state",
        # Advanced Business Logic & Access Control
        "workflow_inference", "abac_context", "token_binding",
        # Client-Side Security
        "client_hardening",
        # Authorization & Permission Logic
        "permission_matrix",
        # Integration Exploitation & Defensive Testing
        "integration_exploiter", "defensive_evasion",
    ],

    # Full scan - all available modules
    "full": list(ALL_MODULES.keys()),
}


def get_category_modules(category: str) -> list[str]:
    """Get modules for a category. Returns empty list if category not found."""
    return CATEGORIES.get(category, [])


def get_all_category_names() -> list[str]:
    """Get all available category names."""
    return list(CATEGORIES.keys())


def is_valid_category(category: str) -> bool:
    """Check if a category name is valid."""
    return category in CATEGORIES


def expand_modules(
    modules: list[str],
    include_categories: bool = True,
) -> list[str]:
    """Expand module list, replacing category names with their modules.

    Args:
        modules: List of module names or category names
        include_categories: If True, expand category names to their modules

    Returns:
        Expanded list of unique module names
    """
    if not include_categories:
        return modules

    result: set[str] = set()
    for item in modules:
        if item in CATEGORIES:
            result.update(CATEGORIES[item])
        else:
            result.add(item)
    return list(result)
