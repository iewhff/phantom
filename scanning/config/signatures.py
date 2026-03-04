"""
Module Signature Configuration.

Defines how different scanner modules should be called based on their
expected function signatures. This allows the module executor to
properly invoke each module with the correct arguments.

Extracted from full_scanner.py for modularization (2026-02-25).
"""

from __future__ import annotations

# Module interface categories:
# STRING_ENDPOINTS: Expect endpoints: List[str] - pass endpoints_list
# TYPED_ENDPOINTS: Expect endpoints: List[SomeDataclass] - pass None
# SIMPLE_INTERFACE: Only take target and **kwargs
# OLD_3ARG_INTERFACE: Expect (target, asset_data, rate_limiter) - MUST pass all 3
# PORT_PARAMS_MODULES: Accept (host, port, extra_params)
# TWO_ARG_MODULES: Expect (target, asset_data) - no rate_limiter

# Modules expecting endpoints: List[str] keyword argument
STRING_ENDPOINTS_MODULES: frozenset[str] = frozenset({"jwt", "cookie"})

# Modules using typed endpoint dataclasses (pass None, let them create defaults)
# race_condition uses (target_url, endpoints) - 2 args
TYPED_ENDPOINTS_MODULES: frozenset[str] = frozenset({"race"})

# Modules with (target, asset_data) - no rate_limiter
TWO_ARG_MODULES: frozenset[str] = frozenset({
    "firebase", "backend", "credential_verifier"
})

# Simple interface: just target (currently empty - all moved to OLD_3ARG)
SIMPLE_INTERFACE_MODULES: frozenset[str] = frozenset()

# Modules with (host, port=None, extra_params=None) signature
PORT_PARAMS_MODULES: frozenset[str] = frozenset({
    "client_hardening", "token_binding", "workflow_inference", "abac_context",
    "concurrency_state", "cross_surface", "permission_matrix",
    "integration_exploiter", "defensive_evasion",
})

# Modules that REQUIRE (host, asset_data, rate_limiter) signature
# Generated from: grep -l "rate_limiter: RateLimiter" scanning/modules/*.py
OLD_3ARG_MODULES: frozenset[str] = frozenset({
    # Injection scanners
    "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
    "nosql", "ssti", "ldap", "crlf",
    # Auth/API modules
    "auth", "oauth", "saml", "authz", "idor", "api", "graphql",
    "mfa", "ratelimit", "grpc", "sse", "websocket",
    # Infrastructure
    "ssl", "headers", "cors", "cloud", "k8s", "dns_rebind",
    "smuggling", "cache", "deser", "prototype",
    # Discovery & CMS
    "dir", "cms", "nuclei",
    # Business logic
    "business", "mass_assign", "business_logic",
    # Other critical modules
    "mobile", "email", "subdomain_takeover",
    "llm", "post_exploit",
    # Session & Token Abuse
    "session_abuse", "creative_exploiter",
    # New modules with standard signature
    "webhook_security", "config_exposure", "secrets_pattern",
    "concurrency_stress",
    # File upload (needs forms from asset_data)
    "file_upload",
    # Additional scanners with rate limiter support
    "open_redirect", "host_header", "cache_deception", "clickjacking",
    "info_disclosure",
    # Previously missing 3-arg modules
    "csrf", "supabase", "wasm", "logic_chain", "advanced_rls",
    "communications", "third_party",
})


def get_module_signature_type(name: str) -> str:
    """
    Get the signature type for a module.

    Args:
        name: Module short name

    Returns:
        Signature type string: 'old_3arg', 'two_arg', 'string_endpoints',
        'typed_endpoints', 'port_params', or 'simple'
    """
    if name in OLD_3ARG_MODULES:
        return "old_3arg"
    if name in TWO_ARG_MODULES:
        return "two_arg"
    if name in STRING_ENDPOINTS_MODULES:
        return "string_endpoints"
    if name in TYPED_ENDPOINTS_MODULES:
        return "typed_endpoints"
    if name in PORT_PARAMS_MODULES:
        return "port_params"
    if name in SIMPLE_INTERFACE_MODULES:
        return "simple"
    # Default to old 3-arg for safety
    return "old_3arg"
