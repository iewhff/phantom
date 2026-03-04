"""
Module Interfaces - Module Signature Categories.

Defines which method signature each scanner module expects:
- OLD_3ARG_MODULES: scan(host, asset_data, rate_limiter)
- STRING_ENDPOINTS_MODULES: scan(target, endpoints=List[str])
- TYPED_ENDPOINTS_MODULES: scan(target) - creates own typed endpoints
- TWO_ARG_MODULES: scan(target, asset_data) - no rate_limiter
- PORT_PARAMS_MODULES: scan(host, port=None, extra_params=None)
- SIMPLE_INTERFACE_MODULES: scan(target) only

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import Set

# ═══════════════════════════════════════════════════════════════════════════════
# Module Interface Types
# ═══════════════════════════════════════════════════════════════════════════════


class ModuleInterface(Enum):
    """Module interface/signature types."""

    # scan(host, asset_data, rate_limiter) - MOST COMMON
    OLD_3ARG = auto()

    # scan(target, endpoints=List[str])
    STRING_ENDPOINTS = auto()

    # scan(target) - module creates typed endpoints internally
    TYPED_ENDPOINTS = auto()

    # scan(target, asset_data) - no rate_limiter
    TWO_ARG = auto()

    # scan(host, port=None, extra_params=None)
    PORT_PARAMS = auto()

    # scan(target) only
    SIMPLE = auto()


# ═══════════════════════════════════════════════════════════════════════════════
# Module Categories
# ═══════════════════════════════════════════════════════════════════════════════

# Modules that expect endpoints: List[str] as keyword argument
STRING_ENDPOINTS_MODULES: Set[str] = {"jwt", "cookie"}

# Modules that create their own typed endpoints from target
# host_header, clickjacking moved to OLD_3ARG
TYPED_ENDPOINTS_MODULES: Set[str] = {"race"}

# Modules with (target, asset_data) signature - no rate_limiter
TWO_ARG_MODULES: Set[str] = {"firebase", "backend", "credential_verifier"}

# Modules with simple interface - all moved to OLD_3ARG_MODULES
SIMPLE_INTERFACE_MODULES: Set[str] = set()

# Modules with (host, port=None, extra_params=None) signature
# These use extra_params dict, NOT the old 3-arg signature
PORT_PARAMS_MODULES: Set[str] = {
    "client_hardening",
    "token_binding",
    "workflow_inference",
    "abac_context",
    "concurrency_state",
    "cross_surface",
    "permission_matrix",
    "integration_exploiter",
    "defensive_evasion",
}

# Modules that REQUIRE (host, asset_data, rate_limiter) signature
# Generated from: grep -l "rate_limiter: RateLimiter" scanning/modules/*.py
OLD_3ARG_MODULES: Set[str] = {
    # Injection scanners
    "sqli",
    "xss",
    "dom_xss",
    "cmdi",
    "xxe",
    "ssrf",
    "lfi",
    "nosql",
    "ssti",
    "ldap",
    "crlf",
    # Auth/API modules
    "auth",
    "oauth",
    "saml",
    "authz",
    "idor",
    "api",
    "graphql",
    "mfa",
    "ratelimit",
    "grpc",
    "sse",
    "websocket",
    # Infrastructure
    "ssl",
    "headers",
    "cors",
    "cloud",
    "k8s",
    "dns_rebind",
    "smuggling",
    "cache",
    "deser",
    "prototype",
    # Discovery & CMS
    "dir",
    "cms",
    "nuclei",
    # Business logic
    "business",
    "mass_assign",
    "business_logic",
    # Other critical modules
    "mobile",
    "email",
    "subdomain_takeover",
    "llm",
    "post_exploit",
    # Session & Token Abuse
    "session_abuse",
    "creative_exploiter",
    # New modules with standard signature
    "webhook_security",
    "config_exposure",
    "secrets_pattern",
    "concurrency_stress",
    # File upload (needs forms from asset_data)
    "file_upload",
    # FIX: Additional scanners now with rate limiter support
    "open_redirect",
    "host_header",
    "cache_deception",
    "clickjacking",
    "info_disclosure",
    # FIX: Previously missing 3-arg modules
    "csrf",
    "supabase",
    "wasm",
    "logic_chain",
    "advanced_rls",
    "communications",
    "third_party",
}

# Heavy modules need more time (browser-based, deep injection, auth-dependent)
# Used as fallback when adaptive timeout is not available
HEAVY_MODULES: Set[str] = {
    "sqli",
    "xss",
    "dom_xss",
    "nosql",
    "cmdi",
    "lfi",
    "ssrf",
    "auth",
    "ssti",
    "graphql",
    "api",
    "smuggling",
    "business",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════


def get_module_interface(module_name: str) -> ModuleInterface:
    """
    Get the interface type for a module.

    Args:
        module_name: Short name of the module (e.g., "sqli")

    Returns:
        ModuleInterface enum value
    """
    if module_name in OLD_3ARG_MODULES:
        return ModuleInterface.OLD_3ARG
    elif module_name in STRING_ENDPOINTS_MODULES:
        return ModuleInterface.STRING_ENDPOINTS
    elif module_name in TYPED_ENDPOINTS_MODULES:
        return ModuleInterface.TYPED_ENDPOINTS
    elif module_name in TWO_ARG_MODULES:
        return ModuleInterface.TWO_ARG
    elif module_name in PORT_PARAMS_MODULES:
        return ModuleInterface.PORT_PARAMS
    elif module_name in SIMPLE_INTERFACE_MODULES:
        return ModuleInterface.SIMPLE
    else:
        # Default to OLD_3ARG as most common
        return ModuleInterface.OLD_3ARG


def is_heavy_module(module_name: str) -> bool:
    """Check if module is a heavy module requiring more time."""
    return module_name in HEAVY_MODULES


def is_signature_mismatch(error: TypeError) -> bool:
    """
    Check if TypeError is about wrong number/type of arguments.

    Args:
        error: The TypeError exception

    Returns:
        True if this is a signature mismatch error
    """
    err_msg = str(error).lower()
    signature_indicators = [
        "positional argument",
        "required argument",
        "unexpected keyword argument",
        "takes",
        "got an unexpected",
        "missing",
    ]
    return any(indicator in err_msg for indicator in signature_indicators)
