"""
Safety Configuration for Scanner Modules.

Contains:
- SAFETY_HIERARCHY: Order of safety modes from safest to most aggressive
- MODULE_SAFETY_LEVELS: Minimum safety mode required for each module

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations


# Safety hierarchy - order from safest to most aggressive
# passive → safe → cautious → standard → aggressive → unrestricted
SAFETY_HIERARCHY: list[str] = [
    "passive",
    "safe",
    "cautious",
    "standard",
    "aggressive",
    "unrestricted",
]


# Module safety levels - minimum safety mode required to run each module
# Modules not listed here default to "passive" (always allowed)
#
# Safety hierarchy:
# - passive: Read-only, no payloads, just observation
# - cautious: Sends payloads but low risk, no state modification
# - standard: May modify state, create records, or require auth
# - aggressive: Can affect other users, shared state, or is destructive
MODULE_SAFETY_LEVELS: dict[str, str] = {
    # ═══════════════════════════════════════════════════════════════════
    # PASSIVE: Read-only, no payloads, just observation
    # ═══════════════════════════════════════════════════════════════════
    "headers": "passive",            # Just reads HTTP headers
    "ssl": "passive",                # TLS analysis, no payloads
    "cors": "passive",               # Sends Origin header, reads response
    "backend": "passive",            # Tech fingerprinting, reads responses
    "cms": "passive",                # CMS detection, reads responses
    "info_disclosure": "passive",    # Checks for exposed info
    "cookie_security": "passive",    # Analyzes cookie attributes
    "clickjacking": "passive",       # Checks X-Frame-Options
    "open_redirect": "passive",      # Tests redirect params

    # ═══════════════════════════════════════════════════════════════════
    # CAUTIOUS: Sends payloads but low risk, no state modification
    # ═══════════════════════════════════════════════════════════════════
    "sqli": "cautious",              # SQL payloads in params, no writes
    "xss": "cautious",               # XSS payloads in params
    "dom_xss": "cautious",           # DOM analysis + payloads
    "nosql": "cautious",             # NoSQL payloads in params
    "lfi": "cautious",               # Path traversal in params
    "ssrf": "cautious",              # URL injection, internal probes
    "xxe": "cautious",               # XML payloads (careful with OOB)
    "ssti": "cautious",              # Template injection payloads
    "cmdi": "cautious",              # Command injection (time-based safe)
    "crlf": "cautious",              # Header injection
    "ldap": "cautious",              # LDAP injection
    "xpath": "cautious",             # XPath injection
    "csrf": "cautious",              # Checks CSRF tokens
    "dir": "cautious",               # Directory enumeration
    "api": "cautious",               # API endpoint testing
    "graphql": "cautious",           # GraphQL introspection + queries
    "websocket": "cautious",         # WebSocket testing
    "grpc": "cautious",              # gRPC testing
    "sse": "cautious",               # Server-Sent Events
    "session_abuse": "cautious",     # POST for login/logout + token tampering
    "jwt": "cautious",               # JWT token analysis + tampering
    "mobile_api": "cautious",        # Mobile API testing
    "k8s": "cautious",               # Kubernetes API checks
    "cloud": "cautious",             # Cloud metadata checks
    "secrets_pattern": "cautious",   # Searches for exposed secrets
    "wasm": "cautious",              # WebAssembly analysis (downloads files)

    # ═══════════════════════════════════════════════════════════════════
    # STANDARD: May modify state, create records, or require auth
    # ═══════════════════════════════════════════════════════════════════
    "auth": "standard",              # Authentication testing, login attempts
    "oauth": "standard",             # OAuth flow testing
    "saml": "standard",              # SAML testing
    "mfa": "standard",               # MFA bypass testing
    "authz": "standard",             # Authorization testing
    "idor": "standard",              # IDOR testing (accesses other records)
    "mass_assign": "standard",       # Mass assignment (may modify records)
    "ratelimit": "standard",         # Rate limit testing (sends many requests)
    "business_logic": "standard",    # Business logic (may create orders, etc.)
    "deser": "standard",             # Deserialization (can cause RCE)
    "prototype": "standard",         # Prototype pollution
    "postexploit": "standard",       # Post-exploitation
    "dns_rebind": "standard",        # DNS rebinding
    "race": "standard",              # Race conditions
    "host_header": "standard",       # Host header attacks
    "file_upload": "standard",       # File upload
    "concurrency_stress": "standard",# Parallel requests
    "concurrency_state": "standard", # Race condition testing
    "cross_surface": "standard",     # Cross-surface analysis
    "supabase": "standard",          # Supabase RLS bypass
    "firebase": "standard",          # Firebase security rules
    "rls_bypass": "standard",        # Row-level security bypass
    "webhook_security": "standard",  # Webhook testing
    "workflow_inference": "standard",# Workflow analysis
    "token_binding": "standard",     # Token binding tests
    "config_exposure": "standard",   # Config file exposure
    "logic_chain": "standard",       # Multi-step business logic testing
    "stateful_flow": "standard",     # Multi-step workflow fuzzing

    # ═══════════════════════════════════════════════════════════════════
    # AGGRESSIVE: Can affect other users, shared state, or is destructive
    # ═══════════════════════════════════════════════════════════════════
    "smuggling": "aggressive",       # Request smuggling affects shared state
    "cache": "aggressive",           # Cache poisoning affects other users
    "cache_deception": "aggressive", # Web cache deception
    "creative_exploiter": "aggressive",# Mutations, identity swaps
    "abac_context": "aggressive",    # Context confusion attacks
    "permission_matrix": "aggressive",# Permission boundary testing
    "client_hardening": "aggressive",# Client-side security testing
    "defensive_evasion": "aggressive",# WAF bypass, logging evasion
    "integration_exploiter": "aggressive",# API key validation attacks

    # ═══════════════════════════════════════════════════════════════════
    # Additional modules (filling gaps)
    # ═══════════════════════════════════════════════════════════════════
    "business": "standard",          # Alias for business_logic
    "comms": "standard",             # Communications API (SMS pumping risks)
    "cookie": "passive",             # Cookie security analysis
    "credential_verifier": "standard",# Credential testing
    "email": "cautious",             # Email security checks
    "llm": "cautious",               # LLM prompt injection testing
    "mobile": "cautious",            # Mobile API testing
    "nuclei": "cautious",            # Nuclei template runner
    "subdomain_takeover": "cautious",# Subdomain takeover checks
    "third_party": "passive",        # Third-party library detection
}


def get_module_safety_level(module_name: str) -> str:
    """Get the minimum safety level required for a module.

    Returns "passive" for unknown modules (always allowed).
    """
    return MODULE_SAFETY_LEVELS.get(module_name, "passive")


def is_safe_for_mode(module_name: str, current_mode: str) -> bool:
    """Check if a module can run in the given safety mode.

    A module can run if current_mode is at or above the module's required level
    in the safety hierarchy.
    """
    required_level = get_module_safety_level(module_name)

    try:
        required_idx = SAFETY_HIERARCHY.index(required_level)
        current_idx = SAFETY_HIERARCHY.index(current_mode)
        return current_idx >= required_idx
    except ValueError:
        # Unknown safety mode - allow passive modules only
        return required_level == "passive"


def get_modules_for_mode(mode: str) -> list[str]:
    """Get all modules that can run in the given safety mode."""
    return [
        module for module in MODULE_SAFETY_LEVELS.keys()
        if is_safe_for_mode(module, mode)
    ]


def get_safety_index(mode: str) -> int:
    """Get the numeric index of a safety mode (higher = more aggressive)."""
    try:
        return SAFETY_HIERARCHY.index(mode)
    except ValueError:
        return 0  # Default to passive
