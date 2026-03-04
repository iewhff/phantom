"""
Auth Testing - Cross-User and State-Aware Access Testing.

This module provides infrastructure for testing authentication and authorization:
- State-aware retest (auth vs no-auth comparison)
- Cross-user identity variation testing (horizontal/vertical privilege escalation)
- User identifier extraction and manipulation
- ID expansion for IDOR testing

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from scanning.auth_testing.tester import (
    # Config
    AuthTestConfig,
    # Data
    CrossUserResult,
    StateRetestResult,
    # Main class
    AuthTester,
    # Convenience functions
    state_aware_retest,
    identity_variation_retest,
)

from scanning.auth_testing.helpers import (
    # Helper functions
    extract_user_identifiers,
    contains_victim_data,
    get_auth_headers,
    generate_expanded_ids,
    replace_id_in_url,
    extract_data_content,
)

__all__ = [
    # Config
    "AuthTestConfig",
    # Data
    "CrossUserResult",
    "StateRetestResult",
    # Main class
    "AuthTester",
    # Convenience functions
    "state_aware_retest",
    "identity_variation_retest",
    # Helpers
    "extract_user_identifiers",
    "contains_victim_data",
    "get_auth_headers",
    "generate_expanded_ids",
    "replace_id_in_url",
    "extract_data_content",
]
