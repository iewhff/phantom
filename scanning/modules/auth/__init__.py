"""
Authentication Scanner Package

Modular authentication vulnerability scanning with focused components:
- auth_base: Shared types, constants, and utilities
- auth_jwt_scanner: JWT vulnerability testing
- auth_session_scanner: Session management security
- auth_login_scanner: Login and credential testing
- auth_oauth_scanner: OAuth 2.0 / OIDC security
- auth_privesc_scanner: Privilege escalation testing
- auth_bypass_scanner: Authentication bypass testing

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from .auth_base import (
    # Enums
    AuthVulnType,
    PrivilegeEscalationType,
    # Data classes
    AuthTestResult,
    JWTAnalysis,
    OAuthConfig,
    SessionInfo,
    PrivescTestResult,
    # Utility functions
    extract_form_fields,
    check_successful_login,
    is_jwt,
)

__all__ = [
    # Enums
    "AuthVulnType",
    "PrivilegeEscalationType",
    # Data classes
    "AuthTestResult",
    "JWTAnalysis",
    "OAuthConfig",
    "SessionInfo",
    "PrivescTestResult",
    # Utility functions
    "extract_form_fields",
    "check_successful_login",
    "is_jwt",
]
