"""
Authentication Scanner Base Module - Shared Types and Constants

Provides common data structures, enums, payloads, and utilities
used across all authentication scanner submodules.

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


# ============================================================================
# VULNERABILITY TYPE ENUMS
# ============================================================================

class AuthVulnType(Enum):
    """Authentication vulnerability types."""
    DEFAULT_CREDENTIALS = auto()
    WEAK_PASSWORD = auto()
    BRUTE_FORCE = auto()
    SESSION_FIXATION = auto()
    SESSION_HIJACKING = auto()
    JWT_NONE_ALG = auto()
    JWT_KEY_CONFUSION = auto()
    JWT_WEAK_SECRET = auto()
    JWT_CLAIM_TAMPERING = auto()
    OAUTH_REDIRECT = auto()
    OAUTH_STATE_MISSING = auto()
    OAUTH_TOKEN_LEAK = auto()
    SAML_SIGNATURE_BYPASS = auto()
    IDOR = auto()
    PRIVILEGE_ESCALATION = auto()
    MFA_BYPASS = auto()
    PASSWORD_RESET_FLAW = auto()
    ACCOUNT_ENUMERATION = auto()
    AUTH_BYPASS = auto()


class PrivilegeEscalationType(Enum):
    """Types of privilege escalation attacks."""
    HORIZONTAL_IDOR = auto()          # Access other users' resources
    VERTICAL_ESCALATION = auto()       # Access admin functions
    ROLE_MANIPULATION = auto()         # Change role in requests
    FORCED_BROWSING = auto()          # Direct URL access to admin
    HTTP_METHOD_TAMPERING = auto()    # GET->POST, PUT, DELETE
    PARAMETER_POLLUTION = auto()      # Duplicate params with different values
    MASS_ASSIGNMENT = auto()          # Hidden field manipulation
    PATH_TRAVERSAL_AUTHZ = auto()     # Path manipulation for access
    FUNCTION_LEVEL_ACCESS = auto()    # Accessing restricted functions
    REFERENCE_MANIPULATION = auto()   # Manipulating object references


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class AuthTestResult:
    """Result of an authentication test."""
    test_type: AuthVulnType
    success: bool
    severity: str = "INFO"
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    payload: str = ""
    response_data: dict = field(default_factory=dict)


@dataclass
class JWTAnalysis:
    """JWT token analysis result."""
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    signature: str = ""
    algorithm: str = ""
    is_expired: bool = False
    expiry_time: Optional[int] = None
    issuer: Optional[str] = None
    audience: Optional[str] = None
    vulnerabilities: list[str] = field(default_factory=list)


@dataclass
class OAuthConfig:
    """OAuth configuration detected."""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    client_id: str = ""
    redirect_uri: str = ""
    response_type: str = ""
    scope: str = ""
    state_param: bool = False
    pkce_supported: bool = False


@dataclass
class SessionInfo:
    """Session information for analysis."""
    cookie_name: str = ""
    cookie_value: str = ""
    has_secure: bool = False
    has_httponly: bool = False
    has_samesite: bool = False
    samesite_value: str = ""
    entropy: float = 0.0
    is_predictable: bool = False


@dataclass
class PrivescTestResult:
    """Result of privilege escalation test."""
    test_type: PrivilegeEscalationType
    vulnerable: bool
    severity: str = "INFO"
    confidence: float = 0.0
    endpoint: str = ""
    original_response: str = ""
    exploit_response: str = ""
    evidence: list[str] = field(default_factory=list)
    payload: str = ""


# ============================================================================
# CREDENTIAL PAYLOADS
# ============================================================================

ENTERPRISE_CREDENTIALS = [
    # Standard defaults
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", ""), ("admin", "1234"),
    ("root", "root"), ("root", "toor"), ("root", "password"),
    ("test", "test"), ("user", "user"), ("guest", "guest"),
    ("administrator", "administrator"), ("demo", "demo"),
    # Database defaults
    ("sa", ""), ("sa", "sa"), ("postgres", "postgres"),
    ("mysql", "mysql"), ("oracle", "oracle"),
    # Application defaults
    ("tomcat", "tomcat"), ("manager", "manager"),
    ("weblogic", "weblogic"), ("admin", "weblogic"),
    # Device defaults
    ("admin", "admin1234"), ("admin", "changeme"),
    ("cisco", "cisco"), ("ubnt", "ubnt"),
]


# ============================================================================
# JWT PAYLOADS
# ============================================================================

JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "private",
    "jwt_secret", "jwt-secret", "secretkey", "jwtkey",
    "your-256-bit-secret", "your-secret-key",
]


# ============================================================================
# OAUTH PAYLOADS
# ============================================================================

OAUTH_REDIRECT_PAYLOADS = [
    # Open redirect variations
    "//evil.com", "///evil.com", "////evil.com",
    "https://evil.com", "http://evil.com",
    "/\\evil.com", "/.evil.com",
    # Encoding bypasses
    "https%3A%2F%2Fevil.com", "https:%2F%2Fevil.com",
    # Parameter pollution
    "&redirect_uri=https://evil.com",
    # Subdomain confusion
    "https://legitimate.com.evil.com",
    "https://legitimate.com@evil.com",
    "https://evil.com#legitimate.com",
    "https://evil.com?legitimate.com",
]


# ============================================================================
# AUTH BYPASS PAYLOADS
# ============================================================================

AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"Host": "localhost"},
    {"X-Host": "localhost"},
    {"X-Forwarded-Server": "localhost"},
]


# ============================================================================
# IDOR PAYLOADS
# ============================================================================

IDOR_PATTERNS = [
    # Numeric manipulation
    {"original": "1", "test": ["0", "2", "-1", "999999", "1' OR '1'='1"]},
    {"original": "100", "test": ["99", "101", "1", "0", "-100"]},
    # UUID manipulation
    {"pattern": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
     "test": ["00000000-0000-0000-0000-000000000000"]},
]


# ============================================================================
# MFA BYPASS PAYLOADS
# ============================================================================

MFA_BYPASS_TECHNIQUES = [
    {"name": "null_code", "payload": "", "description": "Empty MFA code"},
    {"name": "zero_code", "payload": "000000", "description": "All zeros"},
    {"name": "array_code", "payload": ["123456"], "description": "Array instead of string"},
    {"name": "object_code", "payload": {"code": "123456"}, "description": "Object injection"},
    {"name": "negative", "payload": "-1", "description": "Negative value"},
    {"name": "special_chars", "payload": "123456' OR '1'='1", "description": "SQL injection in MFA"},
]


# ============================================================================
# PRIVILEGE ESCALATION PAYLOADS
# ============================================================================

ROLE_MANIPULATION_PAYLOADS = [
    # Direct role parameters
    {"param": "role", "values": ["admin", "administrator", "root", "superuser", "super_admin", "system"]},
    {"param": "user_role", "values": ["admin", "manager", "superuser", "owner"]},
    {"param": "userRole", "values": ["ADMIN", "ROLE_ADMIN", "SUPER_ADMIN"]},
    {"param": "access_level", "values": ["9", "10", "99", "100", "999", "admin"]},
    {"param": "accessLevel", "values": ["9", "10", "admin", "full"]},
    {"param": "permission", "values": ["admin", "all", "*", "full"]},
    {"param": "permissions", "values": ["admin", "all", "*", "read,write,delete,admin"]},
    {"param": "group", "values": ["admin", "administrators", "root", "wheel"]},
    {"param": "group_id", "values": ["1", "0", "admin"]},
    {"param": "is_admin", "values": ["1", "true", "yes", "True"]},
    {"param": "isAdmin", "values": ["1", "true", "yes", "True"]},
    {"param": "admin", "values": ["1", "true", "yes", "True"]},
    {"param": "staff", "values": ["1", "true", "yes"]},
    {"param": "is_staff", "values": ["1", "true", "yes"]},
    {"param": "superuser", "values": ["1", "true", "yes"]},
    {"param": "is_superuser", "values": ["1", "true", "yes"]},
    {"param": "type", "values": ["admin", "administrator", "superuser"]},
    {"param": "user_type", "values": ["admin", "administrator", "internal"]},
    {"param": "userType", "values": ["ADMIN", "ADMINISTRATOR", "INTERNAL"]},
    {"param": "privilege", "values": ["admin", "elevated", "high", "max"]},
    {"param": "level", "values": ["admin", "10", "99", "max"]},
]

ADMIN_PATHS_FORCED_BROWSING = [
    # Standard admin paths
    "/admin", "/admin/", "/administrator", "/administrator/",
    "/admin/dashboard", "/admin/panel", "/admin/home",
    "/admin/users", "/admin/settings", "/admin/config",
    "/admin/logs", "/admin/audit", "/admin/reports",
    # Management paths
    "/management", "/manage", "/manager",
    "/management/users", "/management/settings",
    # Console/Control paths
    "/console", "/control", "/controlpanel", "/cp",
    "/dashboard/admin", "/dashboard/management",
    # API admin paths
    "/api/admin", "/api/v1/admin", "/api/v2/admin",
    "/api/admin/users", "/api/admin/settings",
    "/api/management", "/api/internal",
    # Internal paths
    "/internal", "/internal/admin", "/private",
    "/private/admin", "/system", "/system/admin",
    # Debug paths
    "/debug", "/dev", "/test", "/staging",
    "/debug/admin", "/_admin", "/__admin",
    # Common framework paths
    "/wp-admin", "/wp-admin/", "/administrator/index.php",
    "/admin.php", "/admin.html", "/admin.asp",
    "/phpmyadmin", "/adminer", "/adminer.php",
    # REST patterns
    "/users/admin", "/user/1", "/user/0",
    "/accounts/admin", "/profile/admin",
]

HTTP_METHOD_TAMPERING = [
    # Standard methods
    {"method": "GET", "description": "Read-only access attempt"},
    {"method": "POST", "description": "Create/modify attempt"},
    {"method": "PUT", "description": "Update attempt"},
    {"method": "DELETE", "description": "Delete attempt"},
    {"method": "PATCH", "description": "Partial update attempt"},
    # Override headers
    {"method": "POST", "headers": {"X-HTTP-Method-Override": "PUT"}, "description": "Method override PUT"},
    {"method": "POST", "headers": {"X-HTTP-Method-Override": "DELETE"}, "description": "Method override DELETE"},
    {"method": "POST", "headers": {"X-HTTP-Method-Override": "PATCH"}, "description": "Method override PATCH"},
    {"method": "POST", "headers": {"X-Method-Override": "PUT"}, "description": "X-Method override"},
    {"method": "POST", "headers": {"X-HTTP-Method": "PUT"}, "description": "X-HTTP-Method override"},
    # Hidden input override
    {"method": "POST", "params": {"_method": "PUT"}, "description": "Form method override PUT"},
    {"method": "POST", "params": {"_method": "DELETE"}, "description": "Form method override DELETE"},
]

MASS_ASSIGNMENT_PAYLOADS = [
    # User privilege fields
    {"role": "admin"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"is_staff": True},
    {"staff": True},
    {"is_superuser": True},
    {"superuser": True},
    {"verified": True},
    {"is_verified": True},
    {"active": True},
    {"is_active": True},
    {"approved": True},
    {"is_approved": True},
    {"permission_level": "admin"},
    {"access_level": 999},
    {"user_type": "admin"},
    {"account_type": "premium"},
    {"subscription": "enterprise"},
    {"credits": 999999},
    {"balance": 999999},
    # Sensitive fields
    {"password": "newpassword123"},
    {"email_verified": True},
    {"two_factor_enabled": False},
    {"mfa_enabled": False},
]

PARAM_POLLUTION_PAYLOADS = [
    # Duplicate with different values
    {"pattern": "user_id=VICTIM&user_id=ATTACKER", "description": "Duplicate user_id"},
    {"pattern": "id=1&id=999", "description": "Duplicate id"},
    {"pattern": "role=user&role=admin", "description": "Duplicate role"},
    # Array injection
    {"pattern": "id[]=1&id[]=999", "description": "Array id injection"},
    {"pattern": "user_id[0]=1&user_id[1]=999", "description": "Indexed array injection"},
    # JSON in GET
    {"pattern": "data={\"role\":\"admin\"}", "description": "JSON in GET param"},
]

PRIVILEGED_FUNCTIONS = [
    # User management
    {"path": "/users", "methods": ["GET", "POST", "DELETE"], "admin_only": True},
    {"path": "/users/create", "methods": ["POST"], "admin_only": True},
    {"path": "/users/delete", "methods": ["DELETE", "POST"], "admin_only": True},
    {"path": "/users/all", "methods": ["GET"], "admin_only": True},
    {"path": "/api/users", "methods": ["GET", "POST"], "admin_only": True},
    # Settings/Config
    {"path": "/settings", "methods": ["GET", "POST"], "admin_only": True},
    {"path": "/config", "methods": ["GET", "POST"], "admin_only": True},
    {"path": "/api/settings", "methods": ["GET", "POST"], "admin_only": True},
    {"path": "/api/config", "methods": ["GET", "POST"], "admin_only": True},
    # System functions
    {"path": "/system/restart", "methods": ["POST"], "admin_only": True},
    {"path": "/system/backup", "methods": ["GET", "POST"], "admin_only": True},
    {"path": "/logs", "methods": ["GET"], "admin_only": True},
    {"path": "/audit", "methods": ["GET"], "admin_only": True},
    {"path": "/api/logs", "methods": ["GET"], "admin_only": True},
    # Reports
    {"path": "/reports", "methods": ["GET"], "admin_only": True},
    {"path": "/export", "methods": ["GET", "POST"], "admin_only": True},
    {"path": "/api/export", "methods": ["GET", "POST"], "admin_only": True},
    # Billing/Financial
    {"path": "/billing", "methods": ["GET", "POST"], "admin_only": True},
    {"path": "/invoices", "methods": ["GET"], "admin_only": True},
    {"path": "/transactions", "methods": ["GET"], "admin_only": True},
]

PATH_TRAVERSAL_AUTHZ_PAYLOADS = [
    # Basic traversal
    "/admin/../admin",
    "/api/user/../admin",
    "/api/v1/user/../../admin",
    # Encoded traversal
    "/admin%2f..%2fadmin",
    "/api%2fv1%2fuser%2f..%2f..%2fadmin",
    # Double encoding
    "/admin%252f..%252fadmin",
    # Case manipulation
    "/ADMIN", "/Admin", "/AdMiN",
    "/api/ADMIN", "/API/admin",
    # Extension bypass
    "/admin.json", "/admin.xml", "/admin.html",
    "/admin/index", "/admin/index.json",
    # Null byte (legacy)
    "/admin%00", "/admin%00.jpg",
    # Path normalization tricks
    "/./admin", "//admin", "/admin//",
    "/admin/.", "/admin/..",
    # Semicolon injection
    "/admin;", "/admin;.js",
    # Parameter injection in path
    "/admin?", "/admin#",
]


# ============================================================================
# COMMON PATHS
# ============================================================================

LOGIN_PATHS = [
    "/login", "/admin", "/admin/login", "/administrator",
    "/auth/login", "/user/login", "/signin", "/sign-in",
    "/wp-login.php", "/wp-admin", "/panel", "/dashboard",
    "/manage", "/console", "/auth", "/authenticate",
    "/api/auth/login", "/api/v1/auth/login", "/api/login",
    "/account/login", "/member/login", "/portal",
    "/sso/login", "/oauth/authorize", "/connect/authorize",
]

OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
    "/oauth/token", "/oauth2/token", "/connect/token",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
]

PROTECTED_PATHS = [
    "/admin", "/admin/dashboard", "/admin/users", "/admin/settings",
    "/api/admin", "/api/users", "/api/internal",
    "/user/profile", "/dashboard", "/settings", "/config",
    "/management", "/system", "/internal", "/private",
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def extract_form_fields(html_content: str) -> dict[str, Any]:
    """Extract form fields from HTML."""
    result: dict[str, Any] = {
        "username_field": None,
        "password_field": None,
        "action": None,
        "hidden_fields": {},
    }

    # Find form action
    form_match = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
    if form_match:
        result["action"] = form_match.group(1)

    # Find password field
    password_match = re.search(
        r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']+)["\']',
        html_content, re.IGNORECASE
    )
    if not password_match:
        password_match = re.search(
            r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']password["\']',
            html_content, re.IGNORECASE
        )
    if password_match:
        result["password_field"] = password_match.group(1)

    # Find username field
    username_patterns = [
        r'<input[^>]*name=["\'](?:user|username|email|login)["\']',
        r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']+)["\']',
    ]
    for pattern in username_patterns:
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            result["username_field"] = match.group(1) if match.groups() else "username"
            break

    # Find hidden fields
    hidden_matches = re.findall(
        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        html_content,
        re.IGNORECASE
    )
    for name, value in hidden_matches:
        result["hidden_fields"][name] = value

    return result


def check_successful_login(
    login_response: Any,
    original_response: Any,
) -> bool:
    """Check if login was successful."""

    # Check for redirect to different page
    if str(login_response.url) != str(original_response.url):
        if "login" not in str(login_response.url).lower():
            return True

    # Check for success indicators
    success_indicators = [
        "welcome", "dashboard", "logout",
        "sign out", "my account", "profile",
    ]

    content = login_response.text.lower()
    if any(indicator in content for indicator in success_indicators):
        error_indicators = ["invalid", "incorrect", "failed", "error", "wrong"]
        if not any(error in content for error in error_indicators):
            return True

    return False


def is_jwt(value: str) -> bool:
    """Check if value looks like a JWT."""
    parts = value.split(".")
    return len(parts) == 3 and all(len(p) > 10 for p in parts)
