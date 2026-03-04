"""
PHANTOM AI - Domain-Aware Auth Acquisition Strategies

Provides domain-specific authentication strategies for different business types:
- ECOMMERCE: Cart, checkout, account endpoints
- FINTECH: Banking, transfer, KYC endpoints
- SAAS: Workspace, dashboard, OAuth flows
- MARKETPLACE: Seller/buyer registration, escrow
- AUTH_CENTRIC: OAuth consent, SAML, MFA
- CONTENT: CMS login, draft/publish workflows
- API_SERVICE: API key generation, OAuth2

Each strategy knows the common endpoint patterns for its domain,
increasing auth acquisition success rates on diverse targets.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from scanning.business_archetypes import BusinessDomain

__all__ = [
    "AuthStrategy",
    "EcommerceAuthStrategy",
    "FintechAuthStrategy",
    "SaaSAuthStrategy",
    "MarketplaceAuthStrategy",
    "AuthCentricAuthStrategy",
    "ContentAuthStrategy",
    "ApiServiceAuthStrategy",
    "GenericAuthStrategy",
    "get_strategy_for_domain",
    "DOMAIN_STRATEGIES",
]


# =============================================================================
# BASE STRATEGY
# =============================================================================

@dataclass
class AuthStrategy(ABC):
    """Base class for domain-specific auth acquisition strategies."""

    domain: BusinessDomain
    priority: int = 50  # Higher = try first (0-100)

    @property
    @abstractmethod
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        """
        Return list of (path, field_template) for registration endpoints.
        Field template maps field_name -> default_value (None = use generated).
        """
        pass

    @property
    @abstractmethod
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        """
        Return list of (path, username_field, password_field) for login endpoints.
        """
        pass

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        """Return list of (username/email, password) to try."""
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("test", "test"),
            ("user", "user"),
            ("demo", "demo"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        """Return paths to check for authenticated session."""
        return ["/dashboard", "/account", "/profile", "/api/me", "/api/user"]

    @property
    def json_api_endpoints(self) -> list[str]:
        """Return JSON API login/register endpoints to try."""
        return ["/api/login", "/api/register", "/api/auth/login"]


# =============================================================================
# ECOMMERCE STRATEGY
# =============================================================================

@dataclass
class EcommerceAuthStrategy(AuthStrategy):
    """Auth strategy for e-commerce sites (Shopify, Magento, WooCommerce, etc.)."""

    domain: BusinessDomain = field(default=BusinessDomain.ECOMMERCE, init=False)
    priority: int = 80

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            # Shopify-style
            ("/account/register", {"email": None, "password": None, "first_name": None, "last_name": None}),
            # Magento-style
            ("/customer/account/createpost", {"email": None, "password": None, "password_confirmation": None, "firstname": None, "lastname": None}),
            # WooCommerce/WordPress
            ("/my-account", {"email": None, "password": None, "register": "Register"}),
            ("/wp-login.php?action=register", {"user_login": None, "user_email": None}),
            # Generic e-commerce
            ("/register", {"email": None, "password": None, "confirm_password": None}),
            ("/signup", {"email": None, "password": None}),
            ("/account/create", {"email": None, "password": None, "name": None}),
            # PrestaShop
            ("/authentication?create_account=1", {"email": None, "passwd": None, "firstname": None, "lastname": None}),
            # OpenCart
            ("/index.php?route=account/register", {"email": None, "password": None, "confirm": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/account/login", "email", "password"),
            ("/customer/account/loginPost", "login[username]", "login[password]"),
            ("/my-account", "username", "password"),
            ("/wp-login.php", "log", "pwd"),
            ("/login", "email", "password"),
            ("/authentication", "email", "passwd"),
            ("/index.php?route=account/login", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("admin@example.com", "admin123"),
            ("shop@example.com", "shop123"),
            ("test@example.com", "test123"),
            ("customer@example.com", "customer"),
            ("demo@example.com", "demo"),
            # Generic
            ("admin", "admin"),
            ("admin", "password"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/account",
            "/my-account",
            "/customer/account",
            "/cart",
            "/checkout",
            "/wishlist",
            "/orders",
            "/api/cart",
        ]

    @property
    def json_api_endpoints(self) -> list[str]:
        return [
            "/api/customers/login",
            "/api/account/login",
            "/rest/V1/integration/customer/token",  # Magento
            "/api/v1/auth/login",
            "/graphql",  # Shopify Storefront
        ]


# =============================================================================
# FINTECH STRATEGY
# =============================================================================

@dataclass
class FintechAuthStrategy(AuthStrategy):
    """Auth strategy for fintech/banking apps."""

    domain: BusinessDomain = field(default=BusinessDomain.FINTECH, init=False)
    priority: int = 70

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            # Banking-style
            ("/enroll", {"email": None, "password": None, "ssn_last4": "1234", "phone": None}),
            ("/signup", {"email": None, "password": None, "dob": "1990-01-01"}),
            ("/onboarding/create-account", {"email": None, "password": None, "phone": None}),
            ("/api/v1/users/register", {"email": None, "password": None}),
            # Crypto exchanges
            ("/register", {"email": None, "password": None, "confirmPassword": None, "agreeTos": "true"}),
            ("/api/register", {"email": None, "password": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/login", "email", "password"),
            ("/signin", "username", "password"),
            ("/auth/login", "email", "password"),
            ("/api/v1/auth/login", "email", "password"),
            ("/api/login", "email", "password"),
            # Some fintech uses MFA first step
            ("/auth/identify", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("test@example.com", "Test1234!"),
            ("demo@fintech.io", "Demo1234!"),
            ("sandbox@test.com", "Sandbox123"),
            # Test accounts often use these
            ("testuser", "TestPass123"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/dashboard",
            "/accounts",
            "/portfolio",
            "/transactions",
            "/wallet",
            "/api/balance",
            "/api/accounts",
            "/api/v1/me",
        ]


# =============================================================================
# SAAS STRATEGY
# =============================================================================

@dataclass
class SaaSAuthStrategy(AuthStrategy):
    """Auth strategy for SaaS applications."""

    domain: BusinessDomain = field(default=BusinessDomain.SAAS, init=False)
    priority: int = 75

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            # Standard SaaS
            ("/signup", {"email": None, "password": None, "company": None}),
            ("/register", {"email": None, "password": None, "organization": None}),
            ("/trial/signup", {"email": None, "password": None, "plan": "free"}),
            ("/api/v1/signup", {"email": None, "password": None}),
            # Workspace creation
            ("/create-workspace", {"email": None, "password": None, "workspace": None}),
            ("/onboarding", {"email": None, "password": None}),
            # OAuth-first (may not have traditional register)
            ("/auth/signup", {"email": None, "password": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/login", "email", "password"),
            ("/signin", "email", "password"),
            ("/app/login", "email", "password"),
            ("/api/v1/auth/login", "email", "password"),
            ("/auth/login", "email", "password"),
            # SSO entry points
            ("/sso/login", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("admin@example.com", "Admin123!"),
            ("test@company.com", "Test1234"),
            ("demo@saas.io", "Demo1234"),
            ("owner@workspace.com", "Owner123"),
            # Dev/staging accounts
            ("developer", "developer"),
            ("staging", "staging123"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/app",
            "/dashboard",
            "/workspace",
            "/settings",
            "/team",
            "/api/me",
            "/api/v1/user",
            "/api/workspace",
        ]


# =============================================================================
# MARKETPLACE STRATEGY
# =============================================================================

@dataclass
class MarketplaceAuthStrategy(AuthStrategy):
    """Auth strategy for marketplace platforms (sellers + buyers)."""

    domain: BusinessDomain = field(default=BusinessDomain.MARKETPLACE, init=False)
    priority: int = 70

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            # Buyer registration
            ("/register", {"email": None, "password": None, "username": None}),
            ("/signup", {"email": None, "password": None}),
            # Seller registration (often separate)
            ("/seller/register", {"email": None, "password": None, "business_name": None}),
            ("/become-a-seller", {"email": None, "password": None, "store_name": None}),
            ("/merchant/signup", {"email": None, "password": None}),
            # Generic
            ("/api/users/register", {"email": None, "password": None, "type": "buyer"}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/login", "email", "password"),
            ("/signin", "username", "password"),
            ("/seller/login", "email", "password"),
            ("/merchant/login", "email", "password"),
            ("/api/auth/login", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("seller@marketplace.com", "Seller123"),
            ("buyer@test.com", "Buyer123"),
            ("vendor@test.com", "Vendor123"),
            ("merchant", "merchant123"),
            ("test", "test123"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/dashboard",
            "/seller/dashboard",
            "/my-store",
            "/orders",
            "/listings",
            "/api/seller/me",
            "/api/buyer/orders",
        ]


# =============================================================================
# AUTH-CENTRIC STRATEGY
# =============================================================================

@dataclass
class AuthCentricAuthStrategy(AuthStrategy):
    """Auth strategy for auth-focused apps (SSO, identity providers)."""

    domain: BusinessDomain = field(default=BusinessDomain.AUTH_CENTRIC, init=False)
    priority: int = 85

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            # Standard registration
            ("/register", {"email": None, "password": None, "confirmPassword": None}),
            ("/signup", {"email": None, "password": None}),
            ("/auth/register", {"email": None, "password": None}),
            # OAuth providers often have user creation
            ("/oauth/register", {"email": None, "password": None}),
            ("/api/v1/users", {"email": None, "password": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/login", "username", "password"),
            ("/login", "email", "password"),
            ("/signin", "email", "password"),
            ("/auth/login", "email", "password"),
            ("/oauth/authorize", "username", "password"),
            # SAML endpoints
            ("/saml/login", "email", "password"),
            ("/idp/login", "username", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("admin", "admin"),
            ("admin@idp.local", "Admin123"),
            ("testuser", "testuser"),
            ("developer", "developer"),
            # Common SSO test accounts
            ("ssotest", "SSOTest123"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/account",
            "/profile",
            "/settings",
            "/oauth/userinfo",
            "/api/me",
            "/.well-known/openid-configuration",
        ]


# =============================================================================
# CONTENT STRATEGY
# =============================================================================

@dataclass
class ContentAuthStrategy(AuthStrategy):
    """Auth strategy for content management systems."""

    domain: BusinessDomain = field(default=BusinessDomain.CONTENT, init=False)
    priority: int = 65

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            # WordPress
            ("/wp-login.php?action=register", {"user_login": None, "user_email": None}),
            # Drupal
            ("/user/register", {"mail": None, "name": None, "pass[pass1]": None, "pass[pass2]": None}),
            # Joomla
            ("/index.php?option=com_users&view=registration", {"jform[email1]": None, "jform[username]": None, "jform[password1]": None}),
            # Ghost
            ("/ghost/api/v3/admin/session", {"username": None, "password": None}),
            # Generic CMS
            ("/admin/register", {"email": None, "password": None}),
            ("/signup", {"email": None, "password": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            # WordPress
            ("/wp-login.php", "log", "pwd"),
            ("/wp-admin", "log", "pwd"),
            # Drupal
            ("/user/login", "name", "pass"),
            # Joomla
            ("/administrator", "username", "passwd"),
            # Ghost
            ("/ghost/api/v3/admin/session", "username", "password"),
            # Generic
            ("/admin/login", "username", "password"),
            ("/cms/login", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            # WordPress defaults
            ("admin", "admin"),
            ("admin", "password"),
            ("editor", "editor"),
            # Common CMS passwords
            ("admin@site.com", "admin123"),
            ("webmaster", "webmaster"),
            ("root", "root"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/wp-admin",
            "/admin/dashboard",
            "/admin",
            "/ghost/#/dashboard",
            "/user",
            "/api/users/me",
        ]


# =============================================================================
# API SERVICE STRATEGY
# =============================================================================

@dataclass
class ApiServiceAuthStrategy(AuthStrategy):
    """Auth strategy for API-first services."""

    domain: BusinessDomain = field(default=BusinessDomain.API_SERVICE, init=False)
    priority: int = 60

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            ("/api/v1/register", {"email": None, "password": None}),
            ("/api/v1/signup", {"email": None, "password": None}),
            ("/api/users", {"email": None, "password": None}),
            ("/auth/register", {"email": None, "password": None}),
            ("/v1/auth/register", {"email": None, "password": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/api/v1/auth/login", "email", "password"),
            ("/api/v1/login", "email", "password"),
            ("/api/auth/token", "username", "password"),
            ("/oauth/token", "username", "password"),
            ("/v1/auth/login", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("api_user", "api_password"),
            ("developer", "developer"),
            ("test@api.com", "TestApi123"),
            ("admin", "admin"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/api/v1/me",
            "/api/me",
            "/api/user",
            "/api/v1/user",
            "/api/v1/account",
        ]

    @property
    def json_api_endpoints(self) -> list[str]:
        return [
            "/api/v1/auth/login",
            "/api/v1/login",
            "/api/login",
            "/oauth/token",
            "/v1/auth/token",
        ]


# =============================================================================
# GENERIC (FALLBACK) STRATEGY
# =============================================================================

@dataclass
class GenericAuthStrategy(AuthStrategy):
    """Generic fallback strategy for unknown domains."""

    domain: BusinessDomain = field(default=BusinessDomain.UNKNOWN, init=False)
    priority: int = 10  # Lowest priority - used as fallback

    @property
    def register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        return [
            ("/register", {"email": None, "password": None, "confirmPassword": None}),
            ("/signup", {"email": None, "password": None}),
            ("/api/register", {"email": None, "password": None}),
            ("/api/Users", {"email": None, "password": None}),
            ("/auth/register", {"email": None, "password": None}),
            ("/users/sign_up", {"user[email]": None, "user[password]": None}),
        ]

    @property
    def login_endpoints(self) -> list[tuple[str, str, str]]:
        return [
            ("/login", "email", "password"),
            ("/login", "username", "password"),
            ("/signin", "email", "password"),
            ("/api/login", "email", "password"),
            ("/auth/login", "email", "password"),
            ("/rest/user/login", "email", "password"),
        ]

    @property
    def common_credentials(self) -> list[tuple[str, str]]:
        return [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "admin123"),
            ("test", "test"),
            ("user", "user"),
            ("demo", "demo"),
            ("guest", "guest"),
        ]

    @property
    def session_verify_paths(self) -> list[str]:
        return [
            "/dashboard",
            "/account",
            "/profile",
            "/api/me",
            "/api/user",
            "/me",
        ]


# =============================================================================
# STRATEGY REGISTRY
# =============================================================================

DOMAIN_STRATEGIES: dict[BusinessDomain, type[AuthStrategy]] = {
    BusinessDomain.ECOMMERCE: EcommerceAuthStrategy,
    BusinessDomain.FINTECH: FintechAuthStrategy,
    BusinessDomain.SAAS: SaaSAuthStrategy,
    BusinessDomain.MARKETPLACE: MarketplaceAuthStrategy,
    BusinessDomain.AUTH_CENTRIC: AuthCentricAuthStrategy,
    BusinessDomain.CONTENT: ContentAuthStrategy,
    BusinessDomain.API_SERVICE: ApiServiceAuthStrategy,
    BusinessDomain.UNKNOWN: GenericAuthStrategy,
}


def get_strategy_for_domain(domain: BusinessDomain | str | None) -> AuthStrategy:
    """
    Get the appropriate auth strategy for a business domain.

    Args:
        domain: BusinessDomain enum or string domain name

    Returns:
        AuthStrategy instance for the domain (GenericAuthStrategy if unknown)
    """
    if domain is None:
        return GenericAuthStrategy()

    # Convert string to enum if needed
    if isinstance(domain, str):
        try:
            domain = BusinessDomain(domain.lower())
        except ValueError:
            return GenericAuthStrategy()

    strategy_class = DOMAIN_STRATEGIES.get(domain, GenericAuthStrategy)
    return strategy_class()


def get_all_strategies_ordered() -> list[AuthStrategy]:
    """
    Get all auth strategies ordered by priority (highest first).

    Returns:
        List of AuthStrategy instances
    """
    strategies = [cls() for cls in DOMAIN_STRATEGIES.values()]
    return sorted(strategies, key=lambda s: s.priority, reverse=True)
