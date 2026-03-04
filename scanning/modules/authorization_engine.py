"""
Advanced Authorization Testing Engine.
Tests for horizontal/vertical access control, RBAC/ABAC, and multi-tenant isolation.

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - Only GET requests
- standard: GET + HEAD + OPTIONS only (no state changes)
- aggressive: Full testing with PUT/POST/DELETE
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanning.findings import Finding, VulnType, Severity
from scanning.vuln_scanner import ScanModule
from scanning.exploitability_classifier import (
    ImpactTier, get_impact_tier, get_confidence_for_tier,
)
from utils.endpoint_map import EndpointMap, EndpointCategory
from utils.endpoint_validator import EndpointValidator
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.shared_findings_store import SharedFindingsStore, VulnType as StoreVulnType
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("aggressive",)  # Only aggressive mode allows PUT/DELETE


@dataclass
class Role:
    """Represents a user role for authorization testing."""
    name: str
    level: int  # Higher = more privileged
    token: str | None = None
    session: dict[str, str] = field(default_factory=dict)
    accessible_endpoints: list[str] = field(default_factory=list)


@dataclass
class AuthzTestCase:
    """Authorization test case."""
    name: str
    source_role: str
    target_role: str
    endpoint: str
    method: str
    expected_denied: bool
    payload: dict[str, Any] | None = None


class AuthorizationEngine(ScanModule):
    """
    Advanced Authorization Testing Engine.

    Tests for:
    - Horizontal access control (user A accessing user B's data)
    - Vertical access control (low priv accessing high priv functions)
    - RBAC bypass (role-based access control)
    - ABAC bypass (attribute-based access control)
    - Multi-tenant isolation
    - Privilege escalation paths
    - Forced browsing
    - Parameter tampering for authz bypass

    CONFIDENCE TIERS (GAP-3.1 - Honest Calibration):
    - Tier 1 (60-70%): Endpoint accessible, content looks relevant
    - Tier 2 (70-80%): Response contains sensitive data patterns
    - Tier 3 (80-90%): Proven action (different user data, state change)
    - Tier 4 (90-100%): Proven harmful impact (creds, takeover, escalation)
    """

    name = "authorization_engine"

    # =========================================================================
    # CONFIDENCE CALIBRATION (GAP-3.1)
    # Evidence-based confidence, not hype
    # =========================================================================
    CONFIDENCE_TIER_1_ACCESSIBLE = 65.0      # Endpoint returns 200, looks admin-ish
    CONFIDENCE_TIER_2_SENSITIVE = 75.0       # Contains sensitive data keywords
    CONFIDENCE_TIER_3_EXPLOITABLE = 85.0     # Proven different user's data / action worked
    CONFIDENCE_TIER_4_IMPACTFUL = 95.0       # Proven creds/takeover/escalation

    # Strong evidence patterns (boost confidence)
    STRONG_EVIDENCE_PATTERNS = [
        # PII patterns
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone
        r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',  # SSN-like
        # Credential patterns
        r'"password"\s*:\s*"[^"]+',  # Password in JSON
        r'"secret"\s*:\s*"[^"]+',  # Secret in JSON
        r'"api[_-]?key"\s*:\s*"[^"]+',  # API key in JSON
        r'"token"\s*:\s*"[^"]+',  # Token in JSON
    ]

    # Weak evidence (just keywords, not actual data)
    WEAK_EVIDENCE_KEYWORDS = ["admin", "dashboard", "management", "users", "settings"]
    
    # Common role patterns
    ROLE_INDICATORS = {
        "admin": ["admin", "administrator", "superuser", "root", "super"],
        "moderator": ["moderator", "mod", "manager", "supervisor"],
        "user": ["user", "member", "customer", "client"],
        "guest": ["guest", "anonymous", "public", "visitor"],
    }
    
    # Privilege escalation parameters
    PRIVESC_PARAMS = [
        "role", "user_role", "userRole", "admin", "is_admin", "isAdmin",
        "privilege", "level", "access_level", "accessLevel", "permission",
        "permissions", "group", "groups", "user_type", "userType", "type",
        "account_type", "accountType", "membership", "tier",
    ]
    
    # Multi-tenant parameters
    TENANT_PARAMS = [
        "tenant_id", "tenantId", "tenant", "org_id", "orgId", "organization",
        "org", "company_id", "companyId", "company", "account_id", "accountId",
        "workspace", "workspace_id", "workspaceId", "team", "team_id", "teamId",
    ]

    # Hidden admin/debug endpoints to probe on TARGET only
    # These are ONLY tested on the exact target URL provided, never on other domains
    HIDDEN_ADMIN_PATHS = [
        # Spring Boot Actuator
        "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
        "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
        "/actuator/heapdump", "/actuator/threaddump", "/actuator/logfile",
        "/actuator/metrics", "/actuator/prometheus", "/actuator/jolokia",
        # Laravel/PHP
        "/telescope", "/horizon", "/nova", "/_debugbar", "/clockwork",
        "/phpinfo.php", "/info.php", "/php_info.php", "/adminer.php",
        # Django
        "/__debug__", "/admin/doc", "/api-auth", "/silk",
        # Node.js/Express
        "/status", "/health", "/healthcheck", "/api/health",
        "/.well-known/openid-configuration", "/metrics", "/api/metrics",
        # General admin paths
        "/admin", "/administrator", "/admin.php", "/wp-admin",
        "/manager", "/management", "/console", "/dashboard",
        "/control", "/controlpanel", "/cpanel", "/panel",
        # Debug/internal
        "/debug", "/trace", "/api/debug", "/api/trace",
        "/internal", "/api/internal", "/private", "/api/private",
        "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
        "/graphql", "/graphiql", "/playground",
        # Config exposure
        "/config", "/configuration", "/settings", "/api/config",
        "/env", "/environment", "/.env", "/config.json",
        # Backup/sensitive files
        "/backup", "/backups", "/dump", "/export", "/api/export",
        # Version control
        "/.git/config", "/.svn/entries", "/.hg/store",
    ]

    # Headers for bypass attempts
    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Forwarded-For": "::1"},
        {"X-Host": "localhost"},
        {"Host": "localhost"},
        {"X-Forwarded-Proto": "https"},
        {"X-Forwarded-Scheme": "https"},
    ]

    # Path manipulation patterns for bypass
    PATH_BYPASS_PATTERNS = [
        "/",           # Trailing slash
        "/.",          # Trailing dot
        "/./",         # Dot segment
        "//",          # Double slash
        "/..",         # Parent
        "%2e",         # URL encoded dot
        "%2e/",        # URL encoded dot + slash
        "?",           # Query string start
        "?anything",   # Query parameter
        "#",           # Fragment
        ";",           # Parameter separator
        ".json",       # Extension
        ".html",       # Extension
    ]

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.discovered_roles: list[Role] = []
        self.endpoint_permissions: dict[str, list[str]] = {}

    def _calculate_evidence_confidence(
        self,
        response_text: str,
        *,
        has_different_user_data: bool = False,
        has_state_change: bool = False,
        has_credentials: bool = False,
        is_bypass: bool = False,
    ) -> float:
        """
        Calculate confidence based on actual evidence, not just "200 OK".

        GAP-3.1 Fix: Honest confidence calibration
        GAP-3.3 Fix: Uses impact tier system for consistency

        Returns:
            Float confidence value (60-95) based on evidence tier
        """
        import re

        content_lower = response_text.lower()

        # Detect data extraction patterns
        has_data_extraction = False
        for pattern in self.STRONG_EVIDENCE_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                has_data_extraction = True
                break

        # GAP-3.3: Use impact tier system for consistent classification
        tier = get_impact_tier(
            confidence=0,  # We're calculating, not using existing
            has_proof=is_bypass or has_different_user_data,
            has_data_extraction=has_data_extraction,
            has_state_change=has_state_change,
            has_credential_access=has_credentials,
        )

        # Get base confidence for tier
        confidence = get_confidence_for_tier(tier)

        # Fine-tune within tier based on evidence strength
        if tier == ImpactTier.ACCESSIBLE:
            # Bump slightly if weak keywords present
            if any(kw in content_lower for kw in self.WEAK_EVIDENCE_KEYWORDS):
                confidence += 5  # 65 → 70

        elif tier == ImpactTier.EXPLOITABLE:
            # Bump if multiple evidence patterns
            pattern_count = sum(
                1 for p in self.STRONG_EVIDENCE_PATTERNS
                if re.search(p, response_text, re.IGNORECASE)
            )
            if pattern_count >= 2:
                confidence += 5  # 80 → 85

        return confidence
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Scan for authorization vulnerabilities."""
        findings: list[dict[str, Any]] = []

        base_url = f"https://{host}" if not host.startswith("http") else host

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        urls = asset_data.get("urls", [])
        forms = asset_data.get("forms", [])
        
        # Discover roles from responses
        await self._discover_roles(base_url, urls, rate_limiter)
        
        # Test horizontal access control
        horizontal_findings = await self._test_horizontal_access(
            base_url, urls, rate_limiter
        )
        findings.extend(horizontal_findings)
        
        # Test vertical access control
        vertical_findings = await self._test_vertical_access(
            base_url, urls, rate_limiter
        )
        findings.extend(vertical_findings)
        
        # Test privilege escalation via parameters
        privesc_findings = await self._test_privilege_escalation(
            base_url, urls, forms, rate_limiter
        )
        findings.extend(privesc_findings)
        
        # Test multi-tenant isolation
        tenant_findings = await self._test_tenant_isolation(
            base_url, urls, rate_limiter
        )
        findings.extend(tenant_findings)
        
        # Test forced browsing
        forced_findings = await self._test_forced_browsing(
            base_url, rate_limiter
        )
        findings.extend(forced_findings)
        
        # Test function level access
        function_findings = await self._test_function_level_access(
            base_url, urls, rate_limiter
        )
        findings.extend(function_findings)

        # Test hidden/undocumented endpoints on TARGET only
        # This discovers admin panels, debug endpoints, config exposure on the exact target URL
        hidden_findings = await self._test_hidden_endpoints(
            base_url, rate_limiter
        )
        findings.extend(hidden_findings)

        # ====================================================================
        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        # Access control findings enable chains (IDOR + Session → ATO)
        # ====================================================================
        try:
            store = SharedFindingsStore.get_instance()
            for f in findings:
                metadata = f.get("metadata", {})
                vuln_name = f.get("name", "").lower()
                if "idor" in vuln_name:
                    vuln_type = StoreVulnType.IDOR
                elif "auth_bypass" in vuln_name or "bypass" in vuln_name:
                    vuln_type = StoreVulnType.AUTH_BYPASS
                else:
                    vuln_type = StoreVulnType.BROKEN_ACCESS_CONTROL
                await store.add_finding(
                    {
                        "type": vuln_type,
                        "endpoint": f.get("matched_at") or metadata.get("url", ""),
                        "severity": f.get("severity", "HIGH"),
                        "name": f.get("name", "authorization"),
                        "source_role": metadata.get("source_role", ""),
                            "target_role": metadata.get("target_role", ""),
                    },
                    module="authorization_engine",
                )
            if findings:
                logger.debug(f"[AUTHZ] Shared {len(findings)} findings to cross-module store")
        except Exception as e:
            logger.debug(f"[AUTHZ] Could not share findings: {e}")

        return {
            "module": self.name,
            "findings": findings,
            "roles_discovered": [r.name for r in self.discovered_roles],
        }
    
    async def _discover_roles(
        self,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """
        Discover roles from application responses and JWT tokens.

        Enhanced to extract roles from:
        - API endpoints (/api/roles, /api/me, etc.)
        - JWT token claims (role, roles, scope, permissions)
        - Response headers (X-User-Role, etc.)
        - JavaScript/HTML content
        """
        role_patterns = set()
        jwt_roles = set()

        # Check common endpoints that reveal roles
        role_endpoints = [
            "/api/users",
            "/api/roles",
            "/api/permissions",
            "/admin/users",
            "/api/me",
            "/api/profile",
            "/api/user",
            "/api/account",
            "/auth/userinfo",
            "/oauth/userinfo",
            "/.well-known/openid-configuration",
        ]

        # OPTIMIZATION: Filter to only existing endpoints
        validator = EndpointValidator.get_instance()
        existing_endpoints = await validator.filter_existing_endpoints(
            base_url, role_endpoints, rate_limiter, max_concurrent=5
        )

        if not existing_endpoints:
            logger.debug("[AuthzEngine] No role endpoints found, skipping role discovery")

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for url in existing_endpoints:
                await rate_limiter.acquire()

                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        content = response.text.lower()

                        # Find role mentions
                        for role_type, indicators in self.ROLE_INDICATORS.items():
                            for indicator in indicators:
                                if indicator in content:
                                    role_patterns.add(role_type)

                        # Extract roles from JSON responses
                        try:
                            data = response.json()
                            extracted = self._extract_roles_from_json(data)
                            role_patterns.update(extracted)
                        except (json.JSONDecodeError, ValueError):
                            pass

                    # Check for JWT in response
                    jwt_roles.update(self._extract_jwt_roles_from_response(response))

                except (httpx.HTTPError, httpx.TimeoutException):
                    continue

        # Also check cookies and headers from base URL
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            await rate_limiter.acquire()
            try:
                response = await client.get(base_url)
                jwt_roles.update(self._extract_jwt_roles_from_response(response))
            except (httpx.RequestError, httpx.HTTPStatusError):
                pass

        # Merge discovered roles
        all_roles = role_patterns.union(jwt_roles)
        logger.info(f"[AuthzEngine] Discovered roles: {all_roles}")

        # Create role objects with priority ordering
        role_levels = {
            "guest": 0, "anonymous": 0, "public": 0, "visitor": 0,
            "user": 1, "member": 1, "customer": 1, "basic": 1,
            "editor": 2, "author": 2, "contributor": 2,
            "moderator": 3, "mod": 3, "manager": 3, "supervisor": 3,
            "admin": 4, "administrator": 4, "owner": 4,
            "superuser": 5, "superadmin": 5, "root": 5, "super": 5,
        }

        for role in all_roles:
            role_lower = role.lower()
            level = role_levels.get(role_lower, 1)  # Default to user level
            self.discovered_roles.append(Role(name=role, level=level))

        # Ensure we have at least guest and user
        existing_names = {r.name.lower() for r in self.discovered_roles}
        if "guest" not in existing_names:
            self.discovered_roles.append(Role(name="guest", level=0))
        if "user" not in existing_names:
            self.discovered_roles.append(Role(name="user", level=1))

        # Sort by level
        self.discovered_roles.sort(key=lambda r: r.level)

    def _extract_roles_from_json(self, data: dict | list, path: str = "") -> set[str]:
        """Extract role names from JSON response data."""
        roles = set()

        role_keys = ["role", "roles", "user_role", "userRole", "user_type", "userType",
                     "permission", "permissions", "scope", "scopes", "groups", "group",
                     "access_level", "accessLevel", "account_type", "accountType"]

        if isinstance(data, dict):
            for key, value in data.items():
                key_lower = key.lower()

                # Direct role key
                if key_lower in [k.lower() for k in role_keys]:
                    if isinstance(value, str):
                        roles.add(value)
                    elif isinstance(value, list):
                        for v in value:
                            if isinstance(v, str):
                                roles.add(v)

                # Recurse into nested objects
                elif isinstance(value, (dict, list)):
                    roles.update(self._extract_roles_from_json(value, f"{path}.{key}"))

        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    roles.update(self._extract_roles_from_json(item, path))

        return roles

    def _extract_jwt_roles_from_response(self, response: httpx.Response) -> set[str]:
        """
        Extract roles from JWT tokens in response.

        Checks:
        - Authorization header
        - Set-Cookie headers
        - Response body (access_token, id_token fields)
        """
        import base64

        roles = set()

        def decode_jwt_payload(token: str) -> dict | None:
            """Decode JWT payload without verification."""
            try:
                parts = token.split(".")
                if len(parts) != 3:
                    return None

                # Decode payload (part 1)
                payload = parts[1]
                # Add padding if needed
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += "=" * padding

                decoded = base64.urlsafe_b64decode(payload)
                return json.loads(decoded)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                return None

        def extract_roles_from_claims(claims: dict) -> set[str]:
            """Extract roles from JWT claims."""
            found = set()
            role_claim_names = [
                "role", "roles", "scope", "scopes", "permissions", "permission",
                "groups", "group", "authorities", "realm_access", "resource_access",
                "cognito:groups", "custom:role", "user_role", "userRole",
            ]

            for claim_name in role_claim_names:
                if claim_name in claims:
                    value = claims[claim_name]
                    if isinstance(value, str):
                        # Could be space-separated (scopes) or single value
                        found.update(value.split())
                    elif isinstance(value, list):
                        found.update(str(v) for v in value)
                    elif isinstance(value, dict):
                        # Keycloak realm_access format: {"roles": ["admin"]}
                        if "roles" in value:
                            found.update(value["roles"])

            return found

        # Check Authorization header in response
        auth_header = response.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            claims = decode_jwt_payload(token)
            if claims:
                roles.update(extract_roles_from_claims(claims))

        # Check Set-Cookie headers for JWT tokens
        for cookie_header in response.headers.get_list("set-cookie"):
            # Common JWT cookie names
            for cookie_name in ["token", "access_token", "jwt", "auth_token", "session"]:
                if cookie_name + "=" in cookie_header.lower():
                    # Extract cookie value
                    match = re.search(rf'{cookie_name}=([^;]+)', cookie_header, re.IGNORECASE)
                    if match:
                        token = match.group(1)
                        claims = decode_jwt_payload(token)
                        if claims:
                            roles.update(extract_roles_from_claims(claims))

        # Check response body for JWT tokens
        try:
            data = response.json()
            # BUG-FIX: Only process dict responses, not arrays
            if isinstance(data, dict):
                for token_key in ["access_token", "id_token", "token", "jwt"]:
                    if token_key in data:
                        token = None
                        token = data[token_key]
                        if isinstance(token, str):
                            claims = decode_jwt_payload(token)
                            if claims:
                                roles.update(extract_roles_from_claims(claims))
        except (json.JSONDecodeError, ValueError):
            pass

        return roles
    
    async def _test_horizontal_access(
        self,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test horizontal access control (user A vs user B)."""
        findings = []
        max_findings_per_endpoint = 3  # FIX 2026-02-11: Track enumeration scope

        # Find user-specific endpoints
        user_endpoints = []
        user_id_pattern = re.compile(r'/(?:user|users|profile|account|member)s?/(\d+|[a-f0-9-]{36})')
        
        for url in urls:
            match = user_id_pattern.search(url)
            if match:
                user_endpoints.append((url, match.group(1)))
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            # FN-H4 FIX: Increased endpoint limit (was [:10])
            for endpoint, original_id in user_endpoints[:25]:
                # Generate different user IDs to test
                test_ids = self._generate_test_ids(original_id)

                # FIX 2026-02-11: Track enumeration scope instead of breaking after first finding
                accessible_ids: list[str] = []
                endpoint_findings_count = 0

                for test_id in test_ids:
                    await rate_limiter.acquire()

                    test_url = endpoint.replace(original_id, test_id)

                    try:
                        response = await client.get(test_url)

                        if response.status_code == 200:
                            # Check if we got different user's data
                            try:
                                data = response.json()

                                # Look for user identifiers in response
                                response_str = json.dumps(data).lower()

                                # Check if we got DIFFERENT user's data (strong evidence)
                                has_different_user = test_id in response_str
                                has_pii = any(x in response_str for x in ["email", "name", "address", "phone"])

                                if has_different_user or has_pii:
                                    accessible_ids.append(test_id)

                                    # Only create finding for first few, but track all accessible
                                    if endpoint_findings_count < max_findings_per_endpoint:
                                        # GAP-3.1: Calculate confidence based on evidence
                                        conf = self._calculate_evidence_confidence(
                                            response_str,
                                            has_different_user_data=has_different_user,
                                        )
                                        findings.append(Finding(
                                            vuln_type=VulnType.BFLA,
                                            name="Horizontal Privilege Escalation (IDOR)",
                                            severity=Severity.HIGH,
                                            confidence_score=conf,
                                            description=f"User data accessible by changing ID from {original_id} to {test_id}. "
                                                       f"No authorization check prevents accessing other users' data.",
                                            host=base_url,
                                            endpoint=test_url,
                                            evidence=[
                                                f"Original ID: {original_id}",
                                                f"Test ID: {test_id}",
                                                f"Response contains user data (different_user={has_different_user})",
                                                f"Enumeration scope: {len(accessible_ids)} IDs accessible so far",
                                            ],
                                            cvss_score=7.5,
                                            cwe_id="CWE-639",
                                            remediation="Implement authorization checks for all user-specific resources. "
                                                       "Verify the authenticated user has permission to access the requested resource.",
                                            references=[
                                                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                                            ],
                                        ).to_dict())
                                        endpoint_findings_count += 1
                                    # Continue testing to determine enumeration scope
                            except json.JSONDecodeError:
                                pass

                    except Exception as e:
                        logger.debug(f"Horizontal access test error: {e}")

                # Log enumeration scope for audit
                if accessible_ids:
                    logger.info(f"[AUDIT] IDOR enumeration scope: {endpoint} - {len(accessible_ids)} IDs accessible: {accessible_ids[:5]}...")
        
        return findings
    
    def _generate_test_ids(self, original_id: str) -> list[str]:
        """
        Generate test IDs based on original ID format.

        Enhanced to support:
        - Numeric IDs (sequential, boundary)
        - UUIDs (v1, v4, manipulation)
        - MongoDB ObjectIDs (24 hex chars)
        - Base64-encoded IDs
        - Hash-like IDs (MD5, SHA)
        - Custom alphanumeric patterns
        """
        import base64
        import hashlib

        test_ids = []
        id_lower = original_id.lower()

        # 1. Numeric ID (most common for IDOR)
        if original_id.isdigit():
            num = int(original_id)
            test_ids.extend([
                str(num + 1),       # Next user
                str(num - 1),       # Previous user
                str(num + 100),     # Jump forward
                str(num * 2),       # Double
                "1",                # First user (often admin)
                "0",                # Null/system user
                "2",                # Second user
                str(max(1, num - 100)),  # Jump backward
            ])

        # 2. UUID (36 chars with dashes)
        elif len(original_id) == 36 and original_id.count("-") == 4:
            parts = original_id.split("-")
            # Modify last segment
            last_modified = parts[-1][:-1] + ("0" if parts[-1][-1] != "0" else "1")
            test_ids.append("-".join(parts[:-1] + [last_modified]))

            # UUID v1 timestamp manipulation (if v1)
            if parts[2].startswith("1"):  # Version 1
                # Increment timestamp portion
                try:
                    ts_part = int(parts[0], 16)
                    test_ids.append(f"{ts_part + 1:08x}-{'-'.join(parts[1:])}")
                except (ValueError, IndexError):
                    pass

            # Common test UUIDs
            test_ids.extend([
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000000",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                # Same UUID with version bit flipped (v4 -> v1)
                f"{parts[0]}-{parts[1]}-1{parts[2][1:]}-{parts[3]}-{parts[4]}",
            ])

        # 3. MongoDB ObjectID (24 hex characters)
        elif len(original_id) == 24 and all(c in "0123456789abcdef" for c in id_lower):
            # ObjectID format: timestamp(4) + machine(3) + pid(2) + counter(3)
            # Increment counter (last 6 chars)
            try:
                counter = int(original_id[-6:], 16)
                test_ids.append(original_id[:-6] + f"{counter + 1:06x}")
                test_ids.append(original_id[:-6] + f"{counter - 1:06x}")
                test_ids.append(original_id[:-6] + "000001")  # First counter
            except (ValueError, IndexError):
                pass

            test_ids.extend([
                "000000000000000000000001",
                "000000000000000000000000",
            ])

        # 4. Base64-encoded ID (contains =, ends with = or ==, or base64 chars only)
        elif original_id.endswith("=") or (len(original_id) % 4 == 0 and
               all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in original_id)):
            try:
                # Decode, modify, re-encode
                decoded = base64.b64decode(original_id).decode('utf-8', errors='ignore')
                if decoded.isdigit():
                    # Numeric inside base64
                    num = int(decoded)
                    test_ids.append(base64.b64encode(str(num + 1).encode()).decode())
                    test_ids.append(base64.b64encode(str(num - 1).encode()).decode())
                    test_ids.append(base64.b64encode(b"1").decode())
                else:
                    # String inside base64
                    test_ids.append(base64.b64encode(b"1").decode())
                    test_ids.append(base64.b64encode(b"admin").decode())
                    test_ids.append(base64.b64encode(b"0").decode())
            except (ValueError, UnicodeDecodeError):
                pass

            # Common base64 test values
            test_ids.extend([
                base64.b64encode(b"1").decode(),
                base64.b64encode(b"admin").decode(),
            ])

        # 5. MD5 hash (32 hex chars)
        elif len(original_id) == 32 and all(c in "0123456789abcdef" for c in id_lower):
            # Try common values hashed
            test_ids.extend([
                hashlib.md5(b"1").hexdigest(),
                hashlib.md5(b"admin").hexdigest(),
                hashlib.md5(b"0").hexdigest(),
                hashlib.md5(b"test").hexdigest(),
            ])

        # 6. SHA256 hash (64 hex chars)
        elif len(original_id) == 64 and all(c in "0123456789abcdef" for c in id_lower):
            test_ids.extend([
                hashlib.sha256(b"1").hexdigest(),
                hashlib.sha256(b"admin").hexdigest(),
                hashlib.sha256(b"0").hexdigest(),
            ])

        # 7. Short alphanumeric (custom format)
        elif len(original_id) <= 16 and original_id.isalnum():
            # Increment last char
            if original_id[-1].isdigit():
                last_num = int(original_id[-1])
                test_ids.append(original_id[:-1] + str((last_num + 1) % 10))
            elif original_id[-1].isalpha():
                next_char = chr((ord(original_id[-1].lower()) - ord('a') + 1) % 26 + ord('a'))
                test_ids.append(original_id[:-1] + next_char)

            test_ids.extend(["admin", "1", "test", "user1", original_id + "1"])

        # 8. Fallback for unknown formats
        else:
            test_ids.extend(["admin", "1", "test", "0", original_id + "1"])

        # Deduplicate and limit
        seen = set()
        unique_ids = []
        for tid in test_ids:
            if tid and tid not in seen and tid != original_id:
                seen.add(tid)
                unique_ids.append(tid)

        return unique_ids[:8]  # Return up to 8 test IDs
    
    async def _test_vertical_access(
        self,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test vertical access control (low priv vs high priv)."""
        findings = []
        existing_endpoints = []

        # PRIORITY 1: Get ADMIN endpoints from EndpointMap (most reliable)
        endpoint_map = EndpointMap.get_instance()
        admin_endpoints = endpoint_map.get_by_category(EndpointCategory.ADMIN)

        if admin_endpoints:
            for ep in admin_endpoints:
                if ep.verified or ep.confidence >= 0.7:
                    existing_endpoints.append(urljoin(base_url, ep.path))
            logger.info(f"[AuthzEngine] Using {len(existing_endpoints)} admin endpoints from EndpointMap")
        else:
            # FALLBACK: Hardcoded admin paths + EndpointValidator
            admin_paths = [
                "/admin", "/admin/users", "/admin/settings", "/admin/dashboard",
                "/api/admin", "/api/admin/users", "/api/admin/config",
                "/management", "/manager", "/superuser",
                "/api/internal", "/internal",
                "/debug", "/api/debug",
                "/config", "/api/config", "/settings",
            ]

            validator = EndpointValidator.get_instance()
            existing_endpoints = await validator.filter_existing_endpoints(
                base_url, admin_paths, rate_limiter, max_concurrent=5
            )

        if not existing_endpoints:
            logger.debug("[AuthzEngine] No admin endpoints found, skipping vertical access tests")
            return findings

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for url in existing_endpoints:
                await rate_limiter.acquire()
                
                try:
                    response = await client.get(url)
                    
                    # Check if admin endpoint is accessible
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for admin-like content
                        admin_indicators = [
                            "admin", "dashboard", "management", "users",
                            "settings", "config", "system", "debug"
                        ]
                        
                        if any(ind in content for ind in admin_indicators):
                            path = urlparse(url).path
                            # GAP-3.1: Calculate confidence based on evidence
                            # Just seeing "admin" keyword is NOT proof of admin access
                            conf = self._calculate_evidence_confidence(response.text)
                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="Vertical Privilege Escalation - Admin Access",
                                severity=Severity.HIGH,  # Downgrade to HIGH unless proven CRITICAL
                                confidence_score=conf,
                                description=f"Administrative endpoint {path} is accessible without proper authorization. "
                                           f"Note: Verify admin functionality is actually accessible.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    "Endpoint returned 200",
                                    f"Admin keywords detected (confidence: {conf:.0f}%)",
                                ],
                                cvss_score=9.8,
                                cwe_id="CWE-862",
                                remediation="Implement role-based access control (RBAC). "
                                           "Require admin authentication for all admin endpoints.",
                            ).to_dict())
                    
                    elif response.status_code == 403:
                        # Try bypass techniques
                        bypass_findings = await self._test_authz_bypass(
                            client, url, base_url, rate_limiter
                        )
                        findings.extend(bypass_findings)
                        
                except Exception as e:
                    logger.debug(f"Vertical access test error: {e}")
        
        return findings
    
    async def _test_authz_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test authorization bypass techniques."""
        findings = []
        
        bypass_techniques = [
            # HTTP method override
            {"headers": {"X-HTTP-Method-Override": "GET"}},
            {"headers": {"X-Method-Override": "GET"}},
            # Path manipulation
            {"path_suffix": "/"},
            {"path_suffix": "/."},
            {"path_suffix": "/./"},
            {"path_suffix": "%2e"},
            {"path_suffix": "?"},
            {"path_suffix": "#"},
            # Header bypass
            {"headers": {"X-Original-URL": url}},
            {"headers": {"X-Rewrite-URL": url}},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
        ]
        
        for technique in bypass_techniques[:5]:
            await rate_limiter.acquire()
            
            try:
                test_url = url
                headers = technique.get("headers", {})
                
                if "path_suffix" in technique:
                    test_url = url + technique["path_suffix"]
                
                response = await client.get(test_url, headers=headers)
                
                if response.status_code == 200:
                    # GAP-3.1: Bypass IS strong evidence - but verify content
                    conf = self._calculate_evidence_confidence(
                        response.text,
                        is_bypass=True,
                    )
                    findings.append(Finding(
                        vuln_type=VulnType.BFLA,
                        name="Authorization Bypass",
                        severity=Severity.CRITICAL if conf >= 85 else "HIGH",
                        confidence_score=conf,
                        description=f"Authorization can be bypassed using: {technique}",
                        host=base_url,
                        endpoint=url,
                        evidence=[f"Bypass technique: {technique}", f"Confidence: {conf:.0f}%"],
                        cvss_score=9.8 if conf >= 85 else 7.5,
                        cwe_id="CWE-863",
                        remediation="Review authorization logic. Ensure consistent enforcement.",
                    ).to_dict())
                    break

            except (httpx.HTTPError, httpx.TimeoutException):
                pass

        return findings

    async def _test_privilege_escalation(
        self,
        base_url: str,
        urls: list[str],
        forms: list[dict],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test privilege escalation via parameter tampering."""
        findings = []
        existing_endpoints = []

        # PRIORITY 1: Get USER_DATA endpoints from EndpointMap
        endpoint_map = EndpointMap.get_instance()
        user_endpoints = endpoint_map.get_by_category(EndpointCategory.USER_DATA)

        if user_endpoints:
            for ep in user_endpoints:
                if ep.verified or ep.confidence >= 0.7:
                    existing_endpoints.append(urljoin(base_url, ep.path))
            logger.info(f"[AuthzEngine] Using {len(existing_endpoints)} user endpoints from EndpointMap")
        else:
            # FALLBACK: Hardcoded paths + EndpointValidator
            update_endpoints = [
                "/api/user", "/api/profile", "/api/account", "/api/me",
                "/user/update", "/profile/update", "/account/settings",
            ]

            validator = EndpointValidator.get_instance()
            existing_endpoints = await validator.filter_existing_endpoints(
                base_url, update_endpoints, rate_limiter, max_concurrent=5
            )

        if not existing_endpoints:
            logger.debug("[AuthzEngine] No update endpoints found, skipping privilege escalation tests")
            return findings

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for url in existing_endpoints:
                
                # Try to escalate privileges via parameter
                for param in self.PRIVESC_PARAMS[:10]:
                    escalation_payloads = [
                        {param: "admin"},
                        {param: True},
                        {param: 1},
                        {param: "administrator"},
                        {param: ["admin", "user"]},
                    ]
                    
                    for payload in escalation_payloads:
                        try:
                            response = await client.patch(url, json=payload)
                            
                            if response.status_code in [200, 201]:
                                # Check if privilege was changed
                                try:
                                    data = response.json()
                                    response_str = json.dumps(data).lower()
                                    
                                    if any(x in response_str for x in ["admin", "success", "updated"]):
                                        # GAP-3.1: Mass assignment is VERY strong evidence if it worked
                                        # But we need to verify the role actually changed
                                        has_role_change = "admin" in response_str or "role" in response_str
                                        conf = self._calculate_evidence_confidence(
                                            response_str,
                                            has_state_change=has_role_change,
                                        )
                                        findings.append(Finding(
                                            vuln_type=VulnType.BFLA,
                                            name="Privilege Escalation via Mass Assignment",
                                            severity=Severity.CRITICAL if has_role_change else "HIGH",
                                            confidence_score=conf,
                                            description=f"Role/privilege can be escalated by setting {param} parameter.",
                                            host=base_url,
                                            endpoint=url,
                                            evidence=[
                                                f"Parameter: {param}",
                                                f"Payload: {payload}",
                                                f"Role change evidence: {has_role_change}",
                                            ],
                                            cvss_score=9.8 if has_role_change else 7.5,
                                            cwe_id="CWE-915",
                                            remediation="Implement allowlist for updatable fields. "
                                                       "Never allow role/permission updates via user input.",
                                        ).to_dict())
                                        break
                                except json.JSONDecodeError:
                                    pass

                        except (httpx.HTTPError, httpx.TimeoutException):
                            pass

        return findings

    async def _test_tenant_isolation(
        self,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test multi-tenant isolation."""
        findings = []
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for url in urls[:30]:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                # Check for tenant parameters
                for i_param, param in enumerate(params):
                    if param.lower() in [p.lower() for p in self.TENANT_PARAMS]:
                        original_value = params[i_param][0]
                        
                        # Test with different tenant IDs
                        test_values = self._generate_test_ids(original_value)
                        
                        for test_value in test_values:
                            await rate_limiter.acquire()
                            
                            modified_params = dict(params)
                            modified_params[i_param] = [test_value]
                            query = urlencode(modified_params, doseq=True)
                            
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                            
                            try:
                                response = await client.get(test_url)

                                if response.status_code == 200:
                                    # GAP-3.1: Check if we got different tenant's data
                                    content_lower = response.text.lower()
                                    # Strong evidence: test_value appears in response (different tenant data)
                                    has_diff_tenant = test_value.lower() in content_lower

                                    conf = self._calculate_evidence_confidence(
                                        response.text,
                                        has_different_user_data=has_diff_tenant,
                                    )
                                    findings.append(Finding(
                                        vuln_type=VulnType.BFLA,
                                        name="Multi-Tenant Isolation Bypass",
                                        severity=Severity.CRITICAL if has_diff_tenant else "HIGH",
                                        confidence_score=conf,
                                        description=f"Tenant isolation can be bypassed by changing {param} parameter.",
                                        host=base_url,
                                        endpoint=test_url,
                                        evidence=[
                                            f"Original tenant: {original_value}",
                                            f"Test tenant: {test_value}",
                                            f"Different tenant data: {has_diff_tenant}",
                                        ],
                                        cvss_score=9.8 if has_diff_tenant else 7.5,
                                        cwe_id="CWE-639",
                                        remediation="Enforce tenant isolation at all data access layers. "
                                                   "Never trust client-provided tenant IDs.",
                                    ).to_dict())
                                    break

                            except (httpx.HTTPError, httpx.TimeoutException):
                                pass

        return findings

    async def _test_forced_browsing(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for forced browsing to restricted resources."""
        findings = []
        existing_endpoints = []

        # PRIORITY 1: Get relevant endpoints from EndpointMap
        endpoint_map = EndpointMap.get_instance()

        # Get API_REST and USER_DATA endpoints that might be restricted
        for category in [EndpointCategory.API_REST, EndpointCategory.USER_DATA, EndpointCategory.ADMIN]:
            for ep in endpoint_map.get_by_category(category):
                if ep.verified or ep.confidence >= 0.7:
                    url = urljoin(base_url, ep.path)
                    if url not in existing_endpoints:
                        existing_endpoints.append(url)

        if existing_endpoints:
            logger.info(f"[AuthzEngine] Using {len(existing_endpoints)} endpoints from EndpointMap for forced browsing")
        else:
            # FALLBACK: Hardcoded restricted paths + EndpointValidator
            restricted_paths = [
                # Documents
                "/documents/1", "/docs/confidential", "/files/private",
                "/reports/internal", "/exports/all",
                # API resources
                "/api/exports", "/api/reports", "/api/logs",
                "/api/audit", "/api/metrics", "/api/analytics",
                # Admin functions
                "/api/users/all", "/api/transactions/all",
                "/api/orders/all", "/api/customers",
            ]

            validator = EndpointValidator.get_instance()
            existing_endpoints = await validator.filter_existing_endpoints(
                base_url, restricted_paths, rate_limiter, max_concurrent=5
            )

        if not existing_endpoints:
            logger.debug("[AuthzEngine] No restricted paths found, skipping forced browsing tests")
            return findings

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for url in existing_endpoints:
                await rate_limiter.acquire()

                path = urlparse(url).path

                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        # Check if it contains sensitive data
                        content_indicators = [
                            "email", "password", "credit", "ssn", "address",
                            "phone", "salary", "revenue", "secret"
                        ]
                        
                        if any(ind in response.text.lower() for ind in content_indicators):
                            # GAP-3.1: Calculate based on actual evidence
                            conf = self._calculate_evidence_confidence(response.text)
                            matched_indicators = [
                                ind for ind in content_indicators
                                if ind in response.text.lower()
                            ]
                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="Forced Browsing - Sensitive Data Exposure",
                                severity=Severity.HIGH if conf >= 75 else "MEDIUM",
                                confidence_score=conf,
                                description=f"Restricted resource accessible via direct URL: {path}",
                                host=base_url,
                                endpoint=url,
                                evidence=[f"Keywords found: {matched_indicators[:3]}", f"Confidence: {conf:.0f}%"],
                                cvss_score=7.5 if conf >= 75 else 5.3,
                                cwe_id="CWE-425",
                                remediation="Implement proper access controls on all resources.",
                            ).to_dict())

                except (httpx.HTTPError, httpx.TimeoutException):
                    pass

        return findings

    async def _test_function_level_access(
        self,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test function-level access control."""
        findings = []

        # Identify and test destructive operations
        dangerous_methods = [
            ("DELETE", "/api/users/1"),
            ("DELETE", "/api/posts/1"),
            ("POST", "/api/admin/reset"),
            ("POST", "/api/users/1/ban"),
            ("PUT", "/api/config"),
            ("POST", "/api/export/all"),
        ]

        # ⚠️ SAFE MODE: Skip DELETE/PUT/POST tests in non-aggressive modes
        if not ALLOW_WRITES:
            logger.info("⚠️ SAFE MODE: Skipping destructive authorization tests (DELETE/PUT/POST)")
            logger.info("   Run with --safe-mode=aggressive to enable these tests")
            # Return early with informational finding
            findings.append(Finding(
                vuln_type=VulnType.BFLA,
                name="Function Level Authorization Test Skipped",
                severity=Severity.INFO,
                confidence_score=0,
                description="Destructive authorization tests (DELETE/PUT/POST) were skipped due to safe mode. "
                           "Run with --safe-mode=aggressive to test these endpoints.",
                host=base_url,
                endpoint=base_url,
                evidence=["Safe mode active", f"Skipped {len(dangerous_methods)} dangerous endpoint tests"],
                cvss_score=0.0,
                cwe_id="CWE-285",
                remediation="Run with --safe-mode=aggressive to test these endpoints.",
                references=[],
            ).to_dict())
            return findings

        # OPTIMIZATION: Filter to only existing endpoints (extract paths)
        paths_only = [path for _, path in dangerous_methods]
        validator = EndpointValidator.get_instance()
        existing_paths = await validator.filter_existing_endpoints(
            base_url, paths_only, rate_limiter, max_concurrent=5
        )

        # Rebuild list with only existing paths
        existing_paths_set = {urlparse(url).path for url in existing_paths}
        filtered_methods = [(m, p) for m, p in dangerous_methods if p in existing_paths_set]

        if not filtered_methods:
            logger.debug("[AuthzEngine] No dangerous endpoints found, skipping function level tests")
            return findings

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for method, path in filtered_methods:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)
                
                try:
                    if method == "DELETE":
                        response = await client.delete(url)
                    elif method == "PUT":
                        response = await client.put(url, json={})
                    else:
                        response = await client.post(url, json={})
                    
                    if response.status_code in [200, 201, 204]:
                        # GAP-3.1: Destructive action working is strong evidence
                        # But we should verify state actually changed

                        # ═══════════════════════════════════════════════════════════════
                        # STATE-04 FIX: Verify state change, don't assume from status
                        # 201/204 alone is NOT proof of state mutation
                        # ═══════════════════════════════════════════════════════════════
                        verified_state_change = False
                        state_evidence = []

                        if response.status_code == 204:
                            # 204 No Content - could be real deletion or just no-op
                            # Try to GET the resource to verify deletion
                            await rate_limiter.acquire()
                            try:
                                verify_resp = await client.get(url)
                                if verify_resp.status_code in (404, 410):
                                    verified_state_change = True
                                    state_evidence.append("Resource deleted (verified 404)")
                                elif verify_resp.status_code == 200:
                                    # Resource still exists - 204 was misleading
                                    logger.debug(f"[STATE-04] DELETE returned 204 but resource still exists: {url}")
                            except Exception:
                                pass

                        elif response.status_code == 201:
                            # 201 Created - check if response indicates new resource
                            resp_text = response.text.lower()
                            # Look for creation indicators
                            if any(ind in resp_text for ind in ('"id":', '"created"', '"_id":', 'location:')):
                                verified_state_change = True
                                state_evidence.append("Creation confirmed (response has ID/location)")
                            elif response.headers.get("Location"):
                                verified_state_change = True
                                state_evidence.append(f"Location header: {response.headers.get('Location')}")

                        elif response.status_code == 200:
                            # 200 OK - check for meaningful response content
                            resp_text = response.text.lower()
                            if any(ind in resp_text for ind in ('"success"', '"updated"', '"modified"')):
                                verified_state_change = True
                                state_evidence.append("Modification confirmed (success indicators)")

                        # Calculate confidence based on verification
                        conf = self._calculate_evidence_confidence(
                            response.text,
                            has_state_change=verified_state_change,
                        )

                        # Reduce severity if state change not verified
                        if verified_state_change:
                            severity = "CRITICAL" if response.status_code in [201, 204] else "HIGH"
                            cvss = 8.1 if response.status_code in [201, 204] else 6.5
                        else:
                            severity = "HIGH" if response.status_code in [201, 204] else "MEDIUM"
                            cvss = 6.5 if response.status_code in [201, 204] else 5.0
                            state_evidence.append("State change UNVERIFIED - response accepted but persistence not confirmed")

                        findings.append(Finding(
                            vuln_type=VulnType.BFLA,
                            name="Broken Function Level Authorization",
                            severity=severity,
                            confidence_score=conf,
                            description=f"Privileged function {method} {path} accessible without proper authorization.",
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"Method: {method}",
                                f"Status: {response.status_code}",
                                f"Confidence: {conf:.0f}%",
                                *state_evidence,
                            ],
                            cvss_score=cvss,
                            cwe_id="CWE-285",
                            remediation="Implement function-level access control. "
                                       "Verify user has permission for each operation.",
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
                            ],
                        ).to_dict())

                except (httpx.HTTPError, httpx.TimeoutException):
                    pass

        return findings

    async def _test_hidden_endpoints(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Test for hidden/undocumented endpoints that may expose admin functionality.

        Enhanced discovery includes:
        - Framework-specific admin/debug endpoints (Spring Actuator, Laravel, Django, etc.)
        - Internal API endpoints (/api/internal, /api/private)
        - Debug/trace/config endpoints
        - Auth bypass techniques per endpoint
        """
        findings = []
        discovered_hidden: list[tuple[str, str, int]] = []  # (path, content_preview, status)

        # First pass: probe all hidden paths to find existing ones
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for path in self.HIDDEN_ADMIN_PATHS:
                url = urljoin(base_url, path)
                await rate_limiter.acquire()

                try:
                    response = await client.get(url, headers=self._auth_headers)
                    status = response.status_code

                    # Skip obvious 404s
                    if status == 404:
                        continue

                    # If 200, this is an exposed hidden endpoint
                    if status == 200:
                        content = response.text[:500]
                        content_lower = content.lower()

                        # Verify it's not a SPA catch-all (returns same HTML for everything)
                        is_spa = self._is_spa_response(content_lower)
                        if is_spa:
                            continue

                        # Categorize by type of sensitive content
                        severity = "MEDIUM"
                        cvss = 5.3
                        vuln_name = "Hidden Endpoint Exposed"

                        # Spring Actuator - very sensitive
                        if "actuator" in path or any(x in content_lower for x in
                                                      ["jvm", "heapdump", "beans", "configprops"]):
                            severity = "CRITICAL"
                            cvss = 9.1
                            vuln_name = "Spring Actuator Endpoint Exposed"

                        # Debug endpoints - sensitive
                        elif any(x in path for x in ["/debug", "/trace", "/__debug__", "/env"]):
                            severity = "HIGH"
                            cvss = 7.5
                            vuln_name = "Debug Endpoint Exposed"

                        # Admin panel
                        elif any(x in content_lower for x in
                                 ["admin", "dashboard", "management", "control panel"]):
                            severity = "HIGH"
                            cvss = 7.5
                            vuln_name = "Admin Endpoint Accessible"

                        # Config/environment
                        elif any(x in content_lower for x in
                                 ["password", "secret", "api_key", "database", "connection_string"]):
                            severity = "CRITICAL"
                            cvss = 9.8
                            vuln_name = "Configuration/Secrets Exposed"

                        # API documentation
                        elif any(x in content_lower for x in ["swagger", "openapi", "api-docs"]):
                            severity = "LOW"
                            cvss = 3.7
                            vuln_name = "API Documentation Exposed"

                        discovered_hidden.append((path, content[:200], status))

                        # GAP-3.1: Calculate confidence based on content, not just path
                        conf = self._calculate_evidence_confidence(content)

                        # Use "info_disclosure" for hidden endpoints, not "authorization"
                        # This prevents false chain matches with IDOR/authz patterns
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name=vuln_name,
                            severity=severity if conf >= 80 else "MEDIUM",  # Downgrade if low confidence
                            confidence_score=conf,
                            description=(
                                f"Hidden/undocumented endpoint found at {path}. "
                                f"This endpoint may expose sensitive functionality or data "
                                f"that was not intended to be publicly accessible."
                            ),
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"Endpoint: {path}",
                                f"Status: {status}",
                                f"Confidence: {conf:.0f}%",
                            ],
                            cvss_score=cvss if conf >= 80 else 5.3,
                            cwe_id="CWE-200" if "config" in path.lower() else "CWE-862",
                            remediation=(
                                "1. Restrict access to admin/debug endpoints in production. "
                                "2. For Spring Boot: disable actuator endpoints or secure them. "
                                "3. For development tools: ensure they're disabled in production. "
                                "4. Implement proper authentication/authorization checks. "
                                "5. Review server configuration for exposed internal paths."
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                            ],
                            metadata={
                                "hidden_path": path,
                                "content_type": response.headers.get("content-type", ""),
                            },
                        ).to_dict())

                    # If 401/403, try auth bypass techniques
                    elif status in (401, 403):
                        bypass_finding = await self._try_hidden_endpoint_bypass(
                            client, url, path, base_url, rate_limiter
                        )
                        if bypass_finding:
                            findings.append(bypass_finding)

                except (httpx.HTTPError, httpx.TimeoutException) as e:
                    logger.debug(f"[AUTHZ] Hidden endpoint probe failed for {path}: {e}")

        if discovered_hidden:
            logger.info(f"[AUTHZ] Discovered {len(discovered_hidden)} hidden endpoints")

        # ═══════════════════════════════════════════════════════════════════
        # ANTI-SPAM: Consolidate similar hidden endpoint findings
        # Instead of 15 "Spring Actuator Endpoint Exposed", create 1 with all paths
        # ═══════════════════════════════════════════════════════════════════
        findings = self._consolidate_hidden_endpoint_findings(findings)

        return findings

    def _consolidate_hidden_endpoint_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Consolidate multiple similar hidden endpoint findings into single findings.

        Example: 15 "Spring Actuator Endpoint Exposed" → 1 with all 15 paths listed
        """
        MAX_FINDINGS_PER_TYPE = 1  # Consolidate all into one finding per type

        # Group by finding name
        by_name: dict[str, list[dict]] = {}
        other_findings: list[dict] = []

        for f in findings:
            name = f.get("name", "")
            # Only consolidate hidden endpoint types
            if any(x in name for x in ["Exposed", "Hidden Endpoint", "Debug Endpoint"]):
                if name not in by_name:
                    by_name[name] = []
                by_name[name].append(f)
            else:
                other_findings.append(f)

        consolidated = []
        for name, group in by_name.items():
            if len(group) <= MAX_FINDINGS_PER_TYPE:
                consolidated.extend(group)
            else:
                # Consolidate into single finding
                best = group[0]  # Take first (usually highest severity)
                all_paths = [
                    f.get("metadata", {}).get("hidden_path", "")
                    or f.get("matched_at", "").replace(f.get("host", ""), "")
                    for f in group
                ]
                all_paths = [p for p in all_paths if p]

                # Update description with all paths
                best["description"] = (
                    f"{best.get('description', '')}\n\n"
                    f"**Affected Endpoints ({len(group)} total):**\n"
                    + "\n".join(f"- {p}" for p in all_paths[:20])
                    + (f"\n... and {len(all_paths) - 20} more" if len(all_paths) > 20 else "")
                )

                # Update evidence
                best["evidence"] = [
                    f"Total exposed endpoints: {len(group)}",
                    f"Paths: {', '.join(all_paths[:10])}{'...' if len(all_paths) > 10 else ''}",
                ]

                # Update metadata
                best["metadata"] = best.get("metadata", {})
                best["metadata"]["consolidated_count"] = len(group)
                best["metadata"]["all_paths"] = all_paths

                consolidated.append(best)
                logger.debug(
                    f"[AUTHZ] Consolidated {len(group)} '{name}' findings into 1"
                )

        return consolidated + other_findings

    async def _try_hidden_endpoint_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        path: str,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> dict[str, Any] | None:
        """
        Try various bypass techniques on a 401/403 protected endpoint.

        Tests:
        - Header manipulation (X-Forwarded-For, X-Original-URL, etc.)
        - Path manipulation (trailing slash, encoding, etc.)
        - Method override headers
        """
        # Try header bypasses
        for bypass_headers in self.BYPASS_HEADERS[:10]:  # Limit to avoid noise
            await rate_limiter.acquire()

            try:
                response = await client.get(url, headers=bypass_headers)

                if response.status_code == 200:
                    content = response.text[:200]

                    # Verify it's not empty or error page
                    if len(content) > 50 and not self._is_spa_response(content.lower()):
                        # GAP-3.1: Bypass is strong evidence, but verify content
                        conf = self._calculate_evidence_confidence(content, is_bypass=True)
                        return Finding(
                            vuln_type=VulnType.BFLA,
                            name="Authorization Bypass on Hidden Endpoint",
                            severity=Severity.CRITICAL if conf >= 85 else "HIGH",
                            confidence_score=conf,
                            description=(
                                f"Protected hidden endpoint {path} can be accessed "
                                f"by bypassing authentication using header manipulation."
                            ),
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"Original response: 401/403",
                                f"Bypass headers: {bypass_headers}",
                                f"Bypassed response: 200 (confidence: {conf:.0f}%)",
                            ],
                            cvss_score=9.8,
                            cwe_id="CWE-863",
                            remediation=(
                                "Fix authorization logic to not rely on client-provided headers. "
                                "Validate X-Forwarded-* headers only from trusted proxies. "
                                "Implement authorization at the application layer, not proxy."
                            ),
                            metadata={
                                "bypass_technique": "header_manipulation",
                                "bypass_headers": bypass_headers,
                            },
                        ).to_dict()
            except (httpx.HTTPError, httpx.TimeoutException):
                pass

        # Try path manipulation bypasses
        for suffix in self.PATH_BYPASS_PATTERNS[:8]:  # Limit
            if suffix == "":
                continue

            await rate_limiter.acquire()
            test_url = url.rstrip("/") + suffix

            try:
                response = await client.get(test_url)

                if response.status_code == 200:
                    content = response.text[:200]

                    if len(content) > 50 and not self._is_spa_response(content.lower()):
                        # GAP-3.1: Path bypass is strong evidence
                        conf = self._calculate_evidence_confidence(content, is_bypass=True)
                        return Finding(
                            vuln_type=VulnType.BFLA,
                            name="Authorization Bypass via Path Manipulation",
                            severity=Severity.CRITICAL if conf >= 85 else "HIGH",
                            confidence_score=conf,
                            description=(
                                f"Protected endpoint {path} can be accessed "
                                f"by manipulating the path with '{suffix}'."
                            ),
                            host=base_url,
                            endpoint=test_url,
                            evidence=[
                                f"Original path: {path} -> 401/403",
                                f"Bypassed path: {path}{suffix} -> 200",
                                f"Confidence: {conf:.0f}%",
                            ],
                            cvss_score=9.1,
                            cwe_id="CWE-863",
                            remediation=(
                                "Normalize paths before authorization checks. "
                                "Use allowlist approach for URL matching. "
                                "Test authorization with various path encodings."
                            ),
                            metadata={
                                "bypass_technique": "path_manipulation",
                                "bypass_suffix": suffix,
                            },
                        ).to_dict()
            except (httpx.HTTPError, httpx.TimeoutException):
                pass

        return None

    def _is_spa_response(self, content_lower: str) -> bool:
        """Check if response looks like a SPA catch-all (same HTML for any path)."""
        # Strong SPA framework indicators
        spa_indicators = [
            # Angular (all versions)
            "ng-app", "ng-controller", "data-ng-", "angular", "ng-version",
            "<app-root", "ngsw", "zone.js",
            # React/Next.js
            "react", "_app", "__next", "data-reactroot", "data-reactid",
            "__react_devtools", "react-dom",
            # Vue/Nuxt
            "vue", "nuxt", "v-app", "data-v-", "__vue__", "vue-router",
            # Svelte/SvelteKit
            "svelte", "sveltekit", "data-svelte",
            # Other frameworks
            "ember", "glimmer", "backbone", "knockout",
            "qwik", "solid", "astro-island", "remix",
        ]

        # Known application signatures that indicate SPA catch-all
        known_apps = [
            "juice shop", "owasp", "bjoern kimminich",  # Juice Shop
            "webgoat", "dvwa", "hackazon",               # Other test apps
        ]

        # Check for known test apps (always false positive for hidden endpoints)
        if any(app in content_lower for app in known_apps):
            return True

        # SPA typically has HTML with JS app bootstrap
        if "<html" in content_lower and any(ind in content_lower for ind in spa_indicators):
            return True

        # SPA catch-all: returns same HTML shell with router handling
        # Check for typical SPA HTML structure (small HTML, loading main.js/bundle.js)
        if "<html" in content_lower and "<!doctype html>" in content_lower[:100]:
            # Check for typical SPA bundle patterns
            bundle_patterns = ["main.js", "bundle.js", "app.js", "vendor.js", "runtime"]
            if any(bp in content_lower for bp in bundle_patterns):
                # Also check that it's NOT returning actual API data
                if not any(x in content_lower for x in ['"status":', '"data":', '"error":', '"message":']):
                    return True

        return False
