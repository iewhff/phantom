"""
Advanced Authorization Testing Engine.
Tests for horizontal/vertical access control, RBAC/ABAC, and multi-tenant isolation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.endpoint_map import EndpointMap, EndpointCategory
from utils.endpoint_validator import EndpointValidator
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


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
    """
    
    name = "authorization_engine"
    
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
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
        self.discovered_roles: list[Role] = []
        self.endpoint_permissions: dict[str, list[str]] = {}
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Scan for authorization vulnerabilities."""
        findings: list[dict[str, Any]] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
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
        """Discover roles from application responses."""
        role_patterns = set()

        # Check common endpoints that reveal roles
        role_endpoints = [
            "/api/users",
            "/api/roles",
            "/api/permissions",
            "/admin/users",
            "/api/me",
            "/api/profile",
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
                except Exception:
                    continue
        
        # Create role objects
        for i, role in enumerate(["guest", "user", "moderator", "admin"]):
            if role in role_patterns or role in ["guest", "user"]:
                self.discovered_roles.append(Role(name=role, level=i))
    
    async def _test_horizontal_access(
        self,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test horizontal access control (user A vs user B)."""
        findings = []
        
        # Find user-specific endpoints
        user_endpoints = []
        user_id_pattern = re.compile(r'/(?:user|users|profile|account|member)s?/(\d+|[a-f0-9-]{36})')
        
        for url in urls:
            match = user_id_pattern.search(url)
            if match:
                user_endpoints.append((url, match.group(1)))
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint, original_id in user_endpoints[:10]:
                # Generate different user IDs to test
                test_ids = self._generate_test_ids(original_id)
                
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
                                
                                if test_id in response_str or any(
                                    x in response_str for x in ["email", "name", "address", "phone"]
                                ):
                                    findings.append(Finding(
                                        type="authorization",
                                        name="Horizontal Privilege Escalation (IDOR)",
                                        severity="HIGH",
                                        description=f"User data accessible by changing ID from {original_id} to {test_id}. "
                                                   f"No authorization check prevents accessing other users' data.",
                                        host=base_url,
                                        matched_at=test_url,
                                        evidence=[
                                            f"Original ID: {original_id}",
                                            f"Test ID: {test_id}",
                                            "Response contains user data",
                                        ],
                                        cvss_score=7.5,
                                        cwe="CWE-639",
                                        remediation="Implement authorization checks for all user-specific resources. "
                                                   "Verify the authenticated user has permission to access the requested resource.",
                                        references=[
                                            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                                        ],
                                    ).to_dict())
                                    break
                            except json.JSONDecodeError:
                                pass
                                
                    except Exception as e:
                        logger.debug(f"Horizontal access test error: {e}")
        
        return findings
    
    def _generate_test_ids(self, original_id: str) -> list[str]:
        """Generate test IDs based on original ID format."""
        test_ids = []
        
        # Numeric ID
        if original_id.isdigit():
            num = int(original_id)
            test_ids.extend([str(num + 1), str(num - 1), str(num + 100), "1", "0"])
        
        # UUID
        elif len(original_id) == 36 and "-" in original_id:
            # Modify last character
            test_ids.append(original_id[:-1] + ("0" if original_id[-1] != "0" else "1"))
            # Common test UUIDs
            test_ids.extend([
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000000",
            ])
        
        # Short hash
        else:
            test_ids.extend(["admin", "1", "test", original_id + "1"])
        
        return test_ids[:5]
    
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
                            findings.append(Finding(
                                type="authorization",
                                name="Vertical Privilege Escalation - Admin Access",
                                severity="CRITICAL",
                                description=f"Administrative endpoint {path} is accessible without proper authorization.",
                                host=base_url,
                                matched_at=url,
                                evidence=[
                                    "Endpoint returned 200",
                                    "Admin content detected",
                                ],
                                cvss_score=9.8,
                                cwe="CWE-862",
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
                    findings.append(Finding(
                        type="authorization",
                        name="Authorization Bypass",
                        severity="CRITICAL",
                        description=f"Authorization can be bypassed using: {technique}",
                        host=base_url,
                        matched_at=url,
                        evidence=[f"Bypass technique: {technique}"],
                        cvss_score=9.8,
                        cwe="CWE-863",
                        remediation="Review authorization logic. Ensure consistent enforcement.",
                    ).to_dict())
                    break
                    
            except Exception:
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
                                        findings.append(Finding(
                                            type="authorization",
                                            name="Privilege Escalation via Mass Assignment",
                                            severity="CRITICAL",
                                            description=f"Role/privilege can be escalated by setting {param} parameter.",
                                            host=base_url,
                                            matched_at=url,
                                            evidence=[
                                                f"Parameter: {param}",
                                                f"Payload: {payload}",
                                            ],
                                            cvss_score=9.8,
                                            cwe="CWE-915",
                                            remediation="Implement allowlist for updatable fields. "
                                                       "Never allow role/permission updates via user input.",
                                        ).to_dict())
                                        break
                                except json.JSONDecodeError:
                                    pass
                                    
                        except Exception:
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
                for param in params:
                    if param.lower() in [p.lower() for p in self.TENANT_PARAMS]:
                        original_value = params[param][0]
                        
                        # Test with different tenant IDs
                        test_values = self._generate_test_ids(original_value)
                        
                        for test_value in test_values:
                            await rate_limiter.acquire()
                            
                            modified_params = dict(params)
                            modified_params[param] = [test_value]
                            query = urlencode(modified_params, doseq=True)
                            
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                            
                            try:
                                response = await client.get(test_url)
                                
                                if response.status_code == 200:
                                    findings.append(Finding(
                                        type="authorization",
                                        name="Multi-Tenant Isolation Bypass",
                                        severity="CRITICAL",
                                        description=f"Tenant isolation can be bypassed by changing {param} parameter.",
                                        host=base_url,
                                        matched_at=test_url,
                                        evidence=[
                                            f"Original tenant: {original_value}",
                                            f"Test tenant: {test_value}",
                                        ],
                                        cvss_score=9.8,
                                        cwe="CWE-639",
                                        remediation="Enforce tenant isolation at all data access layers. "
                                                   "Never trust client-provided tenant IDs.",
                                    ).to_dict())
                                    break
                                    
                            except Exception:
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
                            findings.append(Finding(
                                type="authorization",
                                name="Forced Browsing - Sensitive Data Exposure",
                                severity="HIGH",
                                description=f"Restricted resource accessible via direct URL: {path}",
                                host=base_url,
                                matched_at=url,
                                evidence=["Resource contains sensitive data"],
                                cvss_score=7.5,
                                cwe="CWE-425",
                                remediation="Implement proper access controls on all resources.",
                            ).to_dict())
                            
                except Exception:
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
                        findings.append(Finding(
                            type="authorization",
                            name="Broken Function Level Authorization",
                            severity="HIGH",
                            description=f"Privileged function {method} {path} accessible without proper authorization.",
                            host=base_url,
                            matched_at=url,
                            evidence=[f"Method: {method}", f"Status: {response.status_code}"],
                            cvss_score=8.1,
                            cwe="CWE-285",
                            remediation="Implement function-level access control. "
                                       "Verify user has permission for each operation.",
                            references=[
                                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
                            ],
                        ).to_dict())
                        
                except Exception:
                    pass
        
        return findings
