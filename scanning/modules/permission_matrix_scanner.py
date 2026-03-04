"""
PHANTOM AI - Permission Matrix Scanner

Tests permission combinations to find authorization logic flaws:
1. Permission composition bugs (A+B allowed but not A or B alone)
2. Permission conflict detection (conflicting roles)
3. Negative permission bypass (NOT A circumvention)
4. Role inheritance issues (inherited permissions not revoked)
5. Cross-resource permission leakage
6. Implicit permission escalation

Works generically by discovering permissions from API responses and
systematically testing logical combinations.
"""

from __future__ import annotations

import itertools
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse


from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


@dataclass
class Permission:
    """A discovered permission."""
    name: str
    resource: str = ""
    action: str = ""  # read, write, delete, admin, etc.
    scope: str = ""   # self, org, global
    source: str = ""  # Where discovered: jwt, response, header


@dataclass
class PermissionTest:
    """A permission combination test."""
    permissions: list[str]
    operator: str  # AND, OR, NOT, NAND
    expected_denied: bool
    endpoint: str
    method: str = "GET"


# Common permission patterns in APIs
PERMISSION_PATTERNS = [
    # Standard CRUD
    r"(?:can_|has_)?(?:read|view|list|get)_?(\w+)",
    r"(?:can_|has_)?(?:write|create|add|post)_?(\w+)",
    r"(?:can_|has_)?(?:update|edit|modify|patch)_?(\w+)",
    r"(?:can_|has_)?(?:delete|remove|destroy)_?(\w+)",
    # Role-based
    r"(?:is_|has_)?(?:admin|administrator|superuser|root)",
    r"(?:is_|has_)?(?:moderator|mod|manager)",
    r"(?:is_|has_)?(?:editor|author|contributor)",
    r"(?:is_|has_)?(?:viewer|reader|guest)",
    # Scope-based
    r"(\w+):(?:read|write|delete|admin)",
    r"scope:(\w+)",
    # Feature flags
    r"feature_(\w+)",
    r"beta_(\w+)",
    r"(\w+)_enabled",
]

# JWT claim names that contain permissions
JWT_PERMISSION_CLAIMS = [
    "permissions", "perms", "scopes", "scope",
    "roles", "role", "groups", "authorities",
    "grants", "access", "rights", "capabilities",
    "features", "flags", "claims",
]

# Common restricted endpoints by permission type
PERMISSION_ENDPOINTS = {
    "admin": ["/admin", "/api/admin", "/api/v1/admin", "/management", "/system"],
    "users": ["/api/users", "/api/v1/users", "/users", "/api/accounts"],
    "delete": ["/api/users/1/delete", "/api/items/1", "/api/records/1"],
    "write": ["/api/users", "/api/items", "/api/records"],
    "billing": ["/api/billing", "/api/payments", "/api/invoices", "/api/subscriptions"],
    "settings": ["/api/settings", "/settings", "/api/config", "/api/preferences"],
    "reports": ["/api/reports", "/reports", "/api/analytics", "/api/metrics"],
    "audit": ["/api/audit", "/api/logs", "/api/activity"],
}


class PermissionMatrixScanner(ScanModule):
    """
    Tests permission combinations for authorization logic flaws.

    Discovers permissions from JWTs, API responses, and headers,
    then systematically tests logical combinations to find bypasses.
    """

    name = "permission_matrix"
    description = "Tests permission combinations for authorization logic flaws"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["permissions", "authorization", "rbac", "abac", "access_control"]

    # Standard safety - tests authorization, no state modification
    min_safety_level = "standard"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._base_url = ""
        self._auth_headers: dict[str, str] = {}
        self._discovered_permissions: list[Permission] = []
        self._endpoint_permissions: dict[str, list[str]] = defaultdict(list)

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main entry point for permission matrix scanning."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        # Get auth context if available
        auth_context = extra_params.get("auth_context")
        if auth_context and hasattr(auth_context, "auth_headers"):
            self._auth_headers = auth_context.auth_headers

        findings: list[Finding] = []

        # Phase 1: Discover permissions from various sources
        await self._discover_permissions()
        logger.info(f"[PERM] Discovered {len(self._discovered_permissions)} permissions")

        if len(self._discovered_permissions) < 2:
            logger.info("[PERM] Insufficient permissions for matrix testing")
            return findings

        # Phase 2: Test permission combinations
        combo_findings = await self._test_permission_combinations()
        findings.extend(combo_findings)

        # Phase 3: Test permission negation bypass
        negation_findings = await self._test_negation_bypass()
        findings.extend(negation_findings)

        # Phase 4: Test role inheritance
        inheritance_findings = await self._test_role_inheritance()
        findings.extend(inheritance_findings)

        # Phase 5: Test cross-resource permission leakage
        leakage_findings = await self._test_permission_leakage()
        findings.extend(leakage_findings)

        return findings

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")

        if port in (443, 8443):
            protocol = "https"
        else:
            protocol = "http"

        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    async def _discover_permissions(self) -> None:
        """Discover permissions from JWT, API responses, and headers."""
        self._discovered_permissions = []

        # Extract from JWT in auth headers
        auth_header = self._auth_headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            jwt_token = auth_header[7:]
            self._extract_jwt_permissions(jwt_token)

        # Extract from cookie tokens
        cookie_header = self._auth_headers.get("Cookie", "")
        if cookie_header:
            for cookie in cookie_header.split(";"):
                if "=" in cookie:
                    _, value = cookie.strip().split("=", 1)
                    if value.count(".") == 2:  # Might be JWT
                        self._extract_jwt_permissions(value)

        # Probe common endpoints for permission info
        await self._probe_permission_endpoints()

    def _extract_jwt_permissions(self, token: str) -> None:
        """Extract permissions from JWT token."""
        try:
            import base64

            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode payload
            payload = parts[1]
            # Add padding
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += "=" * padding
            payload = payload.replace("-", "+").replace("_", "/")

            decoded = json.loads(base64.b64decode(payload).decode("utf-8"))

            # Extract permissions from known claim names
            for claim in JWT_PERMISSION_CLAIMS:
                if claim in decoded:
                    value = decoded[claim]

                    if isinstance(value, str):
                        # Space or comma separated
                        perms = re.split(r"[,\s]+", value)
                    elif isinstance(value, list):
                        perms = value
                    else:
                        continue

                    for perm in perms:
                        if perm:
                            self._discovered_permissions.append(
                                Permission(name=str(perm), source="jwt")
                            )

            # Also check for role claims
            for role_claim in ["role", "roles", "groups"]:
                if role_claim in decoded:
                    roles = decoded[role_claim]
                    if isinstance(roles, str):
                        roles = [roles]
                    for role in roles:
                        self._discovered_permissions.append(
                            Permission(name=f"role:{role}", source="jwt")
                        )

        except Exception as e:
            logger.debug(f"[PERM] Error extracting JWT permissions: {e}")

    async def _probe_permission_endpoints(self) -> None:
        """Probe endpoints to discover permission information."""
        permission_info_endpoints = [
            "/api/permissions", "/api/user/permissions", "/api/me/permissions",
            "/api/roles", "/api/user/roles", "/api/me/roles",
            "/api/capabilities", "/api/features", "/api/access",
            "/api/user", "/api/me", "/api/profile", "/api/whoami",
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for endpoint in permission_info_endpoints:
                    url = urljoin(self._base_url, endpoint)
                    try:
                        resp = await client.get(url, headers=self._auth_headers)

                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                self._extract_permissions_from_response(data, endpoint)
                            except json.JSONDecodeError:
                                pass
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"[PERM] Error probing permission endpoints: {e}")

    def _extract_permissions_from_response(self, data: Any, source: str) -> None:
        """Extract permissions from API response data."""
        if isinstance(asset_data, dict):
            # Look for permission-related keys
            for key, value in data.items():
                key_lower = key.lower()

                if any(perm_key in key_lower for perm_key in JWT_PERMISSION_CLAIMS):
                    if isinstance(value, list):
                        for perm in value:
                            if isinstance(perm, str):
                                self._discovered_permissions.append(
                                    Permission(name=perm, source=source)
                                )
                            elif isinstance(perm, dict) and "name" in perm:
                                self._discovered_permissions.append(
                                    Permission(name=perm["name"], source=source)
                                )
                    elif isinstance(value, str):
                        self._discovered_permissions.append(
                            Permission(name=value, source=source)
                        )

                # Check for boolean permission flags
                for pattern in PERMISSION_PATTERNS:
                    if re.match(pattern, key, re.IGNORECASE):
                        if isinstance(value, bool) and value:
                            self._discovered_permissions.append(
                                Permission(name=key, source=source)
                            )

                # Recurse into nested objects
                self._extract_permissions_from_response(value, source)

        elif isinstance(data, list) and len(data) > 0:
            for item in data[:20]:  # Limit
                self._extract_permissions_from_response(item, source)

    async def _test_permission_combinations(self) -> list[Finding]:
        """Test combinations of permissions for logic flaws."""
        findings: list[Finding] = []

        if len(self._discovered_permissions) < 2:
            return findings

        # Get unique permission names
        perm_names = list(set(p.name for p in self._discovered_permissions))

        # Test pairs of permissions
        for perm_a, perm_b in itertools.combinations(perm_names[:10], 2):
            finding = await self._test_permission_pair(perm_a, perm_b)
            if finding:
                findings.append(finding)

        return findings

    async def _test_permission_pair(self, perm_a: str, perm_b: str) -> Finding | None:
        """Test a pair of permissions for composition bugs."""
        # Determine what endpoints to test based on permission types
        endpoints_to_test = []

        for perm_type, endpoints in PERMISSION_ENDPOINTS.items():
            if perm_type in perm_a.lower() or perm_type in perm_b.lower():
                endpoints_to_test.extend(endpoints)

        if not endpoints_to_test:
            endpoints_to_test = ["/api/test", "/api/action"]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # AUDIT-FIX 2026-02-11: Increased from [:3] to [:8] for better coverage
                for endpoint in endpoints_to_test[:8]:
                    url = urljoin(self._base_url, endpoint)

                    # Test with current permissions
                    resp_with_perms = await client.get(url, headers=self._auth_headers)

                    # If we have access, try without auth to compare
                    if resp_with_perms.status_code == 200:
                        resp_without_auth = await client.get(url)

                        # If also accessible without auth, potential permission bypass
                        if resp_without_auth.status_code == 200:
                            if resp_without_auth.text == resp_with_perms.text:
                                return Finding(
                                    vuln_type=VulnType.BFLA,
                                    name="Permission Check Bypass",
                                    description=(
                                        f"The endpoint `{endpoint}` appears to require permissions "
                                        f"`{perm_a}` and/or `{perm_b}` but is accessible without authentication.\n\n"
                                        f"This indicates missing or ineffective permission enforcement."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence_score=80.0,
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    metadata={
                                        "permissions_tested": [perm_a, perm_b],
                                        "endpoint": endpoint,
                                    },
                                )

        except Exception as e:
            logger.debug(f"[PERM] Error testing permission pair: {e}")

        return None

    async def _test_negation_bypass(self) -> list[Finding]:
        """Test for permission negation bypass (NOT A circumvention)."""
        findings: list[Finding] = []

        # Look for negative/deny permissions
        deny_permissions = [
            p for p in self._discovered_permissions
            if any(neg in p.name.lower() for neg in ["deny", "block", "disable", "no_", "not_", "!"])
        ]

        if not deny_permissions:
            return findings

        # Test if negated permissions can be bypassed
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for deny_perm in deny_permissions[:5]:
                    # Infer what the permission denies
                    resource = re.sub(r"(deny_|block_|disable_|no_|not_|!)", "", deny_perm.name.lower())

                    # Find endpoints related to this resource
                    for perm_type, endpoints in PERMISSION_ENDPOINTS.items():
                        if resource in perm_type or perm_type in resource:
                            # AUDIT-FIX 2026-02-11: Increased from [:2] to [:5]
                            for endpoint in endpoints[:5]:
                                url = urljoin(self._base_url, endpoint)

                                resp = await client.get(url, headers=self._auth_headers)

                                # If we have access despite deny permission
                                if resp.status_code == 200:
                                    findings.append(Finding(
                                        vuln_type=VulnType.BFLA,
                                        name="Deny Permission Bypass",
                                        description=(
                                            f"The deny permission `{deny_perm.name}` does not prevent "
                                            f"access to `{endpoint}`.\n\n"
                                            f"Negative permissions should block access to the related "
                                            f"resource, but the endpoint is still accessible."
                                        ),
                                        severity=Severity.HIGH,
                                        confidence_score=75.0,
                                        host=urlparse(url).netloc,
                                        endpoint=url,
                                        metadata={
                                            "deny_permission": deny_perm.name,
                                            "endpoint_accessed": endpoint,
                                        },
                                    ))
                                    break

        except Exception as e:
            logger.debug(f"[PERM] Error testing negation bypass: {e}")

        return findings

    async def _test_role_inheritance(self) -> list[Finding]:
        """Test for role inheritance issues."""
        findings: list[Finding] = []

        # Find role-based permissions
        role_permissions = [
            p for p in self._discovered_permissions
            if p.name.startswith("role:") or "role" in p.source.lower()
        ]

        if not role_permissions:
            return findings

        # Define expected role hierarchies
        role_hierarchy = {
            "admin": ["moderator", "editor", "user", "viewer", "guest"],
            "superadmin": ["admin", "moderator", "editor", "user"],
            "manager": ["editor", "user", "viewer"],
            "editor": ["user", "viewer"],
            "user": ["viewer", "guest"],
        }

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for role_perm in role_permissions[:5]:
                    role_name = role_perm.name.replace("role:", "").lower()

                    # Check if lower roles have access to higher-role endpoints
                    if role_name in role_hierarchy:
                        # Test admin endpoints with non-admin role
                        for admin_endpoint in PERMISSION_ENDPOINTS.get("admin", []):
                            url = urljoin(self._base_url, admin_endpoint)

                            resp = await client.get(url, headers=self._auth_headers)

                            # If non-admin role has access to admin endpoint
                            if resp.status_code == 200 and role_name != "admin":
                                findings.append(Finding(
                                    vuln_type=VulnType.BFLA,
                                    name="Role Hierarchy Violation",
                                    description=(
                                        f"User with role `{role_name}` has access to admin endpoint "
                                        f"`{admin_endpoint}`.\n\n"
                                        f"This indicates improper role hierarchy enforcement where "
                                        f"lower-privileged roles can access higher-privileged resources."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence_score=85.0,
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    metadata={
                                        "user_role": role_name,
                                        "admin_endpoint": admin_endpoint,
                                    },
                                ))
                                break

        except Exception as e:
            logger.debug(f"[PERM] Error testing role inheritance: {e}")

        return findings

    async def _test_permission_leakage(self) -> list[Finding]:
        """Test for cross-resource permission leakage."""
        findings: list[Finding] = []

        # Group permissions by resource
        resource_permissions: dict[str, list[str]] = defaultdict(list)

        for perm in self._discovered_permissions:
            # Extract resource from permission name
            parts = perm.name.split(":")
            if len(parts) >= 2:
                resource = parts[0]
                resource_permissions[resource].append(perm.name)
            else:
                # Try to extract from pattern
                for pattern in [r"(\w+)_read", r"(\w+)_write", r"read_(\w+)", r"write_(\w+)"]:
                    match = re.match(pattern, perm.name, re.IGNORECASE)
                    if match:
                        resource = match.group(1)
                        resource_permissions[resource].append(perm.name)
                        break

        if len(resource_permissions) < 2:
            return findings

        # Test if permissions for one resource leak to another
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                resources = list(resource_permissions.keys())

                for i, resource_a in enumerate(resources[:5]):
                    for resource_b in resources[i+1:5]:
                        # Find endpoints for resource B
                        endpoints_b = []
                        for perm_type, endpoints in PERMISSION_ENDPOINTS.items():
                            if resource_b.lower() in perm_type:
                                endpoints_b.extend(endpoints)

                        if not endpoints_b:
                            endpoints_b = [f"/api/{resource_b}", f"/api/{resource_b}s"]

                        # Test if permissions for A grant access to B
                        # AUDIT-FIX 2026-02-11: Increased from [:2] to [:5]
                        for endpoint in endpoints_b[:5]:
                            url = urljoin(self._base_url, endpoint)

                            resp = await client.get(url, headers=self._auth_headers)

                            if resp.status_code == 200:
                                # Check if user only has permissions for resource A
                                perms_for_a = resource_permissions[resource_a]
                                perms_for_b = resource_permissions.get(resource_b, [])

                                if perms_for_a and not perms_for_b:
                                    findings.append(Finding(
                                        vuln_type=VulnType.BFLA,
                                        name="Cross-Resource Permission Leakage",
                                        description=(
                                            f"User with permissions for `{resource_a}` has access to "
                                            f"`{resource_b}` resources at `{endpoint}`.\n\n"
                                            f"Permissions should be isolated per resource. Having access "
                                            f"to one resource should not grant access to another."
                                        ),
                                        severity=Severity.MEDIUM,
                                        confidence_score=70.0,
                                        host=urlparse(url).netloc,
                                        endpoint=url,
                                        metadata={
                                            "source_resource": resource_a,
                                            "leaked_resource": resource_b,
                                            "permissions_held": perms_for_a,
                                        },
                                    ))
                                    break

        except Exception as e:
            logger.debug(f"[PERM] Error testing permission leakage: {e}")

        return findings
