"""
Privilege Escalation Scanner

Enterprise-grade privilege escalation testing including:
- Horizontal IDOR (accessing other users' resources)
- Vertical escalation (accessing admin functions)
- Role manipulation attacks
- Forced browsing to admin paths
- HTTP method tampering
- Parameter pollution
- Mass assignment vulnerabilities
- Path traversal for authorization bypass
- Function-level access control

CWE Coverage:
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
- CWE-269: Improper Privilege Management
- CWE-285: Improper Authorization
- CWE-862: Missing Authorization
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

from .auth_base import (
    ADMIN_PATHS_FORCED_BROWSING,
    HTTP_METHOD_TAMPERING,
    MASS_ASSIGNMENT_PAYLOADS,
    PARAM_POLLUTION_PAYLOADS,
    PATH_TRAVERSAL_AUTHZ_PAYLOADS,
    PRIVILEGED_FUNCTIONS,
    ROLE_MANIPULATION_PAYLOADS,
)

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class PrivilegeEscalationScanner:
    """
    Privilege Escalation Scanner

    Comprehensive testing for horizontal and vertical privilege escalation,
    IDOR vulnerabilities, and authorization bypass techniques.
    """

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0

    async def scan(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive privilege escalation vulnerability scan.

        Tests for:
        - Horizontal IDOR
        - Vertical escalation
        - Role manipulation
        - Forced browsing
        - HTTP method tampering
        - Parameter pollution
        - Mass assignment
        - Path traversal authz bypass
        - Function-level access control
        """
        findings = []

        try:
            # Phase 1: Horizontal IDOR Testing
            idor_findings = await self._test_horizontal_idor(
                base_url, asset_data, rate_limiter
            )
            findings.extend(idor_findings)

            # Phase 2: Vertical Escalation Testing
            vertical_findings = await self._test_vertical_escalation(
                base_url, rate_limiter
            )
            findings.extend(vertical_findings)

            # Phase 3: Role Manipulation
            role_findings = await self._test_role_manipulation(
                base_url, asset_data, rate_limiter
            )
            findings.extend(role_findings)

            # Phase 4: Forced Browsing
            browsing_findings = await self._test_forced_browsing(
                base_url, rate_limiter
            )
            findings.extend(browsing_findings)

            # Phase 5: HTTP Method Tampering
            method_findings = await self._test_http_method_tampering(
                base_url, asset_data, rate_limiter
            )
            findings.extend(method_findings)

            # Phase 6: Parameter Pollution
            pollution_findings = await self._test_parameter_pollution(
                base_url, asset_data, rate_limiter
            )
            findings.extend(pollution_findings)

            # Phase 7: Mass Assignment
            mass_findings = await self._test_mass_assignment(
                base_url, asset_data, rate_limiter
            )
            findings.extend(mass_findings)

            # Phase 8: Path Traversal Authorization Bypass
            path_findings = await self._test_path_traversal_authz(
                base_url, rate_limiter
            )
            findings.extend(path_findings)

            # Phase 9: Function-Level Access Control
            function_findings = await self._test_function_level_access(
                base_url, rate_limiter
            )
            findings.extend(function_findings)

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.error(f"Privilege escalation testing error: {e}")

        return findings

    async def _test_horizontal_idor(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for horizontal IDOR vulnerabilities."""
        findings = []
        endpoints = asset_data.get("endpoints", []) if isinstance(asset_data, dict) else []

        # ID parameter patterns
        id_patterns = [
            r'[?&/](id|user_id|userId|uid|account|profile|account_id|accountId)=([^&]+)',
            r'[?&/](order_id|orderId|order|invoice|invoice_id)=([^&]+)',
            r'[?&/](doc_id|docId|document|file_id|fileId)=([^&]+)',
            r'[?&/](msg_id|message|chat_id|conversation)=([^&]+)',
            r'[?&/](project_id|projectId|workspace|org_id)=([^&]+)',
            r'/users/(\d+)', r'/user/(\d+)',
            r'/accounts/(\d+)', r'/account/(\d+)',
            r'/orders/(\d+)', r'/order/(\d+)',
            r'/profiles/(\d+)', r'/profile/(\d+)',
            r'[?&/]([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        ]

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in endpoints[:15]:
                for pattern in id_patterns:
                    matches = re.findall(pattern, endpoint, re.IGNORECASE)

                    if not matches:
                        continue

                    for match in matches:
                        if isinstance(match, tuple):
                            param_name = match[0]
                            original_id = match[1] if len(match) > 1 else match[0]
                        else:
                            param_name, original_id = "id", match

                        # Generate test IDs
                        test_ids = self._generate_idor_test_ids(original_id)

                        # Get baseline response
                        await rate_limiter.acquire()
                        try:
                            original_resp = await client.get(endpoint)
                            original_hash = hashlib.md5(original_resp.text.encode()).hexdigest()
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                        # FN-FIX 2026-02-08: Test ALL IDs (was [:5])
                        for test_id in test_ids[:10]:
                            await rate_limiter.acquire()

                            # Build test URL
                            test_endpoint = self._build_idor_test_url(
                                endpoint, param_name, original_id, test_id
                            )

                            try:
                                test_resp = await client.get(test_endpoint)
                                test_hash = hashlib.md5(test_resp.text.encode()).hexdigest()

                                # Analyze response for IDOR
                                idor_result = self._analyze_idor_response(
                                    original_resp, test_resp,
                                    original_hash, test_hash,
                                    param_name, original_id, test_id
                                )

                                if idor_result["vulnerable"]:
                                    findings.append(Finding(
                                        vuln_type=VulnType.BFLA,
                                        name="Horizontal IDOR Vulnerability",
                                        severity=idor_result["severity"],
                                        description=f"Horizontal privilege escalation via parameter '{param_name}'. "
                                                   f"Able to access other users' resources by modifying identifier. "
                                                   f"{idor_result['reason']}",
                                        host=base_url,
                                        endpoint=test_endpoint,
                                        evidence=[
                                            f"Vulnerable parameter: {param_name}",
                                            f"Original ID: {original_id}",
                                            f"Test ID: {test_id}",
                                            f"Response diff: {idor_result['diff_type']}",
                                            f"Confidence: {idor_result['confidence']:.0%}",
                                            *idor_result.get("extra_evidence", []),
                                        ],
                                        cvss_score=7.5,
                                        cwe_id="CWE-639",
                                        remediation="Implement proper authorization checks. "
                                                   "Verify that the authenticated user owns or has "
                                                   "permission to access the requested resource.",
                                    ).to_dict())
                                    # FN-FIX 2026-02-08: Don't break - test ALL IDs to find enumeration scope

                            except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                                logger.debug(f"IDOR test failed for {test_endpoint}: {e}")

        return findings

    def _generate_idor_test_ids(self, original_id: str) -> list[str]:
        """Generate IDOR test IDs based on original ID type."""
        test_ids = []

        if original_id.isdigit():
            orig_int = int(original_id)
            test_ids = [
                str(orig_int - 1),
                str(orig_int + 1),
                str(orig_int - 10),
                str(orig_int + 10),
                "0", "1", "-1",
                str(orig_int * 2),
                "999999", "9999999",
            ]
        elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', original_id, re.I):
            # UUID
            test_ids = [
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
                "11111111-1111-1111-1111-111111111111",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                original_id[:-1] + ('0' if original_id[-1] != '0' else '1'),
            ]
        else:
            # String/other ID
            test_ids = [
                "admin", "root", "administrator", "system",
                "1", "0", "-1",
                "test", "guest", "user",
                original_id + "1",
                original_id[:-1] if len(original_id) > 1 else "x",
            ]

        return test_ids

    def _build_idor_test_url(
        self, endpoint: str, param_name: str, original_id: str, test_id: str
    ) -> str:
        """Build IDOR test URL with proper ID replacement."""
        # Try query parameter replacement
        test_endpoint = re.sub(
            rf'([?&]{re.escape(param_name)}=)[^&]+',
            rf'\g<1>{test_id}',
            endpoint,
            flags=re.IGNORECASE
        )

        # If no change, try path segment replacement
        if test_endpoint == endpoint:
            test_endpoint = endpoint.replace(f'/{original_id}', f'/{test_id}')

        # If still no change, try direct replacement
        if test_endpoint == endpoint:
            test_endpoint = endpoint.replace(original_id, test_id)

        return test_endpoint

    def _analyze_idor_response(
        self,
        original_resp: httpx.Response,
        test_resp: httpx.Response,
        original_hash: str,
        test_hash: str,
        param_name: str,
        original_id: str,
        test_id: str,
    ) -> dict[str, Any]:
        """Analyze response to detect IDOR vulnerability."""
        result: dict[str, Any] = {
            "vulnerable": False,
            "severity": "HIGH",
            "confidence": 0.0,
            "reason": "",
            "diff_type": "",
            "extra_evidence": [],
        }

        # Check for successful access (200 OK)
        if test_resp.status_code != 200:
            return result

        # Check for different content (potential IDOR)
        if original_hash != test_hash and len(test_resp.text) > 100:
            result["diff_type"] = "content_different"

            # Look for user-specific data patterns
            user_patterns = [
                r'"(user|username|name)":\s*"([^"]+)"',
                r'"email":\s*"([^"]+)"',
                r'"id":\s*(\d+)',
            ]

            original_user_data = []
            test_user_data = []

            for pattern in user_patterns:
                orig_matches = re.findall(pattern, original_resp.text.lower(), re.I)
                test_matches = re.findall(pattern, test_resp.text.lower(), re.I)
                original_user_data.extend(orig_matches)
                test_user_data.extend(test_matches)

            if test_user_data and test_user_data != original_user_data:
                result["vulnerable"] = True
                result["confidence"] = 0.9
                result["reason"] = "Different user data returned for modified identifier"
                result["extra_evidence"].append(
                    f"User data difference detected: {len(test_user_data)} user indicators"
                )
                return result

            # Check for significant content length difference
            len_diff = abs(len(test_resp.text) - len(original_resp.text))
            if len_diff > 50:
                result["vulnerable"] = True
                result["confidence"] = 0.7
                result["reason"] = "Significant content difference for modified identifier"
                result["extra_evidence"].append(f"Content length diff: {len_diff} bytes")
                return result

        # Check for ID reflection in response
        if (test_resp.status_code == 200 and
            original_resp.status_code == 200 and
            len(test_resp.text) > 500):
            if test_id in test_resp.text or str(test_id) in test_resp.text:
                result["vulnerable"] = True
                result["confidence"] = 0.6
                result["severity"] = "MEDIUM"
                result["reason"] = "Test ID reflected in response"
                result["diff_type"] = "id_reflected"
                return result

        return result

    async def _test_vertical_escalation(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for vertical privilege escalation."""
        findings = []

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for func in PRIVILEGED_FUNCTIONS:
                for method in func["methods"][:2]:
                    await rate_limiter.acquire()

                    url = urljoin(base_url, func["path"])

                    try:
                        if method == "GET":
                            resp = await client.get(url)
                        elif method == "POST":
                            resp = await client.post(url, json={})
                        elif method == "PUT":
                            resp = await client.put(url, json={})
                        elif method == "DELETE":
                            resp = await client.delete(url)
                        else:
                            continue

                        # Analyze response for privilege escalation
                        if resp.status_code == 200:
                            if self._is_privileged_content(resp.text, func["path"]):
                                findings.append(Finding(
                                    vuln_type=VulnType.BFLA,
                                    name="Vertical Privilege Escalation",
                                    severity=Severity.CRITICAL,
                                    description=f"Admin/privileged function accessible without proper authorization. "
                                               f"Endpoint '{func['path']}' should require elevated privileges.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"Privileged path: {func['path']}",
                                        f"HTTP method: {method}",
                                        f"Status code: {resp.status_code}",
                                        f"Response length: {len(resp.text)} bytes",
                                    ],
                                    cvss_score=9.1,
                                    cwe_id="CWE-269",
                                    remediation="Implement role-based access control (RBAC). "
                                               "Verify user has required permissions before allowing "
                                               "access to privileged functions.",
                                ).to_dict())
                                break

                        # Check for interesting 403 bypasses
                        elif resp.status_code == 403:
                            bypass_result = await self._try_403_bypass(
                                client, url, method, rate_limiter
                            )
                            if bypass_result:
                                findings.append(bypass_result)

                    except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                        logger.debug(f"Vertical escalation test failed for {url}: {e}")

        return findings

    def _is_privileged_content(self, content: str, path: str) -> bool:
        """Check if response content appears to be privileged data."""
        content_lower = content.lower()

        admin_indicators = [
            "admin", "dashboard", "management", "settings", "configuration",
            "users list", "all users", "system", "audit", "logs",
            "permissions", "roles", "billing", "invoice", "report",
        ]

        indicator_count = sum(1 for ind in admin_indicators if ind in content_lower)

        # Check for data tables/lists
        table_patterns = [
            r'<table[^>]*>', r'<tr[^>]*>', r'"data"\s*:\s*\[',
            r'"users"\s*:\s*\[', r'"items"\s*:\s*\[',
        ]

        table_count = sum(1 for p in table_patterns if re.search(p, content, re.I))

        if len(content) > 500 and (indicator_count >= 2 or table_count >= 2):
            return True

        strong_indicators = ["all users", "system settings", "admin panel", "manage users"]
        if any(ind in content_lower for ind in strong_indicators):
            return True

        return False

    async def _try_403_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str,
        rate_limiter: RateLimiter,
    ) -> Optional[dict]:
        """Try various techniques to bypass 403 Forbidden."""
        bypass_techniques = [
            {"headers": {"X-Original-URL": urlparse(url).path}},
            {"headers": {"X-Rewrite-URL": urlparse(url).path}},
            {"headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"headers": {"X-Custom-IP-Authorization": "127.0.0.1"}},
            {"url_suffix": "/"},
            {"url_suffix": "/."},
            {"url_suffix": "%20"},
            {"url_transform": "upper"},
        ]

        parsed = urlparse(url)

        for technique in bypass_techniques[:5]:
            await rate_limiter.acquire()

            try:
                test_url = url
                headers = {}

                if "headers" in technique:
                    headers = technique["headers"]
                elif "url_suffix" in technique:
                    test_url = url + technique["url_suffix"]
                elif "url_transform" in technique:
                    if technique["url_transform"] == "upper":
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.upper()}"

                if method == "GET":
                    resp = await client.get(test_url, headers=headers)
                else:
                    resp = await client.request(method, test_url, headers=headers)

                if resp.status_code == 200 and len(resp.text) > 200:
                    return Finding(
                        vuln_type=VulnType.BFLA,
                        name="403 Bypass - Privilege Escalation",
                        severity=Severity.HIGH,
                        description=f"403 Forbidden bypass achieved using technique: {technique}. "
                                   "Access control can be circumvented.",
                        host=urlparse(url).netloc,
                        endpoint=test_url,
                        evidence=[
                            f"Original URL: {url}",
                            f"Bypass URL: {test_url}",
                            f"Technique: {str(technique)}",
                            f"Response status: {resp.status_code}",
                        ],
                        cvss_score=7.5,
                        cwe_id="CWE-285",
                        remediation="Fix access control to handle URL variations and "
                                   "header manipulation. Normalize URLs before authorization check.",
                    ).to_dict()

            except (httpx.HTTPError, httpx.TimeoutException, OSError):
                continue

        return None

    async def _test_role_manipulation(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for role parameter manipulation vulnerabilities."""
        findings = []
        endpoints = asset_data.get("endpoints", []) if isinstance(asset_data, dict) else []

        # Find user-related endpoints
        user_endpoints = [
            e for e in endpoints
            if any(kw in e.lower() for kw in ["user", "profile", "account", "register", "update"])
        ]

        common_endpoints = [
            "/api/user", "/api/users", "/api/profile", "/api/account",
            "/user/update", "/profile/update", "/account/settings",
            "/api/v1/user", "/api/v1/users", "/api/v1/profile",
        ]

        test_endpoints = list(set(user_endpoints[:5] + common_endpoints[:10]))

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in test_endpoints:
                url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)

                for role_payload in ROLE_MANIPULATION_PAYLOADS[:10]:
                    for value in role_payload["values"][:3]:
                        await rate_limiter.acquire()

                        payload = {role_payload["param"]: value}

                        try:
                            resp = await client.post(url, json=payload)

                            if resp.status_code in [200, 201]:
                                resp_text = resp.text.lower()
                                success_indicators = [
                                    "success", "updated", "created", "admin",
                                    '"role":"admin"', '"isadmin":true',
                                ]

                                if any(ind in resp_text for ind in success_indicators):
                                    findings.append(Finding(
                                        vuln_type=VulnType.BFLA,
                                        name="Role Manipulation Vulnerability",
                                        severity=Severity.CRITICAL,
                                        description=f"Possible privilege escalation via role parameter manipulation. "
                                                   f"Parameter '{role_payload['param']}' may allow role changes.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[
                                            f"Parameter: {role_payload['param']}",
                                            f"Value: {value}",
                                            f"Status code: {resp.status_code}",
                                            f"Response snippet: {resp.text[:200]}",
                                        ],
                                        cvss_score=9.1,
                                        cwe_id="CWE-269",
                                        remediation="Never trust client-supplied role values. "
                                                   "Role assignment should be server-controlled.",
                                    ).to_dict())
                                    break

                        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                            logger.debug(f"Role manipulation test failed: {e}")

        return findings

    async def _test_forced_browsing(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for forced browsing to admin/privileged areas."""
        findings = []

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for path in ADMIN_PATHS_FORCED_BROWSING[:30]:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    resp = await client.get(url)

                    if resp.status_code == 200:
                        content_lower = resp.text.lower()

                        admin_indicators = [
                            "admin", "dashboard", "management", "control panel",
                            "settings", "configuration", "users", "system",
                        ]

                        indicator_count = sum(
                            1 for ind in admin_indicators if ind in content_lower
                        )

                        if indicator_count >= 2 and len(resp.text) > 500:
                            severity = "CRITICAL" if "admin" in path.lower() else "HIGH"

                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="Forced Browsing - Admin Access",
                                severity=severity,
                                description=f"Admin/privileged area accessible via direct URL access. "
                                           f"No authentication required for '{path}'.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Admin path: {path}",
                                    f"Status code: {resp.status_code}",
                                    f"Content length: {len(resp.text)} bytes",
                                    f"Admin indicators found: {indicator_count}",
                                ],
                                cvss_score=9.1,
                                cwe_id="CWE-862",
                                remediation="Implement authentication and authorization for all "
                                           "admin/privileged paths.",
                            ).to_dict())

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Forced browsing test failed for {url}: {e}")

        return findings

    async def _test_http_method_tampering(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for HTTP method tampering vulnerabilities."""
        findings = []
        endpoints = asset_data.get("endpoints", []) if isinstance(asset_data, dict) else []

        sensitive_patterns = ["user", "account", "profile", "admin", "settings", "delete"]
        test_endpoints = [
            e for e in endpoints[:20]
            if any(p in e.lower() for p in sensitive_patterns)
        ]

        api_endpoints = [
            "/api/user", "/api/users", "/api/account", "/api/profile",
            "/api/settings", "/api/admin", "/user", "/account",
        ]

        all_endpoints = list(set(test_endpoints[:10] + api_endpoints[:5]))

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in all_endpoints:
                url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)

                # Get baseline with GET
                await rate_limiter.acquire()
                try:
                    get_resp = await client.get(url)
                except (httpx.HTTPError, httpx.TimeoutException, OSError):
                    continue

                for tampering in HTTP_METHOD_TAMPERING:
                    await rate_limiter.acquire()

                    try:
                        method = tampering["method"]
                        headers = tampering.get("headers", {})
                        params = tampering.get("params", {})

                        if method == "GET" and not headers and not params:
                            continue

                        if method == "POST":
                            if params:
                                resp = await client.post(url, data=params, headers=headers)
                            else:
                                resp = await client.post(url, json={}, headers=headers)
                        elif method == "PUT":
                            resp = await client.put(url, json={}, headers=headers)
                        elif method == "DELETE":
                            resp = await client.delete(url, headers=headers)
                        elif method == "PATCH":
                            resp = await client.patch(url, json={}, headers=headers)
                        else:
                            continue

                        if self._is_method_tampering_vulnerable(get_resp, resp, tampering):
                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="HTTP Method Tampering Vulnerability",
                                severity=Severity.HIGH,
                                description=f"HTTP method tampering may allow unauthorized actions. "
                                           f"{tampering['description']}.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Original method: GET -> {method}",
                                    f"Technique: {tampering['description']}",
                                    f"GET status: {get_resp.status_code}",
                                    f"Tampered status: {resp.status_code}",
                                ],
                                cvss_score=7.5,
                                cwe_id="CWE-285",
                                remediation="Implement method-aware access control. "
                                           "Validate permissions for each action type separately.",
                            ).to_dict())
                            break

                    except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                        logger.debug(f"Method tampering test failed: {e}")

        return findings

    def _is_method_tampering_vulnerable(
        self,
        get_resp: httpx.Response,
        tampered_resp: httpx.Response,
        tampering: dict,
    ) -> bool:
        """Analyze if method tampering indicates vulnerability."""
        if get_resp.status_code in [401, 403] and tampered_resp.status_code == 200:
            return True

        if tampering.get("headers") and tampered_resp.status_code in [200, 201, 204]:
            if any(word in tampered_resp.text.lower() for word in
                   ["success", "updated", "deleted", "created"]):
                return True

        if tampering["method"] in ["DELETE", "PUT"] and tampered_resp.status_code in [200, 204]:
            return True

        return False

    async def _test_parameter_pollution(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for parameter pollution vulnerabilities."""
        findings = []
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])

        id_endpoints = [
            e for e in endpoints
            if re.search(r'[?&](id|user_id|userId|account)=', e, re.I)
        ]

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in id_endpoints[:10]:
                await rate_limiter.acquire()

                try:
                    baseline_resp = await client.get(endpoint)

                    for pollution in PARAM_POLLUTION_PAYLOADS:
                        await rate_limiter.acquire()

                        if "?" in endpoint:
                            polluted_url = f"{endpoint}&{pollution['pattern']}"
                        else:
                            polluted_url = f"{endpoint}?{pollution['pattern']}"

                        polluted_resp = await client.get(polluted_url)

                        if (polluted_resp.status_code == 200 and
                            polluted_resp.text != baseline_resp.text and
                            len(polluted_resp.text) > 100):

                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="Parameter Pollution Vulnerability",
                                severity=Severity.MEDIUM,
                                description=f"Parameter pollution may allow access control bypass. "
                                           f"{pollution['description']}.",
                                host=base_url,
                                endpoint=polluted_url,
                                evidence=[
                                    f"Pollution pattern: {pollution['pattern']}",
                                    f"Original endpoint: {endpoint}",
                                    "Response difference detected",
                                ],
                                cvss_score=6.5,
                                cwe_id="CWE-235",
                                remediation="Use strict parameter parsing. "
                                           "Reject requests with duplicate parameters.",
                            ).to_dict())
                            break

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Parameter pollution test failed: {e}")

        return findings

    async def _test_mass_assignment(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for mass assignment vulnerabilities."""
        findings = []

        update_endpoints = [
            "/api/user", "/api/profile", "/api/account", "/api/me",
            "/user/update", "/profile/update", "/account/update",
            "/api/v1/user", "/api/v1/profile", "/api/v1/me",
            "/settings", "/preferences",
        ]

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in update_endpoints:
                url = urljoin(base_url, endpoint)

                # OPTIMIZATION: First check if endpoint exists
                try:
                    await rate_limiter.acquire()
                    probe = await client.get(url)
                    if probe.status_code == 404:
                        continue  # Skip non-existent endpoints
                except Exception:
                    continue

                for payload in MASS_ASSIGNMENT_PAYLOADS[:15]:
                    await rate_limiter.acquire()

                    try:
                        for method in ["PUT", "PATCH", "POST"]:
                            if method == "PUT":
                                resp = await client.put(url, json=payload)
                            elif method == "PATCH":
                                resp = await client.patch(url, json=payload)
                            else:
                                resp = await client.post(url, json=payload)

                            if resp.status_code in [200, 201]:
                                resp_lower = resp.text.lower()
                                field_name = list(payload.keys())[0]
                                field_value = str(list(payload.values())[0]).lower()

                                if (field_name.lower() in resp_lower or
                                    field_value in resp_lower or
                                    "success" in resp_lower):

                                    findings.append(Finding(
                                        vuln_type=VulnType.BFLA,
                                        name="Mass Assignment Vulnerability",
                                        severity=Severity.HIGH,
                                        description=f"Privileged field '{field_name}' may be assignable. "
                                                   f"Mass assignment could allow privilege escalation.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[
                                            f"Payload: {json.dumps(payload)}",
                                            f"Method: {method}",
                                            f"Status: {resp.status_code}",
                                            "Field appears accepted",
                                        ],
                                        cvss_score=7.5,
                                        cwe_id="CWE-915",
                                        remediation="Use allowlists for permitted fields. "
                                                   "Never directly bind request data to models.",
                                    ).to_dict())
                                    break
                            break

                    except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                        logger.debug(f"Mass assignment test failed: {e}")

        return findings

    async def _test_path_traversal_authz(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for path traversal authorization bypass."""
        findings = []

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for path in PATH_TRAVERSAL_AUTHZ_PAYLOADS:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    resp = await client.get(url, follow_redirects=False)

                    if resp.status_code == 200:
                        content_lower = resp.text.lower()

                        if any(ind in content_lower for ind in
                               ["admin", "dashboard", "management", "settings"]):

                            severity = "HIGH"
                            if ".." in path or "%2f" in path.lower():
                                severity = "CRITICAL"

                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="Path Traversal Authorization Bypass",
                                severity=severity,
                                description=f"Path manipulation allows access control bypass. "
                                           f"Admin content accessible via '{path}'.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Bypass path: {path}",
                                    f"Status: {resp.status_code}",
                                    "Admin content detected",
                                ],
                                cvss_score=8.1,
                                cwe_id="CWE-22",
                                remediation="Normalize paths before authorization check. "
                                           "Use canonical paths. Block path traversal sequences.",
                            ).to_dict())

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Path traversal authz test failed: {e}")

        return findings

    async def _test_function_level_access(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for function-level access control issues."""
        findings = []

        privileged_apis = [
            {"path": "/api/admin/users", "method": "GET", "desc": "List all users"},
            {"path": "/api/admin/users", "method": "DELETE", "desc": "Delete users"},
            {"path": "/api/admin/config", "method": "POST", "desc": "Modify config"},
            {"path": "/api/admin/logs", "method": "GET", "desc": "View logs"},
            {"path": "/api/users/export", "method": "GET", "desc": "Export users"},
            {"path": "/api/backup", "method": "POST", "desc": "Create backup"},
            {"path": "/api/restore", "method": "POST", "desc": "Restore backup"},
            {"path": "/api/system/info", "method": "GET", "desc": "System info"},
            {"path": "/api/debug", "method": "GET", "desc": "Debug info"},
            {"path": "/graphql", "method": "POST", "desc": "GraphQL endpoint"},
            {"path": "/api/v1/internal", "method": "GET", "desc": "Internal API"},
            {"path": "/api/keys", "method": "GET", "desc": "API keys"},
            {"path": "/api/tokens", "method": "GET", "desc": "Access tokens"},
        ]

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for api in privileged_apis:
                await rate_limiter.acquire()

                url = urljoin(base_url, api["path"])

                try:
                    if api["method"] == "GET":
                        resp = await client.get(url)
                    elif api["method"] == "POST":
                        resp = await client.post(url, json={})
                    elif api["method"] == "DELETE":
                        resp = await client.delete(url)
                    else:
                        continue

                    if resp.status_code == 200 and len(resp.text) > 50:
                        if not any(err in resp.text.lower() for err in
                                   ["error", "forbidden", "unauthorized", "not found"]):

                            findings.append(Finding(
                                vuln_type=VulnType.BFLA,
                                name="Function-Level Access Control Missing",
                                severity=Severity.HIGH,
                                description=f"Privileged API function accessible without authorization. "
                                           f"{api['desc']} at {api['path']}.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Function: {api['desc']}",
                                    f"Endpoint: {api['path']}",
                                    f"Method: {api['method']}",
                                    f"Status: {resp.status_code}",
                                ],
                                cvss_score=7.5,
                                cwe_id="CWE-285",
                                remediation="Implement function-level access control. "
                                           "Verify permissions before executing any privileged operation.",
                            ).to_dict())

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Function access test failed for {url}: {e}")

        return findings
