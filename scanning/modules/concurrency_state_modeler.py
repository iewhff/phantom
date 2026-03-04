"""
PHANTOM AI - Concurrency State Modeler

Advanced modeling of concurrent interactions to uncover race conditions
and state desynchronization vulnerabilities.

Key Capabilities:
1. TOCTOU Detection — Time-of-check to time-of-use vulnerabilities
2. Double-Spend Testing — Same resource modified concurrently
3. State Consistency Verification — After concurrent ops, verify state
4. Timing Window Exploration — Find vulnerability windows with varied timing
5. Lock Contention Bypass — Optimistic/pessimistic locking failures
6. Atomicity Violation Detection — Non-atomic read-modify-write patterns

Race Condition Categories:
- Check-Then-Act (CTA): Check balance → Transfer (balance could change between)
- Read-Modify-Write (RMW): Read stock → Decrement → Write (non-atomic)
- Double-Apply: Apply coupon twice simultaneously
- Order Dependency: Request B executes before A completes
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)

# SSL context
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class RaceConditionType(Enum):
    """Types of race conditions to test."""
    TOCTOU = auto()           # Time-of-check to time-of-use
    DOUBLE_SPEND = auto()     # Same resource consumed twice
    DOUBLE_APPLY = auto()     # Same action applied twice (coupons, votes)
    READ_MODIFY_WRITE = auto()  # Non-atomic operations
    ORDER_DEPENDENCY = auto()  # Out-of-order execution
    LOCK_BYPASS = auto()      # Lock contention bypass
    STATE_DESYNC = auto()     # Cross-service state inconsistency


@dataclass
class RaceTestCase:
    """A race condition test case."""
    name: str
    race_type: RaceConditionType
    setup_request: dict | None = None  # Request to set up initial state
    competing_requests: list[dict] = field(default_factory=list)  # Requests to race
    verification_request: dict | None = None  # Request to verify state
    expected_behavior: str = ""  # What should happen
    vulnerability_indicator: str = ""  # What indicates a vulnerability
    concurrency_levels: list[int] = field(default_factory=lambda: [2, 5, 10, 20])
    timing_delays_ms: list[int] = field(default_factory=lambda: [0, 1, 5, 10, 50])


@dataclass
class RaceTestResult:
    """Result of a race condition test."""
    test_case: RaceTestCase
    concurrency_level: int
    timing_delay_ms: int
    success_count: int = 0
    failure_count: int = 0
    anomaly_count: int = 0  # Unexpected responses indicating race
    total_time_ms: float = 0.0
    state_before: str = ""
    state_after: str = ""
    response_variations: list[dict] = field(default_factory=list)
    is_vulnerable: bool = False
    vulnerability_evidence: str = ""


# ============================================================================
# RACE CONDITION PATTERNS
# ============================================================================

# Endpoint patterns that are prone to race conditions
RACE_PRONE_PATTERNS = {
    RaceConditionType.DOUBLE_SPEND: [
        (r"/transfer", r"/withdraw", r"/redeem", r"/spend"),
        {"operation": "debit", "resource": "balance"},
    ],
    RaceConditionType.DOUBLE_APPLY: [
        (r"/coupon", r"/discount", r"/promo", r"/voucher", r"/vote", r"/like"),
        {"operation": "apply", "resource": "single-use"},
    ],
    RaceConditionType.TOCTOU: [
        (r"/checkout", r"/reserve", r"/book", r"/claim"),
        {"operation": "check_then_act", "resource": "limited"},
    ],
    RaceConditionType.READ_MODIFY_WRITE: [
        (r"/cart/update", r"/quantity", r"/stock", r"/inventory"),
        {"operation": "increment_decrement", "resource": "counter"},
    ],
    RaceConditionType.ORDER_DEPENDENCY: [
        (r"/step", r"/wizard", r"/phase"),
        {"operation": "sequential", "resource": "workflow"},
    ],
}

# State-changing operations that could race
STATE_CHANGE_OPERATIONS = {
    "add_to_cart": {
        "endpoints": ["/cart/add", "/api/cart", "/basket/add", "/rest/basket"],
        "method": "POST",
        "body_template": {"productId": "{id}", "quantity": 1},
    },
    "apply_coupon": {
        "endpoints": ["/coupon/apply", "/api/coupon", "/promo", "/discount"],
        "method": "POST",
        "body_template": {"code": "{code}"},
    },
    "transfer_funds": {
        "endpoints": ["/transfer", "/api/transfer", "/send", "/pay"],
        "method": "POST",
        "body_template": {"amount": "{amount}", "to": "{recipient}"},
    },
    "update_quantity": {
        "endpoints": ["/cart/update", "/api/cart", "/basket"],
        "method": "PUT",
        "body_template": {"quantity": "{quantity}"},
    },
    "checkout": {
        "endpoints": ["/checkout", "/api/order", "/purchase", "/buy"],
        "method": "POST",
        "body_template": {},
    },
    "vote": {
        "endpoints": ["/vote", "/like", "/upvote", "/rate"],
        "method": "POST",
        "body_template": {"itemId": "{id}"},
    },
    "claim_reward": {
        "endpoints": ["/claim", "/redeem", "/collect", "/reward"],
        "method": "POST",
        "body_template": {"rewardId": "{id}"},
    },
}


class ConcurrencyStateModeler(ScanModule):
    """
    Advanced concurrency state modeler for race condition detection.

    Tests applications under concurrent load with state awareness,
    detecting vulnerabilities that only emerge from timing-dependent
    interactions.
    """

    name = "concurrency_state"
    description = "Advanced race condition and state desynchronization detection"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["concurrency", "race_condition", "state", "toctou", "double_spend"]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = 15.0
        self._base_url = ""
        self._auth_headers: dict[str, str] = {}
        self._rate_limiter: Any = None
        self._discovered_endpoints: list[dict] = []
        self._aiohttp_timeout = aiohttp.ClientTimeout(total=15)

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main scan entry point."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        # Get auth context
        auth_context = extra_params.get("auth_context")
        if auth_context:
            if hasattr(auth_context, "token") and auth_context.token:
                self._auth_headers["Authorization"] = f"Bearer {auth_context.token}"
            if hasattr(auth_context, "cookies") and auth_context.cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in auth_context.cookies.items())
                self._auth_headers["Cookie"] = cookie_str

        # Get rate limiter and endpoints
        self._rate_limiter = extra_params.get("rate_limiter")
        endpoints = extra_params.get("endpoints", [])
        self._discovered_endpoints = [
            {"url": getattr(ep, "url", "") or getattr(ep, "path", ""),
             "method": getattr(ep, "method", "GET")}
            for ep in endpoints
        ]

        findings: list[Finding] = []

        logger.info(f"[RACE] Starting concurrency state analysis on {self._base_url}")

        # Phase 1: Identify race-prone endpoints
        race_endpoints = self._identify_race_prone_endpoints()
        logger.info(f"[RACE] Identified {len(race_endpoints)} race-prone endpoints")

        # Phase 2: Build test cases
        test_cases = self._build_race_test_cases(race_endpoints)
        logger.info(f"[RACE] Built {len(test_cases)} race condition test cases")

        # Phase 3: Execute race tests
        for test_case in test_cases[:10]:  # Limit to 10 test cases
            try:
                result = await self._execute_race_test(test_case)
                if result and result.is_vulnerable:
                    finding = self._create_finding_from_result(result)
                    findings.append(finding)
            except Exception as e:
                logger.debug(f"[RACE] Test case {test_case.name} failed: {e}")

        # Phase 4: Generic double-request testing
        double_req_findings = await self._test_double_request_attacks()
        findings.extend(double_req_findings)

        # Phase 5: State consistency testing
        state_findings = await self._test_state_consistency()
        findings.extend(state_findings)

        # Phase 6: Timing window exploration
        timing_findings = await self._explore_timing_windows()
        findings.extend(timing_findings)

        # Deduplicate
        findings = self._deduplicate_findings(findings)

        logger.info(f"[RACE] Complete: {len(findings)} race condition findings")
        return findings

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")
        protocol = "https" if port in (443, 8443) else "http"
        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    def _identify_race_prone_endpoints(self) -> list[dict]:
        """Identify endpoints that are prone to race conditions."""
        race_endpoints = []

        for ep in self._discovered_endpoints:
            url = ep.get("url", "").lower()
            method = ep.get("method", "GET").upper()

            # Check against race-prone patterns
            for race_type, (patterns, metadata) in RACE_PRONE_PATTERNS.items():
                for pattern in patterns:
                    if pattern in url:
                        entry = {
                            "url": ep.get("url", ""),
                            "method": method,
                            "race_type": race_type,
                        }

                        if isinstance(asset_data, dict):
                            entry["operation"] = metadata.get("operation", "")
                            entry["resource"] = metadata.get("resource", "")

                        race_endpoints.append(entry)
                        break


            # Also check state-changing operations
            for op_name, op_config in STATE_CHANGE_OPERATIONS.items():
                for endpoint_pattern in op_config["endpoints"]:
                    if endpoint_pattern in url:
                        race_endpoints.append({
                            "url": ep.get("url", ""),
                            "method": op_config["method"],
                            "operation": op_name,
                            "body_template": op_config.get("body_template", {}),
                        })
                        break

        return race_endpoints

    def _build_race_test_cases(self, race_endpoints: list[dict]) -> list[RaceTestCase]:
        """Build race condition test cases from identified endpoints."""
        test_cases = []

        for ep in race_endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "POST")
            race_type = ep.get("race_type", RaceConditionType.DOUBLE_APPLY)
            operation = ep.get("operation", "unknown")

            # Build competing requests based on operation type
            if operation in ("apply", "vote", "claim"):
                # Double-apply test: same request twice
                test_cases.append(RaceTestCase(
                    name=f"Double-Apply: {url}",
                    race_type=RaceConditionType.DOUBLE_APPLY,
                    competing_requests=[
                        {"url": url, "method": method, "body": {}},
                        {"url": url, "method": method, "body": {}},
                    ],
                    expected_behavior="Second request should be rejected",
                    vulnerability_indicator="Both requests succeeded with 200/201",
                ))

            elif operation in ("debit", "transfer"):
                # Double-spend test: same withdrawal twice
                test_cases.append(RaceTestCase(
                    name=f"Double-Spend: {url}",
                    race_type=RaceConditionType.DOUBLE_SPEND,
                    competing_requests=[
                        {"url": url, "method": method, "body": {"amount": 100}},
                        {"url": url, "method": method, "body": {"amount": 100}},
                    ],
                    expected_behavior="Second transfer should fail (insufficient funds)",
                    vulnerability_indicator="Both transfers succeeded",
                ))

            elif operation in ("increment_decrement", "update"):
                # Read-modify-write test: concurrent updates
                test_cases.append(RaceTestCase(
                    name=f"Concurrent Update: {url}",
                    race_type=RaceConditionType.READ_MODIFY_WRITE,
                    competing_requests=[
                        {"url": url, "method": "PUT", "body": {"quantity": 5}},
                        {"url": url, "method": "PUT", "body": {"quantity": 5}},
                    ],
                    expected_behavior="Final quantity should be deterministic",
                    vulnerability_indicator="State inconsistency detected",
                ))

            elif operation in ("check_then_act", "reserve"):
                # TOCTOU test: check availability then book
                test_cases.append(RaceTestCase(
                    name=f"TOCTOU: {url}",
                    race_type=RaceConditionType.TOCTOU,
                    competing_requests=[
                        {"url": url, "method": method, "body": {}},
                        {"url": url, "method": method, "body": {}},
                    ],
                    expected_behavior="One booking should fail (already taken)",
                    vulnerability_indicator="Both bookings succeeded",
                ))

        return test_cases

    async def _execute_race_test(self, test_case: RaceTestCase) -> RaceTestResult | None:
        """Execute a race condition test case."""
        best_result = None

        for concurrency in test_case.concurrency_levels[:3]:  # Test up to 3 levels
            for delay_ms in test_case.timing_delays_ms[:3]:  # Test up to 3 delays
                try:
                    result = await self._run_concurrent_requests(
                        test_case, concurrency, delay_ms
                    )

                    if result.is_vulnerable:
                        return result  # Found vulnerability, return immediately

                    if result.anomaly_count > 0:
                        best_result = result  # Keep track of anomalies

                except Exception as e:
                    logger.debug(f"[RACE] Test failed at {concurrency}x/{delay_ms}ms: {e}")

        return best_result

    async def _run_concurrent_requests(
        self,
        test_case: RaceTestCase,
        concurrency: int,
        delay_ms: int,
    ) -> RaceTestResult:
        """Run concurrent requests and analyze results."""
        result = RaceTestResult(
            test_case=test_case,
            concurrency_level=concurrency,
            timing_delay_ms=delay_ms,
        )

        # Prepare requests
        requests = []
        for req_template in test_case.competing_requests:
            for _ in range(concurrency):
                requests.append(req_template.copy())

        # Execute with timing
        start_time = time.time()

        async def execute_request(req: dict, delay: float = 0) -> dict:
            if delay > 0:
                await asyncio.sleep(delay / 1000)  # Convert ms to seconds

            url = req.get("url", "")
            if not url.startswith("http"):
                url = urljoin(self._base_url, url)

            method = req.get("method", "POST")
            body = req.get("body", {})

            try:
                async with aiohttp.ClientSession(timeout=self._aiohttp_timeout) as session:
                    if method == "POST":
                        async with session.post(
                            url, json=body, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            text = await resp.text()
                            return {
                                "status": resp.status,
                                "body": text[:1000],
                                "body_hash": hashlib.md5(text.encode()).hexdigest(),
                            }
                    elif method == "PUT":
                        async with session.put(
                            url, json=body, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            text = await resp.text()
                            return {
                                "status": resp.status,
                                "body": text[:1000],
                                "body_hash": hashlib.md5(text.encode()).hexdigest(),
                            }
                    else:
                        async with session.get(
                            url, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            text = await resp.text()
                            return {
                                "status": resp.status,
                                "body": text[:1000],
                                "body_hash": hashlib.md5(text.encode()).hexdigest(),
                            }
            except Exception as e:
                return {"status": 0, "error": str(e)}

        # Apply staggered delays for timing exploration
        tasks = []
        for i, req in enumerate(requests):
            stagger = (i * delay_ms) / len(requests) if delay_ms > 0 else 0
            tasks.append(execute_request(req, stagger))

        responses = await asyncio.gather(*tasks, return_exceptions=True)
        result.total_time_ms = (time.time() - start_time) * 1000

        # Analyze responses
        success_count = 0
        failure_count = 0
        status_codes = []
        body_hashes = []

        for resp in responses:
            if isinstance(resp, Exception):
                failure_count += 1
                continue

            if isinstance(resp, dict):
                status = resp.get("status", 0)
                status_codes.append(status)

                if status in (200, 201, 202):
                    success_count += 1
                    body_hashes.append(resp.get("body_hash", ""))
                    result.response_variations.append(resp)
                elif status in (400, 409, 422, 429):
                    failure_count += 1
                else:
                    result.anomaly_count += 1

        result.success_count = success_count
        result.failure_count = failure_count

        # Detect race condition indicators
        is_vulnerable, evidence = self._analyze_race_result(
            test_case, success_count, failure_count, status_codes, body_hashes
        )
        result.is_vulnerable = is_vulnerable
        result.vulnerability_evidence = evidence

        return result

    def _analyze_race_result(
        self,
        test_case: RaceTestCase,
        success_count: int,
        failure_count: int,
        status_codes: list[int],
        body_hashes: list[str],
    ) -> tuple[bool, str]:
        """Analyze race test result for vulnerability indicators."""
        evidence_parts = []
        is_vulnerable = False

        # Double-Apply / Double-Spend: All requests succeeded when only one should
        if test_case.race_type in (RaceConditionType.DOUBLE_APPLY, RaceConditionType.DOUBLE_SPEND):
            if success_count > 1 and failure_count == 0:
                is_vulnerable = True
                evidence_parts.append(
                    f"All {success_count} concurrent requests succeeded with status 200/201. "
                    f"Expected: only 1 success, others should get 409/400."
                )

        # TOCTOU: Multiple successful reservations of same resource
        elif test_case.race_type == RaceConditionType.TOCTOU:
            if success_count > 1:
                is_vulnerable = True
                evidence_parts.append(
                    f"{success_count} concurrent requests successfully reserved the same resource. "
                    f"Expected: only 1 reservation, others should fail."
                )

        # Read-Modify-Write: Inconsistent final state
        elif test_case.race_type == RaceConditionType.READ_MODIFY_WRITE:
            unique_hashes = len(set(body_hashes))
            if unique_hashes > 1 and success_count > 2:
                is_vulnerable = True
                evidence_parts.append(
                    f"Concurrent updates produced {unique_hashes} different response states. "
                    f"Indicates non-atomic read-modify-write operations."
                )

        # Generic: Unexpected status code patterns
        if not is_vulnerable:
            # Look for 500 errors under race (server-side race handling failure)
            server_errors = sum(1 for s in status_codes if s >= 500)
            if server_errors > 0 and success_count > 0:
                is_vulnerable = True
                evidence_parts.append(
                    f"Server returned {server_errors} 5xx errors during concurrent access, "
                    f"indicating potential race condition handling failure."
                )

        return is_vulnerable, " ".join(evidence_parts)

    async def _test_double_request_attacks(self) -> list[Finding]:
        """Test for double-request vulnerabilities on state-changing endpoints."""
        findings = []

        # Find POST/PUT/DELETE endpoints
        mutation_endpoints = [
            ep for ep in self._discovered_endpoints
            if ep.get("method", "GET").upper() in ("POST", "PUT", "DELETE")
        ]

        for ep in mutation_endpoints[:5]:  # Limit to 5
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = urljoin(self._base_url, url)
            method = ep.get("method", "POST")

            try:
                # Execute same request twice simultaneously
                async def make_request():
                    async with aiohttp.ClientSession(timeout=self._aiohttp_timeout) as session:
                        if method == "POST":
                            async with session.post(
                                url, json={}, headers=self._auth_headers, ssl=_SSL_CTX
                            ) as resp:
                                return resp.status, await resp.text()
                        elif method == "PUT":
                            async with session.put(
                                url, json={}, headers=self._auth_headers, ssl=_SSL_CTX
                            ) as resp:
                                return resp.status, await resp.text()
                        else:
                            async with session.delete(
                                url, headers=self._auth_headers, ssl=_SSL_CTX
                            ) as resp:
                                return resp.status, await resp.text()

                results = await asyncio.gather(
                    make_request(), make_request(),
                    return_exceptions=True
                )

                # Analyze: both succeeded when one should have failed
                successes = [r for r in results if isinstance(r, tuple) and r[0] in (200, 201)]

                if len(successes) == 2:
                    # Check if responses are identical (double-apply worked)
                    if successes[0][1] == successes[1][1]:
                        findings.append(Finding(
                            name=f"Double-Request Accepted: {urlparse(url).path}",
                            severity=Severity.HIGH,
                            confidence_score=85,
                            vulnerability_type="race_condition",
                            module_name="concurrency_state",
                            description=(
                                f"Endpoint {url} accepted two identical concurrent requests, "
                                f"both returning success. This indicates a double-apply or "
                                f"double-spend vulnerability where the same action can be "
                                f"performed multiple times in a race window."
                            ),
                            endpoint=url,
                            evidence=[
                                f"Request 1: {method} → {successes[0][0]}",
                                f"Request 2: {method} → {successes[1][0]}",
                                f"Both returned identical success responses",
                            ],
                            metadata={
                                "race_type": "double_request",
                                "method": method,
                            },
                        ))

            except Exception as e:
                logger.debug(f"[RACE] Double-request test failed for {url}: {e}")

        return findings

    async def _test_state_consistency(self) -> list[Finding]:
        """Test for state consistency after concurrent operations."""
        findings = []

        # Look for read endpoints that could show state
        read_endpoints = [
            ep for ep in self._discovered_endpoints
            if ep.get("method", "GET").upper() == "GET"
            and any(kw in ep.get("url", "").lower() for kw in
                   ["cart", "balance", "account", "status", "order", "profile"])
        ]

        for ep in read_endpoints[:3]:  # Limit to 3
            url = ep.get("url", "")
            if not url.startswith("http"):
                url = urljoin(self._base_url, url)

            try:
                # Read state multiple times concurrently
                async def read_state():
                    async with aiohttp.ClientSession(timeout=self._aiohttp_timeout) as session:
                        async with session.get(
                            url, headers=self._auth_headers, ssl=_SSL_CTX
                        ) as resp:
                            text = await resp.text()
                            return hashlib.md5(text.encode()).hexdigest(), text[:500]

                # Execute 10 concurrent reads
                results = await asyncio.gather(
                    *[read_state() for _ in range(10)],
                    return_exceptions=True
                )

                valid_results = [r for r in results if isinstance(r, tuple)]

                if len(valid_results) >= 5:
                    unique_hashes = len(set(h for h, _ in valid_results))

                    if unique_hashes > 1:
                        findings.append(Finding(
                            name=f"State Inconsistency: {urlparse(url).path}",
                            severity=Severity.MEDIUM,
                            confidence_score=70,
                            vulnerability_type="race_condition",
                            module_name="concurrency_state",
                            description=(
                                f"Concurrent reads of {url} returned {unique_hashes} different "
                                f"response states. This indicates potential state desynchronization "
                                f"or caching inconsistency under concurrent access."
                            ),
                            endpoint=url,
                            evidence=[
                                f"10 concurrent reads returned {unique_hashes} unique responses",
                                f"Expected: all reads should return consistent state",
                            ],
                            metadata={
                                "race_type": "state_desync",
                                "unique_responses": unique_hashes,
                            },
                        ))

            except Exception as e:
                logger.debug(f"[RACE] State consistency test failed for {url}: {e}")

        return findings

    async def _explore_timing_windows(self) -> list[Finding]:
        """Explore timing windows where race conditions might occur."""
        findings = []

        # Find pairs of related endpoints (check + action)
        check_action_pairs = self._find_check_action_pairs()

        for check_url, action_url in check_action_pairs[:3]:  # Limit to 3 pairs
            try:
                # Vary timing between check and action
                for delay_ms in [0, 1, 5, 10, 50]:
                    result = await self._test_toctou_timing(check_url, action_url, delay_ms)

                    if result.get("vulnerable"):
                        findings.append(Finding(
                            name=f"TOCTOU Window: {delay_ms}ms",
                            severity=Severity.HIGH,
                            confidence_score=80,
                            vulnerability_type="race_condition",
                            module_name="concurrency_state",
                            description=(
                                f"Time-of-check to time-of-use vulnerability found. "
                                f"A {delay_ms}ms window exists between checking ({check_url}) "
                                f"and acting ({action_url}) where state can be modified by "
                                f"a concurrent request."
                            ),
                            endpoint=action_url,
                            evidence=[
                                f"Check endpoint: {check_url}",
                                f"Action endpoint: {action_url}",
                                f"Vulnerable timing window: {delay_ms}ms",
                                result.get("evidence", ""),
                            ],
                            metadata={
                                "race_type": "toctou",
                                "timing_window_ms": delay_ms,
                            },
                        ))
                        break  # Found vulnerability, move to next pair

            except Exception as e:
                logger.debug(f"[RACE] Timing window test failed: {e}")

        return findings

    def _find_check_action_pairs(self) -> list[tuple[str, str]]:
        """Find pairs of check (GET) and action (POST) endpoints."""
        pairs = []

        get_endpoints = [ep for ep in self._discovered_endpoints if ep.get("method") == "GET"]
        post_endpoints = [ep for ep in self._discovered_endpoints if ep.get("method") == "POST"]

        # Look for related endpoints
        for get_ep in get_endpoints:
            get_url = get_ep.get("url", "").lower()
            get_path = urlparse(get_url).path

            for post_ep in post_endpoints:
                post_url = post_ep.get("url", "").lower()
                post_path = urlparse(post_url).path

                # Same base path or related names
                if (get_path.rstrip("/") == post_path.rstrip("/") or
                    get_path.replace("/get", "") == post_path.replace("/add", "") or
                    "check" in get_path and "confirm" in post_path):
                    pairs.append((get_ep.get("url", ""), post_ep.get("url", "")))

        return pairs[:5]  # Limit to 5 pairs

    async def _test_toctou_timing(
        self,
        check_url: str,
        action_url: str,
        delay_ms: int,
    ) -> dict:
        """Test for TOCTOU vulnerability with specific timing."""
        if not check_url.startswith("http"):
            check_url = urljoin(self._base_url, check_url)
        if not action_url.startswith("http"):
            action_url = urljoin(self._base_url, action_url)

        try:
            async def check_and_act():
                async with aiohttp.ClientSession(timeout=self._aiohttp_timeout) as session:
                    # Check
                    async with session.get(
                        check_url, headers=self._auth_headers, ssl=_SSL_CTX
                    ) as resp:
                        check_status = resp.status

                    # Delay
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)

                    # Act
                    async with session.post(
                        action_url, json={}, headers=self._auth_headers, ssl=_SSL_CTX
                    ) as resp:
                        action_status = resp.status
                        action_body = await resp.text()

                    return check_status, action_status, action_body

            # Execute two competing sequences
            results = await asyncio.gather(
                check_and_act(), check_and_act(),
                return_exceptions=True
            )

            valid_results = [r for r in results if isinstance(r, tuple)]

            if len(valid_results) == 2:
                # Both actions succeeded when only one should
                if (valid_results[0][1] in (200, 201) and
                    valid_results[1][1] in (200, 201)):
                    return {
                        "vulnerable": True,
                        "evidence": f"Both check-then-act sequences succeeded at {delay_ms}ms delay",
                    }

        except Exception as e:
            logger.debug(f"[RACE] TOCTOU timing test failed: {e}")

        return {"vulnerable": False}

    def _create_finding_from_result(self, result: RaceTestResult) -> Finding:
        """Create a Finding from a race test result."""
        severity = "HIGH" if result.test_case.race_type in (
            RaceConditionType.DOUBLE_SPEND,
            RaceConditionType.TOCTOU,
        ) else "MEDIUM"

        return Finding(
            name=result.test_case.name,
            severity=severity,
            confidence_score=85 if result.is_vulnerable else 70,
            vulnerability_type="race_condition",
            module_name="concurrency_state",
            description=(
                f"Race condition detected: {result.test_case.race_type.name}. "
                f"{result.vulnerability_evidence} "
                f"Tested at {result.concurrency_level}x concurrency with "
                f"{result.timing_delay_ms}ms timing delay."
            ),
            endpoint=result.test_case.competing_requests[0].get("url", "") if result.test_case.competing_requests else "",
            evidence=[
                f"Race type: {result.test_case.race_type.name}",
                f"Success count: {result.success_count}",
                f"Failure count: {result.failure_count}",
                f"Anomalies: {result.anomaly_count}",
                f"Expected: {result.test_case.expected_behavior}",
            ],
            metadata={
                "race_type": result.test_case.race_type.name,
                "concurrency_level": result.concurrency_level,
                "timing_delay_ms": result.timing_delay_ms,
                "success_count": result.success_count,
                "failure_count": result.failure_count,
            },
        )

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.name, getattr(f, "matched_at", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
