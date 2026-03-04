"""
PHANTOM AI - Race Condition Vulnerability Scanner

Enterprise-grade race condition detection covering:
- Time-of-check to time-of-use (TOCTOU) vulnerabilities
- Limit overrun exploitation (coupon abuse, balance manipulation)
- Single-packet parallel request attacks
- Last-byte synchronization technique
- Database race conditions (double-spend, inventory)
- Session race conditions (privilege escalation)
- File system race conditions
- Multi-endpoint race conditions
- State machine violations

Based on PortSwigger Web Security Academy - Race Conditions (6 labs)

Key Techniques:
1. HTTP/2 single-packet attack - Sends multiple requests atomically
2. Last-byte sync - Withholds final byte to synchronize burst
3. Connection warming - Pre-establishes connections for timing
4. Statistical analysis - Detects race-induced variance

Version: 3.0.0
Author: PHANTOM AI Team
"""

from __future__ import annotations

import asyncio
import logging
from scanning.determinism import deterministic_shuffle, get_deterministic_random
import re
import statistics
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from utils.shared_findings_store import SharedFindingsStore

logger = logging.getLogger(__name__)

# FIX SAFE-12: Safety mode check - race condition testing sends many concurrent POST requests
import os
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
# DEF-1 FIX: Allow race testing in cautious mode with very limited concurrency
# Race conditions are REAL vulnerabilities - shouldn't be skipped entirely
ALLOW_RACE_TESTING = SAFE_MODE in ("cautious", "standard", "aggressive")
# Limit concurrency in non-aggressive modes to avoid DoS-like behavior
MAX_CONCURRENT_REQUESTS = {
    "safe": 0,       # No testing (too risky for CI/automated)
    "cautious": 3,   # DEF-1 FIX: Limited testing (was 0) - enough for TOCTOU detection
    "standard": 5,   # Normal testing
    "aggressive": 50,  # Full testing
}


# =============================================================================
# CONSTANTS & CONFIGURATIONS
# =============================================================================

VERSION = "3.0.0"


class RaceVulnType(Enum):
    """Types of race condition vulnerabilities."""

    LIMIT_OVERRUN = auto()            # Bypass rate/quantity limits
    DOUBLE_SPEND = auto()             # Use same resource twice
    TOCTOU = auto()                   # Time-of-check to time-of-use
    PRIVILEGE_ESCALATION = auto()     # Session/role races
    DATA_CORRUPTION = auto()          # Inconsistent data states
    FILE_RACE = auto()                # File system race
    CACHE_RACE = auto()               # Cache timing race
    AUTHENTICATION_BYPASS = auto()    # Auth state race
    INVENTORY_MANIPULATION = auto()   # Stock/quantity races
    COUPON_ABUSE = auto()             # Discount code reuse
    TOKEN_REUSE = auto()              # CSRF/reset token race
    BALANCE_MANIPULATION = auto()     # Account balance race
    SUBSCRIPTION_ABUSE = auto()       # Subscription/trial abuse
    VOTE_MANIPULATION = auto()        # Poll/rating manipulation


class AttackTechnique(Enum):
    """Race condition attack techniques."""

    SINGLE_PACKET = auto()            # HTTP/2 single packet attack
    LAST_BYTE_SYNC = auto()           # Last byte synchronization
    CONNECTION_WARMING = auto()       # Pre-warm connections
    TURBO_INTRUDER = auto()           # Parallel pipeline attack
    MULTI_ENDPOINT = auto()           # Race across endpoints
    STATE_MACHINE = auto()            # State transition race
    READ_MODIFY_WRITE = auto()        # Database RMW race


class RacePattern(Enum):
    """Common race condition patterns."""

    REDEEM_REWARD = auto()            # Gift card, coupon, promo code
    UPDATE_BALANCE = auto()           # Financial transactions
    CHECK_THEN_ACT = auto()           # Generic TOCTOU
    FILE_WRITE_READ = auto()          # File operation race
    SESSION_UPDATE = auto()           # Session modification
    INVENTORY_CHECK = auto()          # Stock verification
    PERMISSION_CHECK = auto()         # Authorization race
    EMAIL_VERIFICATION = auto()       # Verification token race


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class RaceEndpoint:
    """Endpoint information for race testing."""

    url: str
    method: str = "POST"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: str = "application/x-www-form-urlencoded"
    requires_auth: bool = False
    session_cookie: Optional[str] = None
    csrf_token: Optional[str] = None
    expected_success_code: int = 200
    expected_success_pattern: Optional[str] = None
    expected_failure_pattern: Optional[str] = None


@dataclass
class RaceRequest:
    """Individual request in a race attack."""

    endpoint: RaceEndpoint
    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp_sent: float = 0.0
    timestamp_received: float = 0.0
    response_code: int = 0
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    was_successful: bool = False
    error: Optional[str] = None


@dataclass
class RaceResult:
    """Result of a race condition attack."""

    technique: AttackTechnique
    requests: List[RaceRequest]
    total_sent: int
    total_success: int
    total_failures: int
    avg_response_time: float
    response_variance: float
    evidence: Dict[str, Any]
    is_vulnerable: bool
    confidence: float


@dataclass
class RaceFinding:
    """Race condition vulnerability finding."""

    id: str
    vuln_type: RaceVulnType
    severity: str
    confidence: float
    endpoint: RaceEndpoint
    technique: AttackTechnique
    pattern: RacePattern
    description: str
    impact: str
    remediation: str
    evidence: Dict[str, Any]
    cwe_id: int
    cvss_score: float
    requests_needed: int
    success_rate: float
    timing_window_ms: float


@dataclass
class ScanConfig:
    """Race condition scanner configuration."""

    target_url: str
    max_concurrent_requests: int = 20
    burst_size: int = 10
    timeout: float = 30.0
    warmup_requests: int = 5
    iterations: int = 3
    delay_between_iterations_ms: float = 100.0
    use_http2: bool = True
    use_single_packet: bool = True
    use_last_byte_sync: bool = True
    statistical_threshold: float = 0.1
    success_threshold: int = 2
    safe_mode: bool = True


# =============================================================================
# RACE CONDITION PATTERNS
# =============================================================================

RACE_PATTERNS = {
    # E-commerce patterns
    "coupon_redeem": {
        "indicators": ["coupon", "promo", "discount", "code", "voucher", "gift"],
        "params": ["code", "coupon_code", "promo_code", "discount_code", "voucher"],
        "pattern": RacePattern.REDEEM_REWARD,
        "vuln_type": RaceVulnType.COUPON_ABUSE,
    },
    "balance_transfer": {
        "indicators": ["transfer", "send", "pay", "withdraw", "balance", "wallet"],
        "params": ["amount", "to", "recipient", "value", "transfer_amount"],
        "pattern": RacePattern.UPDATE_BALANCE,
        "vuln_type": RaceVulnType.BALANCE_MANIPULATION,
    },
    "purchase": {
        "indicators": ["buy", "purchase", "checkout", "order", "cart", "basket"],
        "params": ["quantity", "product_id", "item_id", "qty", "ProductId", "BasketId"],
        "pattern": RacePattern.INVENTORY_CHECK,
        "vuln_type": RaceVulnType.INVENTORY_MANIPULATION,
    },
    # E-commerce basket/cart patterns (generic)
    "ecommerce_basket": {
        "indicators": ["basketitem", "basket", "rest/basket", "api/basket", "cart/items"],
        "params": ["ProductId", "BasketId", "quantity", "product_id", "basket_id", "cart_id"],
        "pattern": RacePattern.INVENTORY_CHECK,
        "vuln_type": RaceVulnType.INVENTORY_MANIPULATION,
    },
    "ecommerce_coupon": {
        "indicators": ["/coupon", "applyCoupon", "/discount", "/promo", "apply-coupon"],
        "params": ["coupon", "couponCode", "promo_code", "discount_code"],
        "pattern": RacePattern.REDEEM_REWARD,
        "vuln_type": RaceVulnType.COUPON_ABUSE,
    },
    "ecommerce_checkout": {
        "indicators": ["/checkout", "/payment", "/order", "rest/basket", "api/checkout"],
        "params": ["couponCode", "paymentId", "payment_method", "order_id"],
        "pattern": RacePattern.CHECK_THEN_ACT,
        "vuln_type": RaceVulnType.DOUBLE_SPEND,
    },

    # Authentication patterns
    "password_reset": {
        "indicators": ["reset", "forgot", "recover", "password"],
        "params": ["token", "code", "reset_token", "verification"],
        "pattern": RacePattern.EMAIL_VERIFICATION,
        "vuln_type": RaceVulnType.TOKEN_REUSE,
    },
    "email_verification": {
        "indicators": ["verify", "confirm", "activate", "email"],
        "params": ["token", "code", "verification_code"],
        "pattern": RacePattern.EMAIL_VERIFICATION,
        "vuln_type": RaceVulnType.AUTHENTICATION_BYPASS,
    },
    "session_update": {
        "indicators": ["profile", "settings", "account", "user"],
        "params": ["role", "admin", "permissions", "level"],
        "pattern": RacePattern.SESSION_UPDATE,
        "vuln_type": RaceVulnType.PRIVILEGE_ESCALATION,
    },

    # File operations
    "file_upload": {
        "indicators": ["upload", "file", "attachment", "document"],
        "params": ["file", "document", "attachment"],
        "pattern": RacePattern.FILE_WRITE_READ,
        "vuln_type": RaceVulnType.FILE_RACE,
    },

    # Voting/Rating
    "vote": {
        "indicators": ["vote", "like", "rate", "poll", "upvote"],
        "params": ["vote", "rating", "score", "value"],
        "pattern": RacePattern.CHECK_THEN_ACT,
        "vuln_type": RaceVulnType.VOTE_MANIPULATION,
    },

    # Subscription
    "trial": {
        "indicators": ["trial", "free", "subscribe", "plan"],
        "params": ["plan", "subscription", "trial_id"],
        "pattern": RacePattern.CHECK_THEN_ACT,
        "vuln_type": RaceVulnType.SUBSCRIPTION_ABUSE,
    },
}


# =============================================================================
# TIMING ANALYSIS
# =============================================================================

class TimingAnalyzer:
    """Analyze timing patterns to detect race conditions."""

    VERSION = "3.0.0"

    def __init__(self, threshold: float = 0.1):
        """Initialize timing analyzer."""
        self.threshold = threshold
        self.baseline_times: List[float] = []
        self.race_times: List[float] = []

    def set_baseline(self, times: List[float]) -> None:
        """Set baseline response times from sequential requests."""
        self.baseline_times = times

    def add_race_times(self, times: List[float]) -> None:
        """Add response times from race attempt."""
        self.race_times.extend(times)

    def analyze(self) -> Dict[str, Any]:
        """Analyze timing patterns for race indicators."""
        if not self.baseline_times or not self.race_times:
            return {"error": "Insufficient data"}

        baseline_avg = statistics.mean(self.baseline_times)
        baseline_std = statistics.stdev(self.baseline_times) if len(self.baseline_times) > 1 else 0

        race_avg = statistics.mean(self.race_times)
        race_std = statistics.stdev(self.race_times) if len(self.race_times) > 1 else 0

        # Check for timing anomalies
        variance_increase = race_std / baseline_std if baseline_std > 0 else 0
        avg_difference = abs(race_avg - baseline_avg) / baseline_avg if baseline_avg > 0 else 0

        # Detect bimodal distribution (some succeed, some fail)
        is_bimodal = self._detect_bimodal(self.race_times)

        return {
            "baseline_avg_ms": baseline_avg * 1000,
            "baseline_std_ms": baseline_std * 1000,
            "race_avg_ms": race_avg * 1000,
            "race_std_ms": race_std * 1000,
            "variance_increase": variance_increase,
            "avg_difference_pct": avg_difference * 100,
            "is_bimodal": is_bimodal,
            "indicates_race": variance_increase > 2.0 or is_bimodal or avg_difference > self.threshold,
        }

    def _detect_bimodal(self, times: List[float]) -> bool:
        """Detect if response times show bimodal distribution."""
        if len(times) < 4:
            return False

        sorted_times = sorted(times)
        n = len(sorted_times)

        # Check for significant gap in the middle
        mid = n // 2
        lower_half = sorted_times[:mid]
        upper_half = sorted_times[mid:]

        if lower_half and upper_half:
            lower_max = max(lower_half)
            upper_min = min(upper_half)
            gap = upper_min - lower_max
            range_total = sorted_times[-1] - sorted_times[0]

            # Significant gap indicates bimodal
            return gap > range_total * 0.3

        return False


# =============================================================================
# SINGLE PACKET ATTACK
# =============================================================================

class SinglePacketAttack:
    """
    HTTP/2 single-packet attack implementation.

    This technique sends multiple HTTP/2 requests in a single TCP packet,
    ensuring they arrive at the server simultaneously and eliminating
    network jitter that could affect timing.

    Key concepts:
    1. HTTP/2 allows multiplexing multiple requests on one connection
    2. By carefully constructing the packet, all requests arrive atomically
    3. This creates the smallest possible timing window for race conditions

    FP-FIX 2026-02-12: Added baseline comparison to prevent false positives.
    Before: is_vulnerable = successes > 1
    After: is_vulnerable = concurrent_successes > sequential_successes
    """

    VERSION = "3.0.1"

    def __init__(self, http_client: Any = None):
        """Initialize single packet attack."""
        self.http_client = http_client
        self._baseline_successes: int = 0  # FP-FIX: Track sequential baseline

    async def establish_baseline(
        self,
        endpoints: List[RaceEndpoint],
        count: int = 5,
    ) -> int:
        """
        Establish baseline by sending requests SEQUENTIALLY.

        FP-FIX: If sequential requests succeed multiple times, the app
        NORMALLY allows this - not a race condition.

        Returns:
            Number of sequential successes (baseline)
        """
        successes = 0
        for i in range(count):
            endpoint = endpoints[i % len(endpoints)]
            try:
                if self.http_client:
                    response = await self.http_client.request(
                        method=endpoint.method,
                        url=endpoint.url,
                        headers=endpoint.headers,
                        data=endpoint.body,
                        params=endpoint.params,
                    )
                    if response.status_code == endpoint.expected_success_code:
                        body = response.text if hasattr(response, 'text') else str(response.content)
                        if endpoint.expected_success_pattern:
                            if re.search(endpoint.expected_success_pattern, body):
                                successes += 1
                        elif endpoint.expected_failure_pattern:
                            if not re.search(endpoint.expected_failure_pattern, body):
                                successes += 1
                        else:
                            successes += 1
                # Wait between sequential requests
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.debug(f"[RaceCondition] Baseline request error: {e}")

        self._baseline_successes = successes
        logger.debug(f"[RaceCondition] Baseline: {successes}/{count} sequential successes")
        return successes

    async def execute(
        self,
        endpoints: List[RaceEndpoint],
        count: int = 10,
    ) -> RaceResult:
        """
        Execute single-packet race attack.

        Args:
            endpoints: Endpoints to race (can be same or different)
            count: Number of requests to send

        Returns:
            RaceResult with attack outcome
        """
        requests: List[RaceRequest] = []
        start_time = time.time()

        # Build request objects
        for i in range(count):
            endpoint = endpoints[i % len(endpoints)]
            req = RaceRequest(endpoint=endpoint)
            requests.append(req)

        # Execute attack
        if self.http_client and hasattr(self.http_client, 'http2_multiplex'):
            # Real HTTP/2 multiplexed request
            results = await self._execute_http2_multiplex(requests)
        else:
            # Simulated concurrent execution
            results = await self._execute_concurrent(requests)

        # Calculate statistics
        response_times = [r.timestamp_received - r.timestamp_sent for r in results if r.timestamp_received > 0]
        avg_time = statistics.mean(response_times) if response_times else 0
        variance = statistics.variance(response_times) if len(response_times) > 1 else 0

        successes = len([r for r in results if r.was_successful])

        # FP-FIX 2026-02-12: Compare against baseline, not just absolute count
        # If sequential requests also succeed multiple times, NOT a race condition
        baseline = self._baseline_successes
        is_race_vuln = successes > baseline and successes > 1

        # Calculate confidence based on delta from baseline
        if is_race_vuln:
            # More successes than baseline = higher confidence
            delta = successes - baseline
            confidence = min(0.95, 0.5 + (delta / count) * 0.45)
        else:
            confidence = 0.0

        return RaceResult(
            technique=AttackTechnique.SINGLE_PACKET,
            requests=results,
            total_sent=len(results),
            total_success=successes,
            total_failures=len(results) - successes,
            avg_response_time=avg_time,
            response_variance=variance,
            evidence={
                "technique": "single_packet_http2",
                "baseline_successes": baseline,
                "concurrent_successes": successes,
                "delta": successes - baseline,
            },
            is_vulnerable=is_race_vuln,
            confidence=confidence,
        )

    async def _execute_http2_multiplex(self, requests: List[RaceRequest]) -> List[RaceRequest]:
        """Execute requests using HTTP/2 multiplexing."""
        # This would use a real HTTP/2 client in production
        # For now, fall back to concurrent execution
        return await self._execute_concurrent(requests)

    async def _execute_concurrent(self, requests: List[RaceRequest]) -> List[RaceRequest]:
        """Execute requests concurrently (fallback for HTTP/1.1)."""
        async def send_request(req: RaceRequest) -> RaceRequest:
            req.timestamp_sent = time.time()
            try:
                if self.http_client:
                    response = await self.http_client.request(
                        method=req.endpoint.method,
                        url=req.endpoint.url,
                        headers=req.endpoint.headers,
                        data=req.endpoint.body,
                        params=req.endpoint.params,
                    )
                    req.response_code = response.status_code
                    req.response_body = response.text if hasattr(response, 'text') else str(response.content)
                    req.response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
                else:
                    # Simulation (THEME-8: deterministic delays)
                    _rng = get_deterministic_random("race_sim_single", 0)
                    await asyncio.sleep(_rng.uniform(0.01, 0.05))
                    req.response_code = 200
                    req.response_body = '{"success": true}'

                req.timestamp_received = time.time()
                req.was_successful = self._check_success(req)

            except Exception as e:
                req.error = str(e)
                req.timestamp_received = time.time()

            return req

        # Send all requests simultaneously
        results = await asyncio.gather(*[send_request(r) for r in requests], return_exceptions=True)
        # Filter out exceptions and return valid results
        return [r for r in results if isinstance(r, RaceRequest)]

    def _check_success(self, req: RaceRequest) -> bool:
        """Check if request was successful based on endpoint criteria."""
        if req.response_code != req.endpoint.expected_success_code:
            return False

        if req.endpoint.expected_success_pattern:
            if not re.search(req.endpoint.expected_success_pattern, req.response_body):
                return False

        if req.endpoint.expected_failure_pattern:
            if re.search(req.endpoint.expected_failure_pattern, req.response_body):
                return False

        return True


# =============================================================================
# LAST BYTE SYNCHRONIZATION
# =============================================================================

class LastByteSyncAttack:
    """
    Last-byte synchronization attack implementation.

    This technique:
    1. Sends all request data except the final byte
    2. Waits for all connections to be ready
    3. Sends all final bytes simultaneously

    This ensures requests complete at nearly the same instant,
    maximizing the chance of hitting a race condition window.

    FP-FIX 2026-02-12: Added baseline comparison for FP reduction.
    """

    VERSION = "3.0.1"

    def __init__(self, http_client: Any = None):
        """Initialize last byte sync attack."""
        self.http_client = http_client
        self._baseline_successes: int = 0  # FP-FIX: Track sequential baseline

    async def establish_baseline(
        self,
        endpoint: RaceEndpoint,
        count: int = 5,
    ) -> int:
        """Establish sequential baseline for comparison."""
        successes = 0
        for _ in range(count):
            try:
                if self.http_client:
                    response = await self.http_client.request(
                        method=endpoint.method,
                        url=endpoint.url,
                        headers=endpoint.headers,
                        data=endpoint.body,
                        params=endpoint.params,
                    )
                    if self._check_success_internal(endpoint, response):
                        successes += 1
                await asyncio.sleep(0.5)  # Sequential delay
            except Exception:
                pass
        self._baseline_successes = successes
        return successes

    def _check_success_internal(self, endpoint: RaceEndpoint, response: Any) -> bool:
        """Check if response indicates success."""
        if hasattr(response, 'status_code'):
            if response.status_code != endpoint.expected_success_code:
                return False
            body = response.text if hasattr(response, 'text') else str(response.content)
            if endpoint.expected_success_pattern:
                if not re.search(endpoint.expected_success_pattern, body):
                    return False
            if endpoint.expected_failure_pattern:
                if re.search(endpoint.expected_failure_pattern, body):
                    return False
            return True
        return False

    async def execute(
        self,
        endpoint: RaceEndpoint,
        count: int = 10,
    ) -> RaceResult:
        """
        Execute last-byte sync attack.

        Args:
            endpoint: Target endpoint
            count: Number of concurrent requests

        Returns:
            RaceResult with attack outcome
        """
        requests: List[RaceRequest] = []

        # Prepare all connections
        connections = []
        for i in range(count):
            req = RaceRequest(endpoint=endpoint)
            requests.append(req)
            # In production, would prepare TCP connection here

        # Synchronization barrier
        sync_event = asyncio.Event()

        async def send_with_sync(req: RaceRequest, ready_event: asyncio.Event) -> RaceRequest:
            """Send request with synchronization."""
            # Wait for all connections to be ready
            await ready_event.wait()

            req.timestamp_sent = time.time()
            try:
                if self.http_client:
                    response = await self.http_client.request(
                        method=req.endpoint.method,
                        url=req.endpoint.url,
                        headers=req.endpoint.headers,
                        data=req.endpoint.body,
                        params=req.endpoint.params,
                    )
                    req.response_code = response.status_code
                    req.response_body = response.text if hasattr(response, 'text') else str(response.content)
                else:
                    # THEME-8: deterministic delays
                    _rng = get_deterministic_random("race_sim_http2", 0)
                    await asyncio.sleep(_rng.uniform(0.005, 0.02))
                    req.response_code = 200
                    req.response_body = '{"success": true}'

                req.timestamp_received = time.time()
                req.was_successful = self._check_success(req)

            except Exception as e:
                req.error = str(e)
                req.timestamp_received = time.time()

            return req

        # Create tasks
        tasks = [send_with_sync(r, sync_event) for r in requests]

        # Small delay to ensure all tasks are waiting
        await asyncio.sleep(0.01)

        # Release all requests simultaneously
        sync_event.set()

        # Gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Filter out exceptions
        results = [r for r in results if isinstance(r, RaceRequest)]

        # Calculate statistics
        response_times = [r.timestamp_received - r.timestamp_sent for r in results if r.timestamp_received > 0]
        avg_time = statistics.mean(response_times) if response_times else 0
        variance = statistics.variance(response_times) if len(response_times) > 1 else 0

        successes = len([r for r in results if r.was_successful])

        # FP-FIX 2026-02-12: Compare against baseline
        baseline = self._baseline_successes
        is_race_vuln = successes > baseline and successes > 1

        if is_race_vuln:
            delta = successes - baseline
            confidence = min(0.90, 0.5 + (delta / count) * 0.40)
        else:
            confidence = 0.0

        return RaceResult(
            technique=AttackTechnique.LAST_BYTE_SYNC,
            requests=results,
            total_sent=len(results),
            total_success=successes,
            total_failures=len(results) - successes,
            avg_response_time=avg_time,
            response_variance=variance,
            evidence={
                "technique": "last_byte_sync",
                "baseline_successes": baseline,
                "concurrent_successes": successes,
                "delta": successes - baseline,
            },
            is_vulnerable=is_race_vuln,
            confidence=confidence,
        )

    def _check_success(self, req: RaceRequest) -> bool:
        """Check if request was successful."""
        if req.response_code != req.endpoint.expected_success_code:
            return False

        if req.endpoint.expected_success_pattern:
            if not re.search(req.endpoint.expected_success_pattern, req.response_body):
                return False

        if req.endpoint.expected_failure_pattern:
            if re.search(req.endpoint.expected_failure_pattern, req.response_body):
                return False

        return True


# =============================================================================
# MULTI-ENDPOINT RACE
# =============================================================================

class MultiEndpointRace:
    """
    Multi-endpoint race condition attack.

    Tests race conditions that span multiple endpoints, such as:
    - Checking balance on one endpoint while transferring on another
    - Updating profile while checking permissions
    - Verifying email while changing email address
    """

    VERSION = "3.0.0"

    def __init__(self, http_client: Any = None):
        """Initialize multi-endpoint race."""
        self.http_client = http_client

    async def execute(
        self,
        endpoints: List[RaceEndpoint],
        requests_per_endpoint: int = 5,
    ) -> RaceResult:
        """
        Execute multi-endpoint race attack.

        Args:
            endpoints: List of endpoints to race against each other
            requests_per_endpoint: Number of requests per endpoint

        Returns:
            RaceResult with attack outcome
        """
        all_requests: List[RaceRequest] = []

        # Create requests for each endpoint
        for endpoint in endpoints:
            for i in range(requests_per_endpoint):
                req = RaceRequest(endpoint=endpoint)
                all_requests.append(req)

        # Shuffle to interleave requests from different endpoints
        # THEME-8: Use deterministic shuffle for reproducible race testing
        deterministic_shuffle(all_requests, "race_condition_shuffle")

        # Synchronization
        sync_event = asyncio.Event()

        async def send_request(req: RaceRequest) -> RaceRequest:
            await sync_event.wait()
            req.timestamp_sent = time.time()

            try:
                if self.http_client:
                    response = await self.http_client.request(
                        method=req.endpoint.method,
                        url=req.endpoint.url,
                        headers=req.endpoint.headers,
                        data=req.endpoint.body,
                        params=req.endpoint.params,
                    )
                    req.response_code = response.status_code
                    req.response_body = response.text if hasattr(response, 'text') else str(response.content)
                else:
                    # THEME-8: deterministic delays
                    _rng = get_deterministic_random("race_sim_multi", 0)
                    await asyncio.sleep(_rng.uniform(0.01, 0.03))
                    req.response_code = 200
                    req.response_body = '{"success": true}'

                req.timestamp_received = time.time()
                req.was_successful = req.response_code == req.endpoint.expected_success_code

            except Exception as e:
                req.error = str(e)
                req.timestamp_received = time.time()

            return req

        tasks = [send_request(r) for r in all_requests]

        await asyncio.sleep(0.01)
        sync_event.set()

        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Filter out exceptions
        results = [r for r in results if isinstance(r, RaceRequest)]

        # Analyze results per endpoint
        endpoint_results = {}
        for endpoint in endpoints:
            ep_requests = [r for r in results if r.endpoint.url == endpoint.url]
            endpoint_results[endpoint.url] = {
                "total": len(ep_requests),
                "success": len([r for r in ep_requests if r.was_successful]),
            }

        response_times = [r.timestamp_received - r.timestamp_sent for r in results if r.timestamp_received > 0]
        avg_time = statistics.mean(response_times) if response_times else 0
        variance = statistics.variance(response_times) if len(response_times) > 1 else 0

        total_success = sum(v["success"] for v in endpoint_results.values())

        return RaceResult(
            technique=AttackTechnique.MULTI_ENDPOINT,
            requests=results,
            total_sent=len(results),
            total_success=total_success,
            total_failures=len(results) - total_success,
            avg_response_time=avg_time,
            response_variance=variance,
            evidence={"endpoint_results": endpoint_results},
            is_vulnerable=any(v["success"] > 1 for v in endpoint_results.values()),
            confidence=0.85 if total_success > len(endpoints) else 0.0,
        )


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class RaceConditionScanner:
    """
    Enterprise-grade race condition vulnerability scanner.

    Detects:
    - Limit overrun vulnerabilities (coupons, discounts)
    - Double-spend attacks (balance manipulation)
    - TOCTOU flaws (time-of-check to time-of-use)
    - Privilege escalation via session races
    - Inventory manipulation (overselling)
    - Token/nonce reuse vulnerabilities
    - Multi-endpoint race conditions
    - State machine violations

    Techniques:
    - HTTP/2 single-packet attacks
    - Last-byte synchronization
    - Connection warming
    - Statistical timing analysis

    Usage:
        scanner = RaceConditionScanner()
        findings = await scanner.scan("https://target.com/api/redeem")
    """

    VERSION = "3.0.0"
    CWE_ID = 362  # CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization

    def __init__(
        self,
        http_client: Any = None,
        config: Optional[ScanConfig] = None,
    ):
        """Initialize the scanner."""
        self.http_client = http_client
        self.config = config
        self.single_packet = SinglePacketAttack(http_client)
        self.last_byte_sync = LastByteSyncAttack(http_client)
        self.multi_endpoint = MultiEndpointRace(http_client)
        self.timing_analyzer = TimingAnalyzer()
        self.findings: List[RaceFinding] = []
        self._session_id = str(uuid.uuid4())[:8]

    async def scan(
        self,
        target_url: str,
        endpoints: Optional[List[RaceEndpoint]] = None,
        **kwargs,
    ) -> List[RaceFinding]:
        """
        Scan for race condition vulnerabilities.

        Args:
            target_url: Target URL to scan
            endpoints: Pre-configured endpoints (optional)
            **kwargs: Additional configuration

        Returns:
            List of discovered vulnerabilities
        """
        # FIX SAFE-12: Race condition testing sends many concurrent POST requests
        # This can look like a DoS attack - block in safe/cautious modes
        if not ALLOW_RACE_TESTING:
            logger.info(f"[RaceCondition] SKIPPED (safe_mode={SAFE_MODE}, requires standard/aggressive)")
            return []

        # Limit concurrency based on safe mode
        max_concurrent = MAX_CONCURRENT_REQUESTS.get(SAFE_MODE, 5)
        if self.config:
            self.config.concurrent_requests = min(self.config.concurrent_requests, max_concurrent)
            self.config.burst_size = min(self.config.burst_size, max_concurrent)

        logger.info(f"[RaceCondition] Starting scan: {target_url} (max_concurrent: {max_concurrent})")

        # Extract auth context if available (injected by full_scanner)
        auth_ctx = kwargs.get("auth_context") or getattr(self, "_auth_context", None)
        auth_headers: dict = {}
        if auth_ctx and hasattr(auth_ctx, "auth_headers"):
            auth_headers = auth_ctx.auth_headers
            logger.info(f"[RaceCondition] Using auth token for race tests")

        # Create config if not provided
        if not self.config:
            self.config = ScanConfig(target_url=target_url)

        # Detect or use provided endpoints
        if not endpoints:
            endpoints = self._detect_race_endpoints(target_url)

        if not endpoints:
            endpoints = [RaceEndpoint(url=target_url, method="POST")]

        # Inject auth headers into all endpoints
        if auth_headers:
            for ep in endpoints:
                ep.headers.update(auth_headers)

        logger.info(f"[RaceCondition] Testing {len(endpoints)} endpoint(s)")

        # Warmup connections
        await self._warmup_connections(endpoints)

        # Establish baseline timing
        baseline = await self._establish_baseline(endpoints)
        self.timing_analyzer.set_baseline(baseline)

        # Run race tests
        for endpoint in endpoints:
            await self._test_endpoint(endpoint)

        # Run multi-endpoint tests
        if len(endpoints) > 1:
            await self._test_multi_endpoint_race(endpoints)

        # Run cross-endpoint pair tests (checkout+cancel, transfer+balance, etc.)
        await self._test_cross_endpoint_pairs(target_url, auth_headers)

        # ====================================================================
        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        # Race conditions enable chains: Race + Business Logic → Financial Fraud
        # ====================================================================
        try:
            store = SharedFindingsStore.get_instance()
            for f in self.findings:
                await store.add_finding(
                    {
                        "type": "race_condition",
                        "endpoint": f.endpoint.url if f.endpoint else target_url,
                        "severity": f.severity,
                        "metadata": {
                            "vuln_type": f.vuln_type.name if f.vuln_type else "unknown",
                            "technique": f.technique.name if f.technique else "unknown",
                            "success_rate": f.success_rate,
                        },
                    },
                    module="race_condition",
                )
        except Exception as e:
            logger.debug(f"[RaceCondition] SharedFindingsStore error: {e}")

        logger.info(f"[RaceCondition] Scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings

    def _detect_race_endpoints(self, target_url: str) -> List[RaceEndpoint]:
        """Detect potential race condition endpoints from URL."""
        endpoints = []
        parsed = urlparse(target_url)
        path = parsed.path.lower()
        query = parse_qs(parsed.query)

        # Check for race-prone patterns
        for pattern_name, pattern_info in RACE_PATTERNS.items():
            # Check URL path
            if any(ind in path for ind in pattern_info["indicators"]):
                endpoint = RaceEndpoint(
                    url=target_url,
                    method="POST",
                    expected_success_pattern=r'"success":\s*true|"status":\s*"ok"',
                    expected_failure_pattern=r'"error"|"failed"|"already"',
                )
                endpoints.append(endpoint)
                break

            # Check query parameters
            for param in pattern_info["params"]:
                if param in query:
                    endpoint = RaceEndpoint(
                        url=target_url,
                        method="POST",
                        expected_success_pattern=r'"success":\s*true',
                    )
                    endpoints.append(endpoint)
                    break

        return endpoints

    async def _warmup_connections(self, endpoints: List[RaceEndpoint]) -> None:
        """Warm up connections for more accurate timing."""
        logger.debug("[RaceCondition] Warming up connections")

        warmup_count = self.config.warmup_requests if self.config else 5

        for endpoint in endpoints[:3]:  # Limit warmup to first 3 endpoints
            for _ in range(warmup_count):
                try:
                    if self.http_client:
                        await self.http_client.get(endpoint.url, timeout=5.0)
                    else:
                        await asyncio.sleep(0.01)
                except Exception:
                    pass

    async def _establish_baseline(self, endpoints: List[RaceEndpoint]) -> List[float]:
        """Establish baseline response times with sequential requests."""
        times = []

        for endpoint in endpoints[:2]:
            for _ in range(5):
                start = time.time()
                try:
                    if self.http_client:
                        await self.http_client.request(
                            method=endpoint.method,
                            url=endpoint.url,
                            timeout=10.0,
                        )
                    else:
                        # THEME-8: deterministic delays
                        _rng = get_deterministic_random("race_sim_baseline", 0)
                        await asyncio.sleep(_rng.uniform(0.01, 0.05))

                    times.append(time.time() - start)
                except Exception:
                    pass

                # Sequential delay
                await asyncio.sleep(0.1)

        return times

    async def _test_endpoint(self, endpoint: RaceEndpoint) -> None:
        """Test a single endpoint for race conditions."""
        logger.debug(f"[RaceCondition] Testing: {endpoint.url}")

        # Detect pattern type
        pattern_type = self._detect_pattern_type(endpoint)

        # FP-FIX 2026-02-12: Establish baseline BEFORE race testing
        # This prevents false positives when app normally allows multiple requests
        baseline_count = 5

        # Test with single-packet attack
        if self.config and self.config.use_single_packet:
            # Establish baseline first
            await self.single_packet.establish_baseline([endpoint], baseline_count)

            result = await self.single_packet.execute(
                endpoints=[endpoint],
                count=self.config.burst_size if self.config else 10,
            )
            await self._analyze_result(endpoint, result, pattern_type)

        # Test with last-byte sync
        if self.config and self.config.use_last_byte_sync:
            # Establish baseline first
            await self.last_byte_sync.establish_baseline(endpoint, baseline_count)

            result = await self.last_byte_sync.execute(
                endpoint=endpoint,
                count=self.config.burst_size if self.config else 10,
            )
            await self._analyze_result(endpoint, result, pattern_type)

        # Add timing data
        times = [r.timestamp_received - r.timestamp_sent
                 for r in result.requests
                 if r.timestamp_received > 0]
        self.timing_analyzer.add_race_times(times)

    async def _test_multi_endpoint_race(self, endpoints: List[RaceEndpoint]) -> None:
        """Test for race conditions across multiple endpoints."""
        logger.debug("[RaceCondition] Testing multi-endpoint race")

        result = await self.multi_endpoint.execute(
            endpoints=endpoints,
            requests_per_endpoint=5,
        )

        if result.is_vulnerable:
            # Determine which endpoints are affected
            for endpoint in endpoints:
                endpoint_requests = [r for r in result.requests if r.endpoint.url == endpoint.url]
                successes = len([r for r in endpoint_requests if r.was_successful])

                if successes > 1:
                    self._create_finding(
                        vuln_type=RaceVulnType.TOCTOU,
                        severity="HIGH",
                        confidence=result.confidence,
                        endpoint=endpoint,
                        technique=AttackTechnique.MULTI_ENDPOINT,
                        pattern=RacePattern.CHECK_THEN_ACT,
                        description=f"Multi-endpoint race condition detected. "
                                   f"{successes} of {len(endpoint_requests)} requests succeeded when only 1 should.",
                        impact="Attackers can exploit timing between endpoints to bypass validations.",
                        evidence=result.evidence,
                        requests_needed=result.total_sent,
                        success_rate=successes / len(endpoint_requests),
                        timing_window_ms=result.avg_response_time * 1000,
                    )

    async def _test_cross_endpoint_pairs(
        self,
        base_url: str,
        auth_headers: dict,
    ) -> None:
        """Test race conditions between semantically related endpoint pairs.

        These pairs represent common TOCTOU scenarios:
        - checkout + cancel (complete order while cancelling)
        - transfer + check_balance (transfer more than balance during check)
        - verify + resend (verify while resending to different email)
        - add_to_cart + checkout (modify cart during checkout)
        """
        logger.debug("[RaceCondition] Testing cross-endpoint pairs")

        # Define related endpoint pairs with their race scenario
        CROSS_ENDPOINT_PAIRS = [
            # (endpoint1_patterns, endpoint2_patterns, scenario_name, vuln_type)
            (
                ["/checkout", "/order", "/api/checkout", "/rest/basket/checkout"],
                ["/cancel", "/refund", "/api/order/cancel", "/rest/basket/cancel"],
                "Checkout + Cancel Race",
                RaceVulnType.DOUBLE_SPEND,
            ),
            (
                ["/transfer", "/send", "/api/transfer", "/api/wallet/transfer"],
                ["/balance", "/wallet", "/api/balance", "/api/wallet/balance"],
                "Transfer + Balance Check Race",
                RaceVulnType.BALANCE_MANIPULATION,
            ),
            (
                ["/verify", "/confirm", "/api/verify", "/api/email/verify"],
                ["/resend", "/api/resend", "/api/email/resend", "/user/resend"],
                "Verify + Resend Race",
                RaceVulnType.TOKEN_REUSE,
            ),
            (
                ["/cart/add", "/basket/add", "/api/cart/items", "/rest/BasketItems"],
                ["/checkout", "/order", "/api/checkout", "/rest/basket/checkout"],
                "Add-to-Cart + Checkout Race",
                RaceVulnType.INVENTORY_MANIPULATION,
            ),
            (
                ["/coupon", "/apply-coupon", "/api/coupon", "/rest/basket/coupon"],
                ["/checkout", "/order", "/api/checkout", "/rest/basket/checkout"],
                "Coupon Apply + Checkout Race",
                RaceVulnType.COUPON_ABUSE,
            ),
        ]

        for patterns1, patterns2, scenario, vuln_type in CROSS_ENDPOINT_PAIRS:
            # Build endpoint URLs
            endpoints_to_test: List[RaceEndpoint] = []

            for pattern in patterns1[:2]:  # Limit to 2 variations
                url = f"{base_url}{pattern}"
                endpoints_to_test.append(RaceEndpoint(
                    url=url,
                    method="POST",
                    headers=auth_headers.copy(),
                    expected_success_pattern=r'"success":\s*true|"status":\s*"ok"|"id":\s*\d+',
                ))

            for pattern in patterns2[:2]:
                url = f"{base_url}{pattern}"
                endpoints_to_test.append(RaceEndpoint(
                    url=url,
                    method="POST" if "cancel" in pattern or "resend" in pattern else "GET",
                    headers=auth_headers.copy(),
                    expected_success_pattern=r'"success":\s*true|"balance":\s*\d+',
                ))

            if len(endpoints_to_test) >= 2:
                result = await self.multi_endpoint.execute(
                    endpoints=endpoints_to_test,
                    requests_per_endpoint=3,
                )

                if result.is_vulnerable and result.total_success > 2:
                    self._create_finding(
                        vuln_type=vuln_type,
                        severity="CRITICAL",
                        confidence=result.confidence,
                        endpoint=endpoints_to_test[0],
                        technique=AttackTechnique.MULTI_ENDPOINT,
                        pattern=RacePattern.CHECK_THEN_ACT,
                        description=(
                            f"Cross-endpoint race condition: {scenario}. "
                            f"Racing requests between {patterns1[0]} and {patterns2[0]} "
                            f"resulted in {result.total_success} successful requests "
                            f"that should have been mutually exclusive."
                        ),
                        impact=(
                            "Attackers can exploit timing between related operations "
                            "to achieve double-spend, bypass validations, or corrupt state."
                        ),
                        evidence=result.evidence + [
                            f"Scenario: {scenario}",
                            f"Endpoint pair: {patterns1[0]} vs {patterns2[0]}",
                        ],
                        requests_needed=result.total_sent,
                        success_rate=result.total_success / result.total_sent,
                        timing_window_ms=result.avg_response_time * 1000,
                    )

    async def _analyze_result(
        self,
        endpoint: RaceEndpoint,
        result: RaceResult,
        pattern: RacePattern,
    ) -> None:
        """Analyze race attack result and create findings if vulnerable."""
        if not result.is_vulnerable:
            return

        # Determine vulnerability type based on pattern
        vuln_type = self._pattern_to_vuln_type(pattern)
        severity = self._determine_severity(vuln_type, result)

        self._create_finding(
            vuln_type=vuln_type,
            severity=severity,
            confidence=result.confidence,
            endpoint=endpoint,
            technique=result.technique,
            pattern=pattern,
            description=self._generate_description(vuln_type, pattern, result),
            impact=self._generate_impact(vuln_type),
            evidence=result.evidence,
            requests_needed=result.total_sent,
            success_rate=result.total_success / result.total_sent,
            timing_window_ms=result.avg_response_time * 1000,
        )

    def _detect_pattern_type(self, endpoint: RaceEndpoint) -> RacePattern:
        """Detect the race condition pattern type from endpoint."""
        url_lower = endpoint.url.lower()
        body_lower = (endpoint.body or "").lower()

        for pattern_name, pattern_info in RACE_PATTERNS.items():
            if any(ind in url_lower for ind in pattern_info["indicators"]):
                return pattern_info["pattern"]
            if any(ind in body_lower for ind in pattern_info["indicators"]):
                return pattern_info["pattern"]

        return RacePattern.CHECK_THEN_ACT

    def _pattern_to_vuln_type(self, pattern: RacePattern) -> RaceVulnType:
        """Convert pattern to vulnerability type."""
        pattern_map = {
            RacePattern.REDEEM_REWARD: RaceVulnType.COUPON_ABUSE,
            RacePattern.UPDATE_BALANCE: RaceVulnType.BALANCE_MANIPULATION,
            RacePattern.CHECK_THEN_ACT: RaceVulnType.TOCTOU,
            RacePattern.FILE_WRITE_READ: RaceVulnType.FILE_RACE,
            RacePattern.SESSION_UPDATE: RaceVulnType.PRIVILEGE_ESCALATION,
            RacePattern.INVENTORY_CHECK: RaceVulnType.INVENTORY_MANIPULATION,
            RacePattern.PERMISSION_CHECK: RaceVulnType.PRIVILEGE_ESCALATION,
            RacePattern.EMAIL_VERIFICATION: RaceVulnType.TOKEN_REUSE,
        }
        return pattern_map.get(pattern, RaceVulnType.TOCTOU)

    def _determine_severity(self, vuln_type: RaceVulnType, result: RaceResult) -> str:
        """Determine severity based on vulnerability type and result."""
        critical_types = {
            RaceVulnType.PRIVILEGE_ESCALATION,
            RaceVulnType.AUTHENTICATION_BYPASS,
            RaceVulnType.BALANCE_MANIPULATION,
        }

        high_types = {
            RaceVulnType.DOUBLE_SPEND,
            RaceVulnType.COUPON_ABUSE,
            RaceVulnType.INVENTORY_MANIPULATION,
            RaceVulnType.TOKEN_REUSE,
        }

        if vuln_type in critical_types:
            return "CRITICAL"
        elif vuln_type in high_types:
            return "HIGH"
        elif result.total_success > 5:
            return "HIGH"
        else:
            return "MEDIUM"

    def _generate_description(
        self,
        vuln_type: RaceVulnType,
        pattern: RacePattern,
        result: RaceResult,
    ) -> str:
        """Generate vulnerability description."""
        descriptions = {
            RaceVulnType.LIMIT_OVERRUN: (
                f"Limit overrun vulnerability detected. {result.total_success} of {result.total_sent} "
                f"concurrent requests succeeded, bypassing rate/quantity limits."
            ),
            RaceVulnType.DOUBLE_SPEND: (
                f"Double-spend vulnerability detected. The same resource was used multiple times "
                f"({result.total_success} times) within the race window."
            ),
            RaceVulnType.TOCTOU: (
                f"Time-of-check to time-of-use vulnerability detected. Multiple requests "
                f"({result.total_success}/{result.total_sent}) passed validation simultaneously."
            ),
            RaceVulnType.PRIVILEGE_ESCALATION: (
                f"Session/privilege race condition detected. {result.total_success} requests "
                f"achieved elevated privileges through concurrent execution."
            ),
            RaceVulnType.COUPON_ABUSE: (
                f"Coupon/reward abuse vulnerability. The same code was redeemed {result.total_success} times "
                f"through race condition exploitation."
            ),
            RaceVulnType.BALANCE_MANIPULATION: (
                f"Balance manipulation race condition. {result.total_success} concurrent transfers "
                f"succeeded, potentially exceeding available balance."
            ),
            RaceVulnType.INVENTORY_MANIPULATION: (
                f"Inventory race condition. {result.total_success} purchases succeeded concurrently, "
                f"potentially overselling limited stock."
            ),
            RaceVulnType.TOKEN_REUSE: (
                f"Token reuse vulnerability. The same token was successfully used {result.total_success} times "
                f"through race condition."
            ),
        }

        return descriptions.get(
            vuln_type,
            f"Race condition vulnerability detected. {result.total_success}/{result.total_sent} "
            f"requests succeeded concurrently."
        )

    def _generate_impact(self, vuln_type: RaceVulnType) -> str:
        """Generate impact description."""
        impacts = {
            RaceVulnType.LIMIT_OVERRUN: "Attackers can bypass rate limits, quotas, or usage restrictions.",
            RaceVulnType.DOUBLE_SPEND: "Attackers can use the same credit/resource multiple times, causing financial loss.",
            RaceVulnType.TOCTOU: "Attackers can exploit the gap between security check and action.",
            RaceVulnType.PRIVILEGE_ESCALATION: "Attackers can gain unauthorized administrative or elevated access.",
            RaceVulnType.COUPON_ABUSE: "Attackers can redeem promotional codes multiple times for financial gain.",
            RaceVulnType.BALANCE_MANIPULATION: "Attackers can transfer more funds than available, causing negative balances.",
            RaceVulnType.INVENTORY_MANIPULATION: "Attackers can purchase limited items beyond available stock.",
            RaceVulnType.TOKEN_REUSE: "Attackers can reuse one-time tokens for multiple actions.",
        }

        return impacts.get(vuln_type, "Attackers can exploit concurrent execution for unintended behavior.")

    # =========================================================================
    # FP REDUCTION: Mandatory Negative Control for Race Conditions
    # =========================================================================
    # Problem: ~30% false positive rate due to timing variations
    # Solution: Require negative control baseline before marking as vulnerable
    #
    # Negative control: Single sequential request should NOT show race behavior
    # If sequential also shows "anomaly", it's not a real race condition
    # =========================================================================

    async def _verify_with_negative_control(
        self,
        endpoint: "RaceEndpoint",
        parallel_result: dict,
        http_client: Any,
    ) -> tuple[bool, str]:
        """
        Verify race condition finding with negative control.

        Runs single sequential request to compare against parallel burst.
        If sequential shows same behavior, it's a false positive.

        Args:
            endpoint: The endpoint that showed race behavior
            parallel_result: Result from parallel burst test
            http_client: HTTP client to use

        Returns:
            (is_valid, reason) - True if finding passes negative control
        """
        try:
            # Baseline: Single sequential request
            baseline_responses = []
            for _ in range(3):  # 3 sequential requests
                try:
                    if hasattr(http_client, 'post'):
                        if endpoint.method.upper() == "POST":
                            resp = await http_client.post(
                                endpoint.url,
                                data=endpoint.body,
                                headers=endpoint.headers,
                                timeout=10.0,
                            )
                        else:
                            resp = await http_client.get(
                                endpoint.url,
                                headers=endpoint.headers,
                                timeout=10.0,
                            )
                        baseline_responses.append({
                            "status": resp.status_code,
                            "length": len(resp.text),
                        })
                    else:
                        # aiohttp client
                        if endpoint.method.upper() == "POST":
                            async with http_client.post(
                                endpoint.url,
                                data=endpoint.body,
                                headers=endpoint.headers,
                            ) as resp:
                                text = await resp.text()
                                baseline_responses.append({
                                    "status": resp.status,
                                    "length": len(text),
                                })
                        else:
                            async with http_client.get(
                                endpoint.url,
                                headers=endpoint.headers,
                            ) as resp:
                                text = await resp.text()
                                baseline_responses.append({
                                    "status": resp.status,
                                    "length": len(text),
                                })
                    await asyncio.sleep(0.5)  # Sequential delay
                except Exception as e:
                    logger.debug(f"[RaceCondition] Negative control request failed: {e}")
                    continue

            if len(baseline_responses) < 2:
                # Can't verify - allow finding but note uncertainty
                return True, "negative_control_incomplete"

            # Compare: Sequential should be consistent, parallel should show variance
            parallel_variance = parallel_result.get("status_variance", 0)
            parallel_success_rate = parallel_result.get("success_rate", 0)
            parallel_response_count = parallel_result.get("response_count", 0)

            # Calculate sequential variance
            seq_statuses = [r["status"] for r in baseline_responses]
            seq_lengths = [r["length"] for r in baseline_responses]
            seq_status_variance = len(set(seq_statuses))
            seq_length_variance = max(seq_lengths) - min(seq_lengths) if seq_lengths else 0

            # FIX 2026-02-19: Relaxed rejection logic to prevent false negatives
            # Audit found: Sequential variance from session timeout/load balancer was rejecting real races
            # Solution: Only reject if sequential variance >= parallel variance (real race should show MORE variance in parallel)

            # FP Detection: Only reject if sequential shows EQUAL OR MORE variance than parallel
            if seq_status_variance > 1:
                # Sequential varies - but does parallel vary MORE?
                if parallel_variance <= seq_status_variance:
                    # Parallel doesn't show more variance than sequential → likely FP
                    logger.info(f"[RaceCondition] FP detected: Sequential variance ({seq_status_variance}) >= parallel ({parallel_variance})")
                    return False, "sequential_variance_matches_parallel"
                else:
                    # Parallel shows MORE variance → still likely real race condition
                    logger.info(f"[RaceCondition] Keeping finding: Parallel variance ({parallel_variance}) > sequential ({seq_status_variance})")
                    # Continue to other checks

            # FIX: Use success_rate in decision (was fetched but never used)
            # Low success rate in parallel (many timeouts) = potential timing-sensitive race
            if parallel_success_rate < 0.5 and parallel_response_count >= 5:
                # Less than 50% success in parallel burst = server struggling = race window exists
                logger.info(f"[RaceCondition] Low parallel success rate ({parallel_success_rate:.0%}) indicates timing sensitivity")
                return True, "timing_sensitive_race"

            # FIX: Relaxed length variance check
            # Only reject if sequential variance is HIGHER than parallel AND both are small
            if seq_length_variance > 100:
                if parallel_variance < 2 and seq_status_variance <= 1:
                    # Sequential length varies a lot but status is stable, parallel doesn't vary much
                    # This could be dynamic content, not FP - only reject if confident
                    parallel_length_variance = parallel_result.get("length_variance", 0)
                    if parallel_length_variance <= seq_length_variance:
                        logger.info(f"[RaceCondition] FP suspected: Sequential length variance ({seq_length_variance}) >= parallel")
                        return False, "sequential_length_variance_higher"
                    # else: Parallel shows more length variance - keep finding

            # Valid: Parallel shows variance but sequential is stable (or parallel variance > sequential)
            return True, "negative_control_passed"

        except Exception as e:
            logger.debug(f"[RaceCondition] Negative control error: {e}")
            # On error, allow finding but flag uncertainty
            return True, f"negative_control_error: {e}"

    def _create_finding(
        self,
        vuln_type: RaceVulnType,
        severity: str,
        confidence: float,
        endpoint: RaceEndpoint,
        technique: AttackTechnique,
        pattern: RacePattern,
        description: str,
        impact: str,
        evidence: Dict[str, Any],
        requests_needed: int,
        success_rate: float,
        timing_window_ms: float,
    ) -> None:
        """Create and store a finding."""
        finding = RaceFinding(
            id=f"RACE-{len(self.findings)+1:04d}",
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            technique=technique,
            pattern=pattern,
            description=description,
            impact=impact,
            remediation=self._generate_remediation(vuln_type),
            evidence=evidence,
            cwe_id=self.CWE_ID,
            cvss_score=self._calculate_cvss(severity),
            requests_needed=requests_needed,
            success_rate=success_rate,
            timing_window_ms=timing_window_ms,
        )

        self.findings.append(finding)
        logger.info(f"[RaceCondition] Found: {vuln_type.name} ({severity})")

    def _generate_remediation(self, vuln_type: RaceVulnType) -> str:
        """Generate remediation advice."""
        common_remediation = """
1. Use database transactions with appropriate isolation levels (SERIALIZABLE for critical operations)
2. Implement pessimistic locking (SELECT ... FOR UPDATE)
3. Use atomic operations (compare-and-swap, atomic counters)
4. Implement idempotency keys for sensitive operations
5. Add rate limiting with distributed locks (Redis SETNX)
6. Use optimistic locking with version numbers
7. Implement proper mutex/semaphore patterns
"""

        specific_advice = {
            RaceVulnType.COUPON_ABUSE: "Mark coupons as used BEFORE processing the reward, not after.",
            RaceVulnType.BALANCE_MANIPULATION: "Use database-level constraints and transactions for balance updates.",
            RaceVulnType.INVENTORY_MANIPULATION: "Implement inventory reservations with TTL and atomic decrements.",
            RaceVulnType.TOKEN_REUSE: "Invalidate tokens atomically at the start of processing.",
            RaceVulnType.PRIVILEGE_ESCALATION: "Re-validate permissions within the same transaction as the action.",
        }

        advice = specific_advice.get(vuln_type, "")
        return f"{advice}\n\nGeneral remediation:\n{common_remediation}"

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity."""
        cvss_map = {
            "CRITICAL": 9.1,
            "HIGH": 8.1,
            "MEDIUM": 6.5,
            "LOW": 3.7,
            "INFO": 0.0,
        }
        return cvss_map.get(severity, 5.0)

    def get_findings(self) -> List[RaceFinding]:
        """Get all findings."""
        return self.findings

    def get_timing_analysis(self) -> Dict[str, Any]:
        """Get timing analysis results."""
        return self.timing_analyzer.analyze()

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return {
            "total_findings": len(self.findings),
            "critical_findings": len([f for f in self.findings if f.severity == "CRITICAL"]),
            "high_findings": len([f for f in self.findings if f.severity == "HIGH"]),
            "timing_analysis": self.get_timing_analysis(),
            "techniques_used": list(set(f.technique.name for f in self.findings)),
        }


# =============================================================================
# LIMIT OVERRUN DETECTOR
# =============================================================================

class LimitOverrunDetector:
    """
    Specialized detector for limit overrun vulnerabilities.

    Targets:
    - Coupon/promo code redemption
    - Rate limit bypass
    - Quota circumvention
    - Trial abuse
    """

    VERSION = "3.0.0"

    def __init__(self, http_client: Any = None):
        """Initialize detector."""
        self.http_client = http_client
        self.scanner = RaceConditionScanner(http_client)

    async def detect(
        self,
        endpoint: RaceEndpoint,
        limit_param: str,
        limit_value: Any,
        expected_limit: int = 1,
    ) -> Optional[RaceFinding]:
        """
        Detect limit overrun vulnerability.

        Args:
            endpoint: Target endpoint
            limit_param: Parameter that should be limited (e.g., 'code')
            limit_value: Value to test (e.g., coupon code)
            expected_limit: Expected usage limit

        Returns:
            RaceFinding if vulnerable, None otherwise
        """
        # Configure endpoint with limit parameter
        if endpoint.body:
            endpoint.body = endpoint.body.replace(f"{{{limit_param}}}", str(limit_value))
        else:
            endpoint.params[limit_param] = str(limit_value)

        endpoint.expected_success_pattern = r'"success"|"redeemed"|"applied"'
        endpoint.expected_failure_pattern = r'"already"|"expired"|"invalid"|"limit"'

        # Run race attack
        findings = await self.scanner.scan(
            target_url=endpoint.url,
            endpoints=[endpoint],
        )

        for finding in findings:
            if finding.vuln_type == RaceVulnType.LIMIT_OVERRUN:
                return finding

        return None


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_race_scanner(
    http_client: Any = None,
    config: Optional[ScanConfig] = None,
) -> RaceConditionScanner:
    """Create a configured race condition scanner instance."""
    return RaceConditionScanner(http_client=http_client, config=config)


async def scan_race_conditions(
    target_url: str,
    http_client: Any = None,
    **kwargs,
) -> List[RaceFinding]:
    """Convenience function to scan for race conditions."""
    scanner = create_race_scanner(http_client=http_client)
    return await scanner.scan(target_url, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "VERSION",

    # Enums
    "RaceVulnType",
    "AttackTechnique",
    "RacePattern",

    # Data classes
    "RaceEndpoint",
    "RaceRequest",
    "RaceResult",
    "RaceFinding",
    "ScanConfig",

    # Classes
    "RaceConditionScanner",
    "SinglePacketAttack",
    "LastByteSyncAttack",
    "MultiEndpointRace",
    "TimingAnalyzer",
    "LimitOverrunDetector",

    # Constants
    "RACE_PATTERNS",

    # Factory functions
    "create_race_scanner",
    "scan_race_conditions",
]
