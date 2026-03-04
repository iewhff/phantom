"""
Adaptive Timeout System for PHANTOM Scanner
============================================

Philosophy: "Timeouts should match target reality, not arbitrary defaults."

Problem:
- Legacy PHP apps (DVWA, bWAPP) are slow → 300s timeout may be too short
- Modern APIs respond in <100ms → 600s timeout wastes resources
- Different modules have different time requirements

Solution:
- Baseline measurement at scan start
- Target-type based multipliers (PHP legacy vs modern API)
- Module category profiles (quick vs thorough vs network-dependent)
- Dynamic adjustment based on observed performance
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple
from utils.logger import get_logger

logger = get_logger(__name__)

__all__ = [
    # Timeout management
    "AdaptiveTimeoutManager",
    "TimeoutProfile",
    "ModuleCategory",
    "TargetProfile",
    "get_timeout_manager",
    "reset_timeout_manager",
    # Early termination
    "EarlyTerminationController",
    "TerminationReason",
    "ModuleHealth",
    "get_termination_controller",
    "reset_termination_controller",
]


class ModuleCategory(Enum):
    """Module categories based on their execution characteristics."""
    # Quick modules - response analysis only, no active probing
    QUICK = auto()          # cors, headers, ssl, clickjacking (30-60s)

    # Standard modules - active probing with limited payloads
    STANDARD = auto()       # info_disclosure, cookie, rate_limit (120-180s)

    # Thorough modules - deep injection testing, many payloads
    THOROUGH = auto()       # sqli, xss, cmdi, lfi, ssti (300-600s)

    # Network-dependent - external calls, DNS, OOB callbacks
    NETWORK = auto()        # ssrf, dns_rebinding, xxe blind (300-600s)

    # Browser-dependent - requires headless browser interaction
    BROWSER = auto()        # dom_xss, spa crawling (600-900s)

    # Stateful - multi-step flows, session manipulation
    STATEFUL = auto()       # business_logic, auth, race_condition (600-900s)

    # Heavy - protocol-level, multi-request analysis
    HEAVY = auto()          # smuggling, graphql introspection (600-900s)

    # External tools - calls nuclei, nmap, etc.
    EXTERNAL = auto()       # nuclei, linux_tools (900-1200s)


# Module to category mapping
MODULE_CATEGORIES: Dict[str, ModuleCategory] = {
    # QUICK (30-60s baseline)
    "cors": ModuleCategory.QUICK,
    "header_security": ModuleCategory.QUICK,
    "clickjacking": ModuleCategory.QUICK,
    "ssl": ModuleCategory.QUICK,

    # STANDARD (120-180s baseline)
    # G-10 FIX: Moved cookie from QUICK to STANDARD (90s was too short)
    "cookie": ModuleCategory.STANDARD,
    "info_disclosure": ModuleCategory.STANDARD,
    "dir": ModuleCategory.STANDARD,
    "rate_limit": ModuleCategory.STANDARD,
    "open_redirect": ModuleCategory.STANDARD,
    "crlf": ModuleCategory.STANDARD,
    "host_header": ModuleCategory.STANDARD,
    "email_security": ModuleCategory.STANDARD,
    "secrets_pattern": ModuleCategory.STANDARD,
    "config_exposure": ModuleCategory.STANDARD,

    # THOROUGH (300-600s baseline)
    "sqli": ModuleCategory.THOROUGH,
    "xss": ModuleCategory.THOROUGH,
    "cmdi": ModuleCategory.THOROUGH,
    "lfi": ModuleCategory.THOROUGH,
    "ssti": ModuleCategory.THOROUGH,
    "nosql": ModuleCategory.THOROUGH,
    "xxe": ModuleCategory.THOROUGH,
    "deserialization": ModuleCategory.THOROUGH,
    "prototype_pollution": ModuleCategory.THOROUGH,
    "mass_assignment": ModuleCategory.THOROUGH,
    "ldap_xpath": ModuleCategory.STANDARD,  # G-08 FIX: Reduced from THOROUGH (400s→180s)

    # NETWORK (300-600s baseline)
    "ssrf": ModuleCategory.NETWORK,
    "dns_rebinding": ModuleCategory.NETWORK,
    "subdomain_takeover": ModuleCategory.NETWORK,
    "third_party": ModuleCategory.NETWORK,

    # BROWSER (600-900s baseline)
    "dom_xss": ModuleCategory.BROWSER,
    "spa_crawler": ModuleCategory.BROWSER,

    # STATEFUL (600-900s baseline)
    "business_logic": ModuleCategory.STATEFUL,
    "auth": ModuleCategory.STATEFUL,
    "session_abuse": ModuleCategory.STATEFUL,
    "race_condition": ModuleCategory.STATEFUL,
    "oauth": ModuleCategory.STATEFUL,
    "jwt": ModuleCategory.STATEFUL,
    "saml": ModuleCategory.STATEFUL,
    "mfa_bypass": ModuleCategory.STATEFUL,
    "authorization": ModuleCategory.STATEFUL,
    "api_logic": ModuleCategory.STATEFUL,
    "creative_exploiter": ModuleCategory.STATEFUL,

    # HEAVY (600-900s baseline)
    "smuggling": ModuleCategory.HEAVY,
    "graphql": ModuleCategory.HEAVY,
    "grpc": ModuleCategory.HEAVY,
    "websocket": ModuleCategory.HEAVY,
    "api": ModuleCategory.HEAVY,
    "cache_poisoning": ModuleCategory.HEAVY,
    "cache_deception": ModuleCategory.HEAVY,

    # EXTERNAL (900-1200s baseline)
    "nuclei": ModuleCategory.EXTERNAL,
    "linux_tools": ModuleCategory.EXTERNAL,
    "cms": ModuleCategory.EXTERNAL,
    "kubernetes": ModuleCategory.EXTERNAL,
    "cloud": ModuleCategory.EXTERNAL,
    "firebase": ModuleCategory.EXTERNAL,
    "supabase": ModuleCategory.EXTERNAL,
}

# Baseline timeouts per category (in seconds)
CATEGORY_BASE_TIMEOUTS: Dict[ModuleCategory, int] = {
    ModuleCategory.QUICK: 60,
    ModuleCategory.STANDARD: 180,
    ModuleCategory.THOROUGH: 400,
    ModuleCategory.NETWORK: 400,
    ModuleCategory.BROWSER: 600,
    ModuleCategory.STATEFUL: 600,
    ModuleCategory.HEAVY: 600,
    ModuleCategory.EXTERNAL: 900,
}

# MINIMUM timeouts per category (floor - never go below this)
# Even fast targets need time for modules to execute all payloads
# Increased from original values after testing against DVWA/bWAPP
CATEGORY_MIN_TIMEOUTS: Dict[ModuleCategory, int] = {
    ModuleCategory.QUICK: 60,       # Quick checks — ssl/cors/headers finish in <30s typically
    ModuleCategory.STANDARD: 180,   # Need time for enumeration (was 120)
    ModuleCategory.THOROUGH: 360,   # Modules self-limit at 300s; floor gives buffer for slow targets
    ModuleCategory.NETWORK: 400,    # SSRF/DNS need time for callbacks (was 300)
    ModuleCategory.BROWSER: 600,    # DOM XSS needs browser startup + execution (was 400)
    ModuleCategory.STATEFUL: 600,   # Business logic needs multiple requests (was 400)
    ModuleCategory.HEAVY: 600,      # Smuggling needs careful timing (was 400)
    ModuleCategory.EXTERNAL: 900,   # External tools (nuclei) need more time (was 600)
}


class TargetProfile(Enum):
    """Target profiles based on technology and response characteristics."""
    # Legacy PHP applications - typically slow, need more time
    LEGACY_PHP = auto()     # DVWA, bWAPP, Mutillidae (1.5x multiplier)

    # Modern monolith - standard timeout
    MODERN_MONOLITH = auto()  # Laravel, Django, Rails (1.0x multiplier)

    # API-first - fast responses
    API_FIRST = auto()      # FastAPI, Express, Go (0.7x multiplier)

    # SPA with API - mixed
    SPA_BACKEND = auto()    # Next.js, Nuxt (0.9x multiplier)

    # Enterprise Java - can be slow
    ENTERPRISE_JAVA = auto()  # Spring, JBoss (1.3x multiplier)

    # Unknown/Default
    UNKNOWN = auto()        # 1.0x multiplier


# Target profile multipliers
TARGET_MULTIPLIERS: Dict[TargetProfile, float] = {
    TargetProfile.LEGACY_PHP: 1.5,
    TargetProfile.MODERN_MONOLITH: 1.0,
    TargetProfile.API_FIRST: 0.7,
    TargetProfile.SPA_BACKEND: 0.9,
    TargetProfile.ENTERPRISE_JAVA: 1.3,
    TargetProfile.UNKNOWN: 1.0,
}


@dataclass
class TimeoutProfile:
    """Calculated timeout profile for a module."""
    module_name: str
    category: ModuleCategory
    base_timeout: int
    target_multiplier: float
    response_time_multiplier: float
    final_timeout: int
    rationale: str


@dataclass
class TargetBaseline:
    """Baseline measurements for a target."""
    avg_response_time_ms: float = 0.0
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    measured_at: float = 0.0
    sample_count: int = 0
    detected_tech: List[str] = field(default_factory=list)
    target_profile: TargetProfile = TargetProfile.UNKNOWN


class AdaptiveTimeoutManager:
    """
    Manages adaptive timeouts based on target characteristics.

    Usage:
        manager = AdaptiveTimeoutManager()
        await manager.measure_baseline(target_url, client)
        timeout = manager.get_timeout_for_module("sqli")
    """

    def __init__(self):
        self.baseline: Optional[TargetBaseline] = None
        self.module_performance: Dict[str, List[float]] = {}  # module -> [durations]
        self.timeout_adjustments: Dict[str, float] = {}  # module -> multiplier override
        self._lock = asyncio.Lock()

    async def measure_baseline(
        self,
        target_url: str,
        client,  # httpx or aiohttp client
        sample_count: int = 5,
        tech_hints: Optional[List[str]] = None
    ) -> TargetBaseline:
        """
        Measure baseline response times for the target.

        Args:
            target_url: The target URL to measure
            client: HTTP client to use
            sample_count: Number of samples to take
            tech_hints: Known technology hints from fingerprinting

        Returns:
            TargetBaseline with measurements
        """
        response_times: List[float] = []

        for i in range(sample_count):
            try:
                start = time.monotonic()
                # Try to make a simple GET request
                if hasattr(client, 'get'):
                    resp = await asyncio.wait_for(
                        client.get(target_url),
                        timeout=30.0
                    )
                else:
                    # aiohttp session
                    async with client.get(target_url, timeout=30) as resp:
                        await resp.read()

                elapsed_ms = (time.monotonic() - start) * 1000
                response_times.append(elapsed_ms)

                # Small delay between samples
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.debug(f"Baseline measurement {i+1} failed: {e}")
                # Use 5000ms as penalty for failed requests
                response_times.append(5000.0)

        if not response_times:
            response_times = [1000.0]  # Default 1s if all failed

        # Calculate statistics
        sorted_times = sorted(response_times)
        avg = sum(response_times) / len(response_times)
        p95_idx = min(int(len(sorted_times) * 0.95), len(sorted_times) - 1)

        # Detect target profile from tech hints
        profile = self._detect_target_profile(tech_hints or [])

        self.baseline = TargetBaseline(
            avg_response_time_ms=avg,
            min_response_time_ms=min(response_times),
            max_response_time_ms=max(response_times),
            p95_response_time_ms=sorted_times[p95_idx],
            measured_at=time.time(),
            sample_count=len(response_times),
            detected_tech=tech_hints or [],
            target_profile=profile,
        )

        logger.info(
            f"[ADAPTIVE-TIMEOUT] Baseline: avg={avg:.0f}ms, p95={sorted_times[p95_idx]:.0f}ms, "
            f"profile={profile.name}"
        )

        return self.baseline

    def _detect_target_profile(self, tech_hints: List[str]) -> TargetProfile:
        """Detect target profile from technology hints."""
        hints_lower = [h.lower() for h in tech_hints]
        hints_str = " ".join(hints_lower)

        # Legacy PHP detection
        legacy_php_indicators = [
            "php/5", "php/4", "php/7.0", "php/7.1", "php/7.2",
            "dvwa", "bwapp", "mutillidae", "damn vulnerable",
            "webgoat", "hackazon", "owasp benchmark",
            "mysql", "mariadb", "apache/2.2", "apache/2.4.6",
        ]
        for indicator in legacy_php_indicators:
            if indicator in hints_str:
                return TargetProfile.LEGACY_PHP

        # Enterprise Java
        java_indicators = [
            "java", "spring", "tomcat", "jboss", "wildfly",
            "weblogic", "websphere", "glassfish", "jetty",
            "struts", "jsf", "hibernate",
        ]
        for indicator in java_indicators:
            if indicator in hints_str:
                return TargetProfile.ENTERPRISE_JAVA

        # API-first (fast frameworks)
        api_indicators = [
            "fastapi", "express", "gin", "fiber", "actix",
            "axum", "rocket", "warp", "go/", "rust",
            "node", "deno", "bun",
        ]
        for indicator in api_indicators:
            if indicator in hints_str:
                return TargetProfile.API_FIRST

        # SPA backends
        spa_indicators = [
            "next", "nuxt", "remix", "sveltekit", "astro",
            "gatsby", "vite", "webpack",
        ]
        for indicator in spa_indicators:
            if indicator in hints_str:
                return TargetProfile.SPA_BACKEND

        # Modern monolith
        modern_indicators = [
            "laravel", "symfony", "django", "flask",
            "rails", "ruby", "phoenix", "elixir",
            "asp.net", "dotnet",
        ]
        for indicator in modern_indicators:
            if indicator in hints_str:
                return TargetProfile.MODERN_MONOLITH

        return TargetProfile.UNKNOWN

    def get_timeout_for_module(self, module_name: str) -> int:
        """
        Get the calculated timeout for a module.

        Args:
            module_name: Name of the module (e.g., "sqli", "xss")

        Returns:
            Timeout in seconds
        """
        # Get module category (default to THOROUGH if unknown)
        category = MODULE_CATEGORIES.get(module_name, ModuleCategory.THOROUGH)

        # Get base timeout for category
        base_timeout = CATEGORY_BASE_TIMEOUTS.get(category, 400)

        # Apply target profile multiplier
        target_multiplier = 1.0
        if self.baseline:
            target_multiplier = TARGET_MULTIPLIERS.get(
                self.baseline.target_profile, 1.0
            )

        # Apply response time multiplier
        response_multiplier = self._calculate_response_multiplier()

        # Apply any manual adjustments
        manual_multiplier = self.timeout_adjustments.get(module_name, 1.0)

        # Calculate final timeout
        final = int(base_timeout * target_multiplier * response_multiplier * manual_multiplier)

        # Apply bounds: category-specific minimum, maximum 1800s (30 min)
        # Even fast targets need time for modules to complete all payload testing
        category_min = CATEGORY_MIN_TIMEOUTS.get(category, 120)
        final = max(category_min, min(final, 1800))

        return final

    def get_timeout_profile(self, module_name: str) -> TimeoutProfile:
        """Get detailed timeout profile for a module."""
        category = MODULE_CATEGORIES.get(module_name, ModuleCategory.THOROUGH)
        base_timeout = CATEGORY_BASE_TIMEOUTS.get(category, 400)

        target_mult = 1.0
        if self.baseline:
            target_mult = TARGET_MULTIPLIERS.get(self.baseline.target_profile, 1.0)

        response_mult = self._calculate_response_multiplier()
        final = self.get_timeout_for_module(module_name)

        rationale = self._build_rationale(module_name, category, target_mult, response_mult)

        return TimeoutProfile(
            module_name=module_name,
            category=category,
            base_timeout=base_timeout,
            target_multiplier=target_mult,
            response_time_multiplier=response_mult,
            final_timeout=final,
            rationale=rationale,
        )

    def _calculate_response_multiplier(self) -> float:
        """Calculate multiplier based on measured response times."""
        if not self.baseline or self.baseline.avg_response_time_ms == 0:
            return 1.0

        avg_ms = self.baseline.avg_response_time_ms

        # Baseline assumption: "normal" response time is 200ms
        # Slower targets get higher multiplier, faster targets get lower
        if avg_ms < 50:
            return 0.6  # Very fast target
        elif avg_ms < 100:
            return 0.8
        elif avg_ms < 200:
            return 1.0  # Normal
        elif avg_ms < 500:
            return 1.2
        elif avg_ms < 1000:
            return 1.5
        elif avg_ms < 2000:
            return 1.8
        else:
            return 2.0  # Very slow target

    def _build_rationale(
        self,
        module_name: str,
        category: ModuleCategory,
        target_mult: float,
        response_mult: float
    ) -> str:
        """Build human-readable rationale for timeout calculation."""
        parts = [f"Module '{module_name}' ({category.name}):"]

        base = CATEGORY_BASE_TIMEOUTS.get(category, 400)
        parts.append(f"  Base: {base}s")

        if target_mult != 1.0:
            profile = self.baseline.target_profile.name if self.baseline else "UNKNOWN"
            parts.append(f"  Target ({profile}): ×{target_mult:.1f}")

        if response_mult != 1.0:
            avg_ms = self.baseline.avg_response_time_ms if self.baseline else 0
            parts.append(f"  Response time ({avg_ms:.0f}ms avg): ×{response_mult:.1f}")

        return " | ".join(parts)

    def record_module_duration(self, module_name: str, duration_seconds: float) -> None:
        """
        Record actual module execution duration for learning.

        This data can be used to refine timeout estimates over time.
        """
        if module_name not in self.module_performance:
            self.module_performance[module_name] = []

        self.module_performance[module_name].append(duration_seconds)

        # Keep only last 10 measurements per module
        if len(self.module_performance[module_name]) > 10:
            self.module_performance[module_name] = self.module_performance[module_name][-10:]

    def adjust_timeout_for_module(self, module_name: str, multiplier: float) -> None:
        """
        Manually adjust timeout for a specific module.

        Args:
            module_name: Module to adjust
            multiplier: Multiplier to apply (e.g., 1.5 for 50% more time)
        """
        self.timeout_adjustments[module_name] = multiplier
        logger.info(f"[ADAPTIVE-TIMEOUT] Manual adjustment: {module_name} ×{multiplier:.1f}")

    def get_all_timeouts(self) -> Dict[str, int]:
        """Get calculated timeouts for all known modules."""
        return {
            module: self.get_timeout_for_module(module)
            for module in MODULE_CATEGORIES.keys()
        }

    def get_summary(self) -> Dict:
        """Get summary of timeout configuration."""
        return {
            "baseline_measured": self.baseline is not None,
            "target_profile": self.baseline.target_profile.name if self.baseline else "NOT_MEASURED",
            "avg_response_ms": self.baseline.avg_response_time_ms if self.baseline else 0,
            "response_multiplier": self._calculate_response_multiplier(),
            "target_multiplier": TARGET_MULTIPLIERS.get(
                self.baseline.target_profile, 1.0
            ) if self.baseline else 1.0,
            "manual_adjustments": dict(self.timeout_adjustments),
            "module_performance_data": {
                k: {
                    "samples": len(v),
                    "avg": sum(v) / len(v) if v else 0,
                    "max": max(v) if v else 0,
                }
                for k, v in self.module_performance.items()
            },
        }


# Global singleton
_timeout_manager: Optional[AdaptiveTimeoutManager] = None


def get_timeout_manager() -> AdaptiveTimeoutManager:
    """Get the global AdaptiveTimeoutManager instance."""
    global _timeout_manager
    if _timeout_manager is None:
        _timeout_manager = AdaptiveTimeoutManager()
    return _timeout_manager


def reset_timeout_manager() -> None:
    """Reset the global timeout manager (for testing)."""
    global _timeout_manager
    _timeout_manager = None


# ============================================================================
# EARLY TERMINATION CONTROLLER
# ============================================================================
# Philosophy: "Don't waste time on unproductive scanning."
#
# Conditions for early termination:
# 1. WAF blocking - >80% requests blocked (403/406/429 with WAF headers)
# 2. Error rate - >60% connection/timeout errors
# 3. Rate limiting - >50% requests return 429
# 4. Finding saturation - module found enough (>20 findings for one module)
# 5. Diminishing returns - no new findings in last 50 requests
# ============================================================================


class TerminationReason(Enum):
    """Reasons for early termination."""
    NONE = auto()              # No termination
    WAF_BLOCKING = auto()      # WAF detected and blocking
    HIGH_ERROR_RATE = auto()   # Too many errors
    RATE_LIMITED = auto()      # Consistent 429s
    FINDING_SATURATION = auto()  # Found enough
    DIMINISHING_RETURNS = auto()  # No new findings recently
    TIMEOUT_IMMINENT = auto()  # About to timeout


@dataclass
class ModuleHealth:
    """Health metrics for a running module."""
    module_name: str
    total_requests: int = 0
    successful_requests: int = 0
    error_requests: int = 0
    waf_blocked_requests: int = 0
    rate_limited_requests: int = 0
    findings_count: int = 0
    last_finding_at_request: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def error_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.error_requests / self.total_requests

    @property
    def waf_block_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.waf_blocked_requests / self.total_requests

    @property
    def rate_limit_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return self.rate_limited_requests / self.total_requests

    @property
    def requests_since_last_finding(self) -> int:
        return self.total_requests - self.last_finding_at_request


class EarlyTerminationController:
    """
    Controller for early termination decisions.

    Usage:
        controller = get_termination_controller()
        controller.start_module("sqli")

        # In module loop:
        controller.record_request("sqli", success=True)
        if controller.should_terminate("sqli"):
            reason = controller.get_termination_reason("sqli")
            break  # Early exit

        # On finding:
        controller.record_finding("sqli")
    """

    # Thresholds (configurable)
    WAF_BLOCK_THRESHOLD = 0.80      # >80% WAF blocks → terminate
    ERROR_RATE_THRESHOLD = 0.60     # >60% errors → terminate
    RATE_LIMIT_THRESHOLD = 0.50     # >50% rate limited → terminate
    FINDING_SATURATION = 20         # >20 findings → enough for one module
    DIMINISHING_RETURNS_REQUESTS = 100  # No findings in last 100 requests → terminate
    MIN_REQUESTS_FOR_DECISION = 10  # Need at least 10 requests before deciding

    def __init__(self):
        self.module_health: Dict[str, ModuleHealth] = {}
        self.terminated_modules: Dict[str, TerminationReason] = {}
        self._lock = asyncio.Lock()

    def start_module(self, module_name: str) -> None:
        """Start tracking a module."""
        self.module_health[module_name] = ModuleHealth(
            module_name=module_name,
            start_time=time.time(),
        )

    def record_request(
        self,
        module_name: str,
        success: bool = True,
        status_code: Optional[int] = None,
        waf_detected: bool = False,
    ) -> None:
        """Record a request result for a module."""
        if module_name not in self.module_health:
            self.start_module(module_name)

        health = self.module_health[module_name]
        health.total_requests += 1

        if success:
            health.successful_requests += 1
        else:
            health.error_requests += 1

        if waf_detected or (status_code in (403, 406) and self._is_waf_response(status_code)):
            health.waf_blocked_requests += 1

        if status_code == 429:
            health.rate_limited_requests += 1

    def _is_waf_response(self, status_code: int) -> bool:
        """Check if status code indicates WAF blocking."""
        # Simple heuristic - could be enhanced with header checking
        return status_code in (403, 406, 418, 429, 503)

    def record_finding(self, module_name: str) -> None:
        """Record a finding for a module."""
        if module_name not in self.module_health:
            self.start_module(module_name)

        health = self.module_health[module_name]
        health.findings_count += 1
        health.last_finding_at_request = health.total_requests

    def should_terminate(self, module_name: str) -> bool:
        """Check if module should terminate early."""
        reason = self.get_termination_reason(module_name)
        return reason != TerminationReason.NONE

    def get_termination_reason(self, module_name: str) -> TerminationReason:
        """Get the reason for termination (or NONE if should continue)."""
        if module_name not in self.module_health:
            return TerminationReason.NONE

        # Check if already terminated
        if module_name in self.terminated_modules:
            return self.terminated_modules[module_name]

        health = self.module_health[module_name]

        # Need minimum requests before deciding
        if health.total_requests < self.MIN_REQUESTS_FOR_DECISION:
            return TerminationReason.NONE

        # Check conditions in priority order
        if health.waf_block_rate >= self.WAF_BLOCK_THRESHOLD:
            self.terminated_modules[module_name] = TerminationReason.WAF_BLOCKING
            logger.warning(
                f"[EARLY-TERM] {module_name}: WAF blocking {health.waf_block_rate:.0%} requests"
            )
            return TerminationReason.WAF_BLOCKING

        if health.error_rate >= self.ERROR_RATE_THRESHOLD:
            self.terminated_modules[module_name] = TerminationReason.HIGH_ERROR_RATE
            logger.warning(
                f"[EARLY-TERM] {module_name}: High error rate {health.error_rate:.0%}"
            )
            return TerminationReason.HIGH_ERROR_RATE

        if health.rate_limit_rate >= self.RATE_LIMIT_THRESHOLD:
            self.terminated_modules[module_name] = TerminationReason.RATE_LIMITED
            logger.warning(
                f"[EARLY-TERM] {module_name}: Rate limited {health.rate_limit_rate:.0%} requests"
            )
            return TerminationReason.RATE_LIMITED

        if health.findings_count >= self.FINDING_SATURATION:
            self.terminated_modules[module_name] = TerminationReason.FINDING_SATURATION
            logger.info(
                f"[EARLY-TERM] {module_name}: Finding saturation ({health.findings_count} findings)"
            )
            return TerminationReason.FINDING_SATURATION

        # Diminishing returns check (only after significant requests)
        if (health.total_requests >= 50 and
            health.requests_since_last_finding >= self.DIMINISHING_RETURNS_REQUESTS):
            self.terminated_modules[module_name] = TerminationReason.DIMINISHING_RETURNS
            logger.info(
                f"[EARLY-TERM] {module_name}: Diminishing returns "
                f"(no findings in last {health.requests_since_last_finding} requests)"
            )
            return TerminationReason.DIMINISHING_RETURNS

        return TerminationReason.NONE

    def get_module_health(self, module_name: str) -> Optional[ModuleHealth]:
        """Get health metrics for a module."""
        return self.module_health.get(module_name)

    def get_summary(self) -> Dict:
        """Get summary of all module health and terminations."""
        return {
            "modules": {
                name: {
                    "total_requests": h.total_requests,
                    "success_rate": h.successful_requests / h.total_requests if h.total_requests else 0,
                    "error_rate": h.error_rate,
                    "waf_block_rate": h.waf_block_rate,
                    "findings": h.findings_count,
                    "runtime_seconds": time.time() - h.start_time,
                }
                for name, h in self.module_health.items()
            },
            "terminated_modules": {
                name: reason.name
                for name, reason in self.terminated_modules.items()
            },
            "active_modules": len(self.module_health) - len(self.terminated_modules),
        }

    def reset(self) -> None:
        """Reset all tracking."""
        self.module_health.clear()
        self.terminated_modules.clear()


# Global singleton for termination controller
_termination_controller: Optional[EarlyTerminationController] = None


def get_termination_controller() -> EarlyTerminationController:
    """Get the global EarlyTerminationController instance."""
    global _termination_controller
    if _termination_controller is None:
        _termination_controller = EarlyTerminationController()
    return _termination_controller


def reset_termination_controller() -> None:
    """Reset the global termination controller (for testing)."""
    global _termination_controller
    _termination_controller = None
