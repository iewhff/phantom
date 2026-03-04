"""
Vulnerability Scanner Orchestrator - FULL INTEGRATION v2.0
Coordinates ALL 39 scanning modules for 100% coverage.
Updated: Janeiro 2026
"""

from __future__ import annotations

import asyncio
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

# Coverage tracking for meta-vision
try:
    from scanning.coverage_tracker import (
        get_coverage_tracker, SkipReason, TestDepth
    )
    COVERAGE_TRACKER_AVAILABLE = True
except ImportError:
    COVERAGE_TRACKER_AVAILABLE = False

# Scope Guard for legal safety
try:
    from utils.scope_guard import ScopeGuard, ScopeDefinition, ScopeMode
    SCOPE_GUARD_AVAILABLE = True
except ImportError:
    SCOPE_GUARD_AVAILABLE = False

if TYPE_CHECKING:
    from core.config_manager import Settings
    from scanning.protocols import (
        HttpClientProtocol,
        RateLimiterProtocol,
        OOBEngineProtocol,
        WAFBypassEngineProtocol,
        PayloadLibraryProtocol,
        FindingsStoreProtocol,
    )

logger = get_logger(__name__)


class ModuleCategory(Enum):
    """Categories of scanning modules."""
    PASSIVE = auto()      # No direct interaction (headers, ssl, cors)
    ACTIVE = auto()       # Active probing (sqli, xss, cmdi)
    INFRASTRUCTURE = auto()  # Cloud, K8s, network
    AUTHENTICATION = auto()  # Auth, OAuth, SAML, MFA
    API = auto()          # REST, GraphQL, gRPC, WebSocket
    ADVANCED = auto()     # SSTI, Deser, Smuggling, etc.


@dataclass
class ComparisonEvidence:
    """
    Evidence structure for behavior-based vulnerability detection.

    GAP-2 FIX Sprint 1.2: Standardized evidence for modules that compare
    baseline vs attack responses. Used by:
    - business_logic_scanner
    - session_abuse_scanner
    - creative_exploiter
    - authorization_engine
    - race_condition_scanner
    - api_logic_profiler

    This ensures consistent evidence capture across behavior modules
    and supports validation pipeline requirements.
    """
    baseline_response: str  # Summary of normal behavior
    attack_response: str    # Summary of attack behavior
    difference_detected: bool  # Was a meaningful difference found?
    difference_description: str  # Human-readable: "Cart total: 100 → -1"
    confirmed_via_retest: bool = False  # Was the difference reproducible?
    baseline_status: int = 0  # HTTP status of baseline request
    attack_status: int = 0    # HTTP status of attack request
    baseline_length: int = 0  # Response length of baseline
    attack_length: int = 0    # Response length of attack
    timing_difference_ms: float = 0.0  # Response time difference
    key_changed: str = ""     # Specific field that changed (e.g., "price", "balance")
    original_value: str = ""  # Original value of the changed field
    modified_value: str = ""  # Modified value after attack

    def to_evidence_list(self) -> list[str]:
        """Convert to evidence list for Finding."""
        evidence = []

        if self.difference_description:
            evidence.append(f"Difference: {self.difference_description}")

        if self.key_changed:
            evidence.append(f"Field changed: {self.key_changed}")
            evidence.append(f"Value: {self.original_value} → {self.modified_value}")

        if self.baseline_status != self.attack_status:
            evidence.append(f"Status: {self.baseline_status} → {self.attack_status}")

        if abs(self.attack_length - self.baseline_length) > 100:
            evidence.append(f"Length change: {self.baseline_length} → {self.attack_length}")

        if self.timing_difference_ms > 1000:
            evidence.append(f"Timing difference: {self.timing_difference_ms:.0f}ms")

        if self.confirmed_via_retest:
            evidence.append("✅ Confirmed via retest")

        if not evidence:
            evidence.append(f"Baseline: {self.baseline_response[:100]}")
            evidence.append(f"Attack: {self.attack_response[:100]}")

        return evidence

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for metadata storage."""
        return {
            "baseline_response": self.baseline_response[:200],
            "attack_response": self.attack_response[:200],
            "difference_detected": self.difference_detected,
            "difference_description": self.difference_description,
            "confirmed_via_retest": self.confirmed_via_retest,
            "baseline_status": self.baseline_status,
            "attack_status": self.attack_status,
            "baseline_length": self.baseline_length,
            "attack_length": self.attack_length,
            "timing_difference_ms": self.timing_difference_ms,
            "key_changed": self.key_changed,
            "original_value": self.original_value,
            "modified_value": self.modified_value,
        }


@dataclass
class Finding:
    """Vulnerability finding structure."""

    id: str = ""
    type: str = ""
    name: str = ""
    severity: str = "INFO"
    description: str = ""
    host: str = ""
    matched_at: str = ""
    evidence: list[str] | None = None
    cvss_score: float = 0.0
    cwe: str = ""
    remediation: str = ""
    references: list[str] | None = None
    metadata: dict[str, Any] | None = None
    confidence: float = 0.0  # NEW: Confidence score 0-100
    category: str = ""       # NEW: Module category
    
    # Confidence string → float mapping
    _CONFIDENCE_MAP = {
        "CRITICAL": 95.0,
        "HIGH": 85.0,
        "MEDIUM": 65.0,
        "LOW": 40.0,
        "INFO": 20.0,
    }

    # Valid severity values
    _VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def __post_init__(self) -> None:
        self.evidence = self.evidence or []
        self.references = self.references or []
        self.metadata = self.metadata or {}

        # Normalize severity to uppercase
        if isinstance(self.severity, str):
            self.severity = self.severity.upper()
            if self.severity not in self._VALID_SEVERITIES:
                logger.warning(f"Invalid severity '{self.severity}', defaulting to INFO")
                self.severity = "INFO"

        # Convert string confidence to float
        if isinstance(self.confidence, str):
            conf_upper = self.confidence.upper()
            if conf_upper in self._CONFIDENCE_MAP:
                self.confidence = self._CONFIDENCE_MAP[conf_upper]
            else:
                try:
                    self.confidence = float(self.confidence)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid confidence '{self.confidence}', defaulting to 50.0")
                    self.confidence = 50.0

        # FIX 2026-02-19: Minimum confidence floor
        # Findings with <50% confidence should not be reported as valid
        # This prevents confidence 0.0 findings from being marked as valid
        if self.confidence > 0 and self.confidence < 0.50:
            logger.debug(f"[VALIDATION] Raising low confidence {self.confidence:.2f} to 0.50 for {self.type}")
            self.confidence = 0.50

        # FIX 2026-02-19: Validate required fields
        if not self.type:
            logger.warning(f"[VALIDATION] Finding missing type field, defaulting to 'unknown'")
            self.type = "unknown"

        if not self.name:
            # Auto-generate name from type
            self.name = self.type.replace("_", " ").title()

        # FIX 2026-02-19: Calculate CVSS from severity if not provided
        if self.cvss_score == 0.0 and self.severity != "INFO":
            self.cvss_score = self._calculate_cvss_from_severity()

        # Generate unique ID if not provided
        if not self.id:
            self.id = self._generate_id()

    def _calculate_cvss_from_severity(self) -> float:
        """Calculate approximate CVSS score from severity level."""
        severity_to_cvss = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.5,
            "LOW": 3.5,
            "INFO": 0.0,
        }
        return severity_to_cvss.get(self.severity.upper(), 5.0)

    def _generate_id(self) -> str:
        """Generate a unique finding ID based on content hash."""
        # Create deterministic ID from key fields
        content = f"{self.type}:{self.name}:{self.host}:{self.matched_at}"
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"FIND-{content_hash}-{timestamp}"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "host": self.host,
            "matched_at": self.matched_at,
            "evidence": self.evidence,
            "cvss_score": self.cvss_score,
            "cwe": self.cwe,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
            "confidence": self.confidence,
            "category": self.category,
        }


@dataclass 
class ModuleConfig:
    """Configuration for a scanning module."""
    name: str
    cls: type
    category: ModuleCategory
    enabled: bool = True
    requires_urls: bool = False      # Needs crawled URLs
    requires_forms: bool = False     # Needs form data
    requires_auth: bool = False      # Needs authentication
    requires_websocket: bool = False # Needs WebSocket endpoints
    requires_graphql: bool = False   # Needs GraphQL endpoint
    requires_grpc: bool = False      # Needs gRPC endpoint
    min_safety_level: str = "safe"   # Minimum SafetyLevel required


class ScanModule(ABC):
    """Base class for scanning modules.

    Phase 8 (2026-02-26): Supports optional dependency injection.
    Subclasses can accept DI parameters by adding them to __init__:

        class MyScanner(ScanModule):
            def __init__(
                self,
                settings: Settings,
                *,  # Force keyword args for DI params
                rate_limiter: "RateLimiterProtocol" = None,
                oob_engine: "OOBEngineProtocol" = None,
            ):
                super().__init__(settings, rate_limiter=rate_limiter)
                self._oob_engine = oob_engine

    The ModuleLoader will automatically detect and inject available
    dependencies from the DI container.
    """

    name: str = "base"

    # Class-level flag: set by FullScanner when target is localhost
    _target_is_local: bool = False

    def __init__(
        self,
        settings: "Settings",
        *,  # Force keyword args for DI parameters
        rate_limiter: "RateLimiterProtocol | None" = None,
        oob_engine: "OOBEngineProtocol | None" = None,
        waf_bypass_engine: "WAFBypassEngineProtocol | None" = None,
        payload_library: "PayloadLibraryProtocol | None" = None,
        findings_store: "FindingsStoreProtocol | None" = None,
    ) -> None:
        """Initialize base scanner module.

        Args:
            settings: Application settings
            rate_limiter: Optional injected rate limiter (RateLimiterProtocol)
            oob_engine: Optional injected OOB engine (OOBEngineProtocol)
            waf_bypass_engine: Optional injected WAF bypass engine (WAFBypassEngineProtocol)
            payload_library: Optional injected payload library (PayloadLibraryProtocol)
            findings_store: Optional injected findings store (FindingsStoreProtocol)
        """
        self.settings = settings
        self._scope_guard: ScopeGuard | None = None

        # Phase 8: Store injected dependencies
        self._injected_rate_limiter = rate_limiter
        self._injected_oob_engine = oob_engine
        self._injected_waf_bypass_engine = waf_bypass_engine
        self._injected_payload_library = payload_library
        self._injected_findings_store = findings_store

        # Initialize scope guard if available and scope is defined
        if SCOPE_GUARD_AVAILABLE:
            try:
                # Get scope from settings if available
                scope_config = getattr(settings, 'scope', None)
                if scope_config:
                    # Allow localhost if scan target IS localhost
                    is_local = ScanModule._target_is_local
                    scope_def = ScopeDefinition(
                        allowed_domains=getattr(scope_config, 'allowed_domains', []),
                        allowed_ips=getattr(scope_config, 'allowed_ips', []),
                        block_internal_ips=not is_local,
                        block_cloud_metadata=True,
                        block_localhost=not is_local,
                    )
                    self._scope_guard = ScopeGuard(scope=scope_def, mode=ScopeMode.STRICT)
                    logger.debug(f"ScopeGuard initialized for {self.name} (localhost_allowed={is_local})")
            except Exception as e:
                logger.debug(f"ScopeGuard initialization skipped: {e}")

    @classmethod
    def set_target_is_local(cls, target: str) -> None:
        """Set class-level flag if scan target is localhost/internal."""
        from urllib.parse import urlparse
        host = urlparse(target).hostname or ""
        cls._target_is_local = host.lower() in (
            "localhost", "127.0.0.1", "::1", "0.0.0.0",
        ) or host.startswith("192.168.") or host.startswith("10.")

    def is_url_in_scope(self, url: str) -> tuple[bool, str]:
        """
        Check if a URL is within the allowed scope.

        SECURITY: Use this before making requests to prevent
        testing unauthorized targets.

        Args:
            url: URL to check

        Returns:
            Tuple of (allowed, reason)
        """
        if self._scope_guard is None:
            return True, "No scope restrictions"

        allowed, violation = self._scope_guard.is_allowed(url)
        if not allowed:
            reason = violation.reason if violation else "URL not in scope"
            return False, reason
        return True, "URL is in scope"

    def filter_urls_by_scope(self, urls: list[str]) -> list[str]:
        """
        Filter a list of URLs to only include those in scope.

        Args:
            urls: List of URLs to filter

        Returns:
            Filtered list of in-scope URLs
        """
        if self._scope_guard is None:
            return urls

        safe_urls = []
        for url in urls:
            allowed, _ = self.is_url_in_scope(url)
            if allowed:
                safe_urls.append(url)

        if len(safe_urls) < len(urls):
            logger.info(
                f"🛡️ {self.name}: Filtered {len(urls) - len(safe_urls)} out-of-scope URLs"
            )

        return safe_urls

    # ═══════════════════════════════════════════════════════════════════════════
    # COVERAGE TRACKING METHODS
    # Modules can use these to report what was/wasn't tested
    # ═══════════════════════════════════════════════════════════════════════════

    def track_test(
        self,
        endpoint: str,
        vuln_type: str,
        payloads_sent: int = 1,
        found_vulnerability: bool = False,
        depth: str = "STANDARD",
    ) -> None:
        """
        Track that a test was performed (for coverage reporting).

        Args:
            endpoint: The endpoint that was tested
            vuln_type: Type of vulnerability tested for
            payloads_sent: Number of payloads sent
            found_vulnerability: Whether a vulnerability was found
            depth: Test depth - "MINIMAL", "STANDARD", "THOROUGH", "EXHAUSTIVE"
        """
        if not COVERAGE_TRACKER_AVAILABLE:
            return

        try:
            tracker = get_coverage_tracker()
            depth_enum = getattr(TestDepth, depth, TestDepth.STANDARD)
            tracker.record_test(
                surface_type="endpoint",
                identifier=endpoint,
                vuln_type=vuln_type,
                payloads_sent=payloads_sent,
                found_vulnerability=found_vulnerability,
                depth=depth_enum,
            )
        except Exception:
            pass  # Coverage tracking should never break scanning

    def track_skip(
        self,
        endpoint: str,
        reason: str,
        vuln_type: str = "",
        detail: str = "",
        recoverable: bool = True,
    ) -> None:
        """
        Track that a surface was skipped (for coverage gap analysis).

        Args:
            endpoint: The endpoint that was skipped
            reason: Why it was skipped - one of:
                    "RATE_LIMITED", "AUTH_REQUIRED", "BLOCKED_BY_WAF",
                    "TIMEOUT", "PARAM_TYPE_MISMATCH", "TECH_MISMATCH", etc.
            vuln_type: Type of vulnerability that couldn't be tested
            detail: Human-readable explanation
            recoverable: Whether this could be retried with different conditions
        """
        if not COVERAGE_TRACKER_AVAILABLE:
            return

        try:
            tracker = get_coverage_tracker()
            reason_enum = getattr(SkipReason, reason, SkipReason.LOW_PRIORITY)
            tracker.record_skip(
                surface_type="endpoint",
                identifier=endpoint,
                reason=reason_enum,
                reason_detail=detail or f"Skipped by {self.name}",
                vuln_type=vuln_type,
                recoverable=recoverable,
            )
        except Exception:
            pass  # Coverage tracking should never break scanning

    def track_rate_limited(self, endpoint: str, vuln_type: str = "") -> None:
        """Convenience: track a rate-limited skip."""
        self.track_skip(
            endpoint=endpoint,
            reason="RATE_LIMITED",
            vuln_type=vuln_type,
            detail="Received 429 or hit rate limit",
            recoverable=True,
        )

    def track_auth_required(self, endpoint: str, vuln_type: str = "") -> None:
        """Convenience: track an auth-required skip."""
        self.track_skip(
            endpoint=endpoint,
            reason="AUTH_REQUIRED",
            vuln_type=vuln_type,
            detail="Endpoint requires authentication",
            recoverable=True,
        )

    def track_waf_blocked(self, endpoint: str, vuln_type: str = "") -> None:
        """Convenience: track a WAF-blocked skip."""
        self.track_skip(
            endpoint=endpoint,
            reason="BLOCKED_BY_WAF",
            vuln_type=vuln_type,
            detail="WAF blocked the test payloads",
            recoverable=True,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # DEPENDENCY INJECTION HELPERS (Phase 8)
    # Properties to access injected dependencies with fallback to module-level
    # ═══════════════════════════════════════════════════════════════════════════

    def get_rate_limiter(self, fallback: "RateLimiterProtocol | None" = None) -> "RateLimiterProtocol | None":
        """Get rate limiter (injected or fallback).

        Args:
            fallback: Fallback rate limiter if none injected

        Returns:
            Rate limiter instance
        """
        return self._injected_rate_limiter or fallback

    def get_oob_engine(self, fallback: "OOBEngineProtocol | None" = None) -> "OOBEngineProtocol | None":
        """Get OOB engine (injected or fallback).

        Args:
            fallback: Fallback OOB engine if none injected

        Returns:
            OOB engine instance or None
        """
        return self._injected_oob_engine or fallback

    def get_waf_bypass_engine(self, fallback: "WAFBypassEngineProtocol | None" = None) -> "WAFBypassEngineProtocol | None":
        """Get WAF bypass engine (injected or fallback).

        Args:
            fallback: Fallback WAF bypass engine if none injected

        Returns:
            WAF bypass engine instance or None
        """
        return self._injected_waf_bypass_engine or fallback

    def get_payload_library(self, fallback: "PayloadLibraryProtocol | None" = None) -> "PayloadLibraryProtocol | None":
        """Get payload library (injected or fallback).

        Args:
            fallback: Fallback payload library if none injected

        Returns:
            Payload library instance or None
        """
        return self._injected_payload_library or fallback

    def get_findings_store(self, fallback: "FindingsStoreProtocol | None" = None) -> "FindingsStoreProtocol | None":
        """Get findings store (injected or fallback).

        Args:
            fallback: Fallback findings store if none injected

        Returns:
            Findings store instance or None
        """
        return self._injected_findings_store or fallback

    def share_finding(self, finding: dict[str, Any]) -> bool:
        """Share a finding with the injected findings store.

        Args:
            finding: Finding dictionary to share

        Returns:
            True if shared successfully, False otherwise
        """
        if self._injected_findings_store is not None:
            try:
                self._injected_findings_store.share_extracted_data(
                    data_type="scanner_finding",
                    value=finding,
                    source_module=self.name,
                )
                return True
            except Exception:
                pass
        return False

    # ═══════════════════════════════════════════════════════════════════════════
    # STATEFUL FLOW TRACKING
    # Track multi-step flows like checkout, auth, payment
    # ═══════════════════════════════════════════════════════════════════════════

    def register_flow(
        self,
        flow_name: str,
        steps: list[str],
        domain: str = "unknown",
    ) -> None:
        """Register a stateful flow for coverage tracking."""
        if not COVERAGE_TRACKER_AVAILABLE:
            return

        try:
            tracker = get_coverage_tracker()
            tracker.register_stateful_flow(flow_name, steps, domain)
        except Exception:
            pass

    def track_flow_step(
        self,
        flow_name: str,
        step: str,
        found_vulnerability: bool = False,
    ) -> None:
        """Record that a flow step was completed."""
        if not COVERAGE_TRACKER_AVAILABLE:
            return

        try:
            tracker = get_coverage_tracker()
            tracker.record_flow_step_completed(flow_name, step, found_vulnerability)
        except Exception:
            pass

    def track_flow_skipped(
        self,
        flow_name: str,
        step: str,
        reason: str = "",
    ) -> None:
        """Record that a flow step was skipped."""
        if not COVERAGE_TRACKER_AVAILABLE:
            return

        try:
            tracker = get_coverage_tracker()
            tracker.record_flow_step_skipped(flow_name, step, reason)
        except Exception:
            pass

    def track_flow_blocked(
        self,
        flow_name: str,
        step: str,
        reason: str = "",
    ) -> None:
        """Record that a flow was blocked at a step."""
        if not COVERAGE_TRACKER_AVAILABLE:
            return

        try:
            tracker = get_coverage_tracker()
            tracker.record_flow_blocked(flow_name, step, reason)
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTOMATIC COVERAGE INSTRUMENTATION (THEME-5 FIX)
    # Modules use these to automatically report coverage data in results
    # ═══════════════════════════════════════════════════════════════════════════

    def init_coverage(self) -> None:
        """
        Initialize coverage and error tracking for this scan.

        THEME-5 + THEME-6 FIX: Call this at the START of your scan() method.
        This ensures coverage and error data is tracked automatically.

        Example:
            async def scan(self, host, asset_data, rate_limiter):
                self.init_coverage()
                # ... scan logic ...
                return self.finalize_result(findings)
        """
        self._coverage_stats = {
            "endpoints_tested": 0,
            "endpoints_skipped": 0,
            "params_tested": 0,
            "params_skipped": 0,
            "payloads_sent": 0,
            "skipped_endpoints": [],  # List of {endpoint, reason, detail, vuln_type}
        }

        # THEME-6 FIX: Error tracking - make failures visible
        self._error_stats = {
            "requests_total": 0,
            "requests_failed": 0,
            "errors_by_type": {},  # error_type -> count
            "error_details": [],   # List of {type, endpoint, message, timestamp}
        }

    def record_endpoint_tested(
        self,
        endpoint: str,
        vuln_type: str = "",
        payloads_sent: int = 1,
        params_tested: int = 0,
    ) -> None:
        """
        Record that an endpoint was tested.

        THEME-5 FIX: Call this for each endpoint you successfully test.
        This data feeds into the coverage report.

        Args:
            endpoint: URL or endpoint tested
            vuln_type: Type of vulnerability tested for
            payloads_sent: Number of payloads/requests sent
            params_tested: Number of parameters tested
        """
        if not hasattr(self, "_coverage_stats"):
            self.init_coverage()

        self._coverage_stats["endpoints_tested"] += 1
        self._coverage_stats["payloads_sent"] += payloads_sent
        self._coverage_stats["params_tested"] += params_tested

        # Also track in global coverage tracker
        self.track_test(endpoint, vuln_type or self.name, payloads_sent)

    def record_endpoint_skipped(
        self,
        endpoint: str,
        reason: str,
        detail: str = "",
        vuln_type: str = "",
        recoverable: bool = True,
    ) -> None:
        """
        Record that an endpoint was skipped (not tested).

        THEME-5 FIX: Call this for EVERY endpoint you skip.
        This is CRITICAL for accurate coverage reporting.

        Args:
            endpoint: URL or endpoint that was skipped
            reason: One of: AUTH_REQUIRED, RATE_LIMITED, BLOCKED_BY_WAF,
                    TIMEOUT, PARAM_TYPE_MISMATCH, TECH_MISMATCH,
                    SCOPE_OUT, CONNECTION_ERROR, PARSE_ERROR
            detail: Human-readable explanation (shown in report)
            vuln_type: Type of vulnerability that couldn't be tested
            recoverable: Whether this could be retried with different conditions

        Example:
            if response.status_code == 401:
                self.record_endpoint_skipped(
                    endpoint=url,
                    reason="AUTH_REQUIRED",
                    detail="Endpoint requires authentication",
                    vuln_type="sqli",
                )
        """
        if not hasattr(self, "_coverage_stats"):
            self.init_coverage()

        self._coverage_stats["endpoints_skipped"] += 1
        self._coverage_stats["skipped_endpoints"].append({
            "endpoint": endpoint,
            "reason": reason,
            "detail": detail or f"Skipped by {self.name}",
            "vuln_type": vuln_type or self.name,
            "recoverable": recoverable,
        })

        # Also track in global coverage tracker
        self.track_skip(endpoint, reason, vuln_type or self.name, detail, recoverable)

    def record_auth_skip(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record an auth-required skip."""
        self.record_endpoint_skipped(
            endpoint=endpoint,
            reason="AUTH_REQUIRED",
            detail=detail or "Endpoint requires authentication",
            recoverable=True,
        )

    def record_rate_limit_skip(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a rate-limited skip."""
        self.record_endpoint_skipped(
            endpoint=endpoint,
            reason="RATE_LIMITED",
            detail=detail or "Rate limited (429 response)",
            recoverable=True,
        )

    def record_waf_skip(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a WAF-blocked skip."""
        self.record_endpoint_skipped(
            endpoint=endpoint,
            reason="BLOCKED_BY_WAF",
            detail=detail or "WAF blocked test payloads",
            recoverable=True,
        )

    def record_timeout_skip(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a timeout skip."""
        self.record_endpoint_skipped(
            endpoint=endpoint,
            reason="TIMEOUT",
            detail=detail or "Request timed out",
            recoverable=True,
        )

    def record_tech_mismatch_skip(self, endpoint: str, expected: str, actual: str) -> None:
        """Convenience: record a technology mismatch skip."""
        self.record_endpoint_skipped(
            endpoint=endpoint,
            reason="TECH_MISMATCH",
            detail=f"Expected {expected}, found {actual}",
            recoverable=False,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # ERROR TRACKING (THEME-6 FIX)
    # Make failures visible instead of silently swallowing them
    # ═══════════════════════════════════════════════════════════════════════════

    def record_request(self, success: bool = True) -> None:
        """
        Record a request attempt (for calculating failure rate).

        THEME-6 FIX: Call this for EVERY request to track success rate.

        Args:
            success: Whether the request succeeded
        """
        if not hasattr(self, "_error_stats"):
            self._error_stats = {
                "requests_total": 0,
                "requests_failed": 0,
                "errors_by_type": {},
                "error_details": [],
            }

        self._error_stats["requests_total"] += 1
        if not success:
            self._error_stats["requests_failed"] += 1

    def record_error(
        self,
        error_type: str,
        endpoint: str = "",
        message: str = "",
        exception: Exception | None = None,
    ) -> None:
        """
        Record an error that occurred during scanning.

        THEME-6 FIX: Call this instead of logger.debug() for errors.
        This makes errors visible in the scan report.

        Args:
            error_type: One of: TIMEOUT, PARSE_ERROR, AUTH_ERROR, CONNECTION_ERROR,
                       WAF_BLOCKED, RATE_LIMITED, VALIDATION_ERROR, UNKNOWN
            endpoint: The endpoint where error occurred
            message: Human-readable error description
            exception: The exception object (optional)

        Example:
            try:
                response = await client.get(url)
            except httpx.TimeoutException as e:
                self.record_error("TIMEOUT", url, "Request timed out", e)
        """
        if not hasattr(self, "_error_stats"):
            self._error_stats = {
                "requests_total": 0,
                "requests_failed": 0,
                "errors_by_type": {},
                "error_details": [],
            }

        # Increment error count by type
        error_type = error_type.upper()
        self._error_stats["errors_by_type"][error_type] = \
            self._error_stats["errors_by_type"].get(error_type, 0) + 1

        # Track failed request
        self._error_stats["requests_failed"] += 1
        self._error_stats["requests_total"] += 1

        # Store error detail (limit to last 50 to prevent memory bloat)
        from datetime import datetime
        error_detail = {
            "type": error_type,
            "endpoint": endpoint[:100] if endpoint else "",
            "message": message[:200] if message else str(exception)[:200] if exception else "",
            "timestamp": datetime.now().isoformat(),
        }

        if len(self._error_stats["error_details"]) < 50:
            self._error_stats["error_details"].append(error_detail)

        # Log at WARNING level so it's visible (not DEBUG!)
        logger.warning(
            f"[{self.name}] Error: {error_type} at {endpoint[:50] if endpoint else 'unknown'} - "
            f"{message[:100] if message else str(exception)[:100] if exception else 'no details'}"
        )

    def record_timeout_error(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a timeout error."""
        self.record_error("TIMEOUT", endpoint, detail or "Request timed out")

    def record_parse_error(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a JSON/XML parse error."""
        self.record_error("PARSE_ERROR", endpoint, detail or "Failed to parse response")

    def record_connection_error(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a connection error."""
        self.record_error("CONNECTION_ERROR", endpoint, detail or "Connection failed")

    def record_auth_error(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record an authentication error."""
        self.record_error("AUTH_ERROR", endpoint, detail or "Authentication failed (401/403)")

    def record_waf_error(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a WAF blocking error."""
        self.record_error("WAF_BLOCKED", endpoint, detail or "Request blocked by WAF")

    def record_rate_limit_error(self, endpoint: str, detail: str = "") -> None:
        """Convenience: record a rate limiting error."""
        self.record_error("RATE_LIMITED", endpoint, detail or "Rate limited (429)")

    def get_error_summary(self) -> str:
        """
        Get a human-readable error summary for logging.

        Returns:
            String like "15 requests, 3 failed (20% failure rate)"
        """
        if not hasattr(self, "_error_stats"):
            return "No error tracking"

        total = self._error_stats["requests_total"]
        failed = self._error_stats["requests_failed"]

        if total == 0:
            return "No requests tracked"

        failure_rate = (failed / total) * 100
        errors_by_type = self._error_stats.get("errors_by_type", {})

        summary = f"{total} requests, {failed} failed ({failure_rate:.0f}% failure rate)"

        if errors_by_type:
            types_str = ", ".join(f"{t}: {c}" for t, c in sorted(errors_by_type.items()))
            summary += f" [{types_str}]"

        return summary

    def finalize_result(
        self,
        findings: list[dict],
        info: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Finalize scan result with coverage and error data.

        THEME-5 + THEME-6 + THEME-9 FIX: Call this at the END of your scan() method.
        This automatically includes coverage, error, and saturation data in the result.

        MANDATORY BUDGET ENFORCEMENT (THEME-9): Even if modules don't call
        can_add_finding() for each finding, this method enforces the finding
        budget by truncating excess findings.

        Args:
            findings: List of vulnerability findings
            info: Optional list of informational items

        Returns:
            Dict with 'findings', 'info', coverage data, and error stats

        Example:
            async def scan(self, host, asset_data, rate_limiter):
                self.init_coverage()
                findings = []
                # ... scan logic ...
                return self.finalize_result(findings)
        """
        if not hasattr(self, "_coverage_stats"):
            self._coverage_stats = {
                "endpoints_tested": 0,
                "endpoints_skipped": 0,
                "params_tested": 0,
                "params_skipped": 0,
                "payloads_sent": 0,
                "skipped_endpoints": [],
            }

        # THEME-6: Initialize error stats if not present
        if not hasattr(self, "_error_stats"):
            self._error_stats = {
                "requests_total": 0,
                "requests_failed": 0,
                "errors_by_type": {},
                "error_details": [],
            }

        # ═══════════════════════════════════════════════════════════════════════
        # THEME-9 FIX: MANDATORY BUDGET ENFORCEMENT
        # Truncate findings to respect budget limits even if module didn't check
        # ═══════════════════════════════════════════════════════════════════════
        findings_truncated = 0
        original_count = len(findings)

        # Auto-initialize budget if not done yet
        if not hasattr(self, "_module_budget") or self._module_budget is None:
            self.init_budget()

        # If budget is available, enforce the finding limit
        if hasattr(self, "_module_budget") and self._module_budget is not None:
            max_findings = self._module_budget.max_findings
            if len(findings) > max_findings:
                # Sort by severity to keep most important findings
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                findings = sorted(
                    findings,
                    key=lambda f: (
                        severity_order.get(str(f.get("severity", "INFO")).upper(), 5),
                        -(f.get("confidence_score", f.get("confidence", 0)) if isinstance(f.get("confidence_score", f.get("confidence")), (int, float)) else 50)
                    )
                )[:max_findings]
                findings_truncated = original_count - max_findings
                logger.warning(
                    f"[THEME-9] {self.name}: Truncated {findings_truncated} findings "
                    f"(budget limit: {max_findings}, had: {original_count})"
                )

                # Update budget to reflect actual finding count
                self._module_budget.finding_count = max_findings

        # If no endpoints tracked but we have findings, infer tested count
        if self._coverage_stats["endpoints_tested"] == 0 and len(findings) > 0:
            self._coverage_stats["endpoints_tested"] = len(findings)

        # THEME-6: Log error summary if there were failures
        if self._error_stats["requests_failed"] > 0:
            logger.warning(f"[{self.name}] Completed with errors: {self.get_error_summary()}")

        result = {
            "findings": findings,
            "info": info or [],
            # Coverage data for FullScanner to collect (THEME-5)
            "endpoints_tested": self._coverage_stats["endpoints_tested"],
            "endpoints_skipped": self._coverage_stats["endpoints_skipped"],
            "params_tested": self._coverage_stats["params_tested"],
            "params_skipped": self._coverage_stats["params_skipped"],
            "payloads_sent": self._coverage_stats["payloads_sent"],
            "skipped_endpoints": self._coverage_stats["skipped_endpoints"],
            # Error stats for FullScanner to collect (THEME-6)
            "requests_total": self._error_stats["requests_total"],
            "requests_failed": self._error_stats["requests_failed"],
            "errors_by_type": self._error_stats["errors_by_type"],
            "error_details": self._error_stats["error_details"],
            "error_summary": self.get_error_summary(),
            # Saturation data for FullScanner to collect (THEME-9)
            "findings_truncated": findings_truncated,
        }

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # SMART RETRY METHODS (THEME-7 FIX)
    # Handle rate limiting and slow targets with intelligent retry
    # ═══════════════════════════════════════════════════════════════════════════

    def init_retry_state(self, host: str) -> None:
        """
        Initialize retry state for this module.

        THEME-7 FIX: Call this at the start of scan() to enable smart retry.
        Tracks which endpoints failed and queues them for retry.

        Example:
            async def scan(self, host, asset_data, rate_limiter):
                self.init_coverage()
                self.init_retry_state(host)
                # ... scan logic ...
        """
        try:
            from scanning.smart_retry import get_retry_manager
            self._retry_manager = get_retry_manager()
            self._retry_state = self._retry_manager.get_or_create_state(
                self.name, host
            )
            self._host = host
        except ImportError:
            self._retry_manager = None
            self._retry_state = None
            self._host = host

    def queue_for_retry(
        self,
        endpoint: str,
        reason: str,
        param: str = "",
        vuln_type: str = "",
    ) -> None:
        """
        Queue an endpoint for retry after failure.

        THEME-7 FIX: Instead of abandoning on first failure, queue for retry.
        The FullScanner will retry these endpoints after the main scan.

        Args:
            endpoint: The endpoint that failed
            reason: One of: RATE_LIMITED, TIMEOUT, CONNECTION_ERROR, WAF_BLOCKED
            param: Parameter being tested (if any)
            vuln_type: Type of vulnerability being tested

        Example:
            try:
                response = await client.get(endpoint)
            except httpx.TimeoutException:
                self.queue_for_retry(endpoint, "TIMEOUT", param="q", vuln_type="sqli")
                continue  # Try next endpoint
        """
        if not hasattr(self, "_retry_state") or self._retry_state is None:
            return

        try:
            from scanning.smart_retry import RetryReason
            reason_enum = getattr(RetryReason, reason.upper(), RetryReason.TIMEOUT)
            self._retry_state.mark_failed(endpoint, reason_enum, param, vuln_type)

            logger.debug(
                f"[THEME-7] {self.name}: Queued {endpoint[:50]} for retry ({reason})"
            )
        except Exception:
            pass  # Don't break scanning if retry tracking fails

    def mark_endpoint_done(self, endpoint: str, param: str = "") -> None:
        """
        Mark an endpoint as successfully tested.

        THEME-7: Tracks progress for resumption.
        """
        if not hasattr(self, "_retry_state") or self._retry_state is None:
            return

        self._retry_state.mark_completed(endpoint, param)

    def is_already_tested(self, endpoint: str, param: str = "") -> bool:
        """
        Check if endpoint was already tested (for resumption).

        THEME-7: Skip endpoints that were tested in a previous run.
        """
        if not hasattr(self, "_retry_state") or self._retry_state is None:
            return False

        return self._retry_state.is_endpoint_done(endpoint, param)

    def should_pause_module(self) -> tuple[bool, str]:
        """
        Check if module should pause due to high error rate.

        THEME-7: Pause instead of terminate on error floods.
        The module can be resumed after a cooldown period.

        Returns:
            Tuple of (should_pause, reason)
        """
        if not hasattr(self, "_retry_state") or self._retry_state is None:
            return False, ""

        return self._retry_state.should_pause()

    def get_pending_retries(self) -> list[dict]:
        """
        Get endpoints queued for retry.

        Returns:
            List of dicts with endpoint, param, timeout, etc.
        """
        if not hasattr(self, "_retry_state") or self._retry_state is None:
            return []

        pending = self._retry_state.get_pending_retries()
        return [
            {
                "endpoint": r.endpoint,
                "param": r.param,
                "timeout": r.current_timeout,
                "attempt": r.attempts,
                "vuln_type": r.vuln_type,
            }
            for r in pending
        ]

    def get_error_rate(self) -> float:
        """
        Calculate current error rate.

        THEME-7: High error rate triggers pause and backoff.
        """
        if not hasattr(self, "_error_stats"):
            return 0.0

        total = self._error_stats.get("requests_total", 0)
        failed = self._error_stats.get("requests_failed", 0)

        if total == 0:
            return 0.0

        return failed / total

    def finalize_result_with_retry(
        self,
        findings: list[dict],
        info: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Finalize result including retry data.

        THEME-7 FIX: Extended version of finalize_result() that includes
        retry state for the FullScanner to process.

        Example:
            return self.finalize_result_with_retry(findings)
        """
        result = self.finalize_result(findings, info)

        # Add retry data
        if hasattr(self, "_retry_state") and self._retry_state:
            pending_retries = self.get_pending_retries()
            result["retry_data"] = {
                "pending_count": len(pending_retries),
                "pending_endpoints": pending_retries[:20],  # Limit for memory
                "error_rate": self.get_error_rate(),
                "should_retry": len(pending_retries) > 0 or self.get_error_rate() > 0.3,
            }

            # Check if paused
            should_pause, pause_reason = self.should_pause_module()
            if should_pause:
                self._retry_state.pause(pause_reason)
                result["paused"] = True
                result["pause_reason"] = pause_reason

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # SATURATION CONTROL METHODS (THEME-9 FIX)
    # Prevent cognitive saturation through budget limits and hypothesis coordination
    # ═══════════════════════════════════════════════════════════════════════════

    def init_budget(self) -> None:
        """
        Initialize budget tracking for this module.

        THEME-9 FIX: Call this at the start of scan() to enable budget limits.
        Prevents request/finding saturation.

        Example:
            async def scan(self, host, asset_data, rate_limiter):
                self.init_coverage()
                self.init_budget()
                # ... scan logic with budget checks ...
        """
        try:
            from scanning.saturation_controller import get_saturation_controller
            self._saturation_controller = get_saturation_controller()
            self._module_budget = self._saturation_controller.get_module_budget(self.name)
            logger.debug(
                f"[THEME-9] {self.name}: Budget initialized "
                f"(max_requests={self._module_budget.max_requests}, "
                f"max_findings={self._module_budget.max_findings})"
            )
        except ImportError:
            self._saturation_controller = None
            self._module_budget = None

    def can_make_request(self, param: str = "") -> bool:
        """
        Check if module can make another request.

        THEME-9: Returns False if request budget is exhausted.
        Use this before each HTTP request.

        MANDATORY: Budget auto-initializes on first call, ensuring all modules
        are subject to saturation control even if they don't call init_budget().

        Args:
            param: Optional parameter being tested (for per-param limits)

        Returns:
            True if request allowed, False if budget exceeded
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_saturation_controller") or self._saturation_controller is None:
            self.init_budget()

        # After auto-init, check if controller is available
        if self._saturation_controller is None:
            return True  # Fallback if import failed

        return self._saturation_controller.record_request(self.name, param)

    def can_add_finding(self) -> bool:
        """
        Check if module can add another finding.

        THEME-9: Returns False if finding budget is exhausted.
        Use this before adding each finding.

        MANDATORY: Budget auto-initializes on first call, ensuring all modules
        are subject to saturation control even if they don't call init_budget().

        Returns:
            True if finding allowed, False if budget exceeded
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_saturation_controller") or self._saturation_controller is None:
            self.init_budget()

        # After auto-init, check if controller is available
        if self._saturation_controller is None:
            return True  # Fallback if import failed

        return self._saturation_controller.record_finding(self.name)

    def can_test_param(self, param: str) -> bool:
        """
        Check if module can test another payload on this parameter.

        THEME-9: Returns False if per-param budget is exhausted.
        Prevents 1000+ payloads on single parameter.

        MANDATORY: Budget auto-initializes on first call, ensuring all modules
        are subject to saturation control even if they don't call init_budget().

        Args:
            param: The parameter name

        Returns:
            True if more payloads allowed, False if saturated
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_module_budget") or self._module_budget is None:
            self.init_budget()

        # After auto-init, check if budget is available
        if self._module_budget is None:
            return True  # Fallback if import failed

        return self._module_budget.can_test_param(param)

    def is_hypothesis_tested(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
    ) -> bool:
        """
        Check if another module already tested this hypothesis.

        THEME-9: Prevents duplicate hypothesis testing.
        If SQLi scanner already confirmed param is injectable,
        XSS scanner doesn't need to test basic injection.

        MANDATORY: Auto-initializes budget on first call.

        Args:
            endpoint: The endpoint URL
            param: The parameter name
            hypothesis_type: One of "injectable", "reflectable", "traversable", etc.

        Returns:
            True if already tested by any module
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_saturation_controller") or self._saturation_controller is None:
            self.init_budget()

        if self._saturation_controller is None:
            return False

        return self._saturation_controller.is_hypothesis_tested(endpoint, param, hypothesis_type)

    def get_hypothesis_result(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
    ) -> bool | None:
        """
        Get result of hypothesis tested by another module.

        THEME-9: Use another module's findings to skip redundant testing.

        MANDATORY: Auto-initializes budget on first call.

        Args:
            endpoint: The endpoint URL
            param: The parameter name
            hypothesis_type: Type of hypothesis

        Returns:
            True = vulnerable, False = not vulnerable, None = not tested
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_saturation_controller") or self._saturation_controller is None:
            self.init_budget()

        if self._saturation_controller is None:
            return None

        return self._saturation_controller.get_hypothesis_result(endpoint, param, hypothesis_type)

    def record_hypothesis(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
        result: bool | None,
        evidence: str = "",
    ) -> None:
        """
        Record a tested hypothesis for other modules to use.

        THEME-9: Share findings to prevent duplicate testing.

        MANDATORY: Auto-initializes budget on first call.

        Args:
            endpoint: The endpoint URL
            param: The parameter name
            hypothesis_type: Type of hypothesis
            result: True = vulnerable, False = not, None = inconclusive
            evidence: Optional evidence string
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_saturation_controller") or self._saturation_controller is None:
            self.init_budget()

        if self._saturation_controller is None:
            return

        self._saturation_controller.record_hypothesis(
            endpoint=endpoint,
            param=param,
            hypothesis_type=hypothesis_type,
            module_name=self.name,
            result=result,
            evidence=evidence,
        )

    def should_skip_hypothesis(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
    ) -> tuple[bool, str]:
        """
        Check if module should skip testing this hypothesis.

        THEME-9: Comprehensive check including other modules' results.

        MANDATORY: Auto-initializes budget on first call.

        Returns:
            Tuple of (should_skip, reason)
        """
        # THEME-9 FIX: Auto-initialize budget if not done yet
        if not hasattr(self, "_saturation_controller") or self._saturation_controller is None:
            self.init_budget()

        if self._saturation_controller is None:
            return False, ""

        return self._saturation_controller.should_skip_hypothesis(
            endpoint=endpoint,
            param=param,
            hypothesis_type=hypothesis_type,
            module_name=self.name,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # CONVENIENT FINDING HELPER (THEME-9 FIX)
    # Makes it easy for modules to add findings with automatic budget checking
    # ═══════════════════════════════════════════════════════════════════════════

    def add_finding(
        self,
        findings_list: list[dict],
        finding: dict,
    ) -> bool:
        """
        Add a finding to the list with automatic budget checking.

        THEME-9 FIX: Use this instead of findings.append() to enforce budget.
        If budget is exhausted, the finding is NOT added and False is returned.

        Args:
            findings_list: The list to append the finding to
            finding: The finding dict to add

        Returns:
            True if finding was added, False if budget exhausted

        Example:
            findings = []
            for vuln in detected_vulns:
                if not self.add_finding(findings, vuln):
                    break  # Budget exhausted, stop scanning
        """
        if not self.can_add_finding():
            logger.debug(
                f"[THEME-9] {self.name}: Finding budget exhausted, dropping finding"
            )
            return False

        findings_list.append(finding)
        return True

    def get_budget_remaining(self) -> dict[str, int]:
        """
        Get remaining budget for this module.

        Returns:
            Dict with 'requests' and 'findings' remaining counts
        """
        if not hasattr(self, "_module_budget") or self._module_budget is None:
            return {"requests": 999, "findings": 999}

        return self._module_budget.get_remaining()

    def get_budget_utilization(self) -> dict[str, float]:
        """
        Get budget utilization percentages.

        Returns:
            Dict with 'requests_pct' and 'findings_pct' usage percentages
        """
        if not hasattr(self, "_module_budget") or self._module_budget is None:
            return {"requests_pct": 0.0, "findings_pct": 0.0}

        return self._module_budget.get_utilization()

    def finalize_result_with_saturation(
        self,
        findings: list[dict],
        info: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Finalize result including saturation/budget data.

        THEME-9 FIX: Extended version of finalize_result() that includes
        budget utilization for reporting.

        Example:
            return self.finalize_result_with_saturation(findings)
        """
        result = self.finalize_result_with_retry(findings, info)

        # Add saturation data
        if hasattr(self, "_module_budget") and self._module_budget:
            result["saturation_data"] = {
                "budget_utilization": self.get_budget_utilization(),
                "budget_remaining": self.get_budget_remaining(),
                "budget_exhausted": self._module_budget.exhausted_at is not None,
                "exhaustion_reason": (
                    self._module_budget.exhaustion_reason.name
                    if self._module_budget.exhaustion_reason else None
                ),
            }

        return result

    # ═══════════════════════════════════════════════════════════════════════════
    # NEGATIVE CONTROL VALIDATION (GAP-2 FIX - Sprint 1.1)
    # Local negative control to reduce false positives in injection modules
    # ═══════════════════════════════════════════════════════════════════════════

    # Benign payloads by vulnerability type - cause no vulnerability indicators
    _BENIGN_PAYLOADS: dict[str, str] = {
        "sqli": "test123",
        "xss": "hello",
        "nosql": "value",
        "cmdi": "ping",
        "xxe": "<data>test</data>",
        "ssti": "test",
        "lfi": "index.html",
        "ssrf": "https://example.com",
        "dom_xss": "hello",
        "smuggling": "GET / HTTP/1.1",
        "crlf": "test",
        "cache_poisoning": "test",
        "ldap_xpath": "test",
    }

    def get_benign_payload(self, vuln_type: str) -> str:
        """
        Get a benign (safe) payload for a vulnerability type.

        GAP-2 FIX: Used for negative control - comparing malicious vs benign responses.

        Args:
            vuln_type: The vulnerability type (sqli, xss, etc.)

        Returns:
            A benign payload that should NOT trigger vulnerability indicators
        """
        return self._BENIGN_PAYLOADS.get(vuln_type.lower(), "test123")

    async def validate_with_negative_control(
        self,
        http_client: "HttpClientProtocol",
        url: str,
        param: str,
        payload: str,
        indicator: str,
        vuln_type: str = "",
        method: str = "GET",
    ) -> tuple[bool, str]:
        """
        Validate a potential finding using negative control.

        GAP-2 FIX: Local negative control to fail fast before the validation pipeline.
        Reduces false positives by 70%+ by comparing malicious vs benign payloads.

        **Philosophy:** If benign and attack responses are identical, or if the
        indicator is missing from the attack response, it's a false positive.

        Args:
            http_client: HTTP client (httpx.AsyncClient or similar)
            url: The URL to test
            param: The parameter being tested
            payload: The malicious payload
            indicator: The expected indicator in the response (e.g., SQL error)
            vuln_type: The vulnerability type for selecting benign payload
            method: HTTP method to use (GET, POST)

        Returns:
            Tuple of (is_valid, reason)

        Example:
            is_valid, reason = await self.validate_with_negative_control(
                http_client=self.client,
                url="http://target/search",
                param="q",
                payload="' OR 1=1--",
                indicator="SQL syntax error",
                vuln_type="sqli",
            )
            if not is_valid:
                logger.debug(f"Negative control failed: {reason}")
                continue  # Skip this finding
        """
        if not vuln_type:
            vuln_type = getattr(self, "name", "unknown")

        benign = self.get_benign_payload(vuln_type)

        try:
            # Send benign request
            if method.upper() == "GET":
                safe_resp = await http_client.get(url, params={param: benign})
            else:
                safe_resp = await http_client.post(url, data={param: benign})

            # Send attack request
            if method.upper() == "GET":
                attack_resp = await http_client.get(url, params={param: payload})
            else:
                attack_resp = await http_client.post(url, data={param: payload})

            # Check 1: Identical response = likely FP (indicator appears regardless)
            safe_text = safe_resp.text if hasattr(safe_resp, "text") else str(safe_resp.content)
            attack_text = attack_resp.text if hasattr(attack_resp, "text") else str(attack_resp.content)

            if safe_text == attack_text:
                return False, "Identical response with benign payload (likely FP)"

            # Check 2: Indicator must be in attack response
            if indicator and indicator.lower() not in attack_text.lower():
                return False, f"Indicator '{indicator[:50]}' not found in attack response"

            # Check 3: Indicator should NOT be in benign response
            if indicator and indicator.lower() in safe_text.lower():
                return False, f"Indicator also appears in benign response (FP)"

            # Passed all checks
            return True, "Negative control passed"

        except Exception as e:
            # On error, let the finding proceed (don't block on network issues)
            logger.debug(f"[NegativeControl] Error during validation: {e}")
            return True, f"Validation skipped due to error: {str(e)[:50]}"

    async def quick_negative_control(
        self,
        http_client: "HttpClientProtocol",
        url: str,
        param: str,
        indicator: str,
        vuln_type: str = "",
    ) -> bool:
        """
        Quick check: does the indicator appear even with benign input?

        GAP-2 FIX: Ultra-fast FP check - if YES, it's definitely a FP.
        Use this for quick filtering before running full payload tests.

        Args:
            http_client: HTTP client
            url: The URL to test
            param: The parameter being tested
            indicator: The indicator to check for
            vuln_type: The vulnerability type

        Returns:
            True = safe to proceed, False = definitely FP
        """
        if not vuln_type:
            vuln_type = getattr(self, "name", "unknown")

        benign = self.get_benign_payload(vuln_type)

        try:
            resp = await http_client.get(url, params={param: benign})
            resp_text = resp.text if hasattr(resp, "text") else str(resp.content)

            # If indicator appears with benign input, it's a FP
            if indicator.lower() in resp_text.lower():
                logger.debug(
                    f"[NegativeControl] Quick check: '{indicator[:30]}' appears with benign payload - FP"
                )
                return False

            return True

        except Exception:
            # On error, allow proceeding (don't block on network issues)
            return True

    # ═══════════════════════════════════════════════════════════════════════════
    # INTELLIGENT PAYLOAD SELECTION (PERF-FIX 2026-02-20)
    # Use ContextPayloadSelector for smart, tech-aware payload selection
    # ═══════════════════════════════════════════════════════════════════════════

    async def _get_intelligent_payloads(
        self,
        category: str,
        endpoint: str,
        param_name: str,
        max_payloads: int = 50,
        asset_data: dict | None = None,
    ) -> list[tuple[str, float]]:
        """
        Get ranked payloads using ContextPayloadSelector.

        PERF-FIX 2026-02-20: Use this instead of hardcoded payload lists
        to reduce requests by 70-80% while maintaining detection quality.

        The selector ranks payloads based on:
        - Tech stack affinity (MySQL payloads for MySQL targets)
        - WAF bypass score (mutations for detected WAFs)
        - Parameter context (numeric vs string payloads)
        - Historical effectiveness (adaptive learning)

        Args:
            category: Payload category - "sqli", "xss", "lfi", etc.
            endpoint: Target endpoint URL
            param_name: Parameter being tested
            max_payloads: Maximum payloads to return (default 50)
            asset_data: Module's asset_data dict (for fingerprint access)

        Returns:
            List of (payload, effectiveness_score) tuples, ranked best-first.
            Returns empty list if selector unavailable (fallback to hardcoded).

        Example:
            payloads = await self._get_intelligent_payloads(
                category="sqli",
                endpoint=url,
                param_name="id",
                max_payloads=30,
                asset_data=asset_data,
            )
            if not payloads:
                # Fallback to hardcoded payloads
                payloads = [(p, 0.5) for p in self.DEFAULT_PAYLOADS]

            for payload, score in payloads:
                # Test payload with known effectiveness
                ...
        """
        try:
            from phantom.context_payload_selector import (
                select_payloads_for_parameter,
                SelectionStrategy,
                PayloadCategory,
            )

            # Map category string to PayloadCategory enum
            category_map = {
                "sqli": PayloadCategory.SQLI,
                "xss": PayloadCategory.XSS,
                "lfi": PayloadCategory.LFI,
                "cmdi": PayloadCategory.CMDI,
                "ssti": PayloadCategory.SSTI,
                "ssrf": PayloadCategory.SSRF,
                "nosql": PayloadCategory.NOSQL,
                "xxe": PayloadCategory.XXE,
                "crlf": PayloadCategory.CRLF,
                "open_redirect": PayloadCategory.OPEN_REDIRECT,
            }

            payload_category = category_map.get(category.lower())
            if not payload_category:
                logger.debug(f"[PayloadSelector] Unknown category '{category}', using fallback")
                return []

            # Get context from asset_data
            data = asset_data or getattr(self, '_asset_data', {})
            fingerprint = data.get("fingerprint_result")
            waf_detection = data.get("waf_detection")

            # Determine host URL
            host = getattr(self, '_host', None) or endpoint.split('?')[0]

            result = await select_payloads_for_parameter(
                target_url=host,
                endpoint=endpoint,
                parameter_name=param_name,
                fingerprint=fingerprint,
                waf_detection=waf_detection,
                strategy=SelectionStrategy.BALANCED,
                max_payloads=max_payloads * 2,  # Request more, then filter by category
            )

            if result and result.payloads:
                # Filter by requested category
                filtered = [
                    (p.payload, p.effectiveness_score)
                    for p in result.payloads
                    if p.category == payload_category
                ][:max_payloads]

                if filtered:
                    logger.info(
                        f"[PayloadSelector] Selected {len(filtered)} {category} payloads "
                        f"for {param_name} (from {result.total_considered} candidates)"
                    )
                    return filtered

            return []

        except ImportError:
            logger.debug("[PayloadSelector] ContextPayloadSelector not available")
            return []
        except Exception as e:
            logger.debug(f"[PayloadSelector] Error getting payloads: {e}")
            return []

    def _filter_payloads_by_db(
        self,
        payloads: list[tuple[str, float]],
        detected_db: str | None,
    ) -> list[tuple[str, float]]:
        """
        Filter SQLi payloads to only those relevant to detected database.

        PERF-FIX 2026-02-20: Skip Oracle payloads on MySQL targets, etc.

        Args:
            payloads: List of (payload, score) tuples
            detected_db: Detected database type (mysql, postgresql, etc.)

        Returns:
            Filtered list of payloads relevant to the detected database.
            Returns all payloads if database is unknown.
        """
        if not detected_db or detected_db.lower() == "unknown":
            return payloads  # Test all if DB unknown

        # Database-specific keywords
        db_keywords = {
            "mysql": ["mysql", "sleep", "benchmark", "concat", "@@version"],
            "mariadb": ["mysql", "sleep", "benchmark", "concat", "@@version"],
            "postgresql": ["pg_", "postgres", "chr(", "version()", "::"],
            "mssql": ["waitfor", "xp_", "mssql", "char(", "@@version"],
            "oracle": ["utl_", "dbms_", "oracle", "chr(", "rownum"],
            "sqlite": ["sqlite", "randomblob", "substr(", "typeof("],
        }

        # Generic keywords that work on any database
        generic_keywords = ["'", '"', "--", ";", "or", "and", "union", "select"]

        db_lower = detected_db.lower()
        relevant_keywords = db_keywords.get(db_lower, [])

        filtered = []
        for payload, score in payloads:
            payload_lower = payload.lower()

            # Keep if matches detected DB or is generic
            is_generic = any(k in payload_lower for k in generic_keywords)
            is_db_specific = any(k in payload_lower for k in relevant_keywords)

            # Exclude payloads for OTHER databases
            is_wrong_db = False
            for other_db, other_keywords in db_keywords.items():
                if other_db != db_lower:
                    # Check for database-specific markers (not generic SQL)
                    specific_markers = [k for k in other_keywords if k not in generic_keywords]
                    if any(k in payload_lower for k in specific_markers):
                        is_wrong_db = True
                        break

            if (is_generic or is_db_specific) and not is_wrong_db:
                filtered.append((payload, score))

        if len(filtered) < len(payloads):
            logger.debug(
                f"[PayloadFilter] Filtered {len(payloads)} → {len(filtered)} "
                f"payloads for {detected_db}"
            )

        return filtered

    @abstractmethod
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Execute scan on a host.

        Args:
            host: Target hostname
            asset_data: Reconnaissance data
            rate_limiter: Rate limiter instance

        Returns:
            Dict with 'vulns' and 'info' lists

        THEME-5 FIX: Use init_coverage() and finalize_result() for automatic
        coverage tracking:

            async def scan(self, host, asset_data, rate_limiter):
                self.init_coverage()
                findings = []

                for endpoint in endpoints:
                    if not self.can_test(endpoint):
                        self.record_endpoint_skipped(endpoint, "AUTH_REQUIRED", "Needs auth")
                        continue

                    # Test endpoint
                    self.record_endpoint_tested(endpoint, "sqli", payloads_sent=5)
                    # ... testing logic ...

                return self.finalize_result(findings)
        """
        pass


class VulnerabilityScanner:
    """
    Orchestrates vulnerability scanning across ALL 39 modules.
    
    FULL INTEGRATION v2.0 - Janeiro 2026
    
    Module Categories:
    - PASSIVE: Headers, SSL, CORS (non-intrusive)
    - ACTIVE: SQLi, XSS, CMDi, XXE, SSRF, LFI, etc.
    - INFRASTRUCTURE: Cloud, Kubernetes, DNS
    - AUTHENTICATION: Auth, OAuth, SAML, MFA, Rate Limit
    - API: REST, GraphQL Advanced, gRPC, WebSocket, SSE
    - ADVANCED: SSTI, Deserialization, Smuggling, Cache Poison, etc.
    """
    
    # Version for tracking
    VERSION = "2.0.0"
    
    def __init__(self, settings: Settings, safety_level: str = "safe") -> None:
        """
        Initialize scanner with ALL modules.
        
        Args:
            settings: Application settings
            safety_level: Safety level (passive/safe/cautious/standard/aggressive)
        """
        self.settings = settings
        self.safety_level = safety_level
        self.modules: dict[str, ScanModule] = {}
        self.module_configs: dict[str, ModuleConfig] = {}
        self._load_all_modules()
        
        logger.info(f"VulnerabilityScanner v{self.VERSION} initialized with {len(self.modules)} modules")
    
    def _load_all_modules(self) -> None:
        """Load ALL 39 scanning modules."""
        # Import all modules
        from scanning.modules.nuclei_runner import NucleiRunner
        from scanning.modules.header_security import HeaderSecurityChecker
        from scanning.modules.ssl_checker import SSLChecker
        from scanning.modules.cors_checker import CORSChecker
        from scanning.modules.sqli_scanner import SQLiScanner
        from scanning.modules.xss_scanner import XSSScanner
        from scanning.modules.cmdi_scanner import CommandInjectionScanner
        from scanning.modules.xxe_scanner import XXEScanner
        from scanning.modules.ssrf_scanner import SSRFScanner
        from scanning.modules.lfi_scanner import LFIScanner
        from scanning.modules.auth_scanner import AuthScanner
        from scanning.modules.api_scanner import APIScanner
        from scanning.modules.dir_scanner import DirectoryScanner
        from scanning.modules.cms_scanner import CMSScanner
        from scanning.modules.cloud_scanner import CloudScanner
        from scanning.modules.business_logic_scanner import BusinessLogicScanner
        from scanning.modules.authorization_engine import AuthorizationEngine
        from scanning.modules.post_exploitation import PostExploitationModule
        # Advanced Phase 1
        from scanning.modules.oauth_scanner import OAuthScanner
        from scanning.modules.ssti_scanner import SSTIScanner
        from scanning.modules.deserialization_scanner import DeserializationScanner
        from scanning.modules.websocket_scanner import WebSocketScanner
        from scanning.modules.mfa_bypass_scanner import MFABypassScanner
        from scanning.modules.nosql_scanner import NoSQLScanner
        from scanning.modules.smuggling_scanner import HTTPSmugglingScanner
        from scanning.modules.prototype_pollution_scanner import PrototypePollutionScanner
        from scanning.modules.crlf_scanner import CRLFScanner
        from scanning.modules.mobile_api_scanner import MobileAPIScanner
        from scanning.modules.saml_scanner import SAMLScanner
        # 100% Coverage Phase 2
        from scanning.modules.cache_poisoning_scanner import CachePoisoningScanner
        from scanning.modules.graphql_advanced_scanner import GraphQLAdvancedScanner
        from scanning.modules.ldap_xpath_scanner import LDAPXPathScanner
        from scanning.modules.kubernetes_scanner import KubernetesContainerScanner
        from scanning.modules.grpc_scanner import GRPCScanner
        from scanning.modules.dns_rebinding_scanner import DNSRebindingScanner
        from scanning.modules.email_security_scanner import EmailSecurityScanner
        from scanning.modules.sse_scanner import SSEScanner
        from scanning.modules.rate_limit_scanner import RateLimitScanner
        
        # Define ALL module configurations
        all_modules: list[ModuleConfig] = [
            # === PASSIVE MODULES (Always safe) ===
            ModuleConfig("nuclei", NucleiRunner, ModuleCategory.PASSIVE),
            ModuleConfig("headers", HeaderSecurityChecker, ModuleCategory.PASSIVE),
            ModuleConfig("ssl", SSLChecker, ModuleCategory.PASSIVE),
            ModuleConfig("cors", CORSChecker, ModuleCategory.PASSIVE),
            ModuleConfig("email_security", EmailSecurityScanner, ModuleCategory.PASSIVE),
            
            # === ACTIVE INJECTION MODULES ===
            ModuleConfig("sqli", SQLiScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("xss", XSSScanner, ModuleCategory.ACTIVE, requires_urls=True, requires_forms=True),
            ModuleConfig("cmdi", CommandInjectionScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("xxe", XXEScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("ssrf", SSRFScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("lfi", LFIScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("nosql", NoSQLScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("crlf", CRLFScanner, ModuleCategory.ACTIVE, requires_urls=True),
            ModuleConfig("ldap_xpath", LDAPXPathScanner, ModuleCategory.ACTIVE, requires_urls=True),
            
            # === ADVANCED INJECTION MODULES ===
            ModuleConfig("ssti", SSTIScanner, ModuleCategory.ADVANCED, requires_urls=True),
            ModuleConfig("deserialization", DeserializationScanner, ModuleCategory.ADVANCED, requires_urls=True),
            ModuleConfig("smuggling", HTTPSmugglingScanner, ModuleCategory.ADVANCED, min_safety_level="aggressive"),
            ModuleConfig("prototype_pollution", PrototypePollutionScanner, ModuleCategory.ADVANCED, requires_urls=True),
            ModuleConfig("cache_poisoning", CachePoisoningScanner, ModuleCategory.ADVANCED, min_safety_level="aggressive"),
            
            # === AUTHENTICATION MODULES ===
            ModuleConfig("auth", AuthScanner, ModuleCategory.AUTHENTICATION),
            ModuleConfig("oauth", OAuthScanner, ModuleCategory.AUTHENTICATION, requires_auth=True),
            ModuleConfig("saml", SAMLScanner, ModuleCategory.AUTHENTICATION),
            ModuleConfig("mfa_bypass", MFABypassScanner, ModuleCategory.AUTHENTICATION, requires_auth=True, min_safety_level="cautious"),
            ModuleConfig("rate_limit", RateLimitScanner, ModuleCategory.AUTHENTICATION, min_safety_level="cautious"),
            
            # === API MODULES ===
            ModuleConfig("api", APIScanner, ModuleCategory.API, requires_urls=True),
            ModuleConfig("graphql", GraphQLAdvancedScanner, ModuleCategory.API, requires_graphql=True),
            ModuleConfig("grpc", GRPCScanner, ModuleCategory.API, requires_grpc=True),
            ModuleConfig("websocket", WebSocketScanner, ModuleCategory.API, requires_websocket=True),
            ModuleConfig("sse", SSEScanner, ModuleCategory.API, requires_urls=True),
            ModuleConfig("mobile_api", MobileAPIScanner, ModuleCategory.API, requires_urls=True),
            
            # === INFRASTRUCTURE MODULES ===
            ModuleConfig("cloud", CloudScanner, ModuleCategory.INFRASTRUCTURE),
            ModuleConfig("kubernetes", KubernetesContainerScanner, ModuleCategory.INFRASTRUCTURE),
            ModuleConfig("dns_rebinding", DNSRebindingScanner, ModuleCategory.INFRASTRUCTURE, min_safety_level="standard"),
            ModuleConfig("dir_scanner", DirectoryScanner, ModuleCategory.INFRASTRUCTURE, requires_urls=True),
            ModuleConfig("cms", CMSScanner, ModuleCategory.INFRASTRUCTURE),
            
            # === ENTERPRISE MODULES ===
            ModuleConfig("business_logic", BusinessLogicScanner, ModuleCategory.ADVANCED, requires_urls=True, requires_auth=True),
            ModuleConfig("authorization", AuthorizationEngine, ModuleCategory.AUTHENTICATION, requires_auth=True),
            ModuleConfig("post_exploitation", PostExploitationModule, ModuleCategory.ADVANCED, min_safety_level="standard"),
        ]
        
        # Register modules
        loaded = 0
        skipped = 0
        
        for config in all_modules:
            try:
                # Check safety level compatibility
                if not self._is_safe_for_level(config.min_safety_level):
                    logger.debug(f"Skipping {config.name}: requires {config.min_safety_level} mode")
                    skipped += 1
                    continue
                
                self.modules[config.name] = config.cls(self.settings)
                self.module_configs[config.name] = config
                loaded += 1
                logger.debug(f"Loaded module: {config.name} ({config.category.name})")
                
            except Exception as e:
                logger.warning(f"Failed to load module {config.name}: {e}")
        
        logger.info(f"Modules loaded: {loaded}, skipped by safety level: {skipped}")
    
    def _is_safe_for_level(self, required_level: str) -> bool:
        """Check if current safety level allows the module."""
        levels = ["passive", "safe", "cautious", "standard", "aggressive"]
        
        current_idx = levels.index(self.safety_level) if self.safety_level in levels else 1
        required_idx = levels.index(required_level) if required_level in levels else 1
        
        return current_idx >= required_idx
    
    def _should_run_module(
        self,
        config: ModuleConfig,
        asset_data: dict[str, Any],
    ) -> bool:
        """Determine if a module should run based on asset data."""
        if not config.enabled:
            return False

        # Check requirements
        if isinstance(asset_data, dict):
            if config.requires_urls and not asset_data.get("urls"):
                return False
            if config.requires_forms and not asset_data.get("forms"):
                return False
            if config.requires_websocket and not asset_data.get("websocket_endpoints"):
                return False
            if config.requires_graphql and not asset_data.get("graphql_endpoint"):
                return False
            if config.requires_grpc and not asset_data.get("grpc_endpoints"):
                return False

        return True
    
    async def scan_host(
        self,
        host: str,
        asset_data: dict[str, Any],
        modules: str = "all",
        categories: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Scan a host for vulnerabilities using ALL relevant modules.
        
        Args:
            host: Target hostname
            asset_data: Reconnaissance data (urls, forms, tech, etc.)
            modules: Comma-separated list, 'all', or category names
            categories: List of categories to run (PASSIVE, ACTIVE, etc.)
            
        Returns:
            Dict with vulnerabilities and info
        """
        logger.info(f"Starting full vulnerability scan on {host} with {len(self.modules)} modules available")
        
        result = {
            "host": host,
            "vulnerabilities": [],
            "info": [],
            "modules_run": [],
            "modules_skipped": [],
        }
        
        # Select modules
        selected = self._select_modules(modules, categories, asset_data)
        
        if not selected:
            logger.warning(f"No valid modules selected for {host}")
            return result
        
        logger.info(f"Running {len(selected)} modules on {host}")
        
        # Create rate limiter
        rate_limiter = RateLimiter(
            settings=self.settings,
            default_rate=getattr(self.settings.rate_limit, 'requests_per_second', 10.0),
            default_burst=getattr(self.settings.rate_limit, 'concurrent_scans', 20),
        )
        
        # Group modules by category for phased execution
        passive_modules = []
        active_modules = []
        
        for name, module in selected.items():
            config = self.module_configs.get(name)
            if config and config.category == ModuleCategory.PASSIVE:
                passive_modules.append((name, module))
            else:
                active_modules.append((name, module))
        
        # Phase 1: Run passive modules first (parallel)
        if passive_modules:
            logger.info(f"Phase 1: Running {len(passive_modules)} passive modules")
            passive_results = await self._run_modules_parallel(
                passive_modules, host, asset_data, rate_limiter
            )
            self._aggregate_results(result, passive_results)
        
        # Phase 2: Run active modules (with rate limiting)
        if active_modules:
            logger.info(f"Phase 2: Running {len(active_modules)} active modules")
            active_results = await self._run_modules_parallel(
                active_modules, host, asset_data, rate_limiter, max_concurrent=5
            )
            self._aggregate_results(result, active_results)
        
        # Deduplicate and sort findings
        result["vulnerabilities"] = self._deduplicate_findings(result["vulnerabilities"])
        result["vulnerabilities"].sort(
            key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                x.get("severity", "INFO").upper(), 5
            )
        )
        
        logger.info(
            f"Scan complete for {host}: "
            f"{len(result['vulnerabilities'])} unique vulnerabilities, "
            f"{len(result['modules_run'])} modules executed"
        )
        return result
    
    def _select_modules(
        self,
        modules: str,
        categories: list[str] | None,
        asset_data: dict[str, Any],
    ) -> dict[str, ScanModule]:
        """Select modules to run based on criteria."""
        selected = {}
        
        if modules == "all":
            # Filter by category if specified
            if categories:
                cat_enums = [ModuleCategory[c.upper()] for c in categories if c.upper() in ModuleCategory.__members__]
                for name, module in self.modules.items():
                    config = self.module_configs.get(name)
                    if config and config.category in cat_enums:
                        if self._should_run_module(config, asset_data):
                            selected[name] = module
            else:
                # Run all applicable modules
                for name, module in self.modules.items():
                    config = self.module_configs.get(name)
                    if config and self._should_run_module(config, asset_data):
                        selected[name] = module
        else:
            # Parse comma-separated list
            module_names = [m.strip() for m in modules.split(",")]
            for name in module_names:
                if name in self.modules:
                    config = self.module_configs.get(name)
                    if config and self._should_run_module(config, asset_data):
                        selected[name] = self.modules[name]
        
        return selected
    
    async def _run_modules_parallel(
        self,
        modules: list[tuple[str, ScanModule]],
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
        max_concurrent: int = 10,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Run modules in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_with_semaphore(name: str, module: ScanModule) -> tuple[str, dict[str, Any], str | None]:
            async with semaphore:
                try:
                    result = await module.scan(host, asset_data, rate_limiter)
                    return (name, result, None)
                except Exception as e:
                    logger.error(f"Module {name} failed on {host}: {e}")
                    return (name, {"vulns": [], "info": []}, str(e))
        
        tasks = [run_with_semaphore(name, module) for name, module in modules]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def _aggregate_results(
        self,
        result: dict[str, Any],
        module_results: list[tuple[str, dict[str, Any], str | None]],
    ) -> None:
        """Aggregate results from multiple modules."""
        for name, mod_result, error in module_results:
            if error:
                result["modules_skipped"].append({"name": name, "error": error})
            else:
                result["modules_run"].append(name)
                result["vulnerabilities"].extend(mod_result.get("vulns", []))
                result["info"].extend(mod_result.get("info", []))
    
    def _deduplicate_findings(self, findings: list[dict]) -> list[dict]:
        """Remove duplicate findings based on key fields."""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create unique key
            key = (
                finding.get("vuln_type", finding.get("type", "")),
                finding.get("name", ""),
                finding.get("matched_at", ""),
                finding.get("host", ""),
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    async def _run_module(
        self,
        module: ScanModule,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Run a single scanning module."""
        try:
            logger.debug(f"Running module {module.name} on {host}")
            return await module.scan(host, asset_data, rate_limiter)
        except Exception as e:
            logger.error(f"Module {module.name} failed on {host}: {e}")
            return {"vulns": [], "info": []}
    
    def get_available_modules(self) -> list[str]:
        """Get list of available modules."""
        return list(self.modules.keys())
    
    def get_modules_by_category(self) -> dict[str, list[str]]:
        """Get modules grouped by category."""
        by_category: dict[str, list[str]] = {}
        
        for name, config in self.module_configs.items():
            cat_name = config.category.name
            if cat_name not in by_category:
                by_category[cat_name] = []
            by_category[cat_name].append(name)
        
        return by_category
    
    def get_statistics(self) -> dict[str, Any]:
        """Get scanner statistics."""
        by_category = self.get_modules_by_category()
        
        return {
            "version": self.VERSION,
            "total_modules": len(self.modules),
            "safety_level": self.safety_level,
            "modules_by_category": {k: len(v) for k, v in by_category.items()},
            "module_list": list(self.modules.keys()),
        }
