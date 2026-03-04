"""
Full Vulnerability Scanner v2.0 - INTELLIGENT SCANNING EDITION
==============================================================

Integrates ALL 39+ scanning modules with INTELLIGENT INFRASTRUCTURE:
- Scope Guard (legal compliance)
- Method Discovery (only test what exists)
- Parameter Analyzer (right payloads for right contexts)
- Negative Control (eliminate false positives)
- Finding Lifecycle (professional findings management)
- OOB Engine (blind vulnerability detection)

SAFETY SYSTEM:
- Global HTTP safety enforcement via SafeAsyncClient
- Environment-based safety mode (PHANTOM_SAFE_MODE)
- Destructive payload blocking at HTTP layer
- Supports: passive, safe, cautious, standard, aggressive

Supports Safe Mode for non-destructive testing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

# ═══════════════════════════════════════════════════════════════════════════════
# 🛡️ CRITICAL: ACTIVATE GLOBAL SAFETY AT MODULE LOAD TIME
# This ensures ALL httpx clients created anywhere are automatically safe
# ═══════════════════════════════════════════════════════════════════════════════
from utils.safe_http_client import enable_global_safety
enable_global_safety()
# ═══════════════════════════════════════════════════════════════════════════════

from utils.logger import get_logger
from utils.shared_findings_store import SharedFindingsStore, get_shared_findings
from utils.exploit_policy_engine import ExploitPolicyEngine, ExploitMode, get_exploit_policy
from utils.scan_client import reset_scan_session, get_circuit_breaker, configure_auto_rate_limiter

# Meta-vision: Coverage Tracker and State Explosion Controller
from scanning.coverage_tracker import (
    reset_coverage_tracker,
    SkipReason,
)
from scanning.state_explosion_controller import (
    reset_explosion_controller,
)
from scanning.focus_lock import (
    reset_focus_lock,
)
from scanning.exhaustion_tracker import (
    reset_exhaustion_tracker,
)
# THEME-14: Model Drift Awareness
from scanning.model_drift_awareness import (
    reset_drift_awareness,
)
# Module Registry - centralized module metadata
from scanning.module_registry import (
    ModuleCategory, ModuleInfo,
    get_module_registry,
)
# NOTE: ValidationPipeline now used via extracted scanning/scan_phases/validation.py

# Critical modules that should NEVER be skipped by classification/tech intel
# The cost of missing a real SQLi/XXE far outweighs the ~30s cost of running the module
NEVER_SKIP_MODULES = frozenset({
    "sqli", "xss", "dom_xss", "nosql", "cmdi", "xxe", "ssti", "lfi", "ssrf",
    "graphql", "websocket", "api", "grpc",  # API security — always test
})

# Adaptive Timeout System
from scanning.adaptive_timeout import (
    get_timeout_manager, reset_timeout_manager,
)
# Auth Refresher for automatic token refresh during long scans
from utils.auth_refresher import (
    AutoAuthRefresher, create_refresher_from_auth_context, setup_auth_refresher_for_target,
)
# NOTE: WAF detection now via extracted scanning/scan_phases/waf_detection.py

# Amplification System (extracted to scanning/amplification/)
from scanning.amplification import (
    AmplificationAction,
    ScanAmplifier,
)

# Configuration (extracted to scanning/config/)
from scanning.config import (
    ALL_MODULES as CONFIG_ALL_MODULES,
    SHORT_TO_REGISTRY_NAME as CONFIG_SHORT_TO_REGISTRY,
    SAFETY_HIERARCHY as CONFIG_SAFETY_HIERARCHY,
    MODULE_SAFETY_LEVELS as CONFIG_MODULE_SAFETY_LEVELS,
    CATEGORIES as CONFIG_CATEGORIES,
    # Module signatures
    STRING_ENDPOINTS_MODULES,
    TYPED_ENDPOINTS_MODULES,
    TWO_ARG_MODULES,
    SIMPLE_INTERFACE_MODULES,
    PORT_PARAMS_MODULES,
    OLD_3ARG_MODULES,
)

# Safety System (extracted to scanning/safety/)
from scanning.safety import (
    SafetyManager,
    SafetyMode,
)

# Module Loader (extracted to scanning/loader/)
from scanning.loader import ModuleLoader

# Metrics System (extracted to scanning/metrics/)
from scanning.metrics import (
    ScanResult,
    normalize_confidence,
)

# Orchestrator (extracted to scanning/orchestrator/)
from scanning.orchestrator import (
    CircuitBreakerManager,
    get_circuit_breaker_manager,
)

# Result Processor (extracted to scanning/result_processor/)
from scanning.result_processor import (
    FindingDeduplicator,
    ResultAggregator,
    share_findings_early,
    share_validated_findings,
    EARLY_SHARE_THRESHOLD,
    VALIDATED_SHARE_THRESHOLD,
)

# NOTE: PhaseInfo from scanning/phase_executor/ used by scan_phases modules

# Finding Enhancer (extracted to scanning/finding_enhancer/)
from scanning.finding_enhancer import (
    FindingValidator,
)

# Module Executor (extracted to scanning/module_executor/)
from scanning.module_executor import (
    OLD_3ARG_MODULES,
    is_signature_mismatch,
)

# Asset Builder (extracted to scanning/asset_builder/)
from scanning.asset_builder import (
    build_asset_data_from_scanner,
)

# Auth Testing (extracted to scanning/auth_testing/)
from scanning.auth_testing import (
    AuthTester,
    get_auth_headers,
    generate_expanded_ids,
    replace_id_in_url,
)

# Discovery (extracted to scanning/discovery/)
from scanning.discovery import (
    get_generic_fallback_endpoints,
    AuthenticatedCrawler,
)

# Scan Phases (extracted to scanning/scan_phases/)
from scanning.scan_phases import (
    DiscoveryPhaseRunner,
    DiscoveryConfig,
    PostProcessingRunner,
    PostProcessingConfig,
    PostProcessingResult,
    # Amplification handlers (extracted)
    AmplificationHandlers,
    # Pipeline scan (extracted)
    run_pipeline_scan,
)

# Second-order detection via extracted scanning/scan_phases/second_order.py
_SECOND_ORDER_AVAILABLE = True
try:
    from scanning.second_order_tracker import SecondOrderTracker
except ImportError:
    _SECOND_ORDER_AVAILABLE = False

if TYPE_CHECKING:
    from core.config_manager import Settings
    from scanning.scan_safety_config import ScanSafetyConfig
    from scanning.auth_context import AuthContext

# Load scanner limits from config (lazy import to avoid circular deps)
def _get_scanner_limits():
    """Get scanner limits with fallback defaults."""
    try:
        from core.config_manager import get_scanner_limits
        return get_scanner_limits()
    except Exception as e:
        logger.debug(f"Scanner limits config unavailable, using defaults: {e}")
        return None

logger = get_logger(__name__)

# Version info
SCANNER_VERSION = "2.0.0-INTELLIGENT"

# ═══════════════════════════════════════════════════════════════════════════════
# SCAN RESULT & METRICS - Moved to scanning/metrics/
# Import: from scanning.metrics import ScanResult, SEVERITY_TO_CONFIDENCE, normalize_confidence
# ═══════════════════════════════════════════════════════════════════════════════


# (ScanResult, SEVERITY_TO_CONFIDENCE, normalize_confidence moved to scanning/metrics/)


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN AMPLIFIER - Moved to scanning/amplification/
# Import: from scanning.amplification import ScanAmplifier, AmplificationAction
# ═══════════════════════════════════════════════════════════════════════════════


# (Code removed - all amplification classes now in scanning/amplification/)



class FullScanner:
    """
    Full vulnerability scanner v2.0 - INTELLIGENT SCANNING EDITION

    Now with FULL INTEGRATION of all professional infrastructure:
    - ScopeGuard: Never scan out-of-scope targets
    - MethodDiscovery: Only test methods that actually exist
    - ParameterAnalyzer: No XSS on integers, no SQLi on JWTs
    - NegativeControl: Eliminate false positives with twin payloads
    - FindingLifecycle: Professional state machine for findings
    - OOBEngine: Detect blind vulnerabilities

    Categories:
    - Injection (SQLi, XSS, CMDi, XXE, NoSQL, SSTI, LDAP, XPath)
    - Authentication (OAuth, SAML, MFA, Auth, Session)
    - API Security (REST, GraphQL, gRPC, WebSocket, SSE)
    - Infrastructure (SSL, Headers, CORS, Cloud, K8s)
    - Advanced (Smuggling, Cache Poisoning, Deserialization, Prototype Pollution)
    """

    VERSION = SCANNER_VERSION

    # ═══════════════════════════════════════════════════════════════════════════════
    # CIRCUIT BREAKER - Moved to scanning/orchestrator/
    # Import: from scanning.orchestrator import CircuitBreakerManager, get_circuit_breaker_manager
    # ═══════════════════════════════════════════════════════════════════════════════

    # Backwards-compatible class-level access (delegates to orchestrator module)
    _circuit_breaker_manager: Optional[CircuitBreakerManager] = None

    @classmethod
    def _get_cb_manager(cls) -> CircuitBreakerManager:
        """Get or create the circuit breaker manager."""
        if cls._circuit_breaker_manager is None:
            cls._circuit_breaker_manager = get_circuit_breaker_manager()
        return cls._circuit_breaker_manager

    @classmethod
    async def _get_circuit_breaker(cls, target: str) -> dict:
        """Get or create circuit breaker state for a target (backwards compat)."""
        manager = cls._get_cb_manager()
        state = await manager.get_state(target)
        # Return dict for backwards compatibility with existing code
        return {
            "consecutive_blocks": state.consecutive_blocks,
            "max_consecutive": state.max_consecutive,
            "pause_duration": state.pause_duration,
            "is_paused": state.is_paused,
            "total_pauses": state.total_pauses,
        }

    @classmethod
    async def _cleanup_circuit_breaker(cls, target: str) -> None:
        """Clean up circuit breaker state after scan completes."""
        manager = cls._get_cb_manager()
        await manager.cleanup(target)

    # ═══════════════════════════════════════════════════════════════════════════════
    # CONFIGURATION - Moved to scanning/config/
    # Import: from scanning.config import ALL_MODULES, SHORT_TO_REGISTRY_NAME, etc.
    # ═══════════════════════════════════════════════════════════════════════════════

    # Reference imported config (backwards compatible class attributes)
    ALL_MODULES = CONFIG_ALL_MODULES
    SHORT_TO_REGISTRY_NAME = CONFIG_SHORT_TO_REGISTRY
    SAFETY_HIERARCHY = CONFIG_SAFETY_HIERARCHY
    MODULE_SAFETY_LEVELS = CONFIG_MODULE_SAFETY_LEVELS
    CATEGORIES = CONFIG_CATEGORIES

    
    def __init__(
        self,
        settings: "Settings",
        safe_mode: str = "safe",
        intelligent_mode: bool = True,
        oob_callback_domain: str = "",
        include_subdomains: bool = False,
        scope: Optional[list[str]] = None,
        safety_config: Optional["ScanSafetyConfig"] = None,
        di_container: Optional[Any] = None,  # Phase 8: Optional DI container
    ) -> None:
        """
        Initialize full scanner.

        Args:
            settings: Application settings
            safe_mode: Safety level (passive, safe, cautious, standard, aggressive)
            intelligent_mode: Enable intelligent scanning infrastructure
            oob_callback_domain: Domain for OOB detection (optional)
            include_subdomains: If False, ONLY scan the exact target domain (no subdomains)
            scope: List of allowed domains for scope enforcement (wildcards supported)
            safety_config: Professional safety configuration (P0 controls)
            di_container: Optional DI container for dependency injection (Phase 8)
        """
        self.settings = settings
        self.safe_mode = safe_mode
        self.intelligent_mode = intelligent_mode
        self.oob_callback_domain = oob_callback_domain
        self.include_subdomains = include_subdomains
        self.scope = scope or []

        # ═══════════════════════════════════════════════════════════════════════
        # 🛡️ SAFETY SYSTEM (extracted to scanning/safety/)
        # Handles P0 controls, scope guard, HTTP safety, and evidence collection
        # ═══════════════════════════════════════════════════════════════════════
        self.safety_config = safety_config
        self._safety_manager = SafetyManager(
            safe_mode=safe_mode,
            safety_config=safety_config,
            scope=self.scope,
            include_subdomains=self.include_subdomains,
            settings=settings,
        )

        # Update safe_mode if overridden by safety_config
        self.safe_mode = self._safety_manager.mode.value

        # Extract safety components for backwards compatibility
        self.payload_analyzer = self._safety_manager.payload_analyzer
        self.proof_config = self._safety_manager.proof_config
        self.evidence_redactor = self._safety_manager.evidence_redactor
        self.scope_guard = self._safety_manager.scope_guard
        self.rate_limiter = self._safety_manager.rate_limiter
        self.safe_scanner = self._safety_manager.safe_scanner
        self.evidence_collector = self._safety_manager.evidence_collector
        self.evidence_engine = self._safety_manager.evidence_engine

        # Map SafetyMode to SafetyLevel for existing code compatibility
        from safe_mode import SafetyLevel
        level_map = {
            SafetyMode.PASSIVE: SafetyLevel.PASSIVE,
            SafetyMode.SAFE: SafetyLevel.SAFE,
            SafetyMode.CAUTIOUS: SafetyLevel.CAUTIOUS,
            SafetyMode.STANDARD: SafetyLevel.STANDARD,
            SafetyMode.AGGRESSIVE: SafetyLevel.AGGRESSIVE,
        }
        self.safety_level = level_map.get(self._safety_manager.mode, SafetyLevel.SAFE)

        # Track if protection was already verified (avoid duplicate checks)
        self._protection_verified = False
        self._evidence_session = None
        # ═══════════════════════════════════════════════════════════════════════

        # ═══════════════════════════════════════════════════════════════════════
        # 📦 MODULE LOADER (extracted to scanning/loader/)
        # Handles dynamic loading, caching, and cleanup of scanner modules
        # Phase 8: Now supports DI container for dependency injection
        # ═══════════════════════════════════════════════════════════════════════
        self._di_container = di_container
        self._di_scope = None
        if self._di_container is not None:
            try:
                self._di_scope = self._di_container.create_scope_sync()
                logger.debug("[FullScanner] DI container initialized with scope")
            except Exception as e:
                logger.debug(f"[FullScanner] DI scope creation failed: {e}")

        self._module_loader = ModuleLoader(
            settings,
            safe_mode=self.safe_mode,
            container=self._di_container,
            scope=self._di_scope,
        )
        # ═══════════════════════════════════════════════════════════════════════

        # Initialize target classifier
        self.target_classifier = None
        self.classification = None

        # Initialize intelligent scanning components
        self.intelligent_scanner = None
        self.intelligent_context = None

        # Store generic fallback endpoints for later merging
        # These are common patterns discovered before intelligent_context is created
        self._fallback_endpoints: list[str] = []

        # Initialize enterprise technology intelligence
        self.tech_intelligence = None
        self.tech_analysis = None
        self.tech_fingerprinter = None
        self.fingerprint_result = None

        # Initialize unified intelligence layer (combines all systems)
        self.unified_intelligence = None
        self.unified_result = None

        if self.intelligent_mode:
            # Import target classifier
            from scanning.target_classifier import TargetClassifier
            self.target_classifier = TargetClassifier(settings)
            
            from scanning.intelligent_scanner import IntelligentScanner, IntelligentScanConfig
            from utils.scope_guard import ScopeMode
            
            # Map safe mode to scope mode
            scope_mode_map = {
                "passive": ScopeMode.STRICT,
                "safe": ScopeMode.STRICT,
                "cautious": ScopeMode.STRICT,
                "standard": ScopeMode.PERMISSIVE,
                "aggressive": ScopeMode.PERMISSIVE,
            }
            
            config = IntelligentScanConfig(
                scope_mode=scope_mode_map.get(safe_mode, ScopeMode.STRICT),
                include_subdomains=self.include_subdomains,
                use_negative_control=True,
                enable_oob=bool(oob_callback_domain),
                oob_callback_domain=oob_callback_domain,
                min_confidence=60.0,
            )
            
            self.intelligent_scanner = IntelligentScanner(settings, config)
            logger.info(f"Intelligent scanning ENABLED")

            # Initialize enterprise technology intelligence
            try:
                from scanning.tech_intelligence import TechIntelligence
                self.tech_intelligence = TechIntelligence(settings)
                logger.info(f"TechIntelligence v{self.tech_intelligence.VERSION} ENABLED")
            except ImportError as e:
                logger.warning(f"TechIntelligence not available: {e}")

            # C1/C4 FIX: Initialize TechFingerprinter (500+ signatures)
            # Complements TechIntelligence with broader detection coverage
            try:
                from phantom.tech_fingerprinter import TechFingerprinter
                self.tech_fingerprinter = TechFingerprinter()
                logger.info(f"TechFingerprinter v{self.tech_fingerprinter.VERSION} ENABLED ({len(self.tech_fingerprinter.database.signatures)} signatures)")
            except ImportError as e:
                self.tech_fingerprinter = None
                logger.warning(f"TechFingerprinter not available: {e}")

            # Initialize unified intelligence layer
            try:
                from scanning.unified_intelligence import UnifiedIntelligence
                self.unified_intelligence = UnifiedIntelligence(settings)
                logger.info(f"UnifiedIntelligence v{self.unified_intelligence.VERSION} ENABLED")
            except ImportError as e:
                logger.warning(f"UnifiedIntelligence not available: {e}")

            # Initialize vulnerability chain engine
            try:
                from scanning.vuln_chain_engine import VulnerabilityChainEngine
                self.chain_engine = VulnerabilityChainEngine()
                logger.info("VulnerabilityChainEngine ENABLED - vulnerability chaining active")
            except ImportError as e:
                self.chain_engine = None
                logger.warning(f"VulnerabilityChainEngine not available: {e}")
        else:
            self.chain_engine = None

        # Initialize Scan Amplifier for adaptive depth and cross-finding amplification
        self.scan_amplifier = ScanAmplifier(self)
        self._pending_amplifications: list[AmplificationAction] = []
        # FIX H3: Limit amplification queue to prevent memory exhaustion
        self._max_amplification_queue_size = 500  # Cap at 500 actions
        logger.info("ScanAmplifier ENABLED - adaptive depth and cross-finding amplification active")

        # Initialize Coverage Tracker for meta-vision
        # Tracks what was tested, what was skipped, and why
        self.coverage_tracker = reset_coverage_tracker()
        logger.info("CoverageTracker ENABLED - meta-vision for test coverage awareness")

        # Initialize State Explosion Controller
        # Manages budget, priority queue, and cut heuristics for adaptive scanning
        limits = _get_scanner_limits()
        total_budget = getattr(limits, 'amplification', None)
        total_budget = getattr(total_budget, 'max_total_actions', 10000) if total_budget else 10000
        self.explosion_controller = reset_explosion_controller(
            total_budget=total_budget,
            max_queue_size=1000,
        )
        logger.info(f"StateExplosionController ENABLED - budget={total_budget}")

        # Initialize Focus Lock for strategic depth
        # Maintains focus on promising vulnerability categories until exhausted
        self.focus_lock = reset_focus_lock()
        logger.info("FocusLock ENABLED - strategic depth with hypothesis persistence")

        # Initialize Exhaustion Tracker for per-finding completion
        # Ensures all vectors are tried before moving on from a finding
        self.exhaustion_tracker = reset_exhaustion_tracker()
        logger.info("ExhaustionTracker ENABLED - per-finding exhaustion criteria")

        # THEME-14: Initialize Model Drift Awareness
        # Tracks pattern freshness and model staleness
        self.drift_awareness = reset_drift_awareness()
        logger.info("ModelDriftAwareness ENABLED - epistemic awareness for pattern staleness")

        # Auth Refresher for automatic token refresh during long scans
        # Prevents auth timeout issues when scanning takes longer than token expiry
        self._auth_refresher: AutoAuthRefresher | None = None
        self._last_auth_refresh_check: float = 0.0
        self._auth_refresh_interval: float = 60.0  # Check every 60 seconds
        logger.debug("AuthRefresher initialization deferred to Phase 2.5")

        logger.info(
            f"FullScanner v{self.VERSION} initialized: "
            f"{len(self.ALL_MODULES)} modules, safe_mode={safe_mode}, intelligent={intelligent_mode}"
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # P0.3: PAYLOAD SAFETY VALIDATION
    # ═══════════════════════════════════════════════════════════════════════════

    def validate_payload(
        self,
        payload: str,
        category: str = "other",
    ) -> tuple[bool, str]:
        """
        Validate a payload against the safety configuration.

        P0.3 FIX: Blocks destructive payloads based on safety level.

        Args:
            payload: The payload to validate
            category: Payload category (sqli, cmdi, xss, etc.)

        Returns:
            Tuple of (is_safe, reason_if_blocked)

        Usage:
            is_safe, reason = scanner.validate_payload("'; DROP TABLE users--", "sqli")
            if not is_safe:
                logger.warning(f"Payload blocked: {reason}")
                return
        """
        if self.payload_analyzer is None:
            # No analyzer configured - use basic safety check
            if self.safe_mode in ("passive", "safe"):
                # In safe modes, block obviously destructive patterns
                destructive_keywords = [
                    "DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT",
                    "rm -rf", "shutdown", "reboot", "mkfs",
                ]
                for keyword in destructive_keywords:
                    if keyword.lower() in payload.lower():
                        return False, f"Destructive keyword '{keyword}' blocked in {self.safe_mode} mode"
            return True, "OK"

        # Use the configured PayloadSafetyAnalyzer
        return self.payload_analyzer.validate(payload, category)

    def filter_payloads(
        self,
        payloads: list[str],
        category: str = "other",
    ) -> list[str]:
        """
        Filter a list of payloads, returning only safe ones.

        P0.3 FIX: Bulk filtering for efficiency.

        Args:
            payloads: List of payloads to filter
            category: Payload category

        Returns:
            List of safe payloads
        """
        if self.payload_analyzer is None:
            # No analyzer - return all (basic check happens per-payload)
            return [p for p in payloads if self.validate_payload(p, category)[0]]

        from scanning.destructive_controls import PayloadCategory

        # Map string category to enum
        try:
            cat_enum = PayloadCategory(category.lower())
        except ValueError:
            cat_enum = PayloadCategory.OTHER

        return self.payload_analyzer.filter_payloads(payloads, cat_enum)

    def get_payload_safety_stats(self) -> dict:
        """Get statistics about blocked payloads."""
        if self.payload_analyzer is None:
            return {"analyzer": "not_configured"}
        return self.payload_analyzer.get_stats()

    # ═══════════════════════════════════════════════════════════════════════════
    # P0.7: EVIDENCE REDACTION
    # ═══════════════════════════════════════════════════════════════════════════

    def redact_finding(self, finding: dict) -> dict:
        """
        Redact sensitive information from a finding.

        P0.7 FIX: Removes PII before including in reports.

        Args:
            finding: The finding dictionary

        Returns:
            Redacted finding
        """
        if self.evidence_redactor is None:
            return finding
        return self.evidence_redactor.redact_finding(finding)

    def redact_findings(self, findings: list[dict]) -> list[dict]:
        """
        Redact sensitive information from multiple findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of redacted findings
        """
        if self.evidence_redactor is None:
            return findings
        return [self.evidence_redactor.redact_finding(f) for f in findings]

    def get_redaction_summary(self) -> dict:
        """Get summary of redactions performed."""
        if self.evidence_redactor is None:
            return {"redactor": "not_configured"}
        return self.evidence_redactor.get_redaction_summary()

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTH REFRESHER: Automatic token refresh for long scans
    # ═══════════════════════════════════════════════════════════════════════════

    def _setup_auth_refresher(
        self,
        auth_context: "AuthContext",
        target: str,
    ) -> AutoAuthRefresher | None:
        """Set up auth refresher with credentials from auth_context."""
        # Delegates to utils.auth_refresher.setup_auth_refresher_for_target
        return setup_auth_refresher_for_target(auth_context, target)

    async def _maybe_refresh_auth(self) -> bool:
        """
        Check if auth refresh is needed and perform refresh if necessary.

        This method should be called periodically during long scans to prevent
        auth timeout issues. It checks the refresh interval and only refreshes
        when needed.

        Returns:
            True if refresh was performed successfully, False otherwise
        """
        import time

        # Skip if no refresher configured
        if not self._auth_refresher or not self._auth_refresher.has_credentials():
            return False

        # Rate limit refresh checks
        now = time.time()
        if now - self._last_auth_refresh_check < self._auth_refresh_interval:
            return False

        self._last_auth_refresh_check = now

        # Check if auth is still fresh using existing method
        # Only refresh if auth is stale (older than 5 minutes since last use)
        if self._auth_context and hasattr(self._auth_context, 'check_auth_freshness'):
            if self._auth_context.check_auth_freshness(max_age_seconds=300):
                # Auth is still fresh, no need to refresh
                return False
        elif self._auth_context and self._auth_context.refresh_status == "fresh":
            # If no check_auth_freshness method, use refresh_status
            return False

        # Perform refresh
        try:
            result = await self._auth_refresher.refresh()
            if result.success:
                # Update auth context with new credentials
                if result.new_token:
                    self._auth_context.token = result.new_token
                    logger.info(
                        f"[AUTH_REFRESHER] Token refreshed successfully "
                        f"(took={result.took_seconds:.2f}s)"
                    )
                if result.new_cookies:
                    if not self._auth_context.cookies:
                        self._auth_context.cookies = {}
                    self._auth_context.cookies.update(result.new_cookies)
                    logger.info(
                        f"[AUTH_REFRESHER] Session cookies refreshed "
                        f"(cookies={len(result.new_cookies)})"
                    )
                return True
            else:
                logger.warning(
                    f"[AUTH_REFRESHER] Refresh failed: {result.error}"
                )
                return False
        except Exception as e:
            logger.warning(f"[AUTH_REFRESHER] Refresh error: {e}")
            return False

    def get_auth_refresher_summary(self) -> dict:
        """Get summary of auth refresher status and activity."""
        if not self._auth_refresher:
            return {"configured": False}
        return self._auth_refresher.get_summary()

    # ═══════════════════════════════════════════════════════════════════════════
    # 📦 MODULE LOADING (extracted to scanning/loader/)
    # ═══════════════════════════════════════════════════════════════════════════

    @property
    def loaded_modules(self) -> dict[str, Any]:
        """Get the dictionary of loaded module instances (backwards compatibility)."""
        return self._module_loader.loaded_modules

    def _load_module(self, name: str) -> Optional[Any]:
        """
        Dynamically load a scanner module.

        Delegates to ModuleLoader which uses ModuleRegistry as the primary
        source of module metadata, with fallback to ALL_MODULES.

        Args:
            name: Short module name (e.g., "sqli") or registry name (e.g., "sqli_scanner")

        Returns:
            Instantiated scanner module or None if loading fails
        """
        result = self._module_loader.load(name)
        return result.module if result.success else None

    def _enqueue_amplification(self, action: AmplificationAction) -> bool:
        """
        Add an amplification action to the queue with size limit check.

        FIX H3: Prevents unbounded queue growth that can exhaust memory.
        Drops low-priority actions when queue is full.

        Args:
            action: The amplification action to enqueue

        Returns:
            True if action was added, False if dropped due to queue limit
        """
        if len(self._pending_amplifications) >= self._max_amplification_queue_size:
            # Queue full - only add if priority is higher than lowest in queue
            if self._pending_amplifications:
                min_priority = min(a.priority for a in self._pending_amplifications)
                if action.priority > min_priority:
                    # Replace lowest priority action
                    for i, existing in enumerate(self._pending_amplifications):
                        if existing.priority == min_priority:
                            self._pending_amplifications[i] = action
                            logger.debug(f"[H3-FIX] Replaced low-priority amplification (priority {min_priority} → {action.priority})")
                            return True
                    return False
                else:
                    logger.debug(f"[H3-FIX] Dropped amplification (queue full, priority {action.priority} <= min {min_priority})")
                    return False
            return False

        self._pending_amplifications.append(action)
        return True

    async def scan(
        self,
        target: str,
        category: str = "web",
        modules: Optional[list[str]] = None,
        concurrent: int = 5,
        skip_classification: bool = False,
        use_linux_tools: bool = True,  # ENABLED BY DEFAULT - tools run before modules
        on_progress: Optional[Any] = None,  # Callback(result) for incremental state updates
        use_pipeline: bool = False,  # Use new Pipeline architecture (experimental)
    ) -> ScanResult:
        """
        Run security scan on target with INTELLIGENT INFRASTRUCTURE.

        This method orchestrates the scanning pipeline:
        0. Classifies target type (NEW - Intelligence before brute force!)
        1. Verifies network protection (Tor/Proxy)
        2. Runs intelligent pre-scan analysis
        3. Executes scanning modules (filtered by classification)
        4. Aggregates and validates results
        5. Finalizes intelligent scan metrics

        Args:
            target: Target URL/host
            category: Scan category (quick, web, api, injection, auth, infra, advanced, full)
            modules: Specific modules to run (overrides category)
            concurrent: Max concurrent module scans
            skip_classification: Skip target classification (default: False)
            use_linux_tools: Run external Linux tools (nmap, nuclei, nikto, etc.)
            use_pipeline: Use the new Pipeline architecture (experimental, default: False)

        Returns:
            ScanResult with all findings

        New Features (v2.0):
            - Phase 2.5: Linux tools orchestration with intelligent chaining
            - Phase 4.3: Vulnerability chain engine (SQLi→RCE, LFI→Secrets, etc.)
        """
        # ═══════════════════════════════════════════════════════════════════════
        # PIPELINE MODE: Use new composable pipeline architecture
        # ═══════════════════════════════════════════════════════════════════════
        if use_pipeline:
            logger.info("[Pipeline] Using new Pipeline architecture")
            return await self.scan_with_pipeline(
                target=target,
                category=category,
                modules=modules,
                concurrent=concurrent,
            )

        result = ScanResult(
            target=target,
            start_time=datetime.now(),
            safe_mode=self.safe_mode,
            intelligent_mode=self.intelligent_mode,
        )

        # ═══════════════════════════════════════════════════════════════════════
        # THEME-8: Initialize deterministic context for reproducible scans
        # ═══════════════════════════════════════════════════════════════════════
        from scanning.determinism import init_deterministic_scan, is_deterministic_mode
        determinism_info = init_deterministic_scan(target)
        if is_deterministic_mode():
            logger.info(f"[THEME-8] Deterministic scan initialized: seed={determinism_info.get('base_seed')}")
            # BUG-FIX: result.info is a list, not a dict
            result.info.append({"type": "determinism", "data": determinism_info})

        # ═══════════════════════════════════════════════════════════════════════
        # THEME-9: Initialize saturation controller for budget limits
        # ═══════════════════════════════════════════════════════════════════════
        from scanning.saturation_controller import reset_saturation_controller, get_saturation_controller
        reset_saturation_controller()
        saturation_ctrl = get_saturation_controller()
        saturation_ctrl.start_scan()
        logger.info("[THEME-9] Saturation controller initialized for cognitive saturation prevention")

        # ═══════════════════════════════════════════════════════════════════════
        # FIX 2026-02-16: Localhost detection — bypass proxy/Tor for local targets
        # Tor cannot route to 127.0.0.1, causing scan failures and 480s timeouts
        # ═══════════════════════════════════════════════════════════════════════
        from utils.scan_client import is_localhost_target
        if is_localhost_target(target):
            import os
            os.environ["PHANTOM_LOCALHOST_TARGET"] = "1"
            logger.info("🏠 Localhost target detected — proxy/Tor will be bypassed")
            # FIX 2026-02-20: Reset cached network protection to pick up the new env var
            # The http_client caches protection settings on first use, so we need to
            # clear the cache after setting PHANTOM_LOCALHOST_TARGET
            try:
                from utils.http_client import reset_network_protection
                reset_network_protection()
            except ImportError:
                pass  # Function not available in older versions
        else:
            import os
            os.environ.pop("PHANTOM_LOCALHOST_TARGET", None)

        # ═══════════════════════════════════════════════════════════════════════
        # NETWORK STATUS BANNER - Show proxy/Tor configuration clearly
        # ═══════════════════════════════════════════════════════════════════════
        no_tor = os.environ.get("PHANTOM_NO_TOR", "").lower() in ("1", "true", "yes")
        localhost_target = os.environ.get("PHANTOM_LOCALHOST_TARGET", "").lower() in ("1", "true", "yes")
        if no_tor or localhost_target:
            reason = "PHANTOM_NO_TOR=1" if no_tor else "localhost target"
            logger.info(f"╔════════════════════════════════════════════════════════════╗")
            logger.info(f"║  🔌 NETWORK: DIRECT CONNECTION (no proxy/Tor)              ║")
            logger.info(f"║  📍 Reason: {reason:<45} ║")
            logger.info(f"╚════════════════════════════════════════════════════════════╝")
        else:
            from utils.http_client import get_network_protection
            protection = get_network_protection()
            if protection.proxy_config.enabled:
                proxy_type = protection.proxy_config.proxy_type.value
                logger.info(f"╔════════════════════════════════════════════════════════════╗")
                logger.info(f"║  🔒 NETWORK: Proxy/Tor ENABLED ({proxy_type:<20})     ║")
                logger.info(f"╚════════════════════════════════════════════════════════════╝")
            else:
                logger.info(f"╔════════════════════════════════════════════════════════════╗")
                logger.info(f"║  🌐 NETWORK: DIRECT CONNECTION (no proxy configured)       ║")
                logger.info(f"╚════════════════════════════════════════════════════════════╝")

        # ═══════════════════════════════════════════════════════════════════════
        # ETHICS-08: Real-time scope validation
        # Block scanning of out-of-scope targets
        # ═══════════════════════════════════════════════════════════════════════
        if self.scope_guard:
            allowed, violation = self.scope_guard.is_allowed(target)
            if not allowed:
                error_msg = f"TARGET BLOCKED BY SCOPE GUARD: {violation.reason if violation else 'Unknown'}"
                logger.error(f"🚫 {error_msg}")
                result.end_time = datetime.now()
                result.scope_violations = 1
                result.errors.append({
                    "type": "scope_violation",
                    "target": target,
                    "reason": violation.reason if violation else "Target not in allowed scope",
                    "message": "Professional pentesting requires staying within defined scope"
                })

                # Log scope violation to audit trail
                try:
                    from utils.audit_logger import get_audit_logger
                    audit = get_audit_logger()
                    if audit:
                        audit.log_scope_violation(
                            url=target,
                            reason=violation.reason if violation else "Target not in allowed scope",
                            blocked=True,
                        )
                        audit.log_scan_aborted(target=target, reason="Scope violation")
                except ImportError:
                    logger.debug("Audit logger unavailable for scope violation event")

                return result

            logger.info(f"✓ Target {target} verified in scope")

        # ═══════════════════════════════════════════════════════════════════════
        # P0-002: Wrap main scan in try/finally for guaranteed cleanup
        # Without this, exceptions cause resource leaks (modules, circuit breakers)
        # ═══════════════════════════════════════════════════════════════════════
        try:
            return await self._scan_main(target, category, modules, concurrent, skip_classification, use_linux_tools, on_progress, result)
        finally:
            # Always cleanup regardless of exceptions
            await self._scan_cleanup(target, result)

    async def scan_with_pipeline(
        self,
        target: str,
        category: str = "web",
        modules: Optional[list[str]] = None,
        concurrent: int = 5,
    ) -> ScanResult:
        """Run security scan using the Pipeline architecture (experimental)."""
        # Delegates to extracted scan_phases.pipeline_scan module
        return await run_pipeline_scan(
            target=target,
            category=category,
            modules=modules,
            concurrent=concurrent,
            safe_mode=self.safe_mode,
            intelligent_mode=self.intelligent_mode,
            include_subdomains=self.include_subdomains,
            get_modules_for_category=self._get_modules_for_category,
            scan_result_class=ScanResult,
        )

    def _get_modules_for_category(self, category: str, modules: Optional[list[str]] = None) -> list[str]:
        """Get list of module names for a scan category."""
        if modules:
            return modules
        return self.CATEGORIES.get(category, self.CATEGORIES.get("web", []))

    async def _scan_cleanup(self, target: str, result: ScanResult) -> None:
        """
        P0-002: Guaranteed cleanup after scan (normal or exception).

        Ensures:
        - result.end_time is set
        - Modules are cleaned up (memory)
        - Circuit breaker is reset
        - Deterministic context finalized
        - Saturation stats collected
        """
        # Set end_time if not already set
        if result.end_time is None:
            result.end_time = datetime.now()

        # Clean up module instances to prevent memory leaks
        try:
            await self._cleanup_modules()
        except Exception as cleanup_err:
            logger.warning(f"[P0-002] Module cleanup error (non-fatal): {cleanup_err}")

        # Clean up circuit breaker for this target
        try:
            await self._cleanup_circuit_breaker(target)
        except Exception as cb_err:
            logger.debug(f"[P0-002] Circuit breaker cleanup error (non-fatal): {cb_err}")

        # Finalize deterministic context if active
        try:
            from scanning.determinism import finalize_deterministic_scan, is_deterministic_mode
            if is_deterministic_mode():
                finalize_deterministic_scan()
        except Exception as det_err:
            logger.debug(f"[P0-002] Determinism cleanup error (non-fatal): {det_err}")

        # Stop session watchdog if active
        try:
            if hasattr(self, '_session_watchdog') and self._session_watchdog:
                await self._session_watchdog.stop()
                # Log watchdog summary
                summary = self._session_watchdog.get_summary()
                if summary.get("total_refreshes", 0) > 0 or summary.get("total_reauths", 0) > 0:
                    logger.info(
                        f"[SESSION_WATCHDOG] Summary: "
                        f"refreshes={summary.get('total_refreshes', 0)}, "
                        f"reauths={summary.get('total_reauths', 0)}"
                    )
        except Exception as wd_err:
            logger.debug(f"[P0-002] Session watchdog cleanup error (non-fatal): {wd_err}")

        # Log to audit trail
        try:
            from utils.audit_logger import get_audit_logger
            audit = get_audit_logger()
            if audit and result.start_time and result.end_time:
                duration = (result.end_time - result.start_time).total_seconds()
                audit.log_scan_completed(
                    target=target,
                    findings_count=len(result.findings),
                    duration_seconds=duration,
                    scope_violations=result.scope_violations,
                )
        except Exception:
            pass  # Non-critical

    async def _scan_main(
        self,
        target: str,
        category: str,
        modules: Optional[list[str]],
        concurrent: int,
        skip_classification: bool,
        use_linux_tools: bool,
        on_progress: Optional[Any],
        result: ScanResult,
    ) -> ScanResult:
        """Main scan logic extracted for try/finally wrapper."""
        # Initialize skip tracking (used by Phase 0 classification)
        skipped_modules: list = []
        skip_reasons: dict = {}

        # Log scan start to audit trail
        try:
            from utils.audit_logger import get_audit_logger
            audit = get_audit_logger()
            if audit:
                audit.log_scan_started(
                    target=target,
                    modules=modules,
                    safe_mode=self.safe_mode,
                    config={"category": category, "concurrent": concurrent},
                )
        except ImportError:
            logger.debug("Audit logger unavailable for scan start event")

        # Set target locality BEFORE modules are loaded — allows ScopeGuard
        # to permit localhost requests when the scan target itself is localhost
        from scanning.vuln_scanner import ScanModule
        ScanModule.set_target_is_local(target)

        # Initialize Evidence Engine v3.0 session for comprehensive evidence collection
        # This provides automatic screenshots, timeline reconstruction, and evidence packages
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._evidence_session = self.evidence_engine.start_session(target=target, scan_id=scan_id)
        self.evidence_engine.add_timeline_event(
            event_type="scan_start",
            description=f"Security scan initiated on {target}",
            url=target,
            details={"safe_mode": self.safe_mode, "intelligent_mode": self.intelligent_mode}
        )
        logger.info(f"📸 Evidence Engine v3.0 session started: {scan_id}")

        # Initialize shared findings store for inter-module communication
        SharedFindingsStore.reset()
        shared_store = get_shared_findings()
        shared_store.set_session(f"{target}_{datetime.now().isoformat()}")
        logger.debug("SharedFindingsStore initialized for inter-module communication")

        # Reset scan client session (circuit breaker, request deduplication)
        reset_scan_session()
        logger.debug("ScanClient session reset (circuit breaker + dedup cache cleared)")

        # Configure auto rate limiter based on settings
        # This applies automatic rate limiting to ALL modules using get_scan_client()
        rate_config = getattr(self.settings, 'rate_limit', None)
        if rate_config:
            configure_auto_rate_limiter(
                requests_per_second=getattr(rate_config, 'requests_per_second', 10.0),
                burst=getattr(rate_config, 'concurrent_scans', 20),
            )
        else:
            configure_auto_rate_limiter(requests_per_second=10.0, burst=20)

        # Initialize exploit policy engine (SECURITY GATEKEEPER)
        # This controls what exploitation operations are allowed
        ExploitPolicyEngine.reset()
        exploit_policy = get_exploit_policy()
        exploit_policy.add_target_scope(target)

        # Set policy mode based on safe_mode setting
        # DETECT_ONLY = passive detection only (no verification payloads)
        # VERIFY = safe verification (confirms vulns but no data extraction)
        # EXPLOIT = disabled (was for exploitation, now removed for safety)
        if self.safe_mode == "passive":
            exploit_policy.set_mode(ExploitMode.DETECT_ONLY)
            logger.info("🛡️ Exploit Policy: DETECT_ONLY mode (passive detection only)")
        else:
            # safe, cautious, standard, aggressive all use VERIFY
            # VERIFY allows confirming vulnerabilities without extracting data
            exploit_policy.set_mode(ExploitMode.VERIFY)
            logger.info("🛡️ Exploit Policy: VERIFY mode (safe verification, no data extraction)")

        # Reset chain engine state for new scan (prevents context/action leakage between scans)
        if self.chain_engine:
            self.chain_engine.reset()
            logger.debug("VulnerabilityChainEngine reset for new scan")

        # Phase 0-0.9: Discovery (target classification, tech intel, endpoint discovery)
        # Uses DiscoveryPhaseRunner for modular phase execution
        discovery_config = DiscoveryConfig(
            intelligent_mode=self.intelligent_mode,
            include_subdomains=getattr(self, "include_subdomains", False),
            skip_classification=skip_classification,
        )
        discovery_runner = DiscoveryPhaseRunner(
            settings=self.settings,
            target_classifier=self.target_classifier,
            tech_intelligence=self.tech_intelligence if hasattr(self, "tech_intelligence") else None,
            tech_fingerprinter=self.tech_fingerprinter if hasattr(self, "tech_fingerprinter") else None,
            evidence_engine=self.evidence_engine if self._evidence_session else None,
            rate_limiter=self.rate_limiter,
            coverage_tracker=getattr(self, "coverage_tracker", None),
            config=discovery_config,
        )
        discovery_result = await discovery_runner.run(target, result)

        # Copy discovery results to scanner instance attributes
        self.classification = discovery_result.classification
        self.tech_analysis = discovery_result.tech_analysis
        self.fingerprint_result = discovery_result.fingerprint_result
        self._api_discovery = discovery_result.api_discovery
        self._api_specification = discovery_result.api_specification
        self._injectable_endpoints = discovery_result.injectable_endpoints
        self._auth_bypass_candidates = discovery_result.auth_bypass_candidates
        self._security_schemes = discovery_result.security_schemes
        self._discovered_subdomains = discovery_result.discovered_subdomains
        self._domain_classification = discovery_result.domain_classification
        self._runtime_engine = discovery_result.runtime_engine
        self._stack_profile = discovery_result.stack_profile

        # Get skipped modules from discovery (with NEVER_SKIP protection already applied)
        skipped_modules = list(discovery_result.skipped_modules)
        skip_reasons = dict(discovery_result.skip_reasons)

        # Phase 0.95: WAF Detection (OPSEC)
        # Detect WAF before heavy scanning to adjust rate and strategy
        await self._detect_waf_early(target, result)

        # Phase 1: Verify network protection
        await self._verify_network_protection(result)

        # Phase 1.5: Adaptive Timeout Baseline Measurement
        await self._calibrate_adaptive_timeout(target, result)

        # Phase 2: Intelligent pre-scan analysis
        if self.intelligent_mode and self.intelligent_scanner:
            should_continue = await self._run_intelligent_pre_scan(target, result)
            if not should_continue:
                return result

        # Determine modules to run
        # L10 FIX: Try loading from config first, fall back to hardcoded CATEGORIES
        module_names = modules
        if not module_names:
            # Try to load category from settings.yaml
            config_categories = None
            try:
                config_categories = getattr(self.settings, 'module_categories', None)
                if hasattr(config_categories, category):
                    module_names = list(getattr(config_categories, category))
                    logger.debug(f"[L10] Loaded category '{category}' from config ({len(module_names)} modules)")
                elif isinstance(config_categories, dict) and category in config_categories:
                    module_names = list(config_categories[category])
                    logger.debug(f"[L10] Loaded category '{category}' from config ({len(module_names)} modules)")
            except Exception:
                pass  # Fall back to hardcoded

            # Fall back to hardcoded CATEGORIES if not found in config
            if not module_names:
                module_names = self.CATEGORIES.get(category, self.CATEGORIES["web"])
        original_count = len(module_names)

        # Track what was requested vs what will run
        result.modules_requested = list(module_names)

        # ═══════════════════════════════════════════════════════════════════════
        # SAFETY FILTER: Remove modules that require a higher safety level
        # than what is currently configured. This prevents dangerous modules
        # (smuggling, cache poisoning, etc.) from running in safe/cautious modes.
        # ═══════════════════════════════════════════════════════════════════════
        current_safety_idx = self.SAFETY_HIERARCHY.index(self.safe_mode) if self.safe_mode in self.SAFETY_HIERARCHY else 1

        safety_blocked = []
        safety_filtered = []
        for mod in module_names:
            required_level = self.MODULE_SAFETY_LEVELS.get(mod, "passive")
            required_idx = self.SAFETY_HIERARCHY.index(required_level) if required_level in self.SAFETY_HIERARCHY else 0
            if current_safety_idx >= required_idx:
                safety_filtered.append(mod)
            else:
                safety_blocked.append(mod)
                logger.warning(
                    f"SAFETY BLOCK: Module '{mod}' requires safety_mode='{required_level}' "
                    f"but current mode is '{self.safe_mode}' — skipping to protect target"
                )
                result.tests_skipped += 1
                if mod not in result.modules_not_executed:
                    result.modules_not_executed.append(mod)
                if mod not in result.skip_reasons:
                    result.skip_reasons[mod] = f"Requires safety_mode='{required_level}', current='{self.safe_mode}'"

                # L4 FIX: Record safety-blocked module to coverage tracker
                self.coverage_tracker.record_skip(
                    surface_type="module",
                    identifier=mod,
                    reason=SkipReason.SAFETY_BLOCKED,
                    reason_detail=f"Module '{mod}' requires safety_mode='{required_level}' but current mode is '{self.safe_mode}'",
                    potential_impact=f"Vulnerabilities testable by {mod} were not checked (dangerous module in safe mode)",
                    module_name=mod,
                )

        if safety_blocked:
            module_names = safety_filtered
            logger.info(
                f"Safety filter: blocked {len(safety_blocked)} dangerous modules "
                f"({', '.join(safety_blocked)}) in {self.safe_mode} mode"
            )
            result.info.append({
                "type": "safety_filter",
                "message": f"Blocked {len(safety_blocked)} modules that require higher safety level",
                "blocked_modules": safety_blocked,
                "current_mode": self.safe_mode,
            })

        # Filter modules based on classification (if available)
        if skipped_modules and not modules:  # Only filter if not using explicit modules
            filtered_modules = []
            for mod in module_names:
                if mod in skipped_modules:
                    reason = skip_reasons.get(mod, "Not applicable for this target type")
                    logger.info(f"   ⏭️ Skipping {mod}: {reason}")
                    result.tests_skipped += 1
                    result.modules_not_executed.append(mod)
                else:
                    filtered_modules.append(mod)

            module_names = filtered_modules
            logger.info(f"📊 Module filtering: {original_count} → {len(module_names)} modules ({original_count - len(module_names)} skipped)")
        elif skipped_modules and modules:
            # User explicitly requested modules - note which ones classification would skip
            overridden = [m for m in modules if m in skipped_modules]
            if overridden:
                logger.info(f"⚠️ User requested modules that classification recommended skipping: {overridden}")
                result.info.append({
                    "type": "classification_override",
                    "message": f"User explicitly requested modules that classification recommended skipping: {overridden}",
                    "overridden_modules": overridden,
                })

        # Phase 2.5: Early abort for inaccessible targets (second-level filter)
        # NOTE: This logic has been relaxed to allow more modules to run
        # Modern SPAs often have API endpoints that can be tested even without visible parameters
        if self.intelligent_context and not modules:  # Only if not explicit module list
            endpoints_with_params = [
                ep for ep in self.intelligent_context.endpoints_discovered if '?' in ep
            ]

            # Also count API-like endpoints (even without query params)
            api_endpoints = [
                ep for ep in self.intelligent_context.endpoints_discovered
                if '/api/' in ep or '/rest/' in ep or '/graphql' in ep or '/v1/' in ep or '/v2/' in ep
            ]

            # Check for 403/401 blocked main page (from classification signals)
            main_page_blocked = False
            if self.classification and self.classification.signals:
                http_status = self.classification.signals.get('http_status', 200)
                main_page_blocked = http_status in (401, 403, 503)
                if main_page_blocked:
                    logger.warning(f"⚠️ Main page returned HTTP {http_status} - target may be blocked")

            # Check if target is essentially inaccessible
            # RELAXED: Don't skip if we found API endpoints or params
            has_testable_content = (
                len(endpoints_with_params) > 0 or
                len(api_endpoints) > 0 or
                result.endpoints_discovered > 3
            )

            is_truly_inaccessible = (
                main_page_blocked and  # Main page blocked
                result.endpoints_discovered <= 1 and  # Only base URL
                not has_testable_content  # No testable content found
            )

            if is_truly_inaccessible:
                # ONLY skip modules that absolutely require parameters
                # Keep: idor, business, api, auth, graphql (can test path-based endpoints)
                STRICTLY_PARAM_DEPENDENT = {
                    'sqli', 'xss', 'cmdi', 'nosql', 'ssti', 'crlf',
                    'xxe', 'ldap', 'mass_assign',
                }

                # Filter out only strictly parameter-dependent modules
                modules_before = len(module_names)
                filtered_modules = []
                for mod in module_names:
                    if mod in STRICTLY_PARAM_DEPENDENT:
                        reason = f"Skipped: No parameters to inject (main page blocked, 0 params)"
                        logger.info(f"   ⏭️ {mod}: {reason}")
                        result.tests_skipped += 1
                        if mod not in result.modules_not_executed:
                            result.modules_not_executed.append(mod)
                        if mod not in result.skip_reasons:
                            result.skip_reasons[mod] = reason
                    else:
                        filtered_modules.append(mod)

                module_names = filtered_modules

                if modules_before != len(module_names):
                    skipped_count = modules_before - len(module_names)
                    logger.info(f"🚫 Target inaccessible - skipped {skipped_count} parameter-dependent modules (kept API/auth modules)")
                    result.info.append({
                        "type": "partial_skip_inaccessible",
                        "message": f"Main page blocked. Skipped {skipped_count} param-dependent modules, kept auth/API modules.",
                        "skipped_count": skipped_count,
                        "remaining_modules": len(module_names),
                    })
            elif result.endpoints_discovered > 1 or len(api_endpoints) > 0:
                # We have endpoints - run all modules
                logger.info(f"✅ Found {result.endpoints_discovered} endpoints, {len(api_endpoints)} API endpoints - running all modules")

        logger.info(f"Starting scan on {target} with {len(module_names)} modules")

        # Phase 1.5: Linux Tools Orchestration (BEFORE modules)
        # Tools like nmap/nuclei/arjun discover things modules should know about
        self._linux_tool_findings = []  # Store for passing to modules
        self._tool_discovered_endpoints = []
        self._tool_discovered_params = {}
        self._discovered_forms = []  # Store forms from crawler for SQLi/XSS/CSRF testing

        if use_linux_tools:
            await self._run_linux_tools_scan(result, target)

        # Phase 2.5: Auth Acquisition
        await self._acquire_auth_for_scan(target, result)

        # Phases 2.55-2.9: Late pre-scan phases (extracted to _run_prescan_late_phases)
        # Handles: session watchdog, auth refresher, authenticated crawl, semantic analyzer,
        # intent-driven module prioritization, and focus lock priority boost
        module_names = await self._run_prescan_late_phases(target, result, module_names)

        # Phase 3: Execute modules
        # AUTH REFRESH: Check and refresh auth before module execution
        await self._maybe_refresh_auth()

        # FIX C2: Add Evidence Engine event for module execution phase
        if self._evidence_session:
            self.evidence_engine.add_timeline_event(
                event_type="phase_start",
                description=f"Phase 3: Executing {len(module_names)} scanning modules",
                url=target,
                details={
                    "phase": "3_module_execution",
                    "module_count": len(module_names),
                    "concurrent": concurrent,
                    "modules": module_names[:10],  # First 10 for brevity
                }
            )

        module_results = await self._execute_modules(target, module_names, concurrent)

        # Phase 4: Aggregate and validate results
        self._aggregate_results(result, module_names, module_results, on_progress=on_progress)

        # Phase 3.5 (THEME-7): Smart Retry for failed modules
        # AUTH REFRESH: Check before retrying modules
        await self._maybe_refresh_auth()

        # Re-run modules that had high error rates or were rate-limited
        retry_findings = await self._smart_retry_phase(target, module_names, module_results, concurrent)
        if retry_findings:
            # Aggregate retry findings
            for finding in retry_findings:
                if isinstance(finding, dict):
                    result.findings.append(finding)
                elif hasattr(finding, 'to_dict'):
                    result.findings.append(finding.to_dict())
            logger.info(f"[THEME-7] Retry phase added {len(retry_findings)} additional finding(s)")

        # Phases 4.1-4.56: Post-processing (extracted to scanning/scan_phases/postprocessing.py)
        # Handles: proof engine, impact validation, chains, exploitability, intent,
        # cost model, deduplication, amplification, escalation, neural analysis,
        # state-aware retest, and identity variation testing
        pp_result = await self._run_post_processing_phases(result, target)

        # Store intent profile from post-processing
        if pp_result.intent_profile:
            self._intent_profile = pp_result.intent_profile

        # Phase 5: Finalize intelligent scan
        self._finalize_intelligent_scan(result)

        # ═══════════════════════════════════════════════════════════════════════════
        # Phase 5.1: ValidationPipeline - 6-Stage FP Elimination
        # FIX 2026-02-19: ValidationPipeline was DISCONNECTED, now integrated
        # ═══════════════════════════════════════════════════════════════════════════
        if result.findings:
            try:
                validated_findings = await self._run_validation_pipeline(result.findings)
                pre_validation_count = len(result.findings)

                # Replace findings with validated versions
                result.findings = validated_findings

                validation_removed = pre_validation_count - len(result.findings)
                if validation_removed > 0:
                    logger.info(f"🔬 Phase 5.1: ValidationPipeline removed {validation_removed} false positives")
                    result.info.append({
                        "type": "validation_pipeline",
                        "pre_validation_count": pre_validation_count,
                        "post_validation_count": len(result.findings),
                        "fp_removed": validation_removed,
                    })
                else:
                    logger.info(f"🔬 Phase 5.1: ValidationPipeline verified {len(result.findings)} findings")
            except Exception as e:
                logger.warning(f"[ValidationPipeline] Phase skipped due to error: {e}")

        # Phase 5.2: Second-Order Vulnerability Detection (2026-02-20)
        # Check if payloads submitted during scan appear at other endpoints
        # Detects: Second-Order XSS, Second-Order SQLi, Stored injection attacks
        if _SECOND_ORDER_AVAILABLE:
            try:
                second_order_findings = await self._phase_5_2_second_order_detection(
                    target, self.rate_limiter, result.findings
                )
                if second_order_findings:
                    logger.info(
                        f"🔍 Phase 5.2: Second-Order Detection found "
                        f"{len(second_order_findings)} additional vulnerabilities"
                    )
                    result.findings.extend(second_order_findings)
                    result.info.append({
                        "type": "second_order_detection",
                        "findings_count": len(second_order_findings),
                    })
            except Exception as e:
                logger.warning(f"[SecondOrderDetection] Phase skipped due to error: {e}")

        # Phase 5.5: Finalize Evidence Engine session and compile evidence packages
        if self._evidence_session:
            self.evidence_engine.add_timeline_event(
                event_type="scan_complete",
                description=f"Scan completed: {len(result.findings)} findings",
                details={
                    "total_findings": len(result.findings),
                    "modules_run": len(result.modules_run),
                    "critical": len([f for f in result.findings if f.get("severity") == "CRITICAL"]),
                    "high": len([f for f in result.findings if f.get("severity") == "HIGH"]),
                }
            )

            # Compile evidence packages for high-severity findings
            for finding in result.findings:
                severity = finding.get("severity", "MEDIUM") if isinstance(finding, dict) else "MEDIUM"
                if severity in ["CRITICAL", "HIGH"]:
                    finding_id = finding.get("id", f"FINDING_{hash(str(finding)) % 10000:04d}")
                    try:
                        package = self.evidence_engine.compile_evidence_package(
                            finding_id=finding_id,
                            finding_type=finding.get("vuln_type", finding.get("type", "unknown")),
                            severity=severity,
                            target_url=finding.get("url", finding.get("matched_at", target)),
                        )
                        finding["evidence_package"] = package.to_dict() if package else None
                    except Exception as e:
                        logger.debug(f"Evidence package compilation failed for {finding_id}: {e}")

            # End evidence session
            evidence_path = self.evidence_engine.end_session()
            if evidence_path:
                result.info.append({
                    "type": "evidence_engine",
                    "version": self.evidence_engine.VERSION,
                    "session_path": str(evidence_path),
                    "statistics": self.evidence_engine.get_statistics(),
                })
                logger.info(f"📸 Evidence collection complete: {evidence_path}")

        # Collect circuit breaker stats
        cb_stats = get_circuit_breaker().get_stats()
        result.circuit_breaker_triggered = cb_stats.get("total_pauses", 0)
        result.rate_limited = cb_stats.get("total_blocked", 0) > 0
        result.total_requests_sent = cb_stats.get("total_requests", 0)
        if cb_stats.get("total_blocked", 0) > 0:
            logger.info(
                f"[OPSEC] Circuit breaker stats: "
                f"pauses={cb_stats['total_pauses']}, "
                f"blocked={cb_stats['total_blocked']}, "
                f"requests={cb_stats['total_requests']}"
            )

        # Phase 6.5: Coverage and Explosion Metrics
        # Add meta-vision data to result for transparency about what was/wasn't tested
        try:
            self.coverage_tracker.log_summary()
            self.explosion_controller.log_summary()

            # Populate coverage metrics on result object
            coverage_data = self.coverage_tracker.to_dict()
            result.coverage_percentage = coverage_data.get("summary", {}).get("coverage_percentage", 0.0)
            result.high_value_gaps = len(coverage_data.get("high_value_gaps", []))
            result.skip_reasons_summary = coverage_data.get("skip_summary", {})

            # Add coverage data to result info
            result.info.append({
                "type": "coverage_tracker",
                "version": "1.0",
                "data": coverage_data,
            })

            result.info.append({
                "type": "explosion_controller",
                "version": "1.0",
                "data": self.explosion_controller.get_metrics(),
            })

            # GAP-A: Focus Lock summary
            if hasattr(self, 'focus_lock') and self.focus_lock:
                focus_summary = self.focus_lock.get_focus_summary()
                result.info.append({
                    "type": "focus_lock",
                    "version": "1.0",
                    "data": focus_summary,
                })
                if focus_summary.get("hypothesis"):
                    hyp = focus_summary["hypothesis"]
                    logger.info(
                        f"[FOCUS] Summary: {hyp['description']} - "
                        f"tried={hyp['vectors_tried']}, succeeded={hyp['vectors_succeeded']}, "
                        f"remaining={hyp['vectors_remaining']}, confidence={hyp['confidence']:.0f}%"
                    )

            # GAP-B: Exhaustion Tracker summary
            if hasattr(self, 'exhaustion_tracker') and self.exhaustion_tracker:
                exhaustion_summary = self.exhaustion_tracker.get_global_summary()
                result.info.append({
                    "type": "exhaustion_tracker",
                    "version": "1.0",
                    "data": exhaustion_summary,
                })
                logger.info(
                    f"[EXHAUSTION] Summary: {exhaustion_summary['total_findings_tracked']} findings tracked, "
                    f"{exhaustion_summary['findings_exhausted']} exhausted, "
                    f"{exhaustion_summary['findings_not_exhausted']} not exhausted"
                )
                # Warn about not-exhausted HIGH+ findings
                not_exhausted = exhaustion_summary.get("not_exhausted_findings", [])
                if not_exhausted:
                    logger.warning(
                        f"[EXHAUSTION] {len(not_exhausted)} HIGH+ findings NOT fully exhausted - "
                        f"consider deeper testing"
                    )

            # THEME-14: Model Drift Awareness Summary
            if hasattr(self, 'drift_awareness') and self.drift_awareness:
                self.drift_awareness.log_health_summary()
                drift_data = self.drift_awareness.to_dict()
                result.info.append({
                    "type": "model_drift_awareness",
                    "version": "1.0",
                    "data": drift_data,
                })
                health = drift_data.get("model_health", {})
                if health.get("health") in ("WARNING", "CRITICAL"):
                    logger.warning(
                        f"[MODEL_DRIFT] {health.get('health')}: {health.get('recommendation', '')}"
                    )

            # THEME-3: Auth Context Usage Summary
            # Report which modules used auth and which were skipped
            auth_usage_summary = self._get_auth_usage_summary()
            if auth_usage_summary:
                result.info.append({
                    "type": "auth_context_usage",
                    "version": "1.0",
                    "data": auth_usage_summary,
                })
                # Log auth usage summary
                if auth_usage_summary.get("modules_with_auth"):
                    logger.info(
                        f"[AUTH-TRACK] {len(auth_usage_summary['modules_with_auth'])} modules used auth"
                    )
                if auth_usage_summary.get("modules_skipped"):
                    skip_count = len(auth_usage_summary["modules_skipped"])
                    logger.warning(
                        f"[AUTH-TRACK] {skip_count} modules SKIPPED due to auth issues"
                    )

            # Auth Refresher Summary
            # Report auto-refresh activity during the scan
            auth_refresher_summary = self.get_auth_refresher_summary()
            if auth_refresher_summary.get("configured"):
                result.info.append({
                    "type": "auth_refresher",
                    "version": "1.0",
                    "data": auth_refresher_summary,
                })
                if auth_refresher_summary.get("refresh_count", 0) > 0:
                    logger.info(
                        f"[AUTH_REFRESHER] {auth_refresher_summary['refresh_count']} token refreshes "
                        f"during scan (method={auth_refresher_summary.get('method', 'unknown')})"
                    )

            # THEME-6: Error Stats Summary
            # Make silent failures visible in the result
            if hasattr(self, "_module_error_stats") and self._module_error_stats:
                error_data = self._module_error_stats

                # Calculate aggregate error stats
                total_errors = sum(m["requests_failed"] for m in error_data.values())
                total_requests = sum(m["requests_total"] for m in error_data.values())
                modules_with_errors = len(error_data)

                result.total_module_errors = total_errors
                result.modules_with_errors = modules_with_errors
                result.error_rate_overall = (total_errors / total_requests * 100) if total_requests > 0 else 0
                result.error_summary_by_module = {
                    name: data["error_summary"]
                    for name, data in error_data.items() if isinstance(data, dict) and "error_summary" in data
                }

                # Add to result.info for report generation
                result.info.append({
                    "type": "module_error_stats",
                    "version": "1.0",
                    "data": {
                        "total_errors": total_errors,
                        "total_requests": total_requests,
                        "modules_with_errors": modules_with_errors,
                        "overall_failure_rate": result.error_rate_overall,
                        "by_module": error_data,
                    },
                })

                # Log error summary if significant
                if result.error_rate_overall >= 10:  # 10%+ failure rate is concerning
                    logger.warning(
                        f"[THEME-6] ⚠️ High error rate: {total_errors} errors across "
                        f"{modules_with_errors} modules ({result.error_rate_overall:.0f}% failure rate)"
                    )
                elif total_errors > 0:
                    logger.info(
                        f"[THEME-6] Error summary: {total_errors} errors in {modules_with_errors} modules "
                        f"({result.error_rate_overall:.0f}% failure rate)"
                    )
        except Exception as e:
            logger.debug(f"[Meta] Coverage/explosion metrics error: {e}")

        result.end_time = datetime.now()
        logger.info(
            f"Scan complete: {len(result.findings)} findings, "
            f"{len(result.modules_run)}/{len(module_names)} modules successful"
        )

        # P0-002: Audit logging moved to _scan_cleanup() for guaranteed execution

        # ═══════════════════════════════════════════════════════════════════════
        # THEME-9: Collect saturation controller stats
        # ═══════════════════════════════════════════════════════════════════════
        from scanning.saturation_controller import get_saturation_controller
        saturation_ctrl = get_saturation_controller()
        saturation_stats = saturation_ctrl.get_stats()
        # BUG-FIX: result.info is a list, not a dict
        result.info.append({"type": "saturation", "data": saturation_stats})

        if saturation_stats.get("modules_exhausted"):
            logger.warning(
                f"[THEME-9] Budget exhausted for modules: "
                f"{', '.join(saturation_stats['modules_exhausted'])}"
            )

        logger.info(
            f"[THEME-9] Saturation summary: "
            f"{saturation_stats['total_requests']:,} requests, "
            f"{saturation_stats['total_findings']:,} findings, "
            f"{saturation_stats['hypothesis_stats']['total_hypotheses']} hypotheses shared"
        )

        # ═══════════════════════════════════════════════════════════════════════
        # THEME-8: Finalize deterministic context
        # ═══════════════════════════════════════════════════════════════════════
        from scanning.determinism import finalize_deterministic_scan, is_deterministic_mode
        if is_deterministic_mode():
            determinism_stats = finalize_deterministic_scan()
            # BUG-FIX: result.info is a list, not a dict
            result.info.append({"type": "determinism_stats", "data": determinism_stats})
            logger.info(f"[THEME-8] Deterministic scan finalized: {determinism_stats.get('components_seeded', 0)} components seeded")

        # P0-002: Cleanup now handled by _scan_cleanup() in finally block
        # This ensures cleanup happens even if an exception occurs earlier
        return result

    def is_url_in_scope(self, url: str) -> tuple:
        """
        Check if a URL is within the defined scope.

        ETHICS-08: Real-time scope blocking for individual requests.
        Modules should call this before making requests to discovered URLs.

        Args:
            url: The URL to check

        Returns:
            Tuple of (is_allowed: bool, reason: str)
        """
        if not self.scope_guard:
            return (True, "No scope defined")

        allowed, violation = self.scope_guard.is_allowed(url)
        if allowed:
            return (True, "URL in scope")
        else:
            reason = violation.reason if violation else "URL not in allowed scope"
            logger.debug(f"🚫 Scope blocked: {url} - {reason}")
            return (False, reason)

    def _get_auth_usage_summary(self) -> dict | None:
        """
        THEME-3: Get auth context usage summary for scan results.

        Returns a summary of which modules used auth and which were skipped.
        """
        try:
            # Check for user_personas first (multi-user mode)
            if hasattr(self, 'user_personas') and self.user_personas:
                return self.user_personas.get_aggregate_usage_summary()

            # Fall back to primary auth_context
            if hasattr(self, 'auth_context') and self.auth_context:
                auth_ctx = self.auth_context
                if hasattr(auth_ctx, 'get_usage_summary'):
                    return auth_ctx.get_usage_summary()

            # No auth tracking available
            return None
        except Exception as e:
            logger.debug(f"[AUTH-TRACK] Error getting auth usage summary: {e}")
            return None

    async def _cleanup_modules(self) -> None:
        """Clean up loaded module instances to prevent memory leaks.

        Delegates to ModuleLoader which handles cleanup() calls and cache clearing.

        FIX FS-04: Module instances can accumulate over multiple scans.
        FIX M2: Also clears module_instances (created in _execute_modules).
        """
        # Cleanup via ModuleLoader
        module_count = await self._module_loader.cleanup()

        # FIX M2: Also clear module_instances (created in _execute_modules)
        if hasattr(self, 'module_instances'):
            module_count += len(self.module_instances)
            self.module_instances.clear()

        logger.debug(f"[Cleanup] Cleared {module_count} module instances")

    async def _calibrate_adaptive_timeout(self, target: str, result: ScanResult) -> None:
        """Phase 1.5: Calibrate timeouts based on target response time."""
        try:
            self.timeout_manager = get_timeout_manager()
            reset_timeout_manager()
            self.timeout_manager = get_timeout_manager()

            # Collect tech hints
            tech_hints = []
            if self.tech_analysis and hasattr(self.tech_analysis, 'technologies') and self.tech_analysis.technologies:
                tech_hints.extend([t.name for t in self.tech_analysis.technologies])
            if self.fingerprint_result and hasattr(self.fingerprint_result, 'technologies') and self.fingerprint_result.technologies:
                tech_hints.extend([t.name for t in self.fingerprint_result.technologies])
            if self.classification and hasattr(self.classification, 'detected_technologies'):
                tech_hints.extend(self.classification.detected_technologies)

            import aiohttp
            async with aiohttp.ClientSession() as session:
                baseline = await self.timeout_manager.measure_baseline(
                    target_url=target, client=session, sample_count=5, tech_hints=tech_hints
                )

            logger.info(
                f"⏱️ Phase 1.5: Adaptive Timeout Calibration "
                f"(profile={baseline.target_profile.name}, avg={baseline.avg_response_time_ms:.0f}ms)"
            )
            result.info.append({
                "type": "adaptive_timeout",
                "target_profile": baseline.target_profile.name,
                "avg_response_ms": baseline.avg_response_time_ms,
                "p95_response_ms": baseline.p95_response_time_ms,
            })
        except Exception as e:
            logger.warning(f"Adaptive timeout calibration failed: {e}")
            self.timeout_manager = None

    async def _acquire_auth_for_scan(self, target: str, result: ScanResult) -> None:
        """Phase 2.5: Acquire authentication for business logic testing."""
        self._auth_context = None
        self._user_personas = None
        try:
            from scanning.auth_context import AuthAcquisition, AuthContext, UserPersonaStore
            auth_acq = AuthAcquisition()

            domain_type = None
            if hasattr(self, '_domain_classification') and self._domain_classification:
                domain_type = self._domain_classification.primary.value

            self._user_personas = await auth_acq.acquire_multiple_users(target, None, count=2, domain=domain_type)

            if self._user_personas.primary.has_auth:
                self._auth_context = self._user_personas.primary
                logger.info(f"[AUTH] Token acquired via {self._auth_context.method} ({self._auth_context.email})")
            else:
                self._auth_context = AuthContext()
                logger.warning("[AUTH] No authentication acquired")

            if self._user_personas.has_multiple_users:
                logger.info(f"[AUTH-MULTI] {len(self._user_personas.all_contexts)} users for cross-user testing")
        except Exception as e:
            logger.warning(f"[AUTH] Auth acquisition failed: {e}")
            from scanning.auth_context import AuthContext, UserPersonaStore
            self._auth_context = AuthContext()
            self._user_personas = UserPersonaStore()
            result.errors.append({
                "type": "auth_acquisition_failed", "phase": "2.5",
                "message": f"Could not acquire authentication: {str(e)[:200]}",
            })

    async def _detect_waf_early(self, target: str, result: ScanResult) -> None:
        """
        Phase 0.95: Detect WAF presence early to adjust scanning strategy.

        Delegates to extracted waf_detection module.
        """
        from scanning.scan_phases.waf_detection import run_waf_detection_phase

        self._waf_detection_result = None

        detection, should_reduce = await run_waf_detection_phase(target, result)

        # Store the raw result for injection scanners
        self._waf_detection_result = detection.raw_result
        self._waf_concurrent_reduction = should_reduce

    async def _verify_network_protection(self, result: ScanResult) -> None:
        """Verify network protection (Tor/Proxy) before scanning."""
        # Skip if protection was already verified (e.g., by CLI)
        if self._protection_verified:
            logger.debug("Network protection already verified, skipping")
            return

        try:
            from utils.http_client import (
                get_protection_status,
                verify_protection,
                is_protection_enabled,
            )

            # Note: We don't print the banner here since the CLI handles that
            # This avoids duplicate "Setting up network protection" messages

            # Skip proxy/Tor verification for localhost targets
            from scanning.vuln_scanner import ScanModule
            if ScanModule._target_is_local:
                logger.debug("Localhost target — skipping proxy/Tor verification")
                self._protection_verified = True
                return

            if is_protection_enabled():
                logger.debug("Verifying network protection...")
                protection_ok = await verify_protection()

                if not protection_ok:
                    logger.error("❌ Network protection verification FAILED!")
                    result.errors.append({
                        "phase": "network_protection",
                        "error": "IP leak detected - protection verification failed",
                        "type": "security_violation"
                    })
                    logger.warning("⚠️  Continuing scan despite protection failure...")
                else:
                    status = get_protection_status()
                    logger.debug(f"Network protection active: {status['type']}")
            else:
                logger.debug("Network protection disabled")

            # Mark as verified to avoid duplicate checks
            self._protection_verified = True

        except ImportError:
            logger.debug("Network protection module not available")

    async def _run_intelligent_pre_scan(self, target: str, result: ScanResult) -> bool:
        """
        Run intelligent pre-scan analysis.

        Returns:
            True if scan should continue, False if blocked by scope violation
        """
        logger.info("🧠 Running intelligent pre-scan analysis...")
        try:
            self.intelligent_context = await self.intelligent_scanner.prepare_scan(target)

            # Merge fallback endpoints from Phase 2.6
            # Phase 2.6 discovered these before intelligent_context existed
            if self._fallback_endpoints:
                existing = set(self.intelligent_context.endpoints_discovered)
                added = 0
                for ep in self._fallback_endpoints:
                    if ep not in existing:
                        self.intelligent_context.endpoints_discovered.append(ep)
                        added += 1
                if added:
                    logger.debug(f"[MERGE] Added {added} fallback endpoints to intelligent_context")

            # Update result with discovery metrics
            result.endpoints_discovered = len(self.intelligent_context.endpoints_discovered)
            result.parameters_analyzed = self.intelligent_context.parameters_analyzed

            # Log sample of discovered endpoints
            endpoints_with_params = [ep for ep in self.intelligent_context.endpoints_discovered if '?' in ep]
            sample = endpoints_with_params[:5] if endpoints_with_params else self.intelligent_context.endpoints_discovered[:5]

            logger.info(
                f"   ✓ Scope validated: {target}"
                f"\n   ✓ Endpoints discovered: {result.endpoints_discovered}"
                f"\n   ✓ With parameters: {len(endpoints_with_params)}"
                f"\n   ✓ Sample: {sample}"
                f"\n   ✓ Parameters analyzed: {result.parameters_analyzed}"
            )
            return True

        except Exception as e:
            if "scope" in str(e).lower():
                logger.error(f"❌ Target out of scope: {e}")
                result.errors.append({
                    "phase": "pre_scan",
                    "error": str(e),
                    "type": "scope_violation"
                })
                result.scope_violations = 1
                result.end_time = datetime.now()
                return False
            else:
                logger.warning(f"Intelligent pre-scan failed, continuing with standard scan: {e}")
                self.intelligent_context = None
                return True

    # =========================================================================
    # SMART RETRY PHASE (THEME-7 FIX)
    # Re-run modules that failed due to recoverable errors
    # =========================================================================

    async def _smart_retry_phase(
        self,
        target: str,
        module_names: list[str],
        module_results: list[dict | Exception],
        concurrent: int,
    ) -> list[dict]:
        """
        Phase 3.5: Smart retry for modules with recoverable failures.

        Delegates to extracted smart_retry module.
        """
        from scanning.scan_phases.smart_retry import run_smart_retry_phase

        result = await run_smart_retry_phase(
            target=target,
            module_names=module_names,
            module_results=module_results,
            concurrent=concurrent,
            load_module=self._load_module,
            run_module=self._run_single_module_with_instance,
        )

        return result.findings

    async def _execute_modules(
        self,
        target: str,
        module_names: list[str],
        concurrent: int,
    ) -> list[dict | Exception]:
        """Execute scanning modules with concurrency control and circuit breaker.

        Delegates to scan_phases.module_executor for core logic.
        """
        from scanning.scan_phases.module_executor import (
            ModuleExecutionContext, ModuleExecutionConfig, execute_modules
        )
        from utils.shared_findings_store import get_shared_findings

        # Build config from settings
        config = ModuleExecutionConfig()
        try:
            config.timeout_heavy = getattr(self.settings.timeouts, 'module_heavy', 900)
            config.timeout_normal = getattr(self.settings.timeouts, 'module_normal', 600)
        except AttributeError:
            pass

        try:
            exec_config = getattr(self.settings, 'scan_execution', {})
            if hasattr(exec_config, 'circuit_breaker'):
                cb = exec_config.circuit_breaker
                config.cb_max_consecutive = getattr(cb, 'max_consecutive_blocks', 3)
                config.cb_pause_duration = getattr(cb, 'pause_duration', 30)
                config.cb_max_backoff = getattr(cb, 'max_backoff_multiplier', 8)
            if hasattr(exec_config, 'jitter'):
                jitter = exec_config.jitter
                config.jitter_min = getattr(jitter, 'min', 0.1)
                config.jitter_max = getattr(jitter, 'max', 0.5)
                config.jitter_sigma = getattr(jitter, 'gaussian_sigma', 0.2)
        except Exception:
            pass

        # Create execution context
        ctx = ModuleExecutionContext(
            settings=self.settings,
            coverage_tracker=self.coverage_tracker,
            shared_findings_store=get_shared_findings(),
            timeout_manager=getattr(self, 'timeout_manager', None),
            load_module_callback=self._load_module,
            run_module_callback=self._run_single_module_with_instance,
            maybe_refresh_auth_callback=self._maybe_refresh_auth,
            waf_concurrent_reduction=getattr(self, '_waf_concurrent_reduction', False),
            config=config,
        )

        # Execute modules
        exec_result = await execute_modules(ctx, target, module_names, concurrent)

        # Store results on self for access by other phases
        self.module_instances = exec_result.module_instances
        self._module_checkpoints = exec_result.module_checkpoints
        self._module_error_stats = exec_result.module_error_stats

        return exec_result.results

    def _aggregate_results(
        self,
        result: ScanResult,
        module_names: list[str],
        module_results: list,
        on_progress: Optional[Any] = None,
    ) -> None:
        """
        Aggregate module results with intelligent validation.

        Uses ResultAggregator (extracted to scanning/result_processor/aggregator.py).
        """
        aggregator = ResultAggregator(
            intelligent_mode=self.intelligent_mode,
            intelligent_context=self.intelligent_context,
            intelligent_scanner=self.intelligent_scanner,
        )

        aggregator.register_components(
            focus_lock=getattr(self, 'focus_lock', None),
            exhaustion_tracker=getattr(self, 'exhaustion_tracker', None),
            scan_amplifier=getattr(self, 'scan_amplifier', None),
            explosion_controller=getattr(self, 'explosion_controller', None),
            evidence_engine=getattr(self, 'evidence_engine', None),
            evidence_session=getattr(self, '_evidence_session', False),
        )

        aggregator.register_callbacks(
            validate_finding=self._validate_finding_intelligent,
            enqueue_amplification=self._enqueue_amplification,
        )

        aggregator.aggregate(result, module_names, module_results, on_progress)

    async def _run_post_processing_phases(
        self,
        result: "ScanResult",
        target: str,
    ) -> PostProcessingResult:
        """
        Run post-processing phases (4.1 through 4.56).

        Uses PostProcessingRunner (extracted to scanning/scan_phases/postprocessing.py).

        Args:
            result: ScanResult to process
            target: Target URL

        Returns:
            PostProcessingResult with phase outcomes
        """
        config = PostProcessingConfig(safe_mode=self.safe_mode)
        runner = PostProcessingRunner(
            settings=self.settings,
            auth_context=self._auth_context,
            rate_limiter=self.rate_limiter,
            config=config,
        )

        # Register callbacks for scanner integration
        runner.register_callbacks(
            maybe_refresh_auth=self._maybe_refresh_auth,
            share_findings_early=self._share_findings_early,
            share_validated_findings=self._share_validated_findings,
            process_vulnerability_chains=self._process_vulnerability_chains,
            deduplicate_findings=self._deduplicate_findings,
            execute_amplification_actions=self._execute_amplification_actions,
            neural_attack_analysis=self._neural_attack_analysis,
            state_aware_retest=self._state_aware_retest,
            identity_variation_retest=self._identity_variation_retest,
            enqueue_amplification=self._enqueue_amplification,
        )

        # Register dependencies
        runner.register_dependencies(
            exhaustion_tracker=getattr(self, 'exhaustion_tracker', None),
            focus_lock=getattr(self, 'focus_lock', None),
            scan_amplifier=getattr(self, 'scan_amplifier', None),
            pending_amplifications=getattr(self, '_pending_amplifications', []),
            user_personas=getattr(self, '_user_personas', None),
            scanner_ref=self,
        )

        return await runner.run(result, target)

    async def _share_findings_early(self, findings: list[dict]) -> None:
        """
        Share findings early for cross-module feedback.

        Called after aggregation but BEFORE proof engine and analysis phases.
        Uses lower confidence threshold (50%) to enable feedback loops.

        Delegates to scanning.result_processor.share_findings_early.

        Args:
            findings: List of aggregated findings (not yet validated)
        """
        if not findings:
            return

        shared_store = get_shared_findings()
        await share_findings_early(
            findings=findings,
            shared_store=shared_store,
            normalize_confidence_func=normalize_confidence,
            threshold=EARLY_SHARE_THRESHOLD,
        )

    async def _share_validated_findings(self, findings: list[dict]) -> None:
        """
        Share validated findings to SharedFindingsStore.

        Only called AFTER deduplication and validation.
        This prevents unvalidated findings from boosting other modules' confidence.

        Delegates to scanning.result_processor.share_validated_findings.

        Args:
            findings: List of validated, deduplicated findings
        """
        if not findings:
            return

        # Get optional audit logger
        audit_logger = None
        try:
            from utils.audit_logger import get_audit_logger
            audit_logger = get_audit_logger()
        except Exception:
            pass

        shared_store = get_shared_findings()
        await share_validated_findings(
            findings=findings,
            shared_store=shared_store,
            normalize_confidence_func=normalize_confidence,
            audit_logger=audit_logger,
            threshold=VALIDATED_SHARE_THRESHOLD,
        )

    def _deduplicate_findings(self, result: ScanResult) -> None:
        """
        Deduplicate findings across modules.

        This prevents the same issue being reported by multiple modules
        (e.g., CORS wildcard reported by both headers and cors modules).

        Delegates to scanning.result_processor.FindingDeduplicator.
        """
        if not result.findings:
            return

        # Import canonical type normalization from constants
        try:
            from scanning.constants import normalize_vuln_type
        except ImportError:
            normalize_vuln_type = None

        # Use extracted deduplicator
        deduplicator = FindingDeduplicator(
            normalize_confidence_func=normalize_confidence,
            normalize_type_func=normalize_vuln_type,
        )
        result.findings = deduplicator.deduplicate(result.findings)

    async def _neural_attack_analysis(
        self, target: str, findings: list
    ) -> list:
        """
        Phase 4.7: Neural Attack Analysis.

        Delegates to extracted neural_analysis module.
        """
        from scanning.scan_phases.neural_analysis import run_neural_attack_analysis

        result = await run_neural_attack_analysis(
            target=target,
            findings=findings,
            http_client=self._http_client,
            rate_limiter=self._rate_limiter,
            safe_mode=self.safe_mode,
        )

        return result.findings

    async def _run_validation_pipeline(self, findings: list) -> list:
        """
        Phase 5.1: Run 6-Stage Validation Pipeline.

        Delegates to extracted ValidationPipelineRunner for FP elimination.
        """
        from scanning.scan_phases.validation import run_validation_pipeline

        if not findings:
            return findings

        result = await run_validation_pipeline(
            findings,
            min_confidence=0.50,
            enable_ai_verification=False,
        )

        return result.findings

    async def _phase_5_2_second_order_detection(
        self,
        target: str,
        rate_limiter: Any,
        existing_findings: list,
    ) -> list[dict]:
        """
        Phase 5.2: Second-Order Vulnerability Detection.

        Delegates to extracted second_order module.
        """
        from scanning.scan_phases.second_order import run_second_order_detection

        # Get auth headers if available
        auth_headers = {}
        if hasattr(self, "_auth_context") and self._auth_context:
            auth_headers = self._auth_context.get_headers()

        # Get asset data for additional render locations
        asset_data = getattr(self, "_asset_data", None)

        result = await run_second_order_detection(
            target=target,
            rate_limiter=rate_limiter,
            auth_headers=auth_headers,
            asset_data=asset_data,
        )

        return result.findings

    async def _run_prescan_late_phases(
        self,
        target: str,
        result: "ScanResult",
        module_names: list[str],
    ) -> list[str]:
        """
        Run late pre-scan phases (2.55-2.9).

        Handles:
        - Phase 2.55: Session Watchdog
        - Phase 2.56: Auth Refresher
        - Phase 2.6: Authenticated Re-Crawl
        - Phase 2.7: Semantic Analyzer
        - Phase 2.9: Intent-Driven Module Prioritization
        - Focus Lock Priority Boost

        Args:
            target: Target URL
            result: ScanResult to update
            module_names: List of module names to potentially reorder

        Returns:
            Reordered module names
        """
        # Phase 2.55: Session Watchdog
        self._session_watchdog = None
        if self._auth_context and self._auth_context.has_auth:
            try:
                from utils.session_watchdog import SessionWatchdog, detect_whoami_endpoint, WatchdogConfig

                whoami_endpoint = detect_whoami_endpoint(
                    target,
                    discovered_endpoints=getattr(self.intelligent_context, 'endpoints_discovered', []) if hasattr(self, 'intelligent_context') else []
                )

                async def _reauth_callback():
                    try:
                        return await self._reauth_for_watchdog(target)
                    except Exception:
                        return None

                async def _refresh_callback():
                    if self._auth_context:
                        success = await self._auth_context.auto_refresh_if_stale(self._http_client, target)
                        return self._auth_context.token if success else None
                    return None

                self._session_watchdog = SessionWatchdog(
                    auth_context=self._auth_context,
                    whoami_endpoint=whoami_endpoint,
                    http_client=self._http_client,
                    reauth_callback=_reauth_callback,
                    refresh_callback=_refresh_callback,
                    config=WatchdogConfig(check_interval=60.0, max_consecutive_failures=3, auto_refresh=True, auto_reauth=True),
                )
                await self._session_watchdog.start()
                logger.info(f"[SESSION_WATCHDOG] Started monitoring session health (whoami: {whoami_endpoint})")
            except Exception as e:
                logger.debug(f"[SESSION_WATCHDOG] Could not initialize: {e}")

        # Phase 2.56: Auth Refresher
        if self._auth_context and self._auth_context.has_auth:
            try:
                self._auth_refresher = self._setup_auth_refresher(self._auth_context, target)
                if self._auth_refresher and self._auth_refresher.has_credentials():
                    logger.info(f"[AUTH_REFRESHER] Initialized with method={self._auth_refresher.get_method().name}")
            except Exception as e:
                logger.debug(f"[AUTH_REFRESHER] Could not initialize: {e}")

        # Phase 2.6: Authenticated Re-Crawl
        new_endpoints = []
        if self._auth_context and self._auth_context.has_auth:
            try:
                logger.info(f"[AUTH-CRAWL] Starting authenticated crawl with {self._auth_context.method} session")
                new_endpoints = await self._authenticated_crawl(target)
                if new_endpoints:
                    logger.info(f"[AUTH-CRAWL] Discovered {len(new_endpoints)} authenticated endpoints")
                    if hasattr(self, 'intelligent_context') and self.intelligent_context:
                        existing = set(self.intelligent_context.endpoints_discovered)
                        for ep in new_endpoints:
                            if ep not in existing:
                                self.intelligent_context.endpoints_discovered.append(ep)
                        result.endpoints_discovered = len(self.intelligent_context.endpoints_discovered)
            except Exception as e:
                logger.warning(f"[AUTH-CRAWL] Error: {e}")
        else:
            logger.info("[NO-AUTH] Auth not acquired, continuing with training app detection...")

        # Generate fallback endpoints
        fallback_endpoints = self._get_generic_fallback_endpoints(target)
        if fallback_endpoints:
            logger.info(f"[DISCOVERY] Generated {len(fallback_endpoints)} common endpoint patterns")
            self._fallback_endpoints = fallback_endpoints
            new_endpoints.extend(fallback_endpoints)

        # Phase 2.7: Semantic Analyzer
        self._semantic_analyzer = None
        try:
            from scanning.semantic_analyzer import initialize_semantic_analyzer
            auth_headers = self._auth_context.auth_headers if self._auth_context else None
            self._semantic_analyzer = await initialize_semantic_analyzer(target, auth_headers)
            logger.info("[SemanticAnalyzer] Initialized for response classification")
        except Exception as e:
            logger.info(f"[SemanticAnalyzer] Initialization failed: {e}")
            result.info.append({
                "type": "semantic_analyzer_failed",
                "phase": "2.7",
                "message": f"Semantic analyzer could not initialize: {str(e)[:200]}",
                "impact": "SPA detection and response classification may be less accurate",
            })

        # Phase 2.9: Intent-Driven Module Prioritization
        try:
            from scanning.attacker_intent_engine import AttackerIntentEngine
            app_context = {}
            if self.tech_analysis and self.tech_analysis.technologies:
                app_context["tech_stack"] = [t.to_dict() for t in self.tech_analysis.technologies]
            if self._domain_classification:
                app_context["detected_features"] = list(self._domain_classification.detected_features)
                app_context["domain_type"] = self._domain_classification.primary.value
            if self.intelligent_context:
                app_context["endpoints"] = self.intelligent_context.endpoints_discovered[:50]

            intent_engine = AttackerIntentEngine()
            intent_engine._app_context = app_context
            ordered_modules = intent_engine.suggest_scan_order(module_names, app_context)

            if ordered_modules != module_names:
                logger.info(f"[INTENT] Reordered {len(module_names)} modules based on goal analysis")
                module_names = ordered_modules
        except Exception as e:
            logger.debug(f"[INTENT] Module prioritization failed: {e}")

        # Focus Lock Priority Boost
        if hasattr(self, 'focus_lock') and self.focus_lock and self.focus_lock.is_focused:
            try:
                focused_modules = set(self.focus_lock.get_focused_modules())
                focused_first = [m for m in module_names if m in focused_modules]
                non_focused = [m for m in module_names if m not in focused_modules]
                if focused_first:
                    module_names = focused_first + non_focused
                    logger.info(f"[FOCUS] Prioritized {len(focused_first)} focused modules: {focused_first[:5]}")
            except Exception as e:
                logger.debug(f"[FOCUS] Priority boost failed: {e}")

        return module_names

    async def _reauth_for_watchdog(self, target: str) -> Any:
        """Re-authenticate for session watchdog callback."""
        from scanning.auth_context import AuthAcquisitionEngine
        domain_type = self._domain_classification.primary if self._domain_classification else None
        auth_acq = AuthAcquisitionEngine(self.settings)
        return await auth_acq.acquire(target, None, domain=domain_type)

    async def _state_aware_retest(self, result: ScanResult, target: str) -> None:
        """
        Phase 4.55: State-Aware Retest — Delegates to auth_testing module.

        Re-test endpoints that had findings WITH auth by testing them WITHOUT auth.
        This discovers auth bypasses and state-dependent vulnerabilities.
        """
        if not hasattr(self, '_auth_context') or not self._auth_context:
            return

        tester = AuthTester(self._auth_context)
        retest_result = await tester.state_aware_retest(result, target)

        # Add findings to result
        if retest_result.auth_bypasses:
            result.findings.extend(retest_result.auth_bypasses)
            logger.info(
                f"🔓 Found {len(retest_result.auth_bypasses)} auth bypass vulnerabilities via state-aware retest"
            )

    async def _identity_variation_retest(self, result: ScanResult, target: str) -> None:
        """
        Phase 4.56: Cross-User Identity Variation Testing — Delegates to auth_testing module.

        Replays discovered sensitive actions with different user contexts
        to find horizontal and vertical privilege escalation.
        """
        if not self._user_personas or not self._user_personas.has_multiple_users:
            return

        tester = AuthTester(self._auth_context)
        cross_result = await tester.identity_variation_retest(result, target, self._user_personas)

        # Add findings to result
        if cross_result.findings:
            result.findings.extend(cross_result.findings)
            logger.info(
                f"🔓 Found {len(cross_result.findings)} cross-user vulnerabilities via identity variation"
            )

    # ═══════════════════════════════════════════════════════════════════════════
    # ADAPTIVE DEPTH HELPER METHODS — Delegates to auth_testing module
    # ═══════════════════════════════════════════════════════════════════════════

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers from auth context — delegates to auth_testing."""
        return get_auth_headers(self._auth_context)

    def _generate_expanded_ids(
        self, original_id: str, working_id: str, expand_to: int
    ) -> list[int | str]:
        """Generate expanded IDs for IDOR testing — delegates to auth_testing."""
        return generate_expanded_ids(original_id, working_id, expand_to)

    def _replace_id_in_url(self, url: str, original_id: str, new_id: str) -> str:
        """Replace an ID in a URL with a new value — delegates to auth_testing."""
        return replace_id_in_url(url, original_id, new_id)

    async def _execute_amplification_actions(self, result: ScanResult, target: str) -> None:
        """
        Phase 4.52: Execute pending amplification actions.

        Delegates to scan_phases.amplification module for core logic.
        Advanced handlers (smuggling, auth bypass) are provided as extra_handlers.
        """
        if not self._pending_amplifications:
            return

        from scanning.scan_phases.amplification import (
            AmplificationContext, AmplificationConfig, execute_amplification_phase
        )

        # Create context with all dependencies
        ctx = AmplificationContext(
            http_client=self.http_client,
            rate_limiter=self.rate_limiter,
            scan_amplifier=self.scan_amplifier,
            pending_amplifications=self._pending_amplifications,
            safe_mode=self.safe_mode,
            safety_hierarchy=self.SAFETY_HIERARCHY,
            module_safety_levels=self.MODULE_SAFETY_LEVELS,
            explosion_controller=self.explosion_controller if hasattr(self, 'explosion_controller') else None,
            load_module_callback=self._load_module,
            run_module_callback=self._run_single_module_with_instance,
            get_auth_headers_callback=self._get_auth_headers,
            generate_expanded_ids_callback=self._generate_expanded_ids,
            replace_id_in_url_callback=self._replace_id_in_url,
            config=AmplificationConfig(max_actions=20, max_backoff_seconds=30.0),
        )

        # Advanced handlers that require full scanner context
        extra_handlers = self._get_advanced_amplification_handlers()

        # Execute amplification phase
        await execute_amplification_phase(ctx, result, target, extra_handlers=extra_handlers)

        # Clear pending actions
        self._pending_amplifications.clear()

    def _get_advanced_amplification_handlers(self) -> dict:
        """Return advanced amplification handlers for smuggling/auth bypass attacks."""
        # Extracted to scanning/scan_phases/amplification_handlers.py
        handlers = AmplificationHandlers(
            rate_limiter=self.rate_limiter,
            http_client=self.http_client,
            get_auth_headers=self._get_auth_headers,
            load_module=self._load_module,
            run_module=self._run_single_module_with_instance,
        )
        return handlers.get_handlers()

    async def _process_vulnerability_chains(self, result: ScanResult, target: str) -> None:
        """
        Process findings through vulnerability chain engine.

        This implements the "vulnerabilities discover vulnerabilities" paradigm:
        - SQLi confirmed → attempt RCE via UDF/COPY
        - LFI confirmed → extract sensitive files
        - IDOR confirmed → enumerate all accessible resources
        - Auth bypass → test privileged endpoints

        Has a global timeout of 300s (5 min) to prevent runaway chain processing.
        """
        if not self.chain_engine:
            logger.debug("Chain engine not available, skipping vulnerability chaining")
            return

        if not result.findings:
            return

        try:
            await asyncio.wait_for(
                self._process_chains_internal(result, target),
                timeout=300.0  # 5 min max for all chain processing
            )
        except asyncio.TimeoutError:
            logger.warning("[CHAIN_ENGINE] Chain processing timed out after 300s")
            result.info.append({
                "type": "chain_timeout",
                "message": "Chain processing timed out after 5 minutes",
            })

    async def _process_chains_internal(self, result: ScanResult, target: str) -> None:
        """
        Internal chain processing (wrapped by timeout).

        Delegates to extracted chain_processing module.
        """
        from scanning.scan_phases.chain_processing import ChainProcessor

        # Set up chain engine context
        technologies = []
        if self.tech_analysis and hasattr(self.tech_analysis, 'technologies'):
            technologies = [t.name for t in self.tech_analysis.technologies]

        endpoints = []
        if self.intelligent_context and hasattr(self.intelligent_context, 'endpoints_discovered'):
            endpoints = self.intelligent_context.endpoints_discovered

        processor = ChainProcessor(self.chain_engine)
        processor.set_context(
            target=target,
            technologies=technologies,
            endpoints=endpoints,
            safe_mode=self.safe_mode,
        )

        chain_result = await processor.process(result.findings)

        # Update result with chain findings
        result.chains_triggered = chain_result.chains_triggered
        result.chain_findings = len(chain_result.chain_findings)
        result.escalations_attempted = chain_result.escalations_attempted

        for cf in chain_result.chain_findings:
            result.add_finding(cf)

    async def _run_linux_tools_scan(self, result: ScanResult, target: str) -> None:
        """
        Phase 2.5: Run Linux security tools orchestration.

        Delegates to extracted linux_tools module.
        """
        from scanning.scan_phases.linux_tools import (
            run_linux_tools_scan,
            apply_linux_tools_result,
        )

        tools_result = await run_linux_tools_scan(
            target=target,
            settings=self.settings,
            safe_mode=self.safe_mode,
            chain_engine=self.chain_engine,
        )

        # Store discoveries for module use
        self._linux_tool_findings = tools_result.findings
        self._tool_discovered_endpoints.extend(tools_result.discovered_endpoints)
        self._tool_discovered_params.update(tools_result.discovered_params)

        # Apply results to scan result
        apply_linux_tools_result(tools_result, result)

    def _get_generic_fallback_endpoints(self, target: str) -> list[str]:
        """Generate generic fallback endpoints — delegates to discovery module."""
        return get_generic_fallback_endpoints(target)

    # NOTE: The ~300 lines of endpoint pattern definitions have been
    # extracted to scanning/discovery/fallback_endpoints.py

    async def _authenticated_crawl(self, target: str) -> list[str]:
        """Authenticated crawl — delegates to discovery module."""
        if not self._auth_context or not self._auth_context.has_auth:
            return []

        crawler = AuthenticatedCrawler(
            auth_context=self._auth_context,
            settings=self.settings,
        )
        result = await crawler.crawl(target)

        # Store discovered forms for injection testing
        if result.forms:
            self._discovered_forms.extend(result.forms)

        return result.endpoints

    # NOTE: The ~200 lines of authenticated crawl logic have been
    # extracted to scanning/discovery/authenticated_crawler.py

    def _finalize_intelligent_scan(self, result: ScanResult) -> None:
        """Finalize intelligent scan and log summary."""
        if not (self.intelligent_mode and self.intelligent_context):
            return

        # Update metrics from intelligent context
        result.tests_skipped += self.intelligent_context.tests_skipped
        result.scope_violations = len(self.intelligent_context.scope_violations)

        # Log intelligent scan summary
        self.intelligent_scanner.finalize_scan(self.intelligent_context)
        logger.info(
            f"🧠 Intelligent Scan Summary:"
            f"\n   Tests skipped (smart): {result.tests_skipped}"
            f"\n   Scope violations blocked: {result.scope_violations}"
            f"\n   Findings validated: {result.negative_control_validations}"
        )

        # Add inter-module communication statistics
        shared_store = get_shared_findings()
        store_stats = shared_store.get_statistics()
        result.info.append({
            "type": "inter_module_communication",
            "shared_findings": store_stats["total_findings"],
            "unique_endpoints_with_vulns": store_stats["unique_endpoints"],
            "findings_by_type": store_stats["by_type"],
            "findings_by_severity": store_stats["by_severity"],
        })
        logger.info(
            f"🔗 Inter-Module Communication:"
            f"\n   Findings shared: {store_stats['total_findings']}"
            f"\n   Unique vulnerable endpoints: {store_stats['unique_endpoints']}"
        )
    
    def _validate_finding_intelligent(self, finding: dict) -> dict:
        """
        Validate a finding using intelligent infrastructure.

        Delegates to scanning.finding_enhancer.FindingValidator.

        Checks:
        - Confidence meets threshold
        - Parameter context is appropriate for attack type
        - Finding has required evidence
        """
        if not self.intelligent_context or not self.intelligent_scanner:
            return finding

        # Use extracted FindingValidator
        validator = FindingValidator(
            min_confidence=self.intelligent_scanner.config.min_confidence,
            intelligent_scanner=self.intelligent_scanner,
            intelligent_context=self.intelligent_context,
        )
        return validator.validate_and_mark(finding)

    def _build_module_asset_data(self, name: str, target: str) -> dict:
        """Build asset_data dictionary for a scanner module."""
        # Ensure fallback endpoints are available
        if not hasattr(self, '_fallback_endpoints') or not self._fallback_endpoints:
            self._fallback_endpoints = self._get_generic_fallback_endpoints(target)

        # Build attrs dict from scanner state
        scanner_attrs = {
            "intelligent_context": self.intelligent_context,
            "classification": self.classification,
            "tech_analysis": self.tech_analysis,
            "discovered_forms": getattr(self, '_discovered_forms', []) or [],
            "fingerprint_result": getattr(self, 'fingerprint_result', None),
            "waf_detection_result": getattr(self, '_waf_detection_result', None),
            "tool_discovered_endpoints": getattr(self, '_tool_discovered_endpoints', []),
            "tool_discovered_params": getattr(self, '_tool_discovered_params', None),
            "linux_tool_findings": getattr(self, '_linux_tool_findings', None),
            "discovered_subdomains": getattr(self, '_discovered_subdomains', set()),
            "fallback_endpoints": self._fallback_endpoints,
            "get_generic_fallback": self._get_generic_fallback_endpoints,
            "shared_store": get_shared_findings(),
            "auth_context": getattr(self, '_auth_context', None),
            "user_personas": getattr(self, '_user_personas', None),
            "domain_classification": getattr(self, '_domain_classification', None),
            "api_discovery": getattr(self, '_api_discovery', None),
            "security_schemes": getattr(self, '_security_schemes', None),
            "semantic_analyzer": getattr(self, '_semantic_analyzer', None),
            "stack_profile": getattr(self, '_stack_profile', None),
            "runtime_engine": getattr(self, '_runtime_engine', None),
        }
        return build_asset_data_from_scanner(target, name, scanner_attrs)

    async def _run_single_module_with_instance(
        self,
        name: str,
        target: str,
        module: Any,
    ) -> dict:
        """Run a single scanner module with pre-loaded instance."""
        
        if not module:
            return {"findings": [], "info": []}
        
        try:
            # Check if module has safe mode support
            if hasattr(module, "set_safe_mode"):
                module.set_safe_mode(self.safe_mode)
            
            # Check if operation is allowed in safe mode
            if not self.safe_scanner.is_operation_allowed(f"scan_{name}"):
                logger.info(f"Module {name} skipped due to safe mode restrictions")
                return {"findings": [], "info": [{"module": name, "skipped": "safe_mode"}]}
            
            # Create a simple rate limiter for compatibility
            from utils.rate_limiter import RateLimiter
            try:
                rate_limiter = RateLimiter(
                    settings=self.settings,
                    default_rate=getattr(self.settings.rate_limit, 'requests_per_second', 10.0),
                    default_burst=getattr(self.settings.rate_limit, 'concurrent_scans', 20),
                )
            except Exception:
                # Fallback simple rate limiter
                rate_limiter = RateLimiter(default_rate=10.0, default_burst=20)
            
            # Build asset_data using AssetDataBuilder (extracted to scanning/asset_builder/)
            # This ~240-line block has been extracted for maintainability
            asset_data = self._build_module_asset_data(name, target)

            # Run the scan - try different method signatures
            result = None

            # NOTE: is_signature_mismatch imported from scanning.scan_phases.module_executor

            # Set rate_limiter attribute on module if it uses one
            # Some modules (jwt, race, etc.) use self.rate_limiter internally
            if hasattr(module, "rate_limiter") or name in {"jwt", "race", "host_header", "clickjacking", "file_upload"}:
                try:
                    module.rate_limiter = rate_limiter
                except AttributeError:
                    pass  # Read-only or no such attribute

            # Inject auth context for race condition scanner
            if name == "race" and hasattr(self, '_auth_context') and self._auth_context:
                try:
                    module._auth_context = self._auth_context
                except AttributeError:
                    pass

            # Extract endpoints list for modules that expect List[str] instead of dict
            endpoints_list = asset_data.get("endpoints", [target])

            # Module signatures imported from scanning.config.signatures

            if hasattr(module, "scan"):
                # OLD_3ARG_MODULES MUST be called with all 3 args - no fallback allowed
                if name in OLD_3ARG_MODULES:
                    result = await module.scan(target, asset_data, rate_limiter)
                else:
                    # Try different signatures with fallbacks for other modules
                    try:
                        if name in STRING_ENDPOINTS_MODULES:
                            # Pass endpoints as List[str]
                            result = await module.scan(target, endpoints=endpoints_list)
                        elif name in TYPED_ENDPOINTS_MODULES:
                            # Let module create typed endpoints from target (pass None)
                            result = await module.scan(target)
                        elif name in SIMPLE_INTERFACE_MODULES:
                            # Simple interface: just target
                            result = await module.scan(target)
                        elif name in PORT_PARAMS_MODULES:
                            # Modules with (host, port, extra_params) signature
                            # Pass asset_data through extra_params dict
                            extra_params = {
                                "auth_context": asset_data.get("auth_context"),
                                "rate_limiter": rate_limiter,
                                "endpoints": asset_data.get("endpoints", []),
                                "verify_ssl": asset_data.get("verify_ssl", False),
                            }
                            result = await module.scan(target, port=None, extra_params=extra_params)
                        elif name in TWO_ARG_MODULES:
                            # Modules with (target, asset_data) - no rate_limiter
                            result = await module.scan(target, asset_data)
                        elif rate_limiter:
                            # Old interface with rate_limiter: scan(host, asset_data, rate_limiter)
                            result = await module.scan(target, asset_data, rate_limiter)
                        else:
                            result = await module.scan(target, asset_data)
                    except TypeError as e:
                        # Only catch signature mismatches, re-raise other TypeErrors
                        if not is_signature_mismatch(e):
                            raise
                        # Try without rate_limiter (old interface fallback)
                        try:
                            result = await module.scan(target, asset_data)
                        except TypeError as e2:
                            if not is_signature_mismatch(e2):
                                raise
                            # Try new interface with endpoints
                            try:
                                result = await module.scan(target, endpoints=endpoints_list)
                            except TypeError as e3:
                                if not is_signature_mismatch(e3):
                                    raise
                                # Final fallback: just target
                                result = await module.scan(target)
            elif hasattr(module, "run"):
                result = await module.run(target)
            else:
                logger.warning(f"Module {name} has no scan/run method")
                return {"findings": [], "info": []}
            
            # Normalize result format
            findings = []
            if isinstance(result, dict):
                findings = result.get("findings", result.get("vulns", result.get("vulnerabilities", [])))
            elif isinstance(result, list):
                findings = result
            
            # Add module info to findings
            for f in findings:
                if isinstance(f, dict):
                    f["module"] = name
                    f["safe_mode"] = self.safe_mode

            # ═══════════════════════════════════════════════════════════════════
            # FEEDBACK-01 FIX: DO NOT share findings here (before validation)
            # Unvalidated findings in SharedFindingsStore cause FP cascades
            # Findings are shared AFTER validation in _share_validated_findings()
            # ═══════════════════════════════════════════════════════════════════

            return {"findings": findings, "info": result.get("info", []) if isinstance(result, dict) else []}
            
        except Exception as e:
            logger.error(f"Module {name} error: {e}")
            raise
    
    async def quick_scan(self, target: str) -> ScanResult:
        """Quick scan - headers, SSL, CORS, directories."""
        return await self.scan(target, category="quick")
    
    async def web_scan(self, target: str) -> ScanResult:
        """Standard web application scan."""
        return await self.scan(target, category="web")
    
    async def api_scan(self, target: str) -> ScanResult:
        """API security scan."""
        return await self.scan(target, category="api")
    
    async def full_scan(self, target: str) -> ScanResult:
        """Full scan with all modules."""
        return await self.scan(target, category="full", concurrent=3)
    
    def get_available_modules(self) -> list[str]:
        """Get list of all available modules (short names)."""
        return list(self.ALL_MODULES.keys())

    def get_registry_modules(self) -> list[ModuleInfo]:
        """Get all modules from the ModuleRegistry."""
        return get_module_registry().get_all()

    def get_modules_by_category(self, category: ModuleCategory) -> list[ModuleInfo]:
        """Get modules by category from the ModuleRegistry."""
        return get_module_registry().get_by_category(category)

    def get_module_info(self, name: str) -> Optional[ModuleInfo]:
        """
        Get module info from registry.

        Args:
            name: Short name (e.g., "sqli") or registry name (e.g., "sqli_scanner")

        Returns:
            ModuleInfo or None if not found
        """
        registry = get_module_registry()
        # Check if this is a short name
        registry_name = self.SHORT_TO_REGISTRY_NAME.get(name, name)
        return registry.get(registry_name)

    def get_categories(self) -> dict[str, list[str]]:
        """Get available scan categories."""
        return self.CATEGORIES.copy()
    
    def get_compliance_report(self) -> dict:
        """Get safe mode compliance report with accurate request counts."""
        from utils.rate_limiter import RateLimiter

        report = self.safe_scanner.get_compliance_report()

        # Update with actual request count from rate limiter
        global_requests = RateLimiter.get_global_request_count()
        if global_requests > 0:
            report["statistics"]["total_requests"] = global_requests

        return report
    
    def get_intelligent_context(self):
        """Get the intelligent scanning context for advanced integrations."""
        return self.intelligent_context
    
    def get_attack_recommendations(self, url: str) -> dict[str, list[str]]:
        """
        Get recommended attacks for each parameter based on context analysis.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dict mapping parameter names to list of recommended attack types
        """
        if not self.intelligent_scanner or not self.intelligent_context:
            return {}
        return self.intelligent_scanner.get_attack_recommendations(
            self.intelligent_context,
            url
        )
