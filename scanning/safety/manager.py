"""
Safety Manager - Central Safety Orchestration.

Encapsulates all safety-related component initialization and management:
- P0 Professional Safety Configuration
- Scope Guard enforcement
- Global HTTP safety
- Payload analysis
- Evidence redaction

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

from .levels import SafetyMode, get_mode_emoji, get_mode_description

if TYPE_CHECKING:
    from safe_mode import SafeScanner, EvidenceCollector
    from utils.scope_guard import ScopeGuard
    from utils.rate_limiter import RateLimiter

logger = logging.getLogger("phantom")


@dataclass
class SafetyComponents:
    """Container for all safety-related components.

    Attributes:
        mode: Current safety mode
        payload_analyzer: P0.3 PayloadSafetyAnalyzer instance
        proof_config: P0.2 ProofPolicy configuration
        evidence_redactor: P0.7 EvidenceRedactor instance
        scope_guard: Scope enforcement instance
        safe_scanner: SafeScanner instance from safe_mode module
        evidence_collector: Evidence collection instance
        rate_limiter: Rate limiting instance
    """
    mode: SafetyMode = field(default=SafetyMode.SAFE)
    payload_analyzer: Optional[Any] = None
    proof_config: Optional[Any] = None
    evidence_redactor: Optional[Any] = None
    scope_guard: Optional["ScopeGuard"] = None
    safe_scanner: Optional["SafeScanner"] = None
    evidence_collector: Optional["EvidenceCollector"] = None
    evidence_engine: Optional[Any] = None
    rate_limiter: Optional["RateLimiter"] = None


class SafetyManager:
    """Central safety orchestration for the scanner.

    Handles initialization and management of all safety-related components
    including P0 professional controls, scope guards, and HTTP safety.
    """

    def __init__(
        self,
        safe_mode: str = "safe",
        safety_config: Optional[Any] = None,
        scope: Optional[list[str]] = None,
        include_subdomains: bool = True,
        settings: Optional[Any] = None,
    ):
        """Initialize the safety manager.

        Args:
            safe_mode: Safety mode string (passive, safe, cautious, standard, aggressive)
            safety_config: Optional SafetyConfig object with professional controls
            scope: List of allowed domains for scope enforcement
            include_subdomains: Whether to include subdomains in scope
            settings: Application settings object
        """
        self.settings = settings
        self.scope = scope or []
        self.include_subdomains = include_subdomains
        self._protection_verified = False

        # Parse safety mode
        self.mode = SafetyMode.from_string(safe_mode)

        # Override from safety_config if provided
        if safety_config:
            self.mode = SafetyMode.from_string(safety_config.safety_level)

        # Initialize components container
        self.components = SafetyComponents(mode=self.mode)

        # Initialize P0 professional safety if config provided
        if safety_config:
            self._init_p0_safety(safety_config)

        # Initialize scope guard
        if self.scope:
            self._init_scope_guard()

        # Enable global HTTP safety
        self._enable_global_safety()

        # Initialize rate limiter
        self._init_rate_limiter()

        # Initialize safe mode components
        self._init_safe_mode_components()

        # Log safety status
        self._log_safety_status()

    def _init_p0_safety(self, safety_config: Any) -> None:
        """Initialize P0 professional safety components."""
        # Validate configuration
        is_valid, errors = safety_config.validate_for_scan()
        if not is_valid:
            for error in errors:
                logger.error(f"[SafetyConfig] Validation error: {error}")
            raise ValueError(f"Safety configuration validation failed: {', '.join(errors)}")

        # Initialize PayloadSafetyAnalyzer
        try:
            self.components.payload_analyzer = safety_config.get_payload_analyzer()
            logger.info(f"[P0.3] PayloadSafetyAnalyzer ENABLED - safety_level={self.mode.value}")
        except ImportError as e:
            logger.warning(f"[P0.3] PayloadSafetyAnalyzer not available: {e}")

        # Initialize ProofConfig
        try:
            self.components.proof_config = safety_config.get_proof_config()
            logger.info(f"[P0.2] ProofPolicy ENABLED - policy={safety_config.proof_policy}")
        except ImportError as e:
            logger.warning(f"[P0.2] ProofConfig not available: {e}")

        # Initialize EvidenceRedactor
        try:
            self.components.evidence_redactor = safety_config.get_evidence_redactor()
            logger.info(f"[P0.7] EvidenceRedactor ENABLED - level={safety_config.redaction_level}")
        except ImportError as e:
            logger.warning(f"[P0.7] EvidenceRedactor not available: {e}")

        # Log RoE status
        logger.info(f"[P0.1] RoE Status: {safety_config.roe.status.value}")
        if safety_config.roe.scope:
            logger.info(f"[P0.1] RoE Scope: {', '.join(safety_config.roe.scope[:3])}...")

        logger.info(f"[P0] Professional Safety Config: {safety_config.to_dict()}")

    def _init_scope_guard(self) -> None:
        """Initialize scope guard for domain enforcement."""
        from utils.scope_guard import ScopeGuard, ScopeDefinition, ScopeMode

        # Allow localhost if any scope domain is local (e.g., localhost, 127.0.0.1)
        local_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
        target_is_local = any(
            d.split(":")[0].lower() in local_hosts
            or d.split(":")[0].startswith("192.168.")
            or d.split(":")[0].startswith("10.")
            for d in self.scope
        )

        # Extract custom ports from scope entries (e.g., "localhost:3000" → 3000)
        extra_ports: list[int] = []
        for d in self.scope:
            if ":" in d and not d.startswith("*."):
                try:
                    port = int(d.split(":")[-1])
                    extra_ports.append(port)
                except ValueError:
                    pass
        allowed_ports = [80, 443, 8080, 8443] + extra_ports

        scope_definition = ScopeDefinition(
            allowed_domains=self.scope,
            allowed_ports=allowed_ports,
            include_subdomains=self.include_subdomains,
            block_internal_ips=not target_is_local,
            block_cloud_metadata=True,
            block_localhost=not target_is_local,
        )

        # Use STRICT mode for bounty/client (professional testing)
        self.components.scope_guard = ScopeGuard(
            scope=scope_definition,
            mode=ScopeMode.STRICT,
        )
        logger.info(f"🔒 ScopeGuard ENABLED - Allowed domains: {', '.join(self.scope)}")

    def _enable_global_safety(self) -> None:
        """Enable global HTTP safety controls."""
        # Set environment variable BEFORE any modules are loaded
        os.environ["PHANTOM_SAFE_MODE"] = self.mode.value

        # Enable global HTTP safety - replaces httpx.AsyncClient with SafeAsyncClient
        from utils.safe_http_client import enable_global_safety
        enable_global_safety()

    def _init_rate_limiter(self) -> None:
        """Initialize rate limiter for endpoint discovery."""
        from utils.rate_limiter import RateLimiter

        try:
            self.components.rate_limiter = RateLimiter(
                settings=self.settings,
                default_rate=getattr(
                    getattr(self.settings, 'rate_limit', None),
                    'requests_per_second',
                    10.0
                ),
                default_burst=getattr(
                    getattr(self.settings, 'rate_limit', None),
                    'concurrent_scans',
                    20
                ),
            )
        except Exception as e:
            # Fallback rate limiter
            logger.debug(f"Rate limiter config error, using defaults: {e}")
            self.components.rate_limiter = RateLimiter(default_rate=10.0, default_burst=20)

    def _init_safe_mode_components(self) -> None:
        """Initialize safe mode scanner and evidence collector."""
        from safe_mode import SafeScanner, SafetyLevel, EvidenceCollector
        from utils.evidence_engine import get_evidence_engine

        # Map SafetyMode to SafetyLevel
        level_map = {
            SafetyMode.PASSIVE: SafetyLevel.PASSIVE,
            SafetyMode.SAFE: SafetyLevel.SAFE,
            SafetyMode.CAUTIOUS: SafetyLevel.CAUTIOUS,
            SafetyMode.STANDARD: SafetyLevel.STANDARD,
            SafetyMode.AGGRESSIVE: SafetyLevel.AGGRESSIVE,
        }

        safety_level = level_map.get(self.mode, SafetyLevel.SAFE)
        self.components.safe_scanner = SafeScanner(safety_level=safety_level)
        self.components.evidence_collector = EvidenceCollector()

        # Initialize Evidence Engine v3.0
        self.components.evidence_engine = get_evidence_engine()

    def _log_safety_status(self) -> None:
        """Log safety status prominently."""
        emoji = get_mode_emoji(self.mode.value)
        desc = get_mode_description(self.mode.value)

        logger.info(f"{emoji} SAFETY MODE: {self.mode.value.upper()}")

        if self.mode in (SafetyMode.PASSIVE, SafetyMode.SAFE):
            logger.info("   - Global HTTP safety: ENABLED")
            logger.info("   - Destructive payload blocking: ENABLED")
            logger.info("   - POST/PUT/PATCH/DELETE: BLOCKED")
        elif self.mode == SafetyMode.CAUTIOUS:
            logger.info("   - Global HTTP safety: ENABLED")
            logger.info("   - Destructive payload blocking: ENABLED")
            logger.info("   - PUT/PATCH/DELETE: BLOCKED")
            logger.info("   - POST: Allowed (payload checked)")
        elif self.mode == SafetyMode.STANDARD:
            logger.info("   - Global HTTP safety: ENABLED")
            logger.info("   - Destructive payload blocking: ENABLED")
            logger.info("   - All methods: Allowed (payload checked)")
        else:  # aggressive/unrestricted
            logger.info("   - Global HTTP safety: MINIMAL")
            logger.info("   - Destructive payload blocking: DISABLED 🔥")
            logger.info("   - All methods: ALLOWED (FULL PENTEST MODE)")
            logger.warning("   ⚠️ AGGRESSIVE MODE - Who's ready to fly on a zipline? I AM! 🪝")

    @property
    def payload_analyzer(self) -> Optional[Any]:
        """Get the payload analyzer component."""
        return self.components.payload_analyzer

    @property
    def proof_config(self) -> Optional[Any]:
        """Get the proof configuration."""
        return self.components.proof_config

    @property
    def evidence_redactor(self) -> Optional[Any]:
        """Get the evidence redactor."""
        return self.components.evidence_redactor

    @property
    def scope_guard(self) -> Optional["ScopeGuard"]:
        """Get the scope guard."""
        return self.components.scope_guard

    @property
    def safe_scanner(self) -> Optional["SafeScanner"]:
        """Get the safe scanner."""
        return self.components.safe_scanner

    @property
    def evidence_collector(self) -> Optional["EvidenceCollector"]:
        """Get the evidence collector."""
        return self.components.evidence_collector

    @property
    def evidence_engine(self) -> Optional[Any]:
        """Get the evidence engine."""
        return self.components.evidence_engine

    @property
    def rate_limiter(self) -> Optional["RateLimiter"]:
        """Get the rate limiter."""
        return self.components.rate_limiter

    def is_mode_allowed(self, required_mode: str) -> bool:
        """Check if current mode allows a required mode level.

        Args:
            required_mode: The minimum required safety mode

        Returns:
            True if current mode is at least as permissive as required
        """
        required = SafetyMode.from_string(required_mode)
        return self.mode >= required

    def validate_payload(self, payload: str, category: str = "other") -> tuple[bool, str]:
        """Validate a payload against safety rules.

        Args:
            payload: The payload to validate
            category: Payload category (sqli, cmdi, xss, etc.)

        Returns:
            Tuple of (is_safe, reason_if_blocked)
        """
        from .validation import validate_payload
        return validate_payload(
            payload, category, self.mode.value, self.components.payload_analyzer
        )

    def filter_payloads(self, payloads: list[str], category: str = "other") -> list[str]:
        """Filter a list of payloads, returning only safe ones.

        Args:
            payloads: List of payloads to filter
            category: Payload category

        Returns:
            List of safe payloads
        """
        from .validation import filter_payloads
        return filter_payloads(
            payloads, category, self.mode.value, self.components.payload_analyzer
        )

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the allowed scope.

        Args:
            url: URL to check

        Returns:
            True if URL is in scope (or no scope defined)
        """
        if not self.components.scope_guard:
            return True

        result = self.components.scope_guard.check(url)
        return result.allowed


def initialize_safety(
    safe_mode: str = "safe",
    safety_config: Optional[Any] = None,
    scope: Optional[list[str]] = None,
    include_subdomains: bool = True,
    settings: Optional[Any] = None,
) -> SafetyManager:
    """Initialize the safety system.

    Convenience function for creating a SafetyManager with all components.

    Args:
        safe_mode: Safety mode string
        safety_config: Optional professional safety configuration
        scope: List of allowed domains
        include_subdomains: Whether to include subdomains in scope
        settings: Application settings

    Returns:
        Configured SafetyManager instance
    """
    return SafetyManager(
        safe_mode=safe_mode,
        safety_config=safety_config,
        scope=scope,
        include_subdomains=include_subdomains,
        settings=settings,
    )
