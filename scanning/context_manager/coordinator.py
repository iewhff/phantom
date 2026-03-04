"""
Context Coordinator - Coordinates Multiple Scan Contexts.

Provides coordination between different context types:
- AuthContext (authentication state)
- IntelligentContext (intelligent scanning context)
- ScanContext (pipeline context)

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════════════


class AuthContextProtocol(Protocol):
    """Protocol for authentication context."""

    @property
    def has_auth(self) -> bool:
        """Check if authentication is available."""
        ...

    @property
    def token(self) -> str:
        """Get authentication token."""
        ...

    @property
    def cookies(self) -> dict[str, str]:
        """Get session cookies."""
        ...

    @property
    def method(self) -> str:
        """Get auth acquisition method."""
        ...

    @property
    def auth_headers(self) -> dict[str, str]:
        """Get authentication headers."""
        ...


class IntelligentContextProtocol(Protocol):
    """Protocol for intelligent scanning context."""

    @property
    def endpoints_discovered(self) -> list[str]:
        """Get discovered endpoints."""
        ...

    @property
    def parameter_analysis(self) -> dict:
        """Get parameter analysis results."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Context State
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ContextState:
    """Tracks the state of all contexts during a scan."""

    # Identity
    scan_id: str = ""
    target: str = ""

    # Context availability
    has_auth_context: bool = False
    has_intelligent_context: bool = False

    # Auth state
    auth_method: str = ""
    auth_acquired_at: Optional[float] = None
    auth_refreshed_at: Optional[float] = None
    auth_refresh_count: int = 0

    # Discovery state
    endpoints_count: int = 0
    parameters_count: int = 0
    forms_count: int = 0

    # Lifecycle
    initialized_at: Optional[float] = None
    finalized_at: Optional[float] = None

    # Metadata
    metadata: dict = field(default_factory=dict)

    @property
    def is_initialized(self) -> bool:
        """Check if context is initialized."""
        return self.initialized_at is not None

    @property
    def is_finalized(self) -> bool:
        """Check if context is finalized."""
        return self.finalized_at is not None

    @property
    def auth_age_seconds(self) -> float:
        """Get age of auth in seconds."""
        if not self.auth_acquired_at:
            return 0.0
        return time.time() - self.auth_acquired_at

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "has_auth_context": self.has_auth_context,
            "has_intelligent_context": self.has_intelligent_context,
            "auth_method": self.auth_method,
            "auth_age_seconds": self.auth_age_seconds,
            "endpoints_count": self.endpoints_count,
            "parameters_count": self.parameters_count,
            "is_initialized": self.is_initialized,
            "is_finalized": self.is_finalized,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Context Coordinator
# ═══════════════════════════════════════════════════════════════════════════════


class ContextCoordinator:
    """Coordinates multiple contexts during a scan.

    Provides:
    - Unified access to different contexts
    - Context lifecycle management
    - Context state tracking
    - Asset data building for modules
    """

    def __init__(
        self,
        scan_id: str = "",
        target: str = "",
    ):
        """Initialize coordinator.

        Args:
            scan_id: Unique scan identifier
            target: Target URL being scanned
        """
        self.scan_id = scan_id
        self.target = target

        # Contexts
        self._auth_context: Optional[AuthContextProtocol] = None
        self._intelligent_context: Optional[IntelligentContextProtocol] = None

        # State tracking
        self._state = ContextState(scan_id=scan_id, target=target)

        # Additional data
        self._tech_stack: dict = {}
        self._waf_detection: Optional[dict] = None
        self._fingerprint_result: Optional[Any] = None
        self._discovered_forms: list[dict] = []
        self._semantic_analyzer: Optional[Any] = None
        self._training_app: str = ""

    @property
    def state(self) -> ContextState:
        """Get current context state."""
        return self._state

    @property
    def has_auth(self) -> bool:
        """Check if authentication is available."""
        return (
            self._auth_context is not None
            and self._auth_context.has_auth
        )

    @property
    def has_intelligent_context(self) -> bool:
        """Check if intelligent context is available."""
        return self._intelligent_context is not None

    # ═══════════════════════════════════════════════════════════════════════════
    # Context Registration
    # ═══════════════════════════════════════════════════════════════════════════

    def register_auth_context(
        self,
        auth_context: AuthContextProtocol,
    ) -> None:
        """Register authentication context.

        Args:
            auth_context: Authentication context instance
        """
        self._auth_context = auth_context
        self._state.has_auth_context = auth_context.has_auth
        self._state.auth_method = auth_context.method if auth_context.has_auth else ""
        self._state.auth_acquired_at = time.time() if auth_context.has_auth else None

        if auth_context.has_auth:
            logger.debug(
                f"[ContextCoordinator] Auth registered: {auth_context.method}"
            )

    def register_intelligent_context(
        self,
        intelligent_context: IntelligentContextProtocol,
    ) -> None:
        """Register intelligent scanning context.

        Args:
            intelligent_context: Intelligent context instance
        """
        self._intelligent_context = intelligent_context
        self._state.has_intelligent_context = True
        self._state.endpoints_count = len(intelligent_context.endpoints_discovered)
        self._state.parameters_count = len(intelligent_context.parameter_analysis)

        logger.debug(
            f"[ContextCoordinator] Intelligent context registered: "
            f"{self._state.endpoints_count} endpoints"
        )

    def register_tech_stack(self, tech_stack: dict) -> None:
        """Register technology stack information."""
        self._tech_stack = tech_stack

    def register_waf_detection(self, waf_result: dict) -> None:
        """Register WAF detection result."""
        self._waf_detection = waf_result

    def register_fingerprint(self, fingerprint: Any) -> None:
        """Register fingerprint result."""
        self._fingerprint_result = fingerprint

    def register_forms(self, forms: list[dict]) -> None:
        """Register discovered forms."""
        self._discovered_forms = forms
        self._state.forms_count = len(forms)

    def register_semantic_analyzer(self, analyzer: Any) -> None:
        """Register semantic analyzer."""
        self._semantic_analyzer = analyzer

    def set_training_app(self, name: str) -> None:
        """Set training app name."""
        self._training_app = name

    # ═══════════════════════════════════════════════════════════════════════════
    # Context Access
    # ═══════════════════════════════════════════════════════════════════════════

    def get_auth_context(self) -> Optional[AuthContextProtocol]:
        """Get authentication context."""
        return self._auth_context

    def get_intelligent_context(self) -> Optional[IntelligentContextProtocol]:
        """Get intelligent scanning context."""
        return self._intelligent_context

    def get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers for requests."""
        if not self._auth_context or not self._auth_context.has_auth:
            return {}
        return self._auth_context.auth_headers

    def get_discovered_endpoints(self) -> list[str]:
        """Get list of discovered endpoints."""
        if not self._intelligent_context:
            return [self.target] if self.target else []
        return self._intelligent_context.endpoints_discovered

    def get_technologies(self) -> list[str]:
        """Get detected technologies."""
        return list(self._tech_stack.keys()) if self._tech_stack else []

    # ═══════════════════════════════════════════════════════════════════════════
    # Asset Data Building
    # ═══════════════════════════════════════════════════════════════════════════

    def build_asset_data(self) -> dict[str, Any]:
        """Build asset_data dictionary for scanner modules.

        This is the data structure passed to each scanner module.

        Returns:
            Dictionary with all context data for modules
        """
        # Extract endpoint data
        endpoints = self.get_discovered_endpoints()

        # Extract parameter names from intelligent context
        parameters = []
        if self._intelligent_context and self._intelligent_context.parameter_analysis:
            for url, analysis in self._intelligent_context.parameter_analysis.items():
                if hasattr(analysis, 'parameters'):
                    for p in analysis.parameters:
                        if hasattr(p, 'name'):
                            parameters.append(p.name)
                        elif isinstance(p, str):
                            parameters.append(p)
                elif isinstance(analysis, dict) and 'parameters' in analysis:
                    for p in analysis['parameters']:
                        if isinstance(p, dict) and 'name' in p:
                            parameters.append(p['name'])
                        elif isinstance(p, str):
                            parameters.append(p)

        # Deduplicate
        parameters = list(set(parameters))

        return {
            # Discovery
            "endpoints": endpoints,
            "parameters": parameters,
            "forms": self._discovered_forms,

            # Technology
            "technologies": self.get_technologies(),
            "fingerprint_result": self._fingerprint_result,
            "waf_detection": self._waf_detection,
            "tech_stack": self._tech_stack,

            # Authentication
            "auth_context": self._auth_context,
            "has_auth": self.has_auth,

            # Analysis
            "semantic_analyzer": self._semantic_analyzer,
            "intelligent_context": self._intelligent_context,

            # Training app
            "training_app": self._training_app,

            # Metadata
            "scan_id": self.scan_id,
            "target": self.target,
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # Lifecycle
    # ═══════════════════════════════════════════════════════════════════════════

    def initialize(self) -> None:
        """Initialize context coordination."""
        self._state.initialized_at = time.time()
        logger.debug(f"[ContextCoordinator] Initialized for {self.target}")

    def finalize(self) -> ContextState:
        """Finalize context coordination.

        Returns:
            Final context state
        """
        self._state.finalized_at = time.time()
        logger.debug(
            f"[ContextCoordinator] Finalized - "
            f"auth={self._state.has_auth_context}, "
            f"intelligent={self._state.has_intelligent_context}, "
            f"endpoints={self._state.endpoints_count}"
        )
        return self._state

    def record_auth_refresh(self) -> None:
        """Record an auth refresh event."""
        self._state.auth_refreshed_at = time.time()
        self._state.auth_refresh_count += 1

    def get_summary(self) -> dict:
        """Get coordinator summary.

        Returns:
            Summary dictionary
        """
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "state": self._state.to_dict(),
            "has_auth": self.has_auth,
            "has_intelligent_context": self.has_intelligent_context,
            "endpoints_count": len(self.get_discovered_endpoints()),
            "technologies": self.get_technologies()[:10],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════


def create_coordinator(
    scan_id: str = "",
    target: str = "",
) -> ContextCoordinator:
    """Create a new context coordinator.

    Args:
        scan_id: Unique scan identifier
        target: Target URL

    Returns:
        Initialized ContextCoordinator
    """
    coordinator = ContextCoordinator(scan_id=scan_id, target=target)
    coordinator.initialize()
    return coordinator


def build_minimal_asset_data(
    target: str,
    endpoints: Optional[list[str]] = None,
    auth_headers: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Build minimal asset data without full coordinator.

    Args:
        target: Target URL
        endpoints: Optional list of endpoints
        auth_headers: Optional auth headers

    Returns:
        Minimal asset_data dictionary
    """
    return {
        "endpoints": endpoints or [target],
        "parameters": [],
        "forms": [],
        "technologies": [],
        "fingerprint_result": None,
        "waf_detection": None,
        "auth_context": None,
        "has_auth": bool(auth_headers),
        "semantic_analyzer": None,
        "intelligent_context": None,
        "training_app": "",
        "scan_id": "",
        "target": target,
    }
