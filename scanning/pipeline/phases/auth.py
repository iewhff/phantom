"""
Authentication Acquisition Phase - Session and Token Acquisition.

This phase handles:
- Phase 2.5: Auth token acquisition (JWT, session, API key)
- Phase 2.55: Session watchdog initialization
- Phase 2.56: Auth refresher setup
- Phase 2.6: Authenticated re-crawl
- Phase 2.7: Semantic analyzer initialization
- Phase 2.9: Intent-driven module prioritization

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Optional

from scanning.pipeline.base import Phase, PhaseResult, PhaseStatus, ScanContext
from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.auth_context import AuthContext, UserPersonaStore

logger = get_logger(__name__)


@dataclass
class AuthConfig:
    """Configuration for auth acquisition phase."""

    enable_multi_user: bool = True
    max_users: int = 2
    enable_session_watchdog: bool = True
    enable_auth_refresher: bool = True
    enable_authenticated_crawl: bool = True
    watchdog_check_interval: float = 60.0
    max_consecutive_failures: int = 3


class AuthAcquisitionPhase(Phase):
    """
    Authentication acquisition phase.

    Consolidates:
    - Phase 2.5: Auth Acquisition
    - Phase 2.55: Session Watchdog
    - Phase 2.56: Auth Refresher
    - Phase 2.6: Authenticated Re-Crawl
    - Phase 2.7: Semantic Analyzer
    - Phase 2.9: Intent-Driven Module Prioritization
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        super().__init__("AuthAcquisitionPhase")
        self.config = config or AuthConfig()

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute auth acquisition phase."""
        auth_acquired = False
        auth_method = "none"
        multi_user = False

        try:
            logger.info(f"[Auth] Starting auth acquisition for {context.target_url}")

            # Sub-phase 2.5: Auth Token Acquisition
            auth_result = await self._acquire_auth(context)
            if auth_result.get("success"):
                auth_acquired = True
                auth_method = auth_result.get("method", "unknown")
                context.is_authenticated = True
                context.auth_headers = auth_result.get("headers", {})
                context.auth_cookies = auth_result.get("cookies", {})
                context.metadata["auth_context"] = auth_result.get("context")
                context.metadata["user_personas"] = auth_result.get("personas")
                multi_user = auth_result.get("multi_user", False)

            # Sub-phase 2.55: Session Watchdog
            if auth_acquired and self.config.enable_session_watchdog:
                watchdog = await self._setup_session_watchdog(context)
                context.metadata["session_watchdog"] = watchdog

            # Sub-phase 2.56: Auth Refresher
            if auth_acquired and self.config.enable_auth_refresher:
                refresher = await self._setup_auth_refresher(context)
                context.metadata["auth_refresher"] = refresher

            # Sub-phase 2.6: Authenticated Re-Crawl
            if auth_acquired and self.config.enable_authenticated_crawl:
                new_endpoints = await self._authenticated_crawl(context)
                context.add_endpoints(new_endpoints)
                logger.info(f"[Auth] Authenticated crawl found {len(new_endpoints)} new endpoints")

            # Sub-phase 2.7: Semantic Analyzer
            semantic = await self._init_semantic_analyzer(context)
            context.metadata["semantic_analyzer"] = semantic

            # Sub-phase 2.9: Intent-Driven Prioritization
            # (Deferred to module execution phase)

            logger.info(
                f"[Auth] Complete: authenticated={auth_acquired}, "
                f"method={auth_method}, multi_user={multi_user}"
            )

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.COMPLETED,
                data={
                    "authenticated": auth_acquired,
                    "auth_method": auth_method,
                    "multi_user": multi_user,
                    "new_endpoints": len(context.endpoints),
                },
            )

        except Exception as e:
            logger.error(f"[Auth] Failed: {e}")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message=str(e),
                data={"authenticated": False},
            )

    async def _acquire_auth(self, context: ScanContext) -> dict[str, Any]:
        """Acquire authentication token."""
        try:
            from scanning.auth_context import AuthAcquisition, AuthContext, UserPersonaStore

            auth_acq = AuthAcquisition()

            # Determine domain type for domain-aware auth
            domain_type = None
            if "domain_classification" in context.metadata:
                domain_info = context.metadata["domain_classification"]
                domain_type = domain_info.get("primary", {}).get("value")

            # Try multi-user acquisition for cross-user testing
            if self.config.enable_multi_user:
                personas = await auth_acq.acquire_multiple_users(
                    context.target_url,
                    None,
                    count=self.config.max_users,
                    domain=domain_type,
                )

                if personas.primary.has_auth:
                    return {
                        "success": True,
                        "method": personas.primary.method,
                        "headers": personas.primary.auth_headers,
                        "cookies": personas.primary.cookies,
                        "context": personas.primary,
                        "personas": personas,
                        "multi_user": personas.has_multiple_users,
                    }

            # Fallback to single-user acquisition
            auth_ctx = await auth_acq.acquire(context.target_url, None, domain=domain_type)
            if auth_ctx and auth_ctx.has_auth:
                return {
                    "success": True,
                    "method": auth_ctx.method,
                    "headers": auth_ctx.auth_headers,
                    "cookies": auth_ctx.cookies,
                    "context": auth_ctx,
                    "personas": None,
                    "multi_user": False,
                }

            return {"success": False}

        except ImportError:
            logger.debug("[Auth] AuthAcquisition not available")
            return {"success": False}
        except Exception as e:
            logger.warning(f"[Auth] Auth acquisition failed: {e}")
            return {"success": False, "error": str(e)}

    async def _setup_session_watchdog(self, context: ScanContext) -> Optional[Any]:
        """Setup session watchdog for auth health monitoring."""
        try:
            from utils.session_watchdog import SessionWatchdog, detect_whoami_endpoint, WatchdogConfig

            auth_ctx = context.metadata.get("auth_context")
            if not auth_ctx:
                return None

            whoami_endpoint = detect_whoami_endpoint(
                context.target_url,
                discovered_endpoints=context.endpoints,
            )

            watchdog = SessionWatchdog(
                auth_context=auth_ctx,
                whoami_endpoint=whoami_endpoint,
                http_client=None,  # Will be injected by caller
                config=WatchdogConfig(
                    check_interval=self.config.watchdog_check_interval,
                    max_consecutive_failures=self.config.max_consecutive_failures,
                    auto_refresh=True,
                    auto_reauth=True,
                ),
            )
            await watchdog.start()
            logger.info(f"[SessionWatchdog] Started monitoring (whoami: {whoami_endpoint})")
            return watchdog

        except ImportError:
            logger.debug("[Auth] SessionWatchdog not available")
            return None
        except Exception as e:
            logger.debug(f"[SessionWatchdog] Could not initialize: {e}")
            return None

    async def _setup_auth_refresher(self, context: ScanContext) -> Optional[Any]:
        """Setup auth refresher for automatic token refresh."""
        try:
            from utils.auth_refresher import create_refresher_from_auth_context

            auth_ctx = context.metadata.get("auth_context")
            if not auth_ctx:
                return None

            refresher = create_refresher_from_auth_context(auth_ctx, context.target_url)
            if refresher and refresher.has_credentials():
                logger.info(f"[AuthRefresher] Initialized with method={refresher.get_method().name}")
                return refresher

            return None

        except ImportError:
            logger.debug("[Auth] AuthRefresher not available")
            return None
        except Exception as e:
            logger.debug(f"[AuthRefresher] Could not initialize: {e}")
            return None

    async def _authenticated_crawl(self, context: ScanContext) -> list[str]:
        """Re-crawl with authentication to discover protected endpoints."""
        try:
            from reconnaissance.authenticated_crawler import AuthenticatedCrawler

            auth_ctx = context.metadata.get("auth_context")
            if not auth_ctx:
                return []

            crawler = AuthenticatedCrawler(auth_context=auth_ctx)
            endpoints = await crawler.crawl(context.target_url)
            return list(endpoints) if endpoints else []

        except ImportError:
            logger.debug("[Auth] AuthenticatedCrawler not available")
            return []
        except Exception as e:
            logger.debug(f"[Auth] Authenticated crawl failed: {e}")
            return []

    async def _init_semantic_analyzer(self, context: ScanContext) -> Optional[Any]:
        """Initialize semantic analyzer for SPA detection."""
        try:
            from scanning.semantic_analyzer import initialize_semantic_analyzer

            auth_headers = context.auth_headers if context.is_authenticated else None
            analyzer = await initialize_semantic_analyzer(context.target_url, auth_headers)
            logger.info("[SemanticAnalyzer] Initialized for response classification")
            return analyzer

        except ImportError:
            logger.debug("[Auth] SemanticAnalyzer not available")
            return None
        except Exception as e:
            logger.debug(f"[SemanticAnalyzer] Initialization failed: {e}")
            return None
