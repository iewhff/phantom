"""
Discovery Phase - Target Discovery and Endpoint Enumeration.

This phase handles:
- Phase 0: Target classification
- Phase 0.5-0.6: Technology fingerprinting
- Phase 0.7: Smart endpoint discovery
- Phase 0.75: Subdomain enumeration
- Phase 0.8: Domain classification
- Phase 0.9: Runtime awareness

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from scanning.pipeline.base import Phase, PhaseResult, PhaseStatus, ScanContext
from utils.logger import get_logger

if TYPE_CHECKING:
    from reconnaissance.smart_discovery import SmartDiscovery
    from phantom.tech_fingerprinter import TechFingerprinter
    from scanning.target_classifier import TargetClassifier
    from scanning.domain_classifier import DomainClassifier

logger = get_logger(__name__)


@dataclass
class DiscoveryConfig:
    """Configuration for discovery phase."""

    enable_subdomain_enum: bool = False
    enable_deep_crawl: bool = True
    max_endpoints: int = 500
    max_subdomains: int = 100
    crawl_depth: int = 3
    timeout_seconds: float = 300.0
    tech_fingerprint_enabled: bool = True
    domain_classification_enabled: bool = True


class DiscoveryPhase(Phase):
    """
    Discovery phase for target enumeration.

    Consolidates:
    - Phase 0: Target Classification
    - Phase 0.5-0.6: Technology Intelligence
    - Phase 0.7: Smart Endpoint Discovery
    - Phase 0.75: Subdomain Enumeration
    - Phase 0.8: Domain Classification
    - Phase 0.9: Runtime Awareness
    """

    def __init__(self, config: Optional[DiscoveryConfig] = None):
        super().__init__("DiscoveryPhase")
        self.config = config or DiscoveryConfig()

        # Lazy-loaded components
        self._target_classifier: Optional["TargetClassifier"] = None
        self._tech_fingerprinter: Optional["TechFingerprinter"] = None
        self._smart_discovery: Optional["SmartDiscovery"] = None
        self._domain_classifier: Optional["DomainClassifier"] = None

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute discovery phase."""
        endpoints_discovered = 0
        subdomains_found = 0

        try:
            # Parse target URL
            parsed = urlparse(context.target_url)
            context.target_host = parsed.netloc or parsed.path

            logger.info(f"[Discovery] Starting discovery for {context.target_url}")

            # Sub-phase 0: Target Classification
            classification = await self._classify_target(context)
            context.phase_results["classification"] = classification

            # Sub-phase 0.5-0.6: Technology Fingerprinting
            if self.config.tech_fingerprint_enabled:
                tech_info = await self._fingerprint_technology(context)
                context.tech_stack = tech_info.get("stack", {})
                context.server = tech_info.get("server", "")
                context.framework = tech_info.get("framework", "")
                context.waf_detected = tech_info.get("waf_detected", False)
                context.waf_type = tech_info.get("waf_type", "")

            # Sub-phase 0.7: Smart Endpoint Discovery
            endpoints = await self._discover_endpoints(context)
            context.add_endpoints(endpoints)
            endpoints_discovered = len(endpoints)

            # Sub-phase 0.75: Subdomain Enumeration (if enabled)
            if self.config.enable_subdomain_enum:
                subdomains = await self._enumerate_subdomains(context)
                context.subdomains = subdomains
                subdomains_found = len(subdomains)

            # Sub-phase 0.8: Domain Classification
            if self.config.domain_classification_enabled:
                domain_info = await self._classify_domain(context)
                context.metadata["domain_classification"] = domain_info

            # Sub-phase 0.9: Runtime Awareness
            runtime_info = await self._analyze_runtime(context)
            context.metadata["runtime_profile"] = runtime_info

            logger.info(
                f"[Discovery] Complete: {endpoints_discovered} endpoints, "
                f"{subdomains_found} subdomains, "
                f"tech={context.framework or 'unknown'}"
            )

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.COMPLETED,
                endpoints_discovered=endpoints_discovered,
                data={
                    "endpoints": len(context.endpoints),
                    "subdomains": subdomains_found,
                    "tech_stack": context.tech_stack,
                    "waf_detected": context.waf_detected,
                    "classification": classification,
                },
            )

        except Exception as e:
            logger.error(f"[Discovery] Failed: {e}")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message=str(e),
                endpoints_discovered=endpoints_discovered,
            )

    async def _classify_target(self, context: ScanContext) -> dict[str, Any]:
        """Classify the target (training app, production, API, etc.)."""
        try:
            from scanning.target_classifier import TargetClassifier

            if not self._target_classifier:
                self._target_classifier = TargetClassifier()

            classification = await self._target_classifier.classify(context.target_url)

            return {
                "target_type": getattr(classification, "target_type", "unknown"),
                "is_training_app": getattr(classification, "is_training_app", False),
                "confidence": getattr(classification, "confidence", 0.0),
            }

        except ImportError:
            logger.debug("[Discovery] TargetClassifier not available")
            return {"target_type": "unknown", "is_training_app": False}
        except Exception as e:
            logger.debug(f"[Discovery] Target classification failed: {e}")
            return {"target_type": "unknown", "is_training_app": False}

    async def _fingerprint_technology(self, context: ScanContext) -> dict[str, Any]:
        """Fingerprint technology stack."""
        try:
            from phantom.tech_fingerprinter import TechFingerprinter

            if not self._tech_fingerprinter:
                self._tech_fingerprinter = TechFingerprinter()

            result = await self._tech_fingerprinter.fingerprint(context.target_url)

            return {
                "stack": getattr(result, "technologies", {}),
                "server": getattr(result, "server", ""),
                "framework": getattr(result, "framework", ""),
                "waf_detected": getattr(result, "waf_detected", False),
                "waf_type": getattr(result, "waf_type", ""),
            }

        except ImportError:
            logger.debug("[Discovery] TechFingerprinter not available")
            return {}
        except Exception as e:
            logger.debug(f"[Discovery] Tech fingerprinting failed: {e}")
            return {}

    async def _discover_endpoints(self, context: ScanContext) -> list[str]:
        """Discover endpoints using smart discovery."""
        try:
            from reconnaissance.smart_discovery import SmartDiscovery

            if not self._smart_discovery:
                self._smart_discovery = SmartDiscovery()

            endpoints = await self._smart_discovery.discover(
                context.target_url,
                max_endpoints=self.config.max_endpoints,
                depth=self.config.crawl_depth,
            )

            return list(endpoints) if endpoints else []

        except ImportError:
            logger.debug("[Discovery] SmartDiscovery not available")
            return self._basic_endpoint_discovery(context)
        except Exception as e:
            logger.debug(f"[Discovery] Endpoint discovery failed: {e}")
            return self._basic_endpoint_discovery(context)

    def _basic_endpoint_discovery(self, context: ScanContext) -> list[str]:
        """Basic endpoint discovery fallback."""
        # Return common endpoints as fallback
        common_endpoints = [
            "/",
            "/api",
            "/api/v1",
            "/login",
            "/register",
            "/admin",
            "/user",
            "/health",
            "/robots.txt",
            "/sitemap.xml",
        ]
        return [f"{context.target_url.rstrip('/')}{ep}" for ep in common_endpoints]

    async def _enumerate_subdomains(self, context: ScanContext) -> list[str]:
        """Enumerate subdomains."""
        try:
            from reconnaissance.subdomain_enum import SubdomainEnumerator

            enumerator = SubdomainEnumerator()
            subdomains = await enumerator.enumerate(
                context.target_host,
                max_results=self.config.max_subdomains,
            )

            return list(subdomains) if subdomains else []

        except ImportError:
            logger.debug("[Discovery] SubdomainEnumerator not available")
            return []
        except Exception as e:
            logger.debug(f"[Discovery] Subdomain enumeration failed: {e}")
            return []

    async def _classify_domain(self, context: ScanContext) -> dict[str, Any]:
        """Classify domain characteristics."""
        try:
            from scanning.domain_classifier import DomainClassifier

            if not self._domain_classifier:
                self._domain_classifier = DomainClassifier()

            result = self._domain_classifier.classify(context.target_url)

            return {
                "category": getattr(result, "category", "unknown"),
                "industry": getattr(result, "industry", "unknown"),
            }

        except ImportError:
            logger.debug("[Discovery] DomainClassifier not available")
            return {}
        except Exception as e:
            logger.debug(f"[Discovery] Domain classification failed: {e}")
            return {}

    async def _analyze_runtime(self, context: ScanContext) -> dict[str, Any]:
        """Analyze runtime characteristics."""
        try:
            from scanning.runtime_awareness import RuntimeAwareness

            awareness = RuntimeAwareness()
            profile = await awareness.profile(context.target_url)

            return {
                "response_time_ms": getattr(profile, "avg_response_time", 0),
                "server_behavior": getattr(profile, "behavior", "standard"),
            }

        except ImportError:
            logger.debug("[Discovery] RuntimeAwareness not available")
            return {}
        except Exception as e:
            logger.debug(f"[Discovery] Runtime analysis failed: {e}")
            return {}
