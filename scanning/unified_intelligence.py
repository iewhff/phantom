"""
Unified Intelligence Layer v1.0
===============================

Combines ALL detection systems into a single, coordinated intelligence layer:
1. TargetClassifier - Target type classification (SPA, Backend, API, BaaS, etc.)
2. TechIntelligence - Technology fingerprinting with CVE correlation
3. IntelligentScanner - Endpoint discovery and parameter analysis

Benefits:
- Single HTTP fetch for all systems (eliminates redundant requests)
- Cross-system signal correlation for higher accuracy
- Unified module recommendations
- Comprehensive intelligence reports

Usage:
    intel = UnifiedIntelligence(settings)
    result = await intel.analyze(target)

    # Access coordinated results
    print(f"Target Type: {result.classification.target_type}")
    print(f"Technologies: {[t.name for t in result.technologies]}")
    print(f"Endpoints: {result.endpoints_discovered}")
    print(f"Recommended Modules: {result.recommended_modules}")
"""

from __future__ import annotations

import asyncio
import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

import httpx

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = logging.getLogger(__name__)


@dataclass
class UnifiedIntelligenceResult:
    """Complete unified intelligence result."""
    target: str

    # Classification result
    classification: Optional[Any] = None  # TargetClassification

    # Technology analysis
    technologies: List[Any] = field(default_factory=list)  # DetectedTechnology
    tech_stack: Dict[str, List[str]] = field(default_factory=dict)

    # Endpoint discovery
    endpoints_discovered: List[str] = field(default_factory=list)
    parameters_analyzed: int = 0
    endpoints_with_params: List[str] = field(default_factory=list)

    # Risk assessment
    eol_technologies: List[str] = field(default_factory=list)
    vulnerable_technologies: List[Tuple[str, str, List[str]]] = field(default_factory=list)

    # Coordinated module recommendations
    recommended_modules: List[str] = field(default_factory=list)
    skip_modules: List[str] = field(default_factory=list)
    skip_reasons: Dict[str, str] = field(default_factory=dict)

    # Scan strategy
    early_abort: bool = False
    early_abort_reason: str = ""
    target_accessible: bool = True
    http_status: int = 200

    # Raw signals (for debugging)
    signals: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    analysis_time: float = 0.0
    confidence_overall: float = 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for reporting."""
        return {
            "target": self.target,
            "classification": self.classification.to_dict() if self.classification else None,
            "technologies": [
                {"name": t.name, "version": t.version, "confidence": t.confidence}
                for t in self.technologies
            ],
            "tech_stack": self.tech_stack,
            "endpoints_discovered": len(self.endpoints_discovered),
            "parameters_analyzed": self.parameters_analyzed,
            "eol_technologies": self.eol_technologies,
            "vulnerable_technologies": [
                {"name": n, "version": v, "cves": c}
                for n, v, c in self.vulnerable_technologies
            ],
            "recommended_modules": self.recommended_modules,
            "skip_modules": self.skip_modules,
            "early_abort": self.early_abort,
            "early_abort_reason": self.early_abort_reason,
            "target_accessible": self.target_accessible,
            "http_status": self.http_status,
            "analysis_time": self.analysis_time,
            "confidence_overall": self.confidence_overall,
        }


class UnifiedIntelligence:
    """
    Unified Intelligence Layer - Coordinates ALL detection systems.

    This is the single point of entry for target intelligence. It:
    1. Fetches target data ONCE and shares it across all systems
    2. Runs all detection systems in parallel
    3. Correlates signals across systems for higher accuracy
    4. Generates coordinated module recommendations
    5. Determines scan strategy (early abort, module filtering, etc.)
    """

    VERSION = "1.0.0"

    def __init__(self, settings: Optional["Settings"] = None):
        self.settings = settings
        self._classifier = None
        self._tech_intel = None
        self._endpoint_discovery = None

        # Initialize components lazily
        logger.info(f"UnifiedIntelligence v{self.VERSION} initialized")

    def _get_classifier(self):
        """Lazy load target classifier."""
        if self._classifier is None:
            try:
                from scanning.target_classifier import TargetClassifier
                self._classifier = TargetClassifier(self.settings)
            except ImportError as e:
                logger.warning(f"TargetClassifier not available: {e}")
        return self._classifier

    def _get_tech_intel(self):
        """Lazy load tech intelligence."""
        if self._tech_intel is None:
            try:
                from scanning.tech_intelligence import TechIntelligence
                self._tech_intel = TechIntelligence(self.settings)
            except ImportError as e:
                logger.warning(f"TechIntelligence not available: {e}")
        return self._tech_intel

    async def analyze(
        self,
        target: str,
        deep_scan: bool = True,
        include_endpoints: bool = True,
    ) -> UnifiedIntelligenceResult:
        """
        Perform comprehensive unified intelligence analysis.

        Args:
            target: Target URL
            deep_scan: Whether to fetch JS files and additional resources
            include_endpoints: Whether to discover endpoints

        Returns:
            UnifiedIntelligenceResult with all intelligence data
        """
        start_time = asyncio.get_event_loop().time()
        result = UnifiedIntelligenceResult(target=target)

        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"

        # Phase 1: Single HTTP fetch for all systems
        logger.info(f"Phase 1: Fetching target data from {target}")
        fetch_result = await self._fetch_target_data(target, deep_scan)

        if not fetch_result["success"]:
            logger.warning(f"Failed to fetch target: {fetch_result.get('error')}")
            result.target_accessible = False
            result.early_abort = True
            result.early_abort_reason = fetch_result.get("error", "Connection failed")
            result.analysis_time = asyncio.get_event_loop().time() - start_time
            return result

        # Store raw signals
        result.http_status = fetch_result["status_code"]
        result.signals = {
            "http_status": fetch_result["status_code"],
            "content_length": len(fetch_result["html"]),
            "response_time": fetch_result["response_time"],
        }

        # Check for blocking (403, 503)
        if fetch_result["status_code"] in (401, 403, 503):
            result.target_accessible = False
            logger.warning(f"Target returned HTTP {fetch_result['status_code']}")

        # Phase 2: Run all detection systems in parallel
        logger.info("Phase 2: Running detection systems in parallel")

        tasks = []

        # Target classification
        classifier = self._get_classifier()
        if classifier:
            tasks.append(("classification", self._run_classification(
                classifier, target, fetch_result
            )))

        # Technology intelligence
        tech_intel = self._get_tech_intel()
        if tech_intel:
            tasks.append(("tech_intel", self._run_tech_intel(
                tech_intel, target, fetch_result, deep_scan
            )))

        # Endpoint discovery (if enabled)
        if include_endpoints:
            tasks.append(("endpoints", self._discover_endpoints(
                target, fetch_result
            )))

        # Run all tasks in parallel
        if tasks:
            task_names, task_coros = zip(*tasks)
            task_results = await asyncio.gather(*task_coros, return_exceptions=True)

            for name, task_result in zip(task_names, task_results):
                if isinstance(task_result, Exception):
                    logger.warning(f"{name} failed: {task_result}")
                    continue

                if name == "classification":
                    result.classification = task_result
                    result.signals.update(task_result.signals if task_result else {})
                elif name == "tech_intel":
                    result.technologies = task_result.technologies if task_result else []
                    result.tech_stack = task_result.tech_stack if task_result else {}
                    result.eol_technologies = task_result.eol_technologies if task_result else []
                    result.vulnerable_technologies = task_result.vulnerable_technologies if task_result else []
                elif name == "endpoints":
                    result.endpoints_discovered = task_result.get("endpoints", [])
                    result.parameters_analyzed = task_result.get("params_count", 0)
                    result.endpoints_with_params = task_result.get("endpoints_with_params", [])

        # Phase 3: Cross-correlate signals and generate recommendations
        logger.info("Phase 3: Correlating signals and generating recommendations")
        result = self._correlate_and_recommend(result)

        # Phase 4: Determine scan strategy
        result = self._determine_scan_strategy(result)

        # Calculate overall confidence
        confidences = []
        if result.classification:
            confidences.append(result.classification.confidence)
        if result.technologies:
            confidences.extend([t.confidence for t in result.technologies])

        if confidences:
            result.confidence_overall = sum(confidences) / len(confidences)

        result.analysis_time = asyncio.get_event_loop().time() - start_time

        logger.info(
            f"Unified analysis complete in {result.analysis_time:.2f}s: "
            f"{len(result.technologies)} technologies, "
            f"{len(result.endpoints_discovered)} endpoints, "
            f"{len(result.recommended_modules)} recommended modules"
        )

        return result

    async def _fetch_target_data(
        self,
        target: str,
        deep_scan: bool = True
    ) -> Dict[str, Any]:
        """
        Fetch all target data in a single coordinated request.
        This data is shared across all detection systems.
        """
        result = {
            "success": False,
            "html": "",
            "headers": {},
            "cookies": {},
            "js_content": "",
            "status_code": 0,
            "response_time": 0.0,
            "error": None,
        }

        try:
            start = asyncio.get_event_loop().time()

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(20.0),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; PetNTester/2.0)"}
            ) as client:
                response = await client.get(target)

                result["html"] = response.text
                result["headers"] = dict(response.headers)
                result["cookies"] = {k: v for k, v in response.cookies.items()}
                result["status_code"] = response.status_code
                result["response_time"] = asyncio.get_event_loop().time() - start
                result["success"] = True

                # Fetch JS files if deep scan enabled
                if deep_scan:
                    js_content = await self._fetch_js_files(client, target, result["html"])
                    result["js_content"] = js_content

        except httpx.ConnectTimeout:
            result["error"] = "Connection timeout"
        except httpx.ConnectError:
            result["error"] = "Connection refused"
        except Exception as e:
            result["error"] = str(e)

        return result

    async def _fetch_js_files(
        self,
        client: httpx.AsyncClient,
        target: str,
        html: str
    ) -> str:
        """Fetch JavaScript files referenced in HTML."""
        js_content = []

        # Find JS file references
        js_patterns = [
            r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
            r'src=["\']([^"\']+\.js)["\']',
        ]

        js_urls = set()
        for pattern in js_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)
                if not url.startswith(("http://", "https://")):
                    from urllib.parse import urljoin
                    url = urljoin(target, url)
                js_urls.add(url)

        # Fetch JS files (limit to first 5 to avoid timeouts)
        for url in list(js_urls)[:5]:
            try:
                response = await client.get(url, timeout=5.0)
                if response.status_code == 200:
                    js_content.append(response.text[:50000])  # Limit size
            except Exception:
                pass

        return "\n".join(js_content)

    async def _run_classification(
        self,
        classifier: Any,
        target: str,
        fetch_result: Dict[str, Any]
    ) -> Any:
        """Run target classification using pre-fetched data."""
        # The classifier currently does its own fetch, but we pass signals
        # Future optimization: refactor classifier to accept pre-fetched data
        try:
            return await classifier.classify(target)
        except Exception as e:
            logger.warning(f"Classification failed: {e}")
            return None

    async def _run_tech_intel(
        self,
        tech_intel: Any,
        target: str,
        fetch_result: Dict[str, Any],
        deep_scan: bool
    ) -> Any:
        """Run technology intelligence using pre-fetched data."""
        try:
            return await tech_intel.analyze(
                target=target,
                html_content=fetch_result["html"],
                headers=fetch_result["headers"],
                cookies=fetch_result["cookies"],
                js_content=fetch_result["js_content"],
                deep_scan=False,  # We already fetched JS
            )
        except Exception as e:
            logger.warning(f"Tech intelligence failed: {e}")
            return None

    async def _discover_endpoints(
        self,
        target: str,
        fetch_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Discover endpoints from HTML content."""
        endpoints = set()
        endpoints_with_params = []

        html = fetch_result["html"]

        # Find links
        link_patterns = [
            r'href=["\']([^"\'#]+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+\.(?:php|asp|jsp|py|rb|do|action))["\']',
        ]

        from urllib.parse import urljoin, urlparse
        base_domain = urlparse(target).netloc

        for pattern in link_patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)

                # Skip javascript: and mailto: links
                if url.startswith(("javascript:", "mailto:", "#", "data:")):
                    continue

                # Make absolute URL
                if not url.startswith(("http://", "https://")):
                    url = urljoin(target, url)

                # Only include same-domain URLs
                if urlparse(url).netloc == base_domain:
                    endpoints.add(url)
                    if "?" in url:
                        endpoints_with_params.append(url)

        # Count unique parameters
        params = set()
        for ep in endpoints_with_params:
            query = urlparse(ep).query
            for param in query.split("&"):
                if "=" in param:
                    params.add(param.split("=")[0])

        return {
            "endpoints": list(endpoints),
            "endpoints_with_params": endpoints_with_params,
            "params_count": len(params),
        }

    def _correlate_and_recommend(
        self,
        result: UnifiedIntelligenceResult
    ) -> UnifiedIntelligenceResult:
        """
        Correlate signals from all systems and generate unified recommendations.

        This is where the magic happens - we combine insights from:
        - Classification (target type)
        - Technology fingerprinting (frameworks, languages)
        - Endpoint discovery (attack surface)
        """
        recommended = set()
        skip = set()
        skip_reasons = {}

        # Start with classification recommendations
        if result.classification:
            recommended.update(result.classification.recommended_modules)
            for mod in result.classification.skip_modules:
                skip.add(mod)
                if mod in result.classification.skip_reasons:
                    skip_reasons[mod] = result.classification.skip_reasons[mod]

        # Layer in tech intelligence recommendations
        for tech in result.technologies:
            if hasattr(tech, 'fingerprint') and tech.fingerprint:
                fp = tech.fingerprint
                for mod in fp.recommended_modules:
                    recommended.add(mod)
                    # If previously skipped, re-enable based on tech detection
                    if mod in skip:
                        skip.remove(mod)
                        if mod in skip_reasons:
                            del skip_reasons[mod]

                for mod in fp.skip_modules:
                    if mod not in recommended:  # Don't skip if another tech recommended it
                        skip.add(mod)
                        if mod in fp.skip_reasons:
                            skip_reasons[mod] = fp.skip_reasons[mod]

        # Adjust based on endpoint discovery
        has_endpoints = len(result.endpoints_discovered) > 0
        has_params = result.parameters_analyzed > 0
        has_endpoints_with_params = len(result.endpoints_with_params) > 0

        # DEF-6 FIX: DON'T skip injection modules just because crawler didn't find params!
        # This was causing massive false negatives because:
        # 1. SPAs hide parameters in JavaScript (not visible to crawlers)
        # 2. Modules can discover their own parameters during testing
        # 3. Path-based injection (LFI, SSRF) doesn't need query params
        # 4. Headers, cookies, POST bodies are injectable without visible URL params
        #
        # Instead of SKIPPING, we just LOG a warning. Modules will run anyway.
        # NEVER_SKIP_MODULES in full_scanner.py provides additional protection.
        if not has_params and not has_endpoints_with_params:
            logger.warning(
                "[Intelligence] No parameters discovered in crawl - "
                "injection modules will still run (they discover their own params)"
            )

        # Always include infrastructure modules
        infrastructure_modules = {'headers', 'ssl', 'cors', 'secrets'}
        recommended.update(infrastructure_modules)
        for mod in infrastructure_modules:
            if mod in skip:
                skip.remove(mod)

        # Remove skipped from recommended
        recommended = recommended - skip

        result.recommended_modules = sorted(recommended)
        result.skip_modules = sorted(skip)
        result.skip_reasons = skip_reasons

        return result

    def _determine_scan_strategy(
        self,
        result: UnifiedIntelligenceResult
    ) -> UnifiedIntelligenceResult:
        """
        Determine scan strategy based on all intelligence.

        Decides:
        - Whether to abort early (inaccessible target)
        - Which module categories to prioritize
        - Concurrency settings based on target type
        """
        # Check for early abort conditions
        if not result.target_accessible:
            if result.http_status in (401, 403):
                # Target is behind auth/WAF
                result.early_abort = True
                result.early_abort_reason = f"Target returned HTTP {result.http_status} - behind WAF or auth"
            elif result.http_status == 503:
                result.early_abort = True
                result.early_abort_reason = "Target unavailable (503)"

        # Check for minimal attack surface
        if (
            len(result.endpoints_discovered) <= 1 and
            result.parameters_analyzed == 0 and
            len(result.endpoints_with_params) == 0 and
            not result.technologies
        ):
            # Very minimal surface - may want to warn
            result.signals["minimal_surface"] = True
            logger.warning("Minimal attack surface detected - scan may have limited findings")

        return result

    def get_scan_profile(
        self,
        result: UnifiedIntelligenceResult
    ) -> Dict[str, Any]:
        """
        Generate a scan profile based on unified intelligence.

        Returns:
            Profile with module list, concurrency, timeouts, etc.
        """
        profile = {
            "modules": result.recommended_modules,
            "skip_modules": result.skip_modules,
            "concurrent": 5,
            "timeout_heavy": 900,
            "timeout_normal": 600,
            "priority_high": [],
            "priority_low": [],
        }

        # Adjust based on target type
        if result.classification:
            target_type = result.classification.target_type.value

            if target_type == "baas_supabase":
                profile["priority_high"] = ["rls_bypass", "supabase", "jwt"]
                profile["concurrent"] = 3  # Respect BaaS rate limits
            elif target_type == "baas_firebase":
                profile["priority_high"] = ["firebase", "firebase_rules", "jwt"]
                profile["concurrent"] = 3
            elif target_type == "spa":
                profile["priority_high"] = ["dom_xss", "xss", "secrets", "cors"]
            elif target_type == "api_first":
                profile["priority_high"] = ["api", "graphql", "jwt", "idor"]
            elif target_type == "backend_classic":
                profile["priority_high"] = ["sqli", "xss", "auth", "csrf"]

        # Adjust based on vulnerable technologies
        if result.vulnerable_technologies:
            profile["priority_high"].extend([
                t[0].lower() for t in result.vulnerable_technologies
            ])

        return profile


# Export convenience function
async def analyze_target(
    target: str,
    settings: Any = None,
    deep_scan: bool = True,
) -> UnifiedIntelligenceResult:
    """
    Convenience function for unified target analysis.

    Usage:
        result = await analyze_target("https://example.com")
        print(f"Type: {result.classification.target_type if result.classification else 'Unknown'}")
        print(f"Technologies: {[t.name for t in result.technologies]}")
        print(f"Recommended: {result.recommended_modules}")
    """
    intel = UnifiedIntelligence(settings)
    return await intel.analyze(target, deep_scan=deep_scan)


__all__ = [
    "UnifiedIntelligence",
    "UnifiedIntelligenceResult",
    "analyze_target",
]
