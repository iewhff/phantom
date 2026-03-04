"""
Asset Data Builder - Builds asset_data for Scanner Modules.

Handles extraction and aggregation of:
- Endpoints (discovered, tool-discovered, training app, EndpointMap)
- Parameters (from intelligent context, tools, endpoint map)
- Technologies (from classification and fingerprinting)
- Context (auth, forms, WAF detection, etc.)

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, Set
from urllib.parse import urlparse

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════════════


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


class ClassificationProtocol(Protocol):
    """Protocol for target classification."""

    detected_technologies: list[str]


class TechAnalysisProtocol(Protocol):
    """Protocol for technology analysis."""

    technologies: list


class EndpointMapProtocol(Protocol):
    """Protocol for endpoint map."""

    def __len__(self) -> int:
        ...

    def __iter__(self):
        ...

    def get_host(self) -> Optional[str]:
        ...

    def get_for_scanner(self, scanner_name: str) -> list:
        ...


class SharedFindingsStoreProtocol(Protocol):
    """Protocol for shared findings store."""

    async def add_finding(self, finding: dict) -> None:
        ...


class AuthContextProtocol(Protocol):
    """Protocol for authentication context."""

    @property
    def has_auth(self) -> bool:
        ...


class APIDiscoveryProtocol(Protocol):
    """Protocol for API discovery."""

    def get_injectable_endpoints_for_scanner(self) -> list:
        ...

    def get_auth_bypass_candidates_for_scanner(self) -> list:
        ...


class StackProfileProtocol(Protocol):
    """Protocol for stack profile."""

    def to_dict(self) -> dict:
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class AssetBuilderConfig:
    """Configuration for asset builder."""

    # Logging
    log_debug: bool = True
    log_info: bool = True
    log_warnings: bool = True

    # Endpoint behavior
    prioritize_training_app: bool = True
    use_generic_fallback: bool = True

    # Modules that need endpoint warnings
    injection_modules: Set[str] = field(
        default_factory=lambda: {
            "sqli",
            "xss",
            "cmdi",
            "lfi",
            "ssti",
            "nosql",
            "xxe",
            "ldap_xpath",
            "ssrf",
        }
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Asset Data
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class AssetData:
    """Asset data for scanner modules."""

    # Core discovery
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)

    # Technology
    technologies: list[str] = field(default_factory=list)
    fingerprint_result: Optional[Any] = None
    waf_detection: Optional[dict] = None

    # Training app
    is_training_app: bool = False
    training_app_endpoints: list[str] = field(default_factory=list)

    # Tool discoveries
    tool_discovered_params: Optional[dict] = None
    tool_findings: Optional[list] = None
    subdomains: list[str] = field(default_factory=list)

    # EndpointMap data
    api_endpoints: list[str] = field(default_factory=list)
    endpoint_params: dict[str, list[str]] = field(default_factory=dict)
    vuln_type_hints: dict[str, list[str]] = field(default_factory=dict)

    # Context
    shared_findings_store: Optional[Any] = None
    auth_context: Optional[Any] = None
    user_personas: list[Any] = field(default_factory=list)
    domain_classification: Optional[Any] = None

    # API discovery
    injectable_endpoints: list[Any] = field(default_factory=list)
    auth_bypass_candidates: list[Any] = field(default_factory=list)
    security_schemes: Optional[Any] = None

    # Analysis
    semantic_analyzer: Optional[Any] = None
    stack_profile: Optional[dict] = None
    runtime_engine: Optional[Any] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for module consumption."""
        return {
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "forms": self.forms,
            "technologies": self.technologies,
            "fingerprint_result": self.fingerprint_result,
            "waf_detection": self.waf_detection,
            "is_training_app": self.is_training_app,
            "training_app_endpoints": self.training_app_endpoints,
            "tool_discovered_params": self.tool_discovered_params,
            "tool_findings": self.tool_findings,
            "subdomains": self.subdomains,
            "api_endpoints": self.api_endpoints,
            "endpoint_params": self.endpoint_params,
            "vuln_type_hints": self.vuln_type_hints,
            "shared_findings_store": self.shared_findings_store,
            "auth_context": self.auth_context,
            "user_personas": self.user_personas,
            "domain_classification": self.domain_classification,
            "injectable_endpoints": self.injectable_endpoints,
            "auth_bypass_candidates": self.auth_bypass_candidates,
            "security_schemes": self.security_schemes,
            "semantic_analyzer": self.semantic_analyzer,
            "stack_profile": self.stack_profile,
            "runtime_engine": self.runtime_engine,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Parameter Extraction
# ═══════════════════════════════════════════════════════════════════════════════


def extract_parameters_from_analysis(parameter_analysis: dict) -> Set[str]:
    """
    Extract parameter names from intelligent context analysis.

    Handles multiple formats:
    - Objects with .parameters attribute containing objects with .name
    - Objects with .param_names attribute
    - Dicts with 'parameters' key containing dicts with 'name'
    - Dicts with 'param_names' key

    Args:
        parameter_analysis: Dict mapping URLs to analysis results

    Returns:
        Set of unique parameter names
    """
    all_param_names: Set[str] = set()

    for url, analysis in parameter_analysis.items():
        # Extract param names from analysis object
        if hasattr(analysis, "parameters"):
            for p in analysis.parameters:
                if hasattr(p, "name"):
                    all_param_names.add(p.name)
                elif isinstance(p, str):
                    all_param_names.add(p)
        elif hasattr(analysis, "param_names"):
            all_param_names.update(analysis.param_names)
        elif isinstance(analysis, dict):
            if "parameters" in analysis:
                for p in analysis["parameters"]:
                    if isinstance(p, dict) and "name" in p:
                        all_param_names.add(p["name"])
                    elif isinstance(p, str):
                        all_param_names.add(p)
            if "param_names" in analysis:
                all_param_names.update(analysis["param_names"])

    return all_param_names


# ═══════════════════════════════════════════════════════════════════════════════
# Asset Data Builder
# ═══════════════════════════════════════════════════════════════════════════════


class AssetDataBuilder:
    """
    Builds asset_data dictionary for scanner modules.

    Aggregates data from multiple sources:
    - Intelligent context (endpoints, parameters)
    - Technology analysis
    - Tool discoveries
    - EndpointMap
    - Auth and user contexts
    - API discovery results
    """

    def __init__(
        self,
        target: str,
        config: Optional[AssetBuilderConfig] = None,
    ):
        """
        Initialize asset builder.

        Args:
            target: Target URL
            config: Builder configuration
        """
        self.target = target
        self.config = config or AssetBuilderConfig()

        # Parse target URL
        parsed = urlparse(target)
        self.scheme = parsed.scheme or "https"
        self.host = parsed.netloc

        # State tracking
        self._warned_no_endpoints = False

        # Data sources (set via register methods)
        self._intelligent_context: Optional[IntelligentContextProtocol] = None
        self._classification: Optional[ClassificationProtocol] = None
        self._tech_analysis: Optional[TechAnalysisProtocol] = None
        self._discovered_forms: list[dict] = []
        self._fingerprint_result: Optional[Any] = None
        self._waf_detection_result: Optional[dict] = None
        self._tool_discovered_endpoints: list[str] = []
        self._tool_discovered_params: Optional[dict] = None
        self._linux_tool_findings: Optional[list] = None
        self._discovered_subdomains: Set[str] = set()
        self._priority_endpoints: list[str] = []
        self._shared_findings_store: Optional[Any] = None
        self._auth_context: Optional[AuthContextProtocol] = None
        self._user_personas: list[Any] = []
        self._domain_classification: Optional[Any] = None
        self._api_discovery: Optional[APIDiscoveryProtocol] = None
        self._security_schemes: Optional[Any] = None
        self._semantic_analyzer: Optional[Any] = None
        self._stack_profile: Optional[StackProfileProtocol] = None
        self._runtime_engine: Optional[Any] = None
        self._generic_fallback_func: Optional[Any] = None

    # ═══════════════════════════════════════════════════════════════════════════
    # Registration Methods
    # ═══════════════════════════════════════════════════════════════════════════

    def register_intelligent_context(
        self, context: IntelligentContextProtocol
    ) -> "AssetDataBuilder":
        """Register intelligent scanning context."""
        self._intelligent_context = context
        return self

    def register_classification(
        self, classification: ClassificationProtocol
    ) -> "AssetDataBuilder":
        """Register target classification."""
        self._classification = classification
        return self

    def register_tech_analysis(
        self, tech_analysis: TechAnalysisProtocol
    ) -> "AssetDataBuilder":
        """Register technology analysis."""
        self._tech_analysis = tech_analysis
        return self

    def register_forms(self, forms: list[dict]) -> "AssetDataBuilder":
        """Register discovered forms."""
        self._discovered_forms = forms or []
        return self

    def register_fingerprint(self, fingerprint: Any) -> "AssetDataBuilder":
        """Register fingerprint result."""
        self._fingerprint_result = fingerprint
        return self

    def register_waf_detection(self, waf_result: dict) -> "AssetDataBuilder":
        """Register WAF detection result."""
        self._waf_detection_result = waf_result
        return self

    def register_tool_discoveries(
        self,
        endpoints: Optional[list[str]] = None,
        params: Optional[dict] = None,
        findings: Optional[list] = None,
    ) -> "AssetDataBuilder":
        """Register tool-discovered data."""
        if endpoints:
            self._tool_discovered_endpoints = endpoints
        if params:
            self._tool_discovered_params = params
        if findings:
            self._linux_tool_findings = findings
        return self

    def register_subdomains(self, subdomains: Set[str]) -> "AssetDataBuilder":
        """Register discovered subdomains."""
        self._discovered_subdomains = subdomains
        return self

    def register_priority_endpoints(self, endpoints: list[str]) -> "AssetDataBuilder":
        """Register priority endpoints to test first (common patterns, fallbacks)."""
        self._priority_endpoints = endpoints or []
        return self

    # Alias for backwards compatibility
    def register_training_app(self, endpoints: list[str]) -> "AssetDataBuilder":
        """Deprecated: use register_priority_endpoints instead."""
        return self.register_priority_endpoints(endpoints)

    def register_shared_store(self, store: Any) -> "AssetDataBuilder":
        """Register shared findings store."""
        self._shared_findings_store = store
        return self

    def register_auth_context(
        self, auth_context: AuthContextProtocol
    ) -> "AssetDataBuilder":
        """Register authentication context."""
        self._auth_context = auth_context
        return self

    def register_user_personas(self, personas: list[Any]) -> "AssetDataBuilder":
        """Register user personas."""
        self._user_personas = personas or []
        return self

    def register_domain_classification(
        self, classification: Any
    ) -> "AssetDataBuilder":
        """Register domain classification."""
        self._domain_classification = classification
        return self

    def register_api_discovery(
        self, api_discovery: APIDiscoveryProtocol
    ) -> "AssetDataBuilder":
        """Register API discovery."""
        self._api_discovery = api_discovery
        return self

    def register_security_schemes(self, schemes: Any) -> "AssetDataBuilder":
        """Register security schemes."""
        self._security_schemes = schemes
        return self

    def register_semantic_analyzer(self, analyzer: Any) -> "AssetDataBuilder":
        """Register semantic analyzer."""
        self._semantic_analyzer = analyzer
        return self

    def register_stack_profile(
        self, profile: StackProfileProtocol
    ) -> "AssetDataBuilder":
        """Register stack profile."""
        self._stack_profile = profile
        return self

    def register_runtime_engine(self, engine: Any) -> "AssetDataBuilder":
        """Register runtime engine."""
        self._runtime_engine = engine
        return self

    def register_generic_fallback(self, func: Any) -> "AssetDataBuilder":
        """Register generic fallback endpoint generator."""
        self._generic_fallback_func = func
        return self

    # ═══════════════════════════════════════════════════════════════════════════
    # Building Methods
    # ═══════════════════════════════════════════════════════════════════════════

    def _collect_technologies(self) -> list[str]:
        """Collect detected technologies from all sources."""
        technologies: list[str] = []

        if self._classification and self._classification.detected_technologies:
            technologies.extend(self._classification.detected_technologies)

        if self._tech_analysis and self._tech_analysis.technologies:
            technologies.extend([t.name for t in self._tech_analysis.technologies])

        # Deduplicate
        return list(set(technologies))

    def _build_base_asset_data(
        self, module_name: str
    ) -> tuple[list[str], list[str]]:
        """
        Build base endpoints and parameters from intelligent context.

        Returns:
            Tuple of (endpoints, parameters)
        """
        technologies = self._collect_technologies()
        forms = self._discovered_forms or []

        if (
            self._intelligent_context
            and self._intelligent_context.endpoints_discovered
        ):
            # Extract parameters from analysis
            all_param_names = set()
            if self._intelligent_context.parameter_analysis:
                all_param_names = extract_parameters_from_analysis(
                    self._intelligent_context.parameter_analysis
                )

            endpoints = self._intelligent_context.endpoints_discovered or []
            parameters = list(all_param_names)

            if all_param_names and self.config.log_info:
                logger.info(
                    f"[MODULE] Extracted {len(all_param_names)} unique params "
                    f"for {module_name}: {list(all_param_names)[:5]}..."
                )
            if self.config.log_debug:
                logger.debug(
                    f"Using {len(endpoints)} discovered endpoints for module {module_name}"
                )

            return endpoints, parameters

        else:
            # Fallback: use target as endpoint
            if not self._warned_no_endpoints and self.config.log_warnings:
                logger.warning(
                    f"[COVERAGE-GAP] No endpoints discovered for target — "
                    f"modules will test BASE URL ONLY. This significantly reduces coverage!"
                )
                self._warned_no_endpoints = True

            endpoints = [self.target]
            parameters = []

            # Apply generic fallback if configured
            if self.config.use_generic_fallback and self._generic_fallback_func:
                generic = self._generic_fallback_func(self.target)
                if generic:
                    endpoints.extend(generic)
                    if self.config.log_info:
                        logger.info(
                            f"[FALLBACK] Added {len(generic)} generic endpoint patterns "
                            f"for broader coverage"
                        )

            if self.config.log_debug:
                logger.debug(
                    f"Using target URL as single endpoint for module {module_name}"
                )

            return endpoints, parameters

    def _merge_tool_endpoints(
        self, endpoints: list[str], module_name: str
    ) -> list[str]:
        """Merge tool-discovered endpoints."""
        if not self._tool_discovered_endpoints:
            return endpoints

        existing = set(endpoints)
        new_endpoints = [
            e for e in self._tool_discovered_endpoints if e not in existing
        ]
        endpoints.extend(new_endpoints)

        if new_endpoints and self.config.log_debug:
            logger.debug(
                f"Added {len(new_endpoints)} tool-discovered endpoints "
                f"for module {module_name}"
            )

        return endpoints

    def _merge_priority_endpoints(
        self, endpoints: list[str], module_name: str
    ) -> tuple[list[str], bool, list[str]]:
        """
        Merge priority endpoints (common patterns, fallbacks) with discovered endpoints.

        Returns:
            Tuple of (updated_endpoints, has_priority, priority_endpoints)
        """
        if not self._priority_endpoints:
            return endpoints, False, []

        existing = set(endpoints)
        new_endpoints = [
            e for e in self._priority_endpoints if e not in existing
        ]

        if self.config.prioritize_training_app:
            # Insert at beginning for priority testing
            for i, ep in enumerate(new_endpoints):
                endpoints.insert(i, ep)
        else:
            endpoints.extend(new_endpoints)

        if new_endpoints and self.config.log_info:
            logger.info(
                f"[MODULE] Prioritized {len(new_endpoints)} training app endpoints "
                f"for {module_name} (inserted at index 0)"
            )
            sample = endpoints[:3]
            logger.info(f"[MODULE] First 3 endpoints for {module_name}: {sample}")

        return endpoints, True, new_endpoints

    def _merge_endpoint_map(
        self, endpoints: list[str], module_name: str
    ) -> tuple[list[str], list[str], dict, dict]:
        """
        Merge EndpointMap data.

        Returns:
            Tuple of (endpoints, api_endpoints, endpoint_params, vuln_hints)
        """
        api_endpoints = []
        endpoint_params = {}
        vuln_hints = {}

        try:
            from utils.endpoint_map import EndpointMap

            endpoint_map = EndpointMap.get_instance()
            if not endpoint_map or len(endpoint_map) == 0:
                return endpoints, api_endpoints, endpoint_params, vuln_hints

            host = endpoint_map.get_host() or self.host

            existing = set(endpoints)
            for ep in endpoint_map:
                full_url = ep.get_full_url(host, self.scheme)
                if full_url and full_url not in existing:
                    endpoints.append(full_url)
                    existing.add(full_url)

            # API endpoints
            for ep in endpoint_map.get_for_scanner("api_scanner"):
                full_url = ep.get_full_url(host, self.scheme)
                if full_url:
                    api_endpoints.append(full_url)

            # Endpoint parameters and vulnerability hints
            for ep in endpoint_map:
                full_url = ep.get_full_url(host, self.scheme)
                if full_url and ep.parameters:
                    param_names = [p.name for p in ep.parameters]
                    if param_names:
                        endpoint_params[full_url] = param_names
                if full_url and ep.metadata and "vulnerability_types" in ep.metadata:
                    vuln_hints[full_url] = ep.metadata["vulnerability_types"]

            if endpoint_params and self.config.log_info:
                logger.info(
                    f"[EndpointMap] Passing {len(endpoint_params)} endpoints "
                    f"with params to modules"
                )

        except Exception as e:
            if self.config.log_warnings:
                logger.warning(
                    f"[COVERAGE-GAP] EndpointMap merge failed: {e} — "
                    f"modules will test base URL only!"
                )

        return endpoints, api_endpoints, endpoint_params, vuln_hints

    def build(self, module_name: str = "") -> AssetData:
        """
        Build asset data for a module.

        Args:
            module_name: Name of the module (for logging)

        Returns:
            AssetData object
        """
        # Build base endpoints and parameters
        endpoints, parameters = self._build_base_asset_data(module_name)

        # Merge tool-discovered endpoints
        endpoints = self._merge_tool_endpoints(endpoints, module_name)

        # Merge priority endpoints (common patterns, fallbacks)
        endpoints, has_priority, priority_endpoints = (
            self._merge_priority_endpoints(endpoints, module_name)
        )

        # Merge EndpointMap
        endpoints, api_endpoints, endpoint_params, vuln_hints = (
            self._merge_endpoint_map(endpoints, module_name)
        )

        # Build asset data
        asset_data = AssetData(
            endpoints=endpoints,
            parameters=parameters,
            forms=self._discovered_forms or [],
            technologies=self._collect_technologies(),
            fingerprint_result=self._fingerprint_result,
            waf_detection=self._waf_detection_result,
            is_training_app=has_priority,
            training_app_endpoints=priority_endpoints,
            tool_discovered_params=self._tool_discovered_params,
            tool_findings=self._linux_tool_findings,
            subdomains=list(self._discovered_subdomains),
            api_endpoints=api_endpoints,
            endpoint_params=endpoint_params,
            vuln_type_hints=vuln_hints,
            shared_findings_store=self._shared_findings_store,
            user_personas=self._user_personas,
            domain_classification=self._domain_classification,
            security_schemes=self._security_schemes,
            semantic_analyzer=self._semantic_analyzer,
            runtime_engine=self._runtime_engine,
        )

        # Add auth context if valid
        if self._auth_context and self._auth_context.has_auth:
            asset_data.auth_context = self._auth_context

        # Add API discovery results
        if self._api_discovery:
            if hasattr(self._api_discovery, "get_injectable_endpoints_for_scanner"):
                injectable = self._api_discovery.get_injectable_endpoints_for_scanner()
                if injectable:
                    asset_data.injectable_endpoints = injectable
                    if self.config.log_debug:
                        logger.debug(
                            f"[API_DISCOVERY] Passing {len(injectable)} "
                            f"injectable endpoints to {module_name}"
                        )

            if hasattr(self._api_discovery, "get_auth_bypass_candidates_for_scanner"):
                auth_bypass = (
                    self._api_discovery.get_auth_bypass_candidates_for_scanner()
                )
                if auth_bypass:
                    asset_data.auth_bypass_candidates = auth_bypass
                    if self.config.log_debug:
                        logger.debug(
                            f"[API_DISCOVERY] Passing {len(auth_bypass)} "
                            f"auth bypass candidates to {module_name}"
                        )

        # Add stack profile
        if self._stack_profile:
            asset_data.stack_profile = self._stack_profile.to_dict()

        return asset_data

    def build_dict(self, module_name: str = "") -> dict[str, Any]:
        """
        Build asset data as dictionary.

        Args:
            module_name: Name of the module (for logging)

        Returns:
            Dictionary for module consumption
        """
        return self.build(module_name).to_dict()


# ═══════════════════════════════════════════════════════════════════════════════
# Convenience Functions
# ═══════════════════════════════════════════════════════════════════════════════


def build_asset_data(
    target: str,
    endpoints: Optional[list[str]] = None,
    parameters: Optional[list[str]] = None,
    technologies: Optional[list[str]] = None,
    auth_context: Optional[Any] = None,
) -> dict[str, Any]:
    """
    Build minimal asset data dictionary.

    Args:
        target: Target URL
        endpoints: Optional endpoint list
        parameters: Optional parameter list
        technologies: Optional technology list
        auth_context: Optional auth context

    Returns:
        Asset data dictionary
    """
    asset = AssetData(
        endpoints=endpoints or [target],
        parameters=parameters or [],
        technologies=technologies or [],
    )
    if auth_context:
        asset.auth_context = auth_context
    return asset.to_dict()


def create_builder(target: str) -> AssetDataBuilder:
    """
    Create a new asset data builder.

    Args:
        target: Target URL

    Returns:
        AssetDataBuilder instance
    """
    return AssetDataBuilder(target)


def build_asset_data_from_scanner(
    target: str,
    module_name: str,
    scanner_attrs: dict,
) -> dict:
    """
    Build asset_data dictionary from scanner attributes.

    This is a convenience function that extracts all relevant attributes
    from a scanner instance and builds the asset data in one call.

    Args:
        target: Target URL
        module_name: Module name (for logging)
        scanner_attrs: Dict of scanner attributes (from getattr calls)

    Returns:
        Complete asset_data dictionary
    """
    builder = AssetDataBuilder(target)

    # Register intelligent context
    if scanner_attrs.get("intelligent_context"):
        builder.register_intelligent_context(scanner_attrs["intelligent_context"])

    # Register classification and tech analysis
    if scanner_attrs.get("classification"):
        builder.register_classification(scanner_attrs["classification"])
    if scanner_attrs.get("tech_analysis"):
        builder.register_tech_analysis(scanner_attrs["tech_analysis"])

    # Register discovered forms
    if scanner_attrs.get("discovered_forms"):
        builder.register_forms(scanner_attrs["discovered_forms"])

    # Register fingerprint and WAF detection
    if scanner_attrs.get("fingerprint_result"):
        builder.register_fingerprint(scanner_attrs["fingerprint_result"])
    if scanner_attrs.get("waf_detection_result"):
        builder.register_waf_detection(scanner_attrs["waf_detection_result"])

    # Register tool discoveries
    builder.register_tool_discoveries(
        endpoints=scanner_attrs.get("tool_discovered_endpoints", []),
        params=scanner_attrs.get("tool_discovered_params"),
        findings=scanner_attrs.get("linux_tool_findings"),
    )

    # Register subdomains
    if scanner_attrs.get("discovered_subdomains"):
        builder.register_subdomains(scanner_attrs["discovered_subdomains"])

    # Register priority endpoints
    if scanner_attrs.get("fallback_endpoints"):
        builder.register_priority_endpoints(scanner_attrs["fallback_endpoints"])

    # Register generic fallback function
    if scanner_attrs.get("get_generic_fallback"):
        builder.register_generic_fallback(scanner_attrs["get_generic_fallback"])

    # Register shared findings store
    if scanner_attrs.get("shared_store"):
        builder.register_shared_store(scanner_attrs["shared_store"])

    # Register auth context
    auth_context = scanner_attrs.get("auth_context")
    if auth_context and getattr(auth_context, "has_auth", False):
        builder.register_auth_context(auth_context)

    # Register user personas
    if scanner_attrs.get("user_personas"):
        builder.register_user_personas(scanner_attrs["user_personas"])

    # Register domain classification
    if scanner_attrs.get("domain_classification"):
        builder.register_domain_classification(scanner_attrs["domain_classification"])

    # Register API discovery
    if scanner_attrs.get("api_discovery"):
        builder.register_api_discovery(scanner_attrs["api_discovery"])

    # Register security schemes
    if scanner_attrs.get("security_schemes"):
        builder.register_security_schemes(scanner_attrs["security_schemes"])

    # Register semantic analyzer
    if scanner_attrs.get("semantic_analyzer"):
        builder.register_semantic_analyzer(scanner_attrs["semantic_analyzer"])

    # Register stack profile and runtime engine
    if scanner_attrs.get("stack_profile"):
        builder.register_stack_profile(scanner_attrs["stack_profile"])
    if scanner_attrs.get("runtime_engine"):
        builder.register_runtime_engine(scanner_attrs["runtime_engine"])

    return builder.build_dict(module_name)
