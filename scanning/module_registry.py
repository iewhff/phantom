"""
Scanner Module Registry.

Provides logical categorization of all scanner modules without requiring file moves.
Used for:
- Module discovery and selection
- Category-based filtering
- Intelligent module ordering
- Documentation generation

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional, Type


class ModuleCategory(Enum):
    """Scanner module categories."""

    # Injection vulnerabilities
    INJECTION = "injection"

    # Authentication & Session
    AUTH = "auth"

    # API & Protocol
    API = "api"

    # Access Control & Authorization
    ACCESS_CONTROL = "access_control"

    # Business Logic
    BUSINESS_LOGIC = "business_logic"

    # Client-Side
    CLIENT_SIDE = "client_side"

    # Infrastructure & Cloud
    INFRASTRUCTURE = "infrastructure"

    # Network & Transport
    NETWORK = "network"

    # Discovery & Reconnaissance
    DISCOVERY = "discovery"

    # Advanced Exploitation
    ADVANCED = "advanced"

    # External Tools
    EXTERNAL = "external"


class ModulePriority(Enum):
    """Module execution priority."""

    CRITICAL = 1  # Run first (core injection, auth bypass)
    HIGH = 2      # Run early (common vulns)
    NORMAL = 3    # Standard priority
    LOW = 4       # Run later (info gathering)
    BACKGROUND = 5  # Run if time permits


@dataclass
class ModuleInfo:
    """Information about a scanner module."""

    name: str
    category: ModuleCategory
    priority: ModulePriority = ModulePriority.NORMAL
    description: str = ""
    requires_auth: bool = False
    is_destructive: bool = False
    timeout_multiplier: float = 1.0
    dependencies: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # Import path for lazy loading
    module_path: str = ""
    class_name: str = ""


class ModuleRegistry:
    """
    Registry of all scanner modules.

    Provides:
    - Module categorization
    - Priority-based ordering
    - Dependency resolution
    - Lazy module loading
    """

    _instance: Optional["ModuleRegistry"] = None
    _modules: dict[str, ModuleInfo] = {}

    def __new__(cls) -> "ModuleRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize module registry with all known modules."""
        self._modules = {}
        self._register_all_modules()

    def _register_all_modules(self) -> None:
        """Register all scanner modules."""

        # ═══════════════════════════════════════════════════════════════════════
        # INJECTION CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="sqli_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.CRITICAL,
            description="SQL Injection detection (error-based, blind, time-based)",
            module_path="scanning.modules.sqli_scanner",
            class_name="SQLiScanner",
            tags=["owasp-top10", "database", "injection"],
            timeout_multiplier=1.5,
        ))

        self._register(ModuleInfo(
            name="xss_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.CRITICAL,
            description="Cross-Site Scripting detection (reflected, stored)",
            module_path="scanning.modules.xss_scanner",
            class_name="XSSScanner",
            tags=["owasp-top10", "client-side", "injection"],
        ))

        self._register(ModuleInfo(
            name="dom_xss_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.HIGH,
            description="DOM-based XSS with browser automation",
            module_path="scanning.modules.dom_xss_scanner",
            class_name="DOMXSSScanner",
            tags=["client-side", "browser", "injection"],
            timeout_multiplier=2.0,
        ))

        self._register(ModuleInfo(
            name="cmdi_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.CRITICAL,
            description="Command Injection (OS command execution)",
            module_path="scanning.modules.cmdi_scanner",
            class_name="CommandInjectionScanner",  # Fixed: was CMDiScanner
            tags=["owasp-top10", "rce", "injection"],
            is_destructive=True,
        ))

        self._register(ModuleInfo(
            name="ssti_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.HIGH,
            description="Server-Side Template Injection",
            module_path="scanning.modules.ssti_scanner",
            class_name="SSTIScanner",
            tags=["rce", "injection", "template"],
        ))

        self._register(ModuleInfo(
            name="nosql_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.HIGH,
            description="NoSQL Injection (MongoDB, etc.)",
            module_path="scanning.modules.nosql_scanner",
            class_name="NoSQLScanner",
            tags=["database", "injection", "mongodb"],
        ))

        self._register(ModuleInfo(
            name="ldap_xpath_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.NORMAL,
            description="LDAP and XPath Injection",
            module_path="scanning.modules.ldap_xpath_scanner",
            class_name="LDAPXPathScanner",
            tags=["injection", "ldap", "xpath"],
        ))

        self._register(ModuleInfo(
            name="xxe_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.HIGH,
            description="XML External Entity Injection",
            module_path="scanning.modules.xxe_scanner",
            class_name="XXEScanner",
            tags=["owasp-top10", "xml", "injection"],
        ))

        self._register(ModuleInfo(
            name="crlf_scanner",
            category=ModuleCategory.INJECTION,
            priority=ModulePriority.NORMAL,
            description="CRLF Injection (HTTP response splitting)",
            module_path="scanning.modules.crlf_scanner",
            class_name="CRLFScanner",
            tags=["injection", "headers"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # AUTH CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="auth_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.HIGH,
            description="Authentication mechanism testing",
            module_path="scanning.modules.auth_scanner",
            class_name="AuthScanner",
            tags=["owasp-top10", "auth"],
        ))

        self._register(ModuleInfo(
            name="jwt_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.HIGH,
            description="JWT token security (alg:none, weak secrets, etc.)",
            module_path="scanning.modules.jwt_scanner",
            class_name="JWTScanner",
            tags=["auth", "jwt", "tokens"],
        ))

        self._register(ModuleInfo(
            name="oauth_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.HIGH,
            description="OAuth/OIDC implementation flaws",
            module_path="scanning.modules.oauth_scanner",
            class_name="OAuthScanner",
            tags=["auth", "oauth", "sso"],
        ))

        self._register(ModuleInfo(
            name="saml_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.NORMAL,
            description="SAML authentication vulnerabilities",
            module_path="scanning.modules.saml_scanner",
            class_name="SAMLScanner",
            tags=["auth", "saml", "sso"],
        ))

        self._register(ModuleInfo(
            name="mfa_bypass_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.HIGH,
            description="Multi-factor authentication bypass",
            module_path="scanning.modules.mfa_bypass_scanner",
            class_name="MFABypassScanner",
            tags=["auth", "mfa", "2fa"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="session_abuse_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.HIGH,
            description="Session management vulnerabilities",
            module_path="scanning.modules.session_abuse_scanner",
            class_name="SessionAbuseScanner",
            tags=["auth", "session"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="credential_verifier",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.NORMAL,
            description="Verify discovered credentials",
            module_path="scanning.modules.credential_verifier",
            class_name="CredentialVerifier",
            tags=["auth", "credentials"],
        ))

        self._register(ModuleInfo(
            name="csrf_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.HIGH,
            description="Cross-Site Request Forgery detection",
            module_path="scanning.modules.csrf_scanner",
            class_name="CSRFScanner",
            tags=["owasp-top10", "auth", "csrf"],
        ))

        self._register(ModuleInfo(
            name="cookie_security_scanner",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.NORMAL,
            description="Cookie security flags analysis",
            module_path="scanning.modules.cookie_security_scanner",
            class_name="CookieSecurityScanner",
            tags=["auth", "cookies"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # API CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="api_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.HIGH,
            description="REST API security testing",
            module_path="scanning.modules.api_scanner",
            class_name="APIScanner",
            tags=["api", "rest"],
        ))

        self._register(ModuleInfo(
            name="api_logic_profiler",
            category=ModuleCategory.API,
            priority=ModulePriority.HIGH,
            description="API business logic and IDOR detection",
            module_path="scanning.modules.api_logic_profiler",
            class_name="APILogicProfiler",
            tags=["api", "idor", "bola"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="graphql_advanced_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.HIGH,
            description="GraphQL security (introspection, injection, batching)",
            module_path="scanning.modules.graphql_advanced_scanner",
            class_name="GraphQLAdvancedScanner",
            tags=["api", "graphql"],
        ))

        self._register(ModuleInfo(
            name="graphql_subscription_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="GraphQL subscription security",
            module_path="scanning.modules.graphql_subscription_scanner",
            class_name="GraphQLSubscriptionScanner",
            tags=["api", "graphql", "websocket"],
        ))

        self._register(ModuleInfo(
            name="grpc_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="gRPC security testing",
            module_path="scanning.modules.grpc_scanner",
            class_name="GRPCScanner",
            tags=["api", "grpc"],
        ))

        self._register(ModuleInfo(
            name="grpc_web_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="gRPC-Web security testing",
            module_path="scanning.modules.grpc_web_scanner",
            class_name="GRPCWebScanner",
            tags=["api", "grpc"],
        ))

        self._register(ModuleInfo(
            name="websocket_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="WebSocket security testing",
            module_path="scanning.modules.websocket_scanner",
            class_name="WebSocketScanner",
            tags=["api", "websocket", "realtime"],
        ))

        self._register(ModuleInfo(
            name="sse_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.LOW,
            description="Server-Sent Events security",
            module_path="scanning.modules.sse_scanner",
            class_name="SSEScanner",
            tags=["api", "sse", "realtime"],
        ))

        self._register(ModuleInfo(
            name="cors_checker",
            category=ModuleCategory.API,
            priority=ModulePriority.HIGH,
            description="CORS misconfiguration detection",
            module_path="scanning.modules.cors_checker",
            class_name="CORSChecker",
            tags=["api", "cors", "headers"],
        ))

        self._register(ModuleInfo(
            name="mobile_api_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="Mobile API security testing",
            module_path="scanning.modules.mobile_api_scanner",
            class_name="MobileAPIScanner",
            tags=["api", "mobile"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # ACCESS CONTROL CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="authorization_engine",
            category=ModuleCategory.ACCESS_CONTROL,
            priority=ModulePriority.CRITICAL,
            description="Authorization bypass and IDOR detection",
            module_path="scanning.modules.authorization_engine",
            class_name="AuthorizationEngine",
            tags=["owasp-top10", "idor", "bola", "authz"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="permission_matrix_scanner",
            category=ModuleCategory.ACCESS_CONTROL,
            priority=ModulePriority.HIGH,
            description="Permission matrix analysis",
            module_path="scanning.modules.permission_matrix_scanner",
            class_name="PermissionMatrixScanner",
            tags=["authz", "rbac"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="abac_context_tester",
            category=ModuleCategory.ACCESS_CONTROL,
            priority=ModulePriority.NORMAL,
            description="Attribute-based access control testing",
            module_path="scanning.modules.abac_context_tester",
            class_name="ABACContextTester",
            tags=["authz", "abac"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="advanced_rls_bypass_scanner",
            category=ModuleCategory.ACCESS_CONTROL,
            priority=ModulePriority.HIGH,
            description="Row-level security bypass detection",
            module_path="scanning.modules.advanced_rls_bypass_scanner",
            class_name="AdvancedRLSBypassScanner",
            tags=["authz", "rls", "database"],
            requires_auth=True,
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # BUSINESS LOGIC CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="business_logic_scanner",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.HIGH,
            description="Business logic flaws detection",
            module_path="scanning.modules.business_logic_scanner",
            class_name="BusinessLogicScanner",
            tags=["logic", "workflow"],
            requires_auth=True,
            timeout_multiplier=2.0,
        ))

        self._register(ModuleInfo(
            name="race_condition_scanner",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.HIGH,
            description="Race condition and TOCTOU vulnerabilities",
            module_path="scanning.modules.race_condition_scanner",
            class_name="RaceConditionScanner",
            tags=["logic", "concurrency", "toctou"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="logic_chain_scanner",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.NORMAL,
            description="Multi-step logic chain testing",
            module_path="scanning.modules.logic_chain_scanner",
            class_name="LogicChainScanner",
            tags=["logic", "workflow"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="workflow_inference_engine",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.NORMAL,
            description="Workflow inference and state machine analysis",
            module_path="scanning.modules.workflow_inference_engine",
            class_name="WorkflowInferenceEngine",
            tags=["logic", "workflow", "state-machine"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="stateful_flow_scanner",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.NORMAL,
            description="Stateful flow vulnerability testing",
            module_path="scanning.modules.stateful_flow_scanner",
            class_name="StatefulFlowScanner",
            tags=["logic", "stateful"],
            requires_auth=True,
        ))

        self._register(ModuleInfo(
            name="concurrency_state_modeler",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.NORMAL,
            description="Concurrency state modeling",
            module_path="scanning.modules.concurrency_state_modeler",
            class_name="ConcurrencyStateModeler",
            tags=["logic", "concurrency"],
        ))

        self._register(ModuleInfo(
            name="concurrency_stress_scanner",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.NORMAL,
            description="Concurrency stress testing",
            module_path="scanning.modules.concurrency_stress_scanner",
            class_name="ConcurrencyStressScanner",
            tags=["logic", "concurrency", "stress"],
        ))

        self._register(ModuleInfo(
            name="rate_limit_scanner",
            category=ModuleCategory.BUSINESS_LOGIC,
            priority=ModulePriority.LOW,
            description="Rate limiting bypass detection",
            module_path="scanning.modules.rate_limit_scanner",
            class_name="RateLimitScanner",
            tags=["logic", "rate-limit"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # CLIENT-SIDE CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="clickjacking_scanner",
            category=ModuleCategory.CLIENT_SIDE,
            priority=ModulePriority.NORMAL,
            description="Clickjacking vulnerability detection",
            module_path="scanning.modules.clickjacking_scanner",
            class_name="ClickjackingScanner",
            tags=["client-side", "framing"],
        ))

        self._register(ModuleInfo(
            name="prototype_pollution_scanner",
            category=ModuleCategory.CLIENT_SIDE,
            priority=ModulePriority.HIGH,
            description="JavaScript prototype pollution",
            module_path="scanning.modules.prototype_pollution_scanner",
            class_name="PrototypePollutionScanner",
            tags=["client-side", "javascript"],
        ))

        self._register(ModuleInfo(
            name="client_hardening_scanner",
            category=ModuleCategory.CLIENT_SIDE,
            priority=ModulePriority.LOW,
            description="Client-side security hardening analysis",
            module_path="scanning.modules.client_hardening_scanner",
            class_name="ClientHardeningScanner",
            tags=["client-side", "headers"],
        ))

        self._register(ModuleInfo(
            name="wasm_scanner",
            category=ModuleCategory.CLIENT_SIDE,
            priority=ModulePriority.LOW,
            description="WebAssembly security analysis",
            module_path="scanning.modules.wasm_scanner",
            class_name="WasmScanner",
            tags=["client-side", "wasm"],
        ))

        self._register(ModuleInfo(
            name="webrtc_scanner",
            category=ModuleCategory.CLIENT_SIDE,
            priority=ModulePriority.LOW,
            description="WebRTC security testing",
            module_path="scanning.modules.webrtc_scanner",
            class_name="WebRTCScanner",
            tags=["client-side", "webrtc"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # INFRASTRUCTURE CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="cloud_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.HIGH,
            description="Cloud misconfiguration detection (AWS, GCP, Azure)",
            module_path="scanning.modules.cloud_scanner",
            class_name="CloudScanner",
            tags=["cloud", "aws", "gcp", "azure"],
        ))

        self._register(ModuleInfo(
            name="kubernetes_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.NORMAL,
            description="Kubernetes security testing",
            module_path="scanning.modules.kubernetes_scanner",
            class_name="KubernetesContainerScanner",
            tags=["cloud", "k8s", "container"],
        ))

        self._register(ModuleInfo(
            name="firebase_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.HIGH,
            description="Firebase misconfiguration detection",
            module_path="scanning.modules.firebase_scanner",
            class_name="FirebaseScanner",
            tags=["cloud", "firebase", "gcp"],
        ))

        self._register(ModuleInfo(
            name="supabase_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.HIGH,
            description="Supabase security testing",
            module_path="scanning.modules.supabase_scanner",
            class_name="SupabaseScanner",
            tags=["cloud", "supabase", "postgres"],
        ))

        self._register(ModuleInfo(
            name="cms_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.NORMAL,
            description="CMS vulnerability detection (WordPress, etc.)",
            module_path="scanning.modules.cms_scanner",
            class_name="CMSScanner",
            tags=["cms", "wordpress"],
        ))

        self._register(ModuleInfo(
            name="ssl_checker",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.LOW,
            description="SSL/TLS configuration analysis",
            module_path="scanning.modules.ssl_checker",
            class_name="SSLChecker",
            tags=["crypto", "ssl", "tls"],
        ))

        self._register(ModuleInfo(
            name="header_security",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.LOW,
            description="Security headers analysis",
            module_path="scanning.modules.header_security",
            class_name="HeaderSecurityChecker",
            tags=["headers", "hardening"],
        ))

        self._register(ModuleInfo(
            name="edge_function_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.NORMAL,
            description="Edge function security (Cloudflare Workers, etc.)",
            module_path="scanning.modules.edge_function_scanner",
            class_name="EdgeFunctionScanner",
            tags=["cloud", "edge", "serverless"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # NETWORK CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="ssrf_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.CRITICAL,
            description="Server-Side Request Forgery detection",
            module_path="scanning.modules.ssrf_scanner",
            class_name="SSRFScanner",
            tags=["owasp-top10", "ssrf", "network"],
        ))

        self._register(ModuleInfo(
            name="dns_rebinding_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.HIGH,
            description="DNS rebinding attack detection",
            module_path="scanning.modules.dns_rebinding_scanner",
            class_name="DNSRebindingScanner",
            tags=["network", "dns"],
        ))

        self._register(ModuleInfo(
            name="smuggling_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.HIGH,
            description="HTTP request smuggling",
            module_path="scanning.modules.smuggling_scanner",
            class_name="HTTPSmugglingScanner",
            tags=["network", "http", "smuggling"],
            timeout_multiplier=2.0,
        ))

        self._register(ModuleInfo(
            name="host_header_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.NORMAL,
            description="Host header injection",
            module_path="scanning.modules.host_header_scanner",
            class_name="HostHeaderScanner",
            tags=["network", "headers"],
        ))

        self._register(ModuleInfo(
            name="cache_poisoning_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.HIGH,
            description="Web cache poisoning",
            module_path="scanning.modules.cache_poisoning_scanner",
            class_name="CachePoisoningScanner",
            tags=["network", "cache"],
        ))

        self._register(ModuleInfo(
            name="cache_deception_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.HIGH,
            description="Web cache deception",
            module_path="scanning.modules.cache_deception_scanner",
            class_name="CacheDeceptionScanner",
            tags=["network", "cache"],
        ))

        self._register(ModuleInfo(
            name="subdomain_takeover_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.HIGH,
            description="Subdomain takeover detection",
            module_path="scanning.modules.subdomain_takeover_scanner",
            class_name="SubdomainTakeoverScanner",
            tags=["network", "subdomain"],
        ))

        self._register(ModuleInfo(
            name="http3_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.LOW,
            description="HTTP/3 QUIC security testing",
            module_path="scanning.modules.http3_scanner",
            class_name="HTTP3Scanner",
            tags=["network", "http3", "quic"],
        ))

        self._register(ModuleInfo(
            name="webtransport_scanner",
            category=ModuleCategory.NETWORK,
            priority=ModulePriority.LOW,
            description="WebTransport security testing",
            module_path="scanning.modules.webtransport_scanner",
            class_name="WebTransportScanner",
            tags=["network", "webtransport"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # DISCOVERY CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="dir_scanner",
            category=ModuleCategory.DISCOVERY,
            priority=ModulePriority.HIGH,
            description="Directory and file enumeration",
            module_path="scanning.modules.dir_scanner",
            class_name="DirectoryScanner",
            tags=["discovery", "enumeration"],
        ))

        self._register(ModuleInfo(
            name="info_disclosure_scanner",
            category=ModuleCategory.DISCOVERY,
            priority=ModulePriority.HIGH,
            description="Information disclosure detection",
            module_path="scanning.modules.info_disclosure_scanner",
            class_name="InfoDisclosureScanner",
            tags=["discovery", "leakage"],
        ))

        self._register(ModuleInfo(
            name="config_exposure_scanner",
            category=ModuleCategory.DISCOVERY,
            priority=ModulePriority.HIGH,
            description="Configuration file exposure",
            module_path="scanning.modules.config_exposure_scanner",
            class_name="ConfigExposureScanner",
            tags=["discovery", "config"],
        ))

        self._register(ModuleInfo(
            name="secrets_pattern_scanner",
            category=ModuleCategory.DISCOVERY,
            priority=ModulePriority.HIGH,
            description="Secret/credential pattern detection",
            module_path="scanning.modules.secrets_pattern_scanner",
            class_name="SecretsPatternScanner",
            tags=["discovery", "secrets", "credentials"],
        ))

        self._register(ModuleInfo(
            name="backend_detector",
            category=ModuleCategory.DISCOVERY,
            priority=ModulePriority.NORMAL,
            description="Backend technology detection",
            module_path="scanning.modules.backend_detector",
            class_name="BackendDetector",
            tags=["discovery", "fingerprint"],
        ))

        self._register(ModuleInfo(
            name="bun_deno_fingerprinter",
            category=ModuleCategory.DISCOVERY,
            priority=ModulePriority.LOW,
            description="Bun/Deno runtime fingerprinting",
            module_path="scanning.modules.bun_deno_fingerprinter",
            class_name="BunDenoFingerprinter",
            tags=["discovery", "fingerprint", "runtime"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # ADVANCED CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="deserialization_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.CRITICAL,
            description="Insecure deserialization (Java, PHP, Python, .NET)",
            module_path="scanning.modules.deserialization_scanner",
            class_name="DeserializationScanner",
            tags=["owasp-top10", "deserialization", "rce"],
            is_destructive=True,
            timeout_multiplier=2.0,
        ))

        self._register(ModuleInfo(
            name="file_upload_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.CRITICAL,
            description="File upload vulnerability detection",
            module_path="scanning.modules.file_upload_scanner",
            class_name="FileUploadScanner",
            tags=["file-upload", "rce"],
            is_destructive=True,
        ))

        self._register(ModuleInfo(
            name="lfi_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.CRITICAL,
            description="Local File Inclusion",
            module_path="scanning.modules.lfi_scanner",
            class_name="LFIScanner",
            tags=["owasp-top10", "lfi", "path-traversal"],
        ))

        self._register(ModuleInfo(
            name="open_redirect_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.NORMAL,
            description="Open redirect vulnerability detection",
            module_path="scanning.modules.open_redirect_scanner",
            class_name="OpenRedirectScanner",
            tags=["redirect", "phishing"],
        ))

        self._register(ModuleInfo(
            name="mass_assignment_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.HIGH,
            description="Mass assignment vulnerability detection",
            module_path="scanning.modules.mass_assignment_scanner",
            class_name="MassAssignmentScanner",
            tags=["api", "mass-assignment"],
        ))

        self._register(ModuleInfo(
            name="creative_exploiter",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.HIGH,
            description="Creative exploitation techniques",
            module_path="scanning.modules.creative_exploiter",
            class_name="CreativeExploiterScanner",
            tags=["exploitation", "advanced"],
            requires_auth=True,
            timeout_multiplier=2.0,
        ))

        self._register(ModuleInfo(
            name="post_exploitation",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.NORMAL,
            description="Post-exploitation techniques",
            module_path="scanning.modules.post_exploitation",
            class_name="PostExploitationModule",
            tags=["exploitation", "post-exploit"],
            is_destructive=True,
        ))

        self._register(ModuleInfo(
            name="integration_exploiter",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.NORMAL,
            description="Third-party integration exploitation",
            module_path="scanning.modules.integration_exploiter",
            class_name="IntegrationExploiter",
            tags=["exploitation", "integrations"],
        ))

        self._register(ModuleInfo(
            name="crypto_weakness_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.NORMAL,
            description="Cryptographic weakness detection",
            module_path="scanning.modules.crypto_weakness_scanner",
            class_name="CryptoWeaknessScanner",
            tags=["crypto", "weakness"],
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # EXTERNAL TOOLS CATEGORY
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="nuclei_runner",
            category=ModuleCategory.EXTERNAL,
            priority=ModulePriority.NORMAL,
            description="Nuclei template execution",
            module_path="scanning.modules.nuclei_runner",
            class_name="NucleiRunner",
            tags=["external", "nuclei"],
            timeout_multiplier=3.0,
        ))

        self._register(ModuleInfo(
            name="linux_tools_wrapper",
            category=ModuleCategory.EXTERNAL,
            priority=ModulePriority.NORMAL,
            description="Linux security tools integration",
            module_path="scanning.modules.linux_tools_wrapper",
            class_name="LinuxToolsWrapper",
            tags=["external", "tools"],
            timeout_multiplier=3.0,
        ))

        # ═══════════════════════════════════════════════════════════════════════
        # AI/LLM CATEGORY (part of ADVANCED)
        # ═══════════════════════════════════════════════════════════════════════
        self._register(ModuleInfo(
            name="llm_security_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.HIGH,
            description="LLM/AI security testing (prompt injection, etc.)",
            module_path="scanning.modules.llm_security_scanner",
            class_name="LLMSecurityScanner",
            tags=["ai", "llm", "prompt-injection"],
        ))

        self._register(ModuleInfo(
            name="ai_prompt_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.HIGH,
            description="AI prompt injection detection",
            module_path="scanning.modules.ai_prompt_scanner",
            class_name="AIPromptScanner",
            tags=["ai", "llm", "prompt-injection"],
        ))

        # Additional modules
        self._register(ModuleInfo(
            name="third_party_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.NORMAL,
            description="Third-party service security",
            module_path="scanning.modules.third_party_scanner",
            class_name="ThirdPartyScanner",
            tags=["third-party", "integrations"],
        ))

        self._register(ModuleInfo(
            name="email_security_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.LOW,
            description="Email security (SPF, DKIM, DMARC)",
            module_path="scanning.modules.email_security_scanner",
            class_name="EmailSecurityScanner",
            tags=["email", "dns"],
        ))

        self._register(ModuleInfo(
            name="communications_api_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="Communication APIs (SMS, Voice, etc.)",
            module_path="scanning.modules.communications_api_scanner",
            class_name="CommunicationsAPIScanner",
            tags=["api", "communications"],
        ))

        self._register(ModuleInfo(
            name="webhook_security_scanner",
            category=ModuleCategory.API,
            priority=ModulePriority.NORMAL,
            description="Webhook security testing",
            module_path="scanning.modules.webhook_security_scanner",
            class_name="WebhookSecurityScanner",
            tags=["api", "webhooks"],
        ))

        self._register(ModuleInfo(
            name="token_binding_validator",
            category=ModuleCategory.AUTH,
            priority=ModulePriority.NORMAL,
            description="Token binding validation",
            module_path="scanning.modules.token_binding_validator",
            class_name="TokenBindingValidator",
            tags=["auth", "tokens"],
        ))

        self._register(ModuleInfo(
            name="defensive_evasion_scanner",
            category=ModuleCategory.ADVANCED,
            priority=ModulePriority.LOW,
            description="Defensive evasion technique testing",
            module_path="scanning.modules.defensive_evasion_scanner",
            class_name="DefensiveEvasionScanner",
            tags=["evasion", "waf-bypass"],
        ))

        self._register(ModuleInfo(
            name="wasm_backend_scanner",
            category=ModuleCategory.INFRASTRUCTURE,
            priority=ModulePriority.LOW,
            description="WebAssembly backend security",
            module_path="scanning.modules.wasm_backend_scanner",
            class_name="WASMBackendScanner",
            tags=["wasm", "backend"],
        ))

        self._register(ModuleInfo(
            name="rsc_scanner",
            category=ModuleCategory.CLIENT_SIDE,
            priority=ModulePriority.NORMAL,
            description="React Server Components security",
            module_path="scanning.modules.rsc_scanner",
            class_name="RSCScanner",
            tags=["react", "rsc", "client-side"],
        ))

    def _register(self, info: ModuleInfo) -> None:
        """Register a module."""
        self._modules[info.name] = info

    def get(self, name: str) -> Optional[ModuleInfo]:
        """Get module info by name."""
        return self._modules.get(name)

    def get_all(self) -> list[ModuleInfo]:
        """Get all registered modules."""
        return list(self._modules.values())

    def get_by_category(self, category: ModuleCategory) -> list[ModuleInfo]:
        """Get modules by category."""
        return [m for m in self._modules.values() if m.category == category]

    def get_by_priority(self, priority: ModulePriority) -> list[ModuleInfo]:
        """Get modules by priority."""
        return [m for m in self._modules.values() if m.priority == priority]

    def get_by_tag(self, tag: str) -> list[ModuleInfo]:
        """Get modules by tag."""
        return [m for m in self._modules.values() if tag in m.tags]

    def get_ordered(self, exclude_destructive: bool = False) -> list[ModuleInfo]:
        """Get modules ordered by priority."""
        modules = list(self._modules.values())
        if exclude_destructive:
            modules = [m for m in modules if not m.is_destructive]
        return sorted(modules, key=lambda m: m.priority.value)

    def get_requiring_auth(self) -> list[ModuleInfo]:
        """Get modules that require authentication."""
        return [m for m in self._modules.values() if m.requires_auth]

    def get_names(self) -> list[str]:
        """Get all module names."""
        return list(self._modules.keys())


# Singleton accessor
def get_module_registry() -> ModuleRegistry:
    """Get the module registry singleton."""
    return ModuleRegistry()
