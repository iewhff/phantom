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

Supports Safe Mode for non-destructive testing.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Dict, List

from utils.logger import get_logger
from utils.shared_findings_store import SharedFindingsStore, get_shared_findings
from utils.exploit_policy_engine import ExploitPolicyEngine, ExploitMode, get_exploit_policy

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version info
SCANNER_VERSION = "2.0.0-INTELLIGENT"


@dataclass
class ScanResult:
    """Result of a full security scan."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: list[dict] = field(default_factory=list)
    info: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    modules_requested: list[str] = field(default_factory=list)  # What user explicitly requested
    safe_mode: str = "safe"

    # NEW: Intelligent scanning metrics
    intelligent_mode: bool = False
    tests_skipped: int = 0
    modules_skipped: list[str] = field(default_factory=list)  # Classification recommendations (may be overridden)
    modules_not_executed: list[str] = field(default_factory=list)  # Actually not run
    skip_reasons: dict = field(default_factory=dict)
    target_classification: str = "unknown"  # Professional display name
    target_type_code: str = "unknown"       # Internal code for tooling
    classification_confidence: float = 0.0
    scope_violations: int = 0
    negative_control_validations: int = 0
    parameters_analyzed: int = 0
    endpoints_discovered: int = 0

    # Vulnerability chain metrics
    chain_findings: int = 0  # Findings discovered via chaining
    chains_triggered: int = 0  # Number of chains executed
    escalations_attempted: int = 0  # Escalation attempts (SQLi→RCE, etc.)

    def add_finding(self, finding) -> None:
        """Add a finding (supports dict or Finding dataclass)."""
        # Convert Finding dataclass to dict if needed
        if hasattr(finding, "to_dict"):
            finding_dict = finding.to_dict()
        elif hasattr(finding, "__dataclass_fields__"):
            from dataclasses import asdict
            finding_dict = asdict(finding)
        elif isinstance(finding, dict):
            finding_dict = finding
        else:
            # Try to convert to dict
            finding_dict = dict(finding) if hasattr(finding, "__iter__") else {"raw": str(finding)}
        
        finding_dict["discovered_at"] = datetime.now().isoformat()
        self.findings.append(finding_dict)
    
    def to_dict(self) -> dict:
        # Generate threat model for business context
        threat_report = None
        if self.findings:
            try:
                from utils.threat_model import generate_threat_report
                threat_report = generate_threat_report(self.findings)
            except Exception:
                threat_report = None

        # Calculate duration
        duration_seconds = 0
        if self.end_time and self.start_time:
            duration_seconds = (self.end_time - self.start_time).total_seconds()

        result = {
            # Methodology & Branding
            "report_metadata": {
                "methodology": "Cloud-First Security Review (CFSR) v2.0",
                "phases": ["Discover", "Classify", "Scan", "Analyze", "Report"],
                "framework": "PetNTester AI Enterprise",
                "version": "2.0.0",
                "generated_at": datetime.now().isoformat(),
            },

            # Scope Definition (protects both parties)
            "scope": {
                "target": self.target,
                "what_was_tested": [
                    "Security headers analysis",
                    "SSL/TLS configuration",
                    "CORS policy validation",
                    "DOM-based XSS detection",
                ] + ([f"Module: {m}" for m in self.modules_run[:5]]),
                "what_was_not_tested": [
                    "Authenticated endpoints (no credentials provided)",
                    "Business logic vulnerabilities",
                    "Rate limiting effectiveness",
                    "WAF bypass techniques",
                    "Social engineering vectors",
                ] + ([f"Not executed: {m}" for m in self.modules_not_executed[:5]]),
                "limitations": [
                    "Non-destructive testing only (Safe Mode)",
                    "No access to source code",
                    "No access to internal network",
                    "Point-in-time assessment",
                ],
                "authorization": "Scan performed with --no-auth flag (educational/authorized use)",
            },

            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration_seconds,
            "findings": self.findings,
            "info": self.info,
            "errors": self.errors,
            "modules_run": self.modules_run,
            "safe_mode": self.safe_mode,
            "intelligent_mode": self.intelligent_mode,

            "summary": {
                "total_findings": len(self.findings),
                "critical": len([f for f in self.findings if f.get("severity") == "CRITICAL"]),
                "high": len([f for f in self.findings if f.get("severity") == "HIGH"]),
                "medium": len([f for f in self.findings if f.get("severity") == "MEDIUM"]),
                "low": len([f for f in self.findings if f.get("severity") == "LOW"]),
                # Action-oriented summary
                "fix_now": len([f for f in self.findings if f.get("severity") in ["CRITICAL", "HIGH"]]),
                "fix_next_sprint": len([f for f in self.findings if f.get("severity") == "MEDIUM"]),
                "fix_when_convenient": len([f for f in self.findings if f.get("severity") == "LOW"]),
            },

            "classification": {
                "target_type": self.target_classification,       # Professional display name
                "target_type_code": self.target_type_code,       # Internal code for tooling
                "confidence": self.classification_confidence,
                "modules_recommended_skip": self.modules_skipped,  # Classification recommendation
                "modules_not_executed": self.modules_not_executed, # Actually not run
                "skip_reasons": self.skip_reasons,
            },

            "intelligent_metrics": {
                "tests_skipped": self.tests_skipped,
                "scope_violations": self.scope_violations,
                "negative_control_validations": self.negative_control_validations,
                "parameters_analyzed": self.parameters_analyzed,
                "endpoints_discovered": self.endpoints_discovered,
            },

            "chain_metrics": {
                "chain_findings": self.chain_findings,
                "chains_triggered": self.chains_triggered,
                "escalations_attempted": self.escalations_attempted,
            },
        }

        # Add threat model if generated
        if threat_report:
            result["threat_model"] = threat_report

        return result


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
    
    # All available scanner modules
    ALL_MODULES = {
        # Base Injection Scanners
        "sqli": "scanning.modules.sqli_scanner.SQLiScanner",
        "xss": "scanning.modules.xss_scanner.XSSScanner",
        "cmdi": "scanning.modules.cmdi_scanner.CommandInjectionScanner",
        "xxe": "scanning.modules.xxe_scanner.XXEScanner",
        "ssrf": "scanning.modules.ssrf_scanner.SSRFScanner",
        "lfi": "scanning.modules.lfi_scanner.LFIScanner",
        
        # Authentication & Authorization
        "auth": "scanning.modules.auth_scanner.AuthScanner",
        "oauth": "scanning.modules.oauth_scanner.OAuthScanner",
        "saml": "scanning.modules.saml_scanner.SAMLScanner",
        "mfa": "scanning.modules.mfa_bypass_scanner.MFABypassScanner",
        "authz": "scanning.modules.authorization_engine.AuthorizationEngine",
        
        # API Security
        "api": "scanning.modules.api_scanner.APIScanner",
        "graphql": "scanning.modules.graphql_advanced_scanner.GraphQLAdvancedScanner",
        "grpc": "scanning.modules.grpc_scanner.GRPCScanner",
        "websocket": "scanning.modules.websocket_scanner.WebSocketScanner",
        "sse": "scanning.modules.sse_scanner.SSEScanner",
        
        # Infrastructure
        "ssl": "scanning.modules.ssl_checker.SSLChecker",
        "headers": "scanning.modules.header_security.HeaderSecurityChecker",
        "cors": "scanning.modules.cors_checker.CORSChecker",
        "cloud": "scanning.modules.cloud_scanner.CloudScanner",
        "k8s": "scanning.modules.kubernetes_scanner.KubernetesContainerScanner",
        
        # CMS & Discovery
        "cms": "scanning.modules.cms_scanner.CMSScanner",
        "dir": "scanning.modules.dir_scanner.DirectoryScanner",
        "nuclei": "scanning.modules.nuclei_runner.NucleiRunner",
        
        # Advanced Attacks
        "nosql": "scanning.modules.nosql_scanner.NoSQLScanner",
        "ssti": "scanning.modules.ssti_scanner.SSTIScanner",
        "deser": "scanning.modules.deserialization_scanner.DeserializationScanner",
        "smuggling": "scanning.modules.smuggling_scanner.HTTPSmugglingScanner",
        "prototype": "scanning.modules.prototype_pollution_scanner.PrototypePollutionScanner",
        "crlf": "scanning.modules.crlf_scanner.CRLFScanner",
        "cache": "scanning.modules.cache_poisoning_scanner.CachePoisoningScanner",
        "dns_rebind": "scanning.modules.dns_rebinding_scanner.DNSRebindingScanner",
        
        # Specialized
        "ldap": "scanning.modules.ldap_xpath_scanner.LDAPXPathScanner",
        "mobile": "scanning.modules.mobile_api_scanner.MobileAPIScanner",
        "email": "scanning.modules.email_security_scanner.EmailSecurityScanner",
        "ratelimit": "scanning.modules.rate_limit_scanner.RateLimitScanner",
        "business": "scanning.modules.business_logic_scanner.BusinessLogicScanner",
        "postexploit": "scanning.modules.post_exploitation.PostExploitationModule",

        # TOP TIER BOUNTY MODULES (Added for maximum bounty potential)
        "dom_xss": "scanning.modules.dom_xss_scanner.DOMXSSScanner",
        "idor": "scanning.modules.api_logic_profiler.APILogicProfiler",
        "csrf": "scanning.modules.csrf_scanner.CSRFScanner",
        "mass_assign": "scanning.modules.mass_assignment_scanner.MassAssignmentScanner",

        # BaaS Security (Supabase, Firebase - common misconfigs = easy bounties)
        "supabase": "scanning.modules.supabase_scanner.SupabaseScanner",
        "firebase": "scanning.modules.firebase_scanner.FirebaseScanner",
        "rls_bypass": "scanning.modules.advanced_rls_bypass_scanner.AdvancedRLSBypassScanner",

        # Discovery & Fingerprinting
        "backend": "scanning.modules.backend_detector.BackendDetector",
        "third_party": "scanning.modules.third_party_scanner.ThirdPartyScanner",

        # Credential Detection & Verification (HackerOne Compliant)
        "credential_verifier": "scanning.modules.credential_verifier.CredentialVerifier",

        # NEW MODULES (PortSwigger Coverage)
        "jwt": "scanning.modules.jwt_scanner.JWTScanner",
        "race": "scanning.modules.race_condition_scanner.RaceConditionScanner",
        "host_header": "scanning.modules.host_header_scanner.HostHeaderScanner",
        "clickjacking": "scanning.modules.clickjacking_scanner.ClickjackingScanner",
        "info_disclosure": "scanning.modules.info_disclosure_scanner.InfoDisclosureScanner",
        "cache_deception": "scanning.modules.cache_deception_scanner.CacheDeceptionScanner",
        "open_redirect": "scanning.modules.open_redirect_scanner.OpenRedirectScanner",
        "file_upload": "scanning.modules.file_upload_scanner.FileUploadScanner",
        "cookie": "scanning.modules.cookie_security_scanner.CookieSecurityScanner",
        "subdomain_takeover": "scanning.modules.subdomain_takeover_scanner.SubdomainTakeoverScanner",
        "llm": "scanning.modules.llm_security_scanner.LLMSecurityScanner",
    }

    # Module categories for selective scanning
    CATEGORIES = {
        "quick": ["headers", "ssl", "cors", "dir", "backend"],
        "web": ["sqli", "xss", "dom_xss", "cmdi", "lfi", "xxe", "ssrf", "csrf", "headers", "ssl", "cors"],
        "api": ["api", "graphql", "grpc", "websocket", "sse", "auth", "oauth", "ratelimit", "idor", "mass_assign"],
        "injection": ["sqli", "xss", "dom_xss", "cmdi", "xxe", "nosql", "ssti", "ldap", "crlf"],
        "auth": ["auth", "oauth", "saml", "mfa", "authz", "ratelimit", "idor", "csrf"],
        "infra": ["ssl", "headers", "cors", "cloud", "k8s", "dns_rebind", "supabase", "firebase"],
        "advanced": ["smuggling", "cache", "deser", "prototype", "dns_rebind", "rls_bypass"],

        # Standard scan - comprehensive web app testing (default for PHANTOM)
        "standard": [
            "headers", "ssl", "cors",           # Infrastructure basics
            "sqli", "xss", "dom_xss",           # Classic injections
            "csrf", "idor", "authz",            # Access control
            "api", "graphql",                   # API security
            "jwt", "auth", "oauth",             # Authentication
            "business",                         # Logic flaws
            "race",                             # Race conditions
            "ssrf", "lfi",                      # Server-side
            "open_redirect",                    # Redirect issues
            "info_disclosure",                  # Info leaks
            "clickjacking",                     # UI redressing
        ],

        # Smart scan - most common high-value modules with reasonable timeout
        "smart": ["sqli", "xss", "headers", "ssl", "cors", "dir", "auth", "api", "idor"],

        # TOP TIER BOUNTY HUNTING - Maximum bounty potential modules
        # Focus on: IDOR/BOLA ($3k-$20k), Access Control, SQLi, XSS
        "bounty": [
            "idor",           # IDOR/BOLA detection - TOP VALUE $3k-$20k
            "sqli",           # SQL Injection - HIGH VALUE
            "xss",            # Reflected/Stored XSS
            "dom_xss",        # DOM-based XSS with browser execution
            "csrf",           # Cross-Site Request Forgery
            "authz",          # Authorization bypass
            "auth",           # Authentication vulnerabilities
            "jwt",            # JWT misconfigurations - HIGH VALUE
            "ssrf",           # Server-Side Request Forgery
            "business",       # Business logic flaws - HIGH VALUE
            "race",           # Race conditions - HIGH VALUE
            "mass_assign",    # Mass assignment
            "api",            # API security issues
            "graphql",        # GraphQL introspection/injection
            "open_redirect",  # Open redirects (chain potential)
            "cache_deception",  # Web cache deception
            "host_header",    # Host header attacks
            "supabase",       # Supabase RLS bypass
            "firebase",       # Firebase misconfigurations
            "rls_bypass",     # Row Level Security bypass
            "mobile",         # Mobile API vulnerabilities
        ],

        # BaaS (Backend-as-a-Service) focused scan
        "baas": ["supabase", "firebase", "rls_bypass", "backend", "third_party", "api"],

        # CLIENT - Professional engagement with ALL critical modules
        # For authorized pentests with no restrictions
        "client": [
            # Critical Injections (MUST run)
            "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
            "nosql", "ssti", "ldap", "crlf",
            # Authentication & Authorization
            "auth", "oauth", "saml", "mfa", "jwt", "authz", "idor",
            # API Security
            "api", "graphql", "grpc", "websocket", "sse",
            # Infrastructure
            "ssl", "headers", "cors", "cloud", "k8s", "dns_rebind",
            # Advanced Attacks
            "smuggling", "cache", "deser", "prototype", "cache_deception",
            # Business Logic
            "business", "race", "mass_assign", "ratelimit",
            # Discovery
            "dir", "cms", "nuclei", "backend", "third_party",
            # BaaS
            "supabase", "firebase", "rls_bypass",
            # Specialized
            "mobile", "email", "host_header", "clickjacking",
            "info_disclosure", "open_redirect", "file_upload",
            "cookie", "subdomain_takeover", "csrf",
        ],

        "full": list(ALL_MODULES.keys()),
    }
    
    def __init__(
        self,
        settings: "Settings",
        safe_mode: str = "safe",
        intelligent_mode: bool = True,
        oob_callback_domain: str = "",
    ) -> None:
        """
        Initialize full scanner.
        
        Args:
            settings: Application settings
            safe_mode: Safety level (passive, safe, cautious, standard, aggressive)
            intelligent_mode: Enable intelligent scanning infrastructure
            oob_callback_domain: Domain for OOB detection (optional)
        """
        self.settings = settings
        self.safe_mode = safe_mode
        self.intelligent_mode = intelligent_mode
        self.oob_callback_domain = oob_callback_domain
        self.loaded_modules: dict[str, Any] = {}

        # Initialize rate limiter for endpoint discovery
        from utils.rate_limiter import RateLimiter
        try:
            self.rate_limiter = RateLimiter(
                settings=settings,
                default_rate=getattr(getattr(settings, 'rate_limit', None), 'requests_per_second', 10.0),
                default_burst=getattr(getattr(settings, 'rate_limit', None), 'concurrent_scans', 20),
            )
        except Exception:
            # Fallback rate limiter
            self.rate_limiter = RateLimiter(default_rate=10.0, default_burst=20)

        # Track if protection was already verified (avoid duplicate checks)
        self._protection_verified = False

        # Import safe mode components
        from safe_mode import SafeScanner, SafetyLevel, EvidenceCollector
        from utils.evidence_engine import get_evidence_engine

        # Map safe mode string to enum
        level_map = {
            "passive": SafetyLevel.PASSIVE,
            "safe": SafetyLevel.SAFE,
            "cautious": SafetyLevel.CAUTIOUS,
            "standard": SafetyLevel.STANDARD,
            "aggressive": SafetyLevel.AGGRESSIVE,
        }

        self.safety_level = level_map.get(safe_mode, SafetyLevel.SAFE)
        self.safe_scanner = SafeScanner(safety_level=self.safety_level)
        self.evidence_collector = EvidenceCollector()

        # Initialize Evidence Engine v3.0 for comprehensive evidence collection
        # This provides automatic screenshots, timeline reconstruction, and evidence packages
        self.evidence_engine = get_evidence_engine()
        self._evidence_session = None
        
        # Initialize target classifier
        self.target_classifier = None
        self.classification = None

        # Initialize intelligent scanning components
        self.intelligent_scanner = None
        self.intelligent_context = None

        # Initialize enterprise technology intelligence
        self.tech_intelligence = None
        self.tech_analysis = None

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

        logger.info(
            f"FullScanner v{self.VERSION} initialized: "
            f"{len(self.ALL_MODULES)} modules, safe_mode={safe_mode}, intelligent={intelligent_mode}"
        )
    
    def _load_module(self, name: str) -> Optional[Any]:
        """Dynamically load a scanner module."""
        if name in self.loaded_modules:
            return self.loaded_modules[name]
        
        if name not in self.ALL_MODULES:
            logger.warning(f"Unknown module: {name}")
            return None
        
        module_path = self.ALL_MODULES[name]
        
        try:
            parts = module_path.rsplit(".", 1)
            module_name, class_name = parts[0], parts[1]
            
            import importlib
            mod = importlib.import_module(module_name)
            cls = getattr(mod, class_name)
            
            instance = cls(self.settings)
            self.loaded_modules[name] = instance
            logger.debug(f"Loaded module: {name}")
            return instance
            
        except Exception as e:
            logger.warning(f"Failed to load module {name}: {e}")
            return None
    
    async def scan(
        self,
        target: str,
        category: str = "web",
        modules: Optional[list[str]] = None,
        concurrent: int = 5,
        skip_classification: bool = False,
        use_linux_tools: bool = True,  # ENABLED BY DEFAULT - tools run before modules
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

        Returns:
            ScanResult with all findings

        New Features (v2.0):
            - Phase 2.5: Linux tools orchestration with intelligent chaining
            - Phase 4.3: Vulnerability chain engine (SQLi→RCE, LFI→Secrets, etc.)
        """
        result = ScanResult(
            target=target,
            start_time=datetime.now(),
            safe_mode=self.safe_mode,
            intelligent_mode=self.intelligent_mode,
        )

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

        # Phase 0: Target Classification (INTELLIGENCE BEFORE BRUTE FORCE)
        skipped_modules = []
        skip_reasons = {}
        
        if self.intelligent_mode and self.target_classifier and not skip_classification:
            try:
                logger.info("🎯 Phase 0: Target Classification...")
                self.classification = await self.target_classifier.classify(target)
                
                # Log classification result (professional name)
                logger.info(f"   Target Type: {self.classification.target_type.display_name}")
                logger.info(f"   Confidence: {self.classification.confidence:.0%}")
                logger.info(f"   Technologies: {self.classification.detected_technologies}")
                logger.info(f"   Skip Modules: {len(self.classification.skip_modules)}")

                # Store classification in result
                result.info.append({
                    "type": "target_classification",
                    "target_type": self.classification.target_type.display_name,  # Professional name
                    "target_type_code": self.classification.target_type.value,    # Internal code
                    "scope_description": self.classification.target_type.scope_description,
                    "confidence": self.classification.confidence,
                    "technologies": self.classification.detected_technologies,
                    "frameworks": self.classification.detected_frameworks,
                    "server": self.classification.detected_server,
                    "cdn": self.classification.detected_cdn,
                    "recommended_modules": self.classification.recommended_modules,
                    "skip_modules": self.classification.skip_modules,
                    "skip_reasons": self.classification.skip_reasons,
                })

                # Sync classification to result fields
                result.target_classification = self.classification.target_type.display_name
                result.target_type_code = self.classification.target_type.value
                result.classification_confidence = self.classification.confidence
                result.modules_skipped = self.classification.skip_modules
                result.skip_reasons = self.classification.skip_reasons

                skipped_modules = self.classification.skip_modules
                skip_reasons = self.classification.skip_reasons

                # Phase 0.5: Enterprise Technology Intelligence (enhanced detection)
                if self.tech_intelligence:
                    try:
                        logger.info("🔬 Phase 0.5: Enterprise Technology Intelligence...")
                        self.tech_analysis = await self.tech_intelligence.analyze(target, deep_scan=True)

                        if self.tech_analysis.technologies:
                            tech_names = [f"{t.name} {t.version}".strip() for t in self.tech_analysis.technologies]
                            logger.info(f"   Detected Technologies: {tech_names}")
                            logger.info(f"   Overall Confidence: {self.tech_analysis.confidence_overall:.0%}")

                            # Check for EOL/vulnerable technologies
                            if self.tech_analysis.eol_technologies:
                                logger.warning(f"   ⚠️ EOL Technologies: {self.tech_analysis.eol_technologies}")
                                result.info.append({
                                    "type": "eol_warning",
                                    "message": "End-of-life technologies detected",
                                    "technologies": self.tech_analysis.eol_technologies,
                                })

                            if self.tech_analysis.vulnerable_technologies:
                                for name, version, cves in self.tech_analysis.vulnerable_technologies:
                                    logger.warning(f"   🚨 Vulnerable: {name} {version} - CVEs: {cves}")
                                result.info.append({
                                    "type": "known_vulnerabilities",
                                    "message": "Technologies with known CVEs detected",
                                    "vulnerabilities": [
                                        {"tech": n, "version": v, "cves": c}
                                        for n, v, c in self.tech_analysis.vulnerable_technologies
                                    ],
                                })

                            # Merge module recommendations from TechIntelligence
                            # (TechIntelligence is more specific, so prioritize it)
                            for mod in self.tech_analysis.skip_modules:
                                if mod not in skipped_modules:
                                    skipped_modules.append(mod)
                                if mod in self.tech_analysis.skip_reasons and mod not in skip_reasons:
                                    skip_reasons[mod] = self.tech_analysis.skip_reasons[mod]

                            logger.info(f"   Recommended Modules: {len(self.tech_analysis.recommended_modules)}")
                            logger.info(f"   Skip Modules: {len(self.tech_analysis.skip_modules)}")

                            # Store tech analysis in result
                            result.info.append({
                                "type": "tech_intelligence",
                                "version": self.tech_intelligence.VERSION,
                                "technologies": [t.to_dict() for t in self.tech_analysis.technologies],
                                "tech_stack": self.tech_analysis.tech_stack,
                                "recommended_modules": self.tech_analysis.recommended_modules,
                                "skip_modules": self.tech_analysis.skip_modules,
                                "analysis_time": self.tech_analysis.analysis_time,
                            })
                        else:
                            logger.info("   No technologies detected via enterprise intelligence")

                    except Exception as e:
                        logger.warning(f"TechIntelligence analysis failed: {e}")

                # Phase 0.7: Smart Endpoint Discovery (NEW - Replaces hardcoded patterns)
                try:
                    from reconnaissance.smart_discovery import SmartEndpointDiscovery, DiscoveryConfig
                    from utils.endpoint_map import EndpointMap

                    logger.info("🗺️ Phase 0.7: Smart Endpoint Discovery...")

                    # Reset endpoint map for new scan
                    EndpointMap.reset()

                    # Get detected technologies
                    technologies = []
                    if self.classification:
                        technologies.extend(self.classification.detected_technologies)
                        technologies.extend(self.classification.detected_frameworks)
                    if self.tech_analysis and self.tech_analysis.technologies:
                        technologies.extend([t.name for t in self.tech_analysis.technologies])

                    # Configure discovery
                    discovery_config = DiscoveryConfig(
                        parse_sitemap=True,
                        parse_robots=True,
                        parse_openapi=True,
                        parse_graphql=True,
                        use_wayback=True,
                        tech_based_inference=bool(technologies),
                        verify_endpoints=True,
                    )

                    discovery = SmartEndpointDiscovery(self.settings, discovery_config)
                    endpoint_map = await discovery.discover(target, self.rate_limiter, technologies)

                    stats = endpoint_map.get_statistics()
                    result.endpoints_discovered = stats['total_endpoints']

                    logger.info(f"   Total Endpoints: {stats['total_endpoints']}")
                    logger.info(f"   Verified: {stats['verified']}")
                    if stats['by_source']:
                        for source, count in stats['by_source'].items():
                            if count > 0:
                                logger.info(f"   - {source}: {count}")

                    result.info.append({
                        "type": "smart_discovery",
                        "version": SmartEndpointDiscovery.VERSION,
                        "statistics": stats,
                    })

                except Exception as e:
                    logger.warning(f"Smart Endpoint Discovery failed: {e}")

            except Exception as e:
                logger.warning(f"Target classification failed: {e}")
                self.classification = None

        # Phase 1: Verify network protection
        await self._verify_network_protection(result)

        # Phase 2: Intelligent pre-scan analysis
        if self.intelligent_mode and self.intelligent_scanner:
            should_continue = await self._run_intelligent_pre_scan(target, result)
            if not should_continue:
                return result

        # Determine modules to run
        module_names = modules if modules else self.CATEGORIES.get(category, self.CATEGORIES["web"])
        original_count = len(module_names)

        # Track what was requested vs what will run
        result.modules_requested = list(module_names)

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

        if use_linux_tools:
            await self._run_linux_tools_scan(result, target)

        # Phase 3: Execute modules
        module_results = await self._execute_modules(target, module_names, concurrent)

        # Phase 4: Aggregate and validate results
        self._aggregate_results(result, module_names, module_results)

        # Phase 4.3: Vulnerability chain processing
        # Process findings to discover additional vulnerabilities through chaining
        await self._process_vulnerability_chains(result, target)

        # Phase 4.5: Cross-module deduplication
        self._deduplicate_findings(result)

        # Phase 5: Finalize intelligent scan
        self._finalize_intelligent_scan(result)

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
                            finding_type=finding.get("type", "unknown"),
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

        result.end_time = datetime.now()
        logger.info(
            f"Scan complete: {len(result.findings)} findings, "
            f"{len(result.modules_run)}/{len(module_names)} modules successful"
        )

        return result

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

    async def _execute_modules(
        self,
        target: str,
        module_names: list[str],
        concurrent: int,
    ) -> list[dict | Exception]:
        """Execute scanning modules with concurrency control."""
        semaphore = asyncio.Semaphore(concurrent)

        # Heavy modules need more time
        HEAVY_MODULES = {'sqli', 'xss', 'nosql', 'cmdi', 'lfi', 'ssrf', 'auth', 'ssti', 'graphql', 'api', 'smuggling'}

        # Get timeouts from settings
        try:
            timeout_heavy = getattr(self.settings.timeouts, 'module_heavy', 900)
            timeout_normal = getattr(self.settings.timeouts, 'module_normal', 600)
        except AttributeError:
            timeout_heavy = 900
            timeout_normal = 600

        logger.debug(f"Module timeouts: heavy={timeout_heavy}s, normal={timeout_normal}s")
        module_instances: dict[str, Any] = {}

        async def run_module(name: str) -> dict:
            async with semaphore:
                module = self._load_module(name)
                if module:
                    module_instances[name] = module

                try:
                    timeout = timeout_heavy if name in HEAVY_MODULES else timeout_normal
                    return await asyncio.wait_for(
                        self._run_single_module_with_instance(name, target, module),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    timeout = timeout_heavy if name in HEAVY_MODULES else timeout_normal
                    logger.warning(f"Module {name} timed out after {timeout}s")

                    # Recover partial findings
                    partial_findings = []
                    if name in module_instances:
                        instance = module_instances[name]
                        if hasattr(instance, 'get_partial_findings'):
                            try:
                                partial_findings = instance.get_partial_findings()
                                if partial_findings:
                                    logger.info(f"🔄 Recovered {len(partial_findings)} partial findings from {name}")
                            except Exception as e:
                                logger.warning(f"Failed to get partial findings from {name}: {e}")

                    return {
                        "findings": partial_findings,
                        "info": [],
                        "error": f"timeout after {timeout}s (recovered {len(partial_findings)} findings)"
                    }

        tasks = [run_module(name) for name in module_names]
        return await asyncio.gather(*tasks, return_exceptions=True)

    def _aggregate_results(
        self,
        result: ScanResult,
        module_names: list[str],
        module_results: list[dict | Exception],
    ) -> None:
        """Aggregate module results with intelligent validation."""
        for i, mod_result in enumerate(module_results):
            module_name = module_names[i]

            if isinstance(mod_result, Exception):
                result.errors.append({
                    "module": module_name,
                    "error": str(mod_result),
                })
                continue

            result.modules_run.append(module_name)

            for finding in mod_result.get("findings", []):
                # Apply intelligent validation if enabled
                if self.intelligent_mode and self.intelligent_context:
                    finding = self._validate_finding_intelligent(finding)

                    # Check if finding was discarded
                    is_discarded = False
                    if hasattr(finding, 'metadata') and finding.metadata:
                        is_discarded = finding.metadata.get("_discarded", False)
                    elif isinstance(finding, dict):
                        is_discarded = finding.get("_discarded", False)

                    if is_discarded:
                        result.tests_skipped += 1
                        continue
                    result.negative_control_validations += 1

                result.add_finding(finding)

                # Evidence Engine v3.0: Record finding in timeline
                if self._evidence_session:
                    finding_type = finding.get("type", "unknown") if isinstance(finding, dict) else "unknown"
                    severity = finding.get("severity", "MEDIUM") if isinstance(finding, dict) else "MEDIUM"
                    url = finding.get("url", finding.get("matched_at", "")) if isinstance(finding, dict) else ""
                    self.evidence_engine.add_timeline_event(
                        event_type="finding",
                        description=f"[{severity}] {finding_type} discovered by {module_name}",
                        url=url,
                        severity=severity,
                        details={"module": module_name, "finding_type": finding_type}
                    )

            result.info.extend(mod_result.get("info", []))

    def _deduplicate_findings(self, result: ScanResult) -> None:
        """
        Deduplicate findings across modules.

        This prevents the same issue being reported by multiple modules
        (e.g., CORS wildcard reported by both headers and cors modules).

        Deduplication key: (normalized_type, host, matched_at)
        """
        if not result.findings:
            return

        seen_keys: set[str] = set()
        unique_findings: list[dict] = []
        duplicates_removed = 0

        # Normalization mapping for finding types
        type_normalization = {
            "cors_wildcard": "cors",
            "cors_null": "cors",
            "cors_arbitrary": "cors",
            "cors_subdomain_inject": "cors",
            "cors_suffix_bypass": "cors",
            "cors_prefix_bypass": "cors",
            "insecure_header": "header_config",  # Separate from missing_header
            "missing_browser_hardening": "missing_headers",
        }

        for finding in result.findings:
            finding_type = finding.get("type", "unknown")
            normalized_type = type_normalization.get(finding_type, finding_type)
            host = finding.get("host", "")
            matched_at = finding.get("matched_at", "")

            # Create dedup key
            key = f"{normalized_type}:{host}:{matched_at}"

            if key not in seen_keys:
                seen_keys.add(key)
                unique_findings.append(finding)
            else:
                duplicates_removed += 1
                logger.debug(f"Deduplicated finding: {finding_type} at {matched_at}")

        if duplicates_removed > 0:
            logger.info(f"🔄 Deduplicated {duplicates_removed} cross-module findings")

        result.findings = unique_findings

    async def _process_vulnerability_chains(self, result: ScanResult, target: str) -> None:
        """
        Process findings through vulnerability chain engine.

        This implements the "vulnerabilities discover vulnerabilities" paradigm:
        - SQLi confirmed → attempt RCE via UDF/COPY
        - LFI confirmed → extract sensitive files
        - IDOR confirmed → enumerate all accessible resources
        - Auth bypass → test privileged endpoints
        """
        if not self.chain_engine:
            logger.debug("Chain engine not available, skipping vulnerability chaining")
            return

        if not result.findings:
            return

        logger.info("🔗 Processing vulnerability chains...")

        # Set up chain engine context
        technologies = []
        if self.tech_analysis and hasattr(self.tech_analysis, 'technologies'):
            technologies = [t.name for t in self.tech_analysis.technologies]

        endpoints = []
        if self.intelligent_context and hasattr(self.intelligent_context, 'endpoints_discovered'):
            endpoints = self.intelligent_context.endpoints_discovered

        self.chain_engine.context = {
            "target": target,
            "technologies": technologies,
            "endpoints": endpoints,
            "safe_mode": self.safe_mode,
        }

        # Process each finding for potential chains
        chain_findings = []
        for finding in result.findings:
            try:
                # Convert Finding dataclass to dict if needed
                if hasattr(finding, 'to_dict'):
                    finding_dict = finding.to_dict()
                elif hasattr(finding, '__dataclass_fields__'):
                    from dataclasses import asdict
                    finding_dict = asdict(finding)
                else:
                    finding_dict = finding

                # Process through chain engine
                new_findings = await self.chain_engine.process_finding(finding_dict)

                if new_findings:
                    result.chains_triggered += 1
                    for new_finding in new_findings:
                        # Mark as chain-discovered
                        if isinstance(new_finding, dict):
                            new_finding["chain_source"] = finding_dict.get("type", "unknown")
                            new_finding["discovered_via"] = "vulnerability_chain"
                        chain_findings.append(new_finding)

            except Exception as e:
                logger.debug(f"Chain processing error for finding: {e}")

        # Add chain-discovered findings
        if chain_findings:
            result.chain_findings = len(chain_findings)
            result.escalations_attempted = self.chain_engine.escalations_attempted if hasattr(self.chain_engine, 'escalations_attempted') else 0
            for cf in chain_findings:
                result.add_finding(cf)
            logger.info(f"🔗 Chain engine discovered {len(chain_findings)} additional findings")
        else:
            logger.debug("No chain escalations triggered")

    async def _run_linux_tools_scan(self, result: ScanResult, target: str) -> None:
        """
        Run Linux security tools orchestration.

        This integrates external tools like nmap, nuclei, nikto, gobuster, etc.
        with intelligent tool chaining (nmap results → trigger nikto/nuclei).

        Tools integrated:
        - nmap/masscan: Port scanning and service detection
        - nuclei: Template-based vulnerability scanning
        - nikto: Web server scanning
        - gobuster/ffuf: Directory brute-forcing
        - testssl/sslscan: SSL/TLS analysis
        - whatweb/httpx: Technology detection
        - arjun: Parameter discovery
        - sqlmap: SQL injection exploitation
        """
        try:
            from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator

            logger.info("🔧 Phase 2.5: Linux Tools Orchestration...")

            # Initialize orchestrator with settings
            orchestrator = LinuxToolsOrchestrator(self.settings)

            # Log available tools
            available = orchestrator.available_tools
            logger.info(f"   Available tools: {len(available)}/{13} ({', '.join(sorted(available)[:5])}...)")

            # Run intelligent scan with tool chaining
            tool_findings = await orchestrator.run_intelligent_scan(target, depth=2)

            if tool_findings:
                logger.info(f"   Linux tools discovered {len(tool_findings)} findings")

                # Store findings for passing to modules
                self._linux_tool_findings = tool_findings

                # Extract endpoints and parameters from tool findings for modules
                for finding in tool_findings:
                    finding_type = finding.get("type", "") if isinstance(finding, dict) else ""
                    metadata = finding.get("metadata", {}) if isinstance(finding, dict) else {}

                    # Extract endpoints from gobuster/ffuf/nuclei
                    if finding_type in ["directory_found", "ffuf_finding", "nuclei_finding"]:
                        path = metadata.get("path", finding.get("matched_at", ""))
                        if path:
                            self._tool_discovered_endpoints.append(path)

                    # Extract parameters from arjun
                    if finding_type == "arjun_parameters":
                        url = metadata.get("url", "")
                        params = metadata.get("parameters", [])
                        if url and params:
                            self._tool_discovered_params[url] = params

                    # Mark as tool-discovered and add to results
                    if isinstance(finding, dict):
                        finding["discovered_via"] = "linux_tools"
                    result.add_finding(finding)

                    # Also process through chain engine
                    if self.chain_engine:
                        try:
                            chain_results = await self.chain_engine.process_finding(finding)
                            for cf in chain_results:
                                cf["chain_source"] = finding.get("type", "linux_tool")
                                cf["discovered_via"] = "linux_tool_chain"
                                result.add_finding(cf)
                        except Exception as e:
                            logger.debug(f"Chain processing for tool finding failed: {e}")

                logger.info(f"   Extracted: {len(self._tool_discovered_endpoints)} endpoints, {len(self._tool_discovered_params)} param sets")

                # Get orchestrator statistics
                stats = orchestrator.get_statistics() if hasattr(orchestrator, 'get_statistics') else {}

                result.info.append({
                    "type": "linux_tools_scan",
                    "findings_count": len(tool_findings),
                    "tools_executed": list(orchestrator.executed_tools) if hasattr(orchestrator, 'executed_tools') else [],
                    "tools_available": list(orchestrator.available_tools) if hasattr(orchestrator, 'available_tools') else [],
                    "findings_by_severity": stats.get("findings_by_severity", {}),
                })

                # Log severity breakdown
                severity_counts = stats.get("findings_by_severity", {})
                if severity_counts:
                    logger.info(f"   Severity: C:{severity_counts.get('CRITICAL', 0)} H:{severity_counts.get('HIGH', 0)} M:{severity_counts.get('MEDIUM', 0)}")
            else:
                logger.info("   No findings from Linux tools")

        except ImportError:
            logger.warning("Linux tools orchestrator not available")
        except Exception as e:
            logger.error(f"Linux tools scan failed: {e}")
            result.errors.append({
                "phase": "linux_tools",
                "error": str(e),
            })

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
        
        Checks:
        - Confidence meets threshold
        - Parameter context is appropriate for attack type
        - Finding has required evidence
        """
        if not self.intelligent_context or not self.intelligent_scanner:
            return finding
        
        # Handle both dict and Finding dataclass objects
        if hasattr(finding, 'confidence'):
            # It's a Finding dataclass
            confidence_val = finding.confidence if finding.confidence else 50
            # Ensure confidence is a float
            try:
                confidence = float(confidence_val) if confidence_val else 50.0
            except (ValueError, TypeError):
                confidence = 50.0
            
            vuln_type = finding.type or ""
            param = getattr(finding, 'parameter', '') or (finding.metadata.get('parameter', '') if finding.metadata else '')
            url = finding.host or finding.matched_at or ""
            
            # Check minimum confidence
            if confidence < self.intelligent_scanner.config.min_confidence:
                if finding.metadata is None:
                    finding.metadata = {}
                finding.metadata["_discarded"] = True
                finding.metadata["_discard_reason"] = f"Low confidence: {confidence}"
                return finding
            
            # Check parameter context
            if param and url:
                should_test, reason = self.intelligent_scanner.should_test_parameter(
                    self.intelligent_context,
                    url,
                    param,
                    vuln_type
                )
                if not should_test:
                    if finding.metadata is None:
                        finding.metadata = {}
                    finding.metadata["_discarded"] = True
                    finding.metadata["_discard_reason"] = reason
                    return finding
        else:
            # It's a dict
            confidence_val = finding.get("confidence", finding.get("confidence_score", 50))
            # Ensure confidence is a float
            try:
                confidence = float(confidence_val) if confidence_val else 50.0
            except (ValueError, TypeError):
                confidence = 50.0
            
            # Check minimum confidence
            if confidence < self.intelligent_scanner.config.min_confidence:
                finding["_discarded"] = True
                finding["_discard_reason"] = f"Low confidence: {confidence}"
                return finding
            
            # Check parameter context
            vuln_type = finding.get("vulnerability_type", finding.get("type", ""))
            param = finding.get("parameter", "")
            url = finding.get("url", "")
            
            if param and url:
                should_test, reason = self.intelligent_scanner.should_test_parameter(
                    self.intelligent_context,
                    url,
                    param,
                    vuln_type
                )
                if not should_test:
                    finding["_discarded"] = True
                    finding["_discard_reason"] = reason
                    return finding
        
        return finding

    async def _run_single_module(
        self,
        name: str,
        target: str,
    ) -> dict:
        """Run a single scanner module."""
        module = self._load_module(name)
        return await self._run_single_module_with_instance(name, target, module)
    
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
            
            # Build asset_data with discovered endpoints, parameters, and technologies
            asset_data = {}

            # Collect detected technologies for modules to use
            detected_technologies = []
            if self.classification and self.classification.detected_technologies:
                detected_technologies.extend(self.classification.detected_technologies)
            if self.tech_analysis and self.tech_analysis.technologies:
                detected_technologies.extend([t.name for t in self.tech_analysis.technologies])
            # Deduplicate
            detected_technologies = list(set(detected_technologies))

            if self.intelligent_context and self.intelligent_context.endpoints_discovered:
                asset_data = {
                    "endpoints": self.intelligent_context.endpoints_discovered or [],
                    "parameters": list(self.intelligent_context.parameter_analysis.keys()) if self.intelligent_context.parameter_analysis else [],
                    "forms": [],  # Could be populated by a form discovery phase
                    "technologies": detected_technologies,  # For nuclei template selection, etc.
                }
                logger.debug(f"Using {len(asset_data['endpoints'])} discovered endpoints for module {name}")
            else:
                # Fallback: use target as endpoint
                asset_data = {
                    "endpoints": [target],
                    "parameters": [],
                    "forms": [],
                    "technologies": detected_technologies,
                }
                logger.debug(f"Using target URL as single endpoint for module {name}")

            # ENHANCEMENT: Add Linux tool discoveries to asset_data
            # This ensures modules know about what tools found (arjun params, gobuster paths, etc.)
            if hasattr(self, '_tool_discovered_endpoints') and self._tool_discovered_endpoints:
                existing = set(asset_data["endpoints"])
                new_endpoints = [e for e in self._tool_discovered_endpoints if e not in existing]
                asset_data["endpoints"].extend(new_endpoints)
                if new_endpoints:
                    logger.debug(f"Added {len(new_endpoints)} tool-discovered endpoints for module {name}")

            if hasattr(self, '_tool_discovered_params') and self._tool_discovered_params:
                asset_data["tool_discovered_params"] = self._tool_discovered_params

            if hasattr(self, '_linux_tool_findings') and self._linux_tool_findings:
                asset_data["tool_findings"] = self._linux_tool_findings

            # CRITICAL: Also merge EndpointMap endpoints into asset_data
            # This ensures all modules have access to SmartEndpointDiscovery results
            try:
                from utils.endpoint_map import EndpointMap
                from urllib.parse import urlparse

                endpoint_map = EndpointMap.get_instance()
                if endpoint_map and len(endpoint_map) > 0:
                    host = endpoint_map.get_host()
                    if not host:
                        parsed = urlparse(target)
                        host = parsed.netloc

                    parsed_target = urlparse(target)
                    scheme = parsed_target.scheme or "https"

                    existing = set(asset_data["endpoints"])
                    for ep in endpoint_map:
                        full_url = ep.get_full_url(host, scheme)
                        if full_url and full_url not in existing:
                            asset_data["endpoints"].append(full_url)
                            existing.add(full_url)

                    # Also add api_endpoints key for modules that specifically look for it
                    api_endpoints = []
                    for ep in endpoint_map.get_for_scanner("api_scanner"):
                        full_url = ep.get_full_url(host, scheme)
                        if full_url:
                            api_endpoints.append(full_url)
                    if api_endpoints:
                        asset_data["api_endpoints"] = api_endpoints
            except Exception as e:
                logger.debug(f"EndpointMap merge to asset_data skipped: {e}")

            # Add shared findings store for inter-module communication
            # Modules can query this to see what other modules have found
            asset_data["shared_findings_store"] = get_shared_findings()

            # Run the scan - try different method signatures
            result = None

            def is_signature_mismatch(error: TypeError) -> bool:
                """Check if TypeError is about wrong number/type of arguments."""
                err_msg = str(error).lower()
                signature_indicators = [
                    "positional argument",
                    "required argument",
                    "unexpected keyword argument",
                    "takes",
                    "got an unexpected",
                    "missing",
                ]
                return any(indicator in err_msg for indicator in signature_indicators)

            # Set rate_limiter attribute on module if it uses one
            # Some modules (jwt, race, etc.) use self.rate_limiter internally
            if hasattr(module, "rate_limiter") or name in {"jwt", "race", "host_header", "clickjacking", "file_upload"}:
                try:
                    module.rate_limiter = rate_limiter
                except AttributeError:
                    pass  # Read-only or no such attribute

            # Extract endpoints list for modules that expect List[str] instead of dict
            endpoints_list = asset_data.get("endpoints", [target])

            # Module interface categorization:
            # STRING_ENDPOINTS: Expect endpoints: List[str] - pass endpoints_list
            # TYPED_ENDPOINTS: Expect endpoints: List[SomeDataclass] - pass None (let them create defaults)
            # SIMPLE_INTERFACE: Only take target and **kwargs
            # OLD_3ARG_INTERFACE: Expect (target, asset_data, rate_limiter) - MUST pass all 3
            STRING_ENDPOINTS_MODULES = {"jwt", "cookie"}
            TYPED_ENDPOINTS_MODULES = {"race", "host_header", "clickjacking", "file_upload"}
            SIMPLE_INTERFACE_MODULES = {"cache_deception", "info_disclosure", "open_redirect"}
            # Modules that REQUIRE (host, asset_data, rate_limiter) signature
            # Generated from: grep -l "rate_limiter: RateLimiter" scanning/modules/*.py
            OLD_3ARG_MODULES = {
                # Injection scanners
                "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
                "nosql", "ssti", "ldap", "crlf",
                # Auth/API modules  
                "auth", "oauth", "saml", "authz", "idor", "api", "graphql",
                "mfa", "ratelimit", "grpc", "sse", "websocket",
                # Infrastructure
                "ssl", "headers", "cors", "cloud", "k8s", "dns_rebind",
                "smuggling", "cache", "deser", "prototype",
                # Discovery & CMS
                "dir", "cms", "nuclei", "backend",
                # Business logic
                "business", "mass_assign",
                # Other critical modules
                "mobile", "email", "subdomain_takeover",
                "llm", "post_exploit",
            }

            if hasattr(module, "scan"):
                try:
                    if name in OLD_3ARG_MODULES:
                        # These modules REQUIRE all 3 arguments - no fallback
                        result = await module.scan(target, asset_data, rate_limiter)
                    elif name in STRING_ENDPOINTS_MODULES:
                        # Pass endpoints as List[str]
                        result = await module.scan(target, endpoints=endpoints_list)
                    elif name in TYPED_ENDPOINTS_MODULES:
                        # Let module create typed endpoints from target (pass None)
                        result = await module.scan(target)
                    elif name in SIMPLE_INTERFACE_MODULES:
                        # Simple interface: just target
                        result = await module.scan(target)
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

            # Share findings with other modules via SharedFindingsStore
            # This enables inter-module communication for smarter testing
            shared_store = get_shared_findings()
            for f in findings:
                if isinstance(f, dict) and f.get("type"):
                    try:
                        await shared_store.add_finding(f, module=name)
                    except Exception as e:
                        logger.debug(f"Could not share finding: {e}")

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
        """Get list of all available modules."""
        return list(self.ALL_MODULES.keys())
    
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
    
    def get_attack_recommendations(self, url: str) -> Dict[str, List[str]]:
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
