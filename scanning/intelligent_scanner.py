"""
Intelligent Scanner Integration v1.0.0-ENTERPRISE
===================================================

Integra TODOS os componentes de infraestrutura:
- Scope Guard (proteção legal)
- Method Discovery (só testar o que existe)
- Parameter Analyzer (payloads certos para contextos certos)
- Negative Control (eliminar falsos positivos)
- Finding Lifecycle (gestão profissional de findings)
- OOB Engine (detecção de blind vulnerabilities)

Esta é a camada que faz tudo funcionar junto!
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.scope_guard import (
    ScopeGuard,
    ScopeDefinition,
    ScopeViolation,
    ScopeViolationType,
    ScopeMode,
)
from utils.method_discovery import (
    MethodDiscoveryEngine,
    MethodDiscoveryResult,
    HTTPMethod,
    EndpointSource,
)
from utils.parameter_analyzer import (
    ParameterContextAnalyzer,
    ParameterProfile,
    ContextAnalysisResult,
    ParameterType,
    AttackRecommendation,
)
from utils.negative_control import (
    NegativeControlEngine,
    NegativeControlPayloads,
    PayloadPair,
    PayloadCategory,
    SignalType,
    SmartPayloadSelector,
)
from utils.finding_lifecycle import (
    FindingManager,
    Finding,
    FindingState,
    Evidence,
    EvidenceType,
    Severity,
)
from utils.oob_engine import (
    OOBEngine,
    OOBProtocol,
)

logger = logging.getLogger(__name__)


@dataclass
class IntelligentScanConfig:
    """Configuration for intelligent scanning"""
    # Scope settings
    include_subdomains: bool = True
    scope_mode: ScopeMode = ScopeMode.STRICT
    
    # Method discovery
    discover_methods: bool = True
    discover_forms: bool = True
    discover_js_endpoints: bool = True
    
    # Parameter analysis
    analyze_parameters: bool = True
    skip_non_testable: bool = True
    
    # Negative control
    use_negative_control: bool = True
    min_confidence: float = 60.0
    
    # OOB detection
    enable_oob: bool = True
    oob_callback_domain: str = ""
    oob_callback_port: int = 8888
    
    # Finding management
    require_minimum_evidence: bool = True
    auto_discard_low_confidence: bool = True
    
    # Concurrency
    max_concurrent_requests: int = 10
    request_delay_ms: int = 100


@dataclass
class IntelligentScanContext:
    """Context for an intelligent scan"""
    target: str
    config: IntelligentScanConfig

    # Components
    scope_guard: Optional[ScopeGuard] = None
    method_discovery: Optional[MethodDiscoveryResult] = None
    parameter_analysis: Dict[str, ContextAnalysisResult] = field(default_factory=dict)
    finding_manager: Optional[FindingManager] = None
    oob_engine: Optional[OOBEngine] = None

    # Runtime state
    endpoints_discovered: List[str] = field(default_factory=list)
    parameters_analyzed: int = 0
    tests_executed: int = 0
    tests_skipped: int = 0
    scope_violations: List[ScopeViolation] = field(default_factory=list)

    # SPA/Browser analysis
    spa_analysis: Optional[Dict[str, Any]] = None

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class IntelligentScanner:
    """
    Intelligent Scanner - The Brain of the Framework
    
    Coordinates all infrastructure components to deliver:
    - Zero false positives (negative control)
    - Context-aware testing (parameter analyzer)
    - Legal compliance (scope guard)
    - Blind vulnerability detection (OOB engine)
    - Professional findings (lifecycle manager)
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    def __init__(
        self,
        settings: Any,
        config: Optional[IntelligentScanConfig] = None
    ):
        """
        Initialize intelligent scanner
        
        Args:
            settings: Application settings
            config: Intelligent scan configuration
        """
        self.settings = settings
        self.config = config or IntelligentScanConfig()
        
        # Initialize components
        self.parameter_analyzer = ParameterContextAnalyzer()
        self.payload_selector = SmartPayloadSelector()
        
        logger.info(f"IntelligentScanner v{self.VERSION} initialized")
    
    async def prepare_scan(self, target: str) -> IntelligentScanContext:
        """
        Prepare scan context with all pre-scan analysis
        
        This runs BEFORE any actual vulnerability testing:
        1. Validate scope
        2. Discover methods
        3. Analyze parameters
        4. Initialize finding manager
        5. Start OOB engine
        """
        ctx = IntelligentScanContext(
            target=target,
            config=self.config,
            start_time=datetime.now()
        )
        
        logger.info(f"Preparing intelligent scan for: {target}")
        
        # 1. Initialize Scope Guard
        ctx.scope_guard = self._init_scope_guard(target)
        
        # 2. Validate target is in scope
        allowed, violation = ctx.scope_guard.is_allowed(target)
        if not allowed:
            logger.error(f"Target not in scope: {violation.reason}")
            ctx.scope_violations.append(violation)
            raise ScopeViolationError(f"Target blocked: {violation.reason}")
        
        # 3. Initialize Finding Manager
        ctx.finding_manager = FindingManager()
        
        # 4. Initialize OOB Engine (if enabled)
        if self.config.enable_oob and self.config.oob_callback_domain:
            ctx.oob_engine = OOBEngine(
                callback_domain=self.config.oob_callback_domain,
                callback_port=self.config.oob_callback_port
            )
            logger.info(f"OOB Engine initialized: {self.config.oob_callback_domain}")
        
        # 5. Discover HTTP methods and endpoints
        if self.config.discover_methods:
            ctx.method_discovery = await self._discover_methods(target)
            ctx.endpoints_discovered = [
                ep.url for ep in ctx.method_discovery.discovered_endpoints
            ]

            # 5.1 Deep crawl - follow links to discover more endpoints with parameters
            ctx.endpoints_discovered = await self._deep_crawl_endpoints(
                target, ctx.endpoints_discovered, max_depth=2
            )

            # 5.2 Browser-based SPA crawl (CRITICAL for modern apps)
            # Increased timeout to 60s for complex SPAs - endpoint discovery is critical
            try:
                spa_result = await self._browser_crawl_spa(target, timeout=60)

                # Add API endpoints found by browser
                for api_ep in spa_result.get("api_endpoints", []):
                    url = api_ep.get("url", "")
                    if url and url not in ctx.endpoints_discovered:
                        ctx.endpoints_discovered.append(url)

                # Store SPA analysis in context
                ctx.spa_analysis = spa_result

                # Log findings
                if spa_result.get("login_detected"):
                    logger.info("   🔐 Login/Auth detected via browser analysis")
                if spa_result.get("api_endpoints"):
                    logger.info(f"   📡 {len(spa_result['api_endpoints'])} API endpoints found via browser")
                if spa_result.get("auth_tokens"):
                    logger.info(f"   🔑 {len(spa_result['auth_tokens'])} auth tokens found in storage")

            except Exception as e:
                logger.debug(f"SPA crawl skipped: {e}")

            logger.info(f"Discovered {len(ctx.endpoints_discovered)} endpoints via IntelligentScanner")

        # 5.3 CRITICAL: Merge endpoints from SmartEndpointDiscovery's EndpointMap
        # SmartEndpointDiscovery (Phase 0.7) often finds many more endpoints than local crawling
        try:
            from utils.endpoint_map import EndpointMap
            from urllib.parse import urlparse
            endpoint_map = EndpointMap.get_instance()

            if endpoint_map and endpoint_map._endpoints:
                # Get host from EndpointMap or extract from target
                host = endpoint_map.get_host()
                if not host:
                    parsed = urlparse(target)
                    host = parsed.netloc

                # Determine scheme from target
                parsed_target = urlparse(target)
                scheme = parsed_target.scheme or "https"

                # Construct full URLs from paths
                map_endpoints = []
                for ep in endpoint_map._endpoints.values():
                    full_url = ep.get_full_url(host, scheme)
                    if full_url:
                        map_endpoints.append(full_url)

                # Merge unique endpoints
                existing = set(ctx.endpoints_discovered)
                new_from_map = [ep for ep in map_endpoints if ep not in existing]

                if new_from_map:
                    ctx.endpoints_discovered.extend(new_from_map)
                    logger.info(f"   ✓ Merged {len(new_from_map)} endpoints from SmartEndpointDiscovery")
                    logger.info(f"   Total endpoints after merge: {len(ctx.endpoints_discovered)}")
        except Exception as e:
            logger.debug(f"EndpointMap merge skipped: {e}")

        # 6. Analyze parameters for the main target
        if self.config.analyze_parameters:
            ctx.parameter_analysis[target] = self.parameter_analyzer.analyze_url(target)
            ctx.parameters_analyzed = ctx.parameter_analysis[target].total_params
            logger.info(f"Analyzed {ctx.parameters_analyzed} parameters")

        return ctx
    
    def _init_scope_guard(self, target: str) -> ScopeGuard:
        """Initialize scope guard for target"""
        scope = ScopeDefinition.from_target(
            target,
            include_subdomains=self.config.include_subdomains
        )
        return ScopeGuard(scope=scope, mode=self.config.scope_mode)
    
    async def _discover_methods(self, target: str) -> MethodDiscoveryResult:
        """Discover available methods for target"""
        async with MethodDiscoveryEngine() as engine:
            return await engine.discover(target)
    
    async def _deep_crawl_endpoints(
        self,
        target: str,
        initial_endpoints: List[str],
        max_depth: int = 2
    ) -> List[str]:
        """
        Deep crawl to discover more endpoints with parameters.
        
        Follows links from discovered pages to find URLs with query parameters.
        """
        import httpx
        import re
        from urllib.parse import urljoin, urlparse
        
        all_endpoints = set(initial_endpoints)
        visited = set()
        to_visit = set()
        
        # Parse target to get base URL
        parsed_target = urlparse(target)
        base_domain = f"{parsed_target.scheme}://{parsed_target.netloc}"
        
        # Add target and initial endpoints to visit queue
        to_visit.add(target)
        for ep in initial_endpoints:
            if self._is_same_domain(target, ep):
                to_visit.add(ep)
        
        async with httpx.AsyncClient(
            timeout=10.0, 
            follow_redirects=True, 
            verify=False,
            headers={"User-Agent": "PenTestAI-Crawler/1.0"}
        ) as client:
            for depth in range(max_depth):
                if not to_visit:
                    break
                    
                # Process current level
                current_level = list(to_visit - visited)[:50]  # Limit per level
                to_visit = set()
                
                for url in current_level:
                    if url in visited:
                        continue
                    visited.add(url)
                    
                    try:
                        response = await client.get(url, timeout=5.0)
                        if response.status_code != 200:
                            continue
                            
                        # Extract links from HTML
                        links = re.findall(r'href=["\']([^"\']+)["\']', response.text)
                        
                        for link in links:
                            # Skip anchors, javascript, mailto
                            if link.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                                continue
                                
                            # Resolve relative URLs
                            if not link.startswith(('http://', 'https://')):
                                link = urljoin(url, link)
                            
                            # Only same domain
                            if not self._is_same_domain(target, link):
                                continue
                            
                            # Add to endpoints
                            all_endpoints.add(link)
                            
                            # If has parameters or is a PHP/ASP file, prioritize
                            if '?' in link or any(ext in link for ext in ['.php', '.asp', '.aspx', '.jsp']):
                                all_endpoints.add(link)
                            
                            # Add to visit queue for next level (only .php/.html pages)
                            if depth < max_depth - 1:
                                if any(ext in link for ext in ['.php', '.html', '.asp', '.aspx', '.jsp', '/']):
                                    if '?' not in link:  # Don't re-crawl parameterized URLs
                                        to_visit.add(link)
                                        
                    except Exception as e:
                        logger.debug(f"Error crawling {url}: {e}")
                        continue
        
        # Prioritize endpoints with parameters
        endpoints_with_params = [ep for ep in all_endpoints if '?' in ep]
        endpoints_without_params = [ep for ep in all_endpoints if '?' not in ep]

        logger.info(f"Deep crawl found {len(endpoints_with_params)} URLs with parameters")

        # Return parameterized URLs first, then others
        return endpoints_with_params + endpoints_without_params[:20]

    async def _browser_crawl_spa(
        self,
        target: str,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Crawl SPA using headless browser to discover:
        - API endpoints (XHR/Fetch calls)
        - WebSocket connections
        - Login forms and auth flows
        - Tokens in localStorage/sessionStorage
        - Dynamic routes

        This is CRITICAL for SPAs where static crawling finds nothing.
        """
        from urllib.parse import urlparse

        result = {
            "api_endpoints": [],
            "websocket_urls": [],
            "login_detected": False,
            "login_form": None,
            "auth_tokens": [],
            "local_storage": {},
            "session_storage": {},
            "cookies": [],
            "dynamic_routes": [],
            "js_files": [],
        }

        try:
            from utils.headless_browser import (
                HeadlessBrowserEngine,
                BrowserConfig,
                BrowserType,
                SecurityLevel,
                is_playwright_available,
            )

            if not is_playwright_available():
                logger.warning("Playwright not available for SPA crawling")
                return result

            config = BrowserConfig(
                browser_type=BrowserType.CHROMIUM,
                headless=True,
                security_level=SecurityLevel.RELAXED,
                timeout=timeout * 1000,
                capture_console=True,
                capture_network=True,
            )

            async with HeadlessBrowserEngine(config) as browser:
                # Navigate to target
                await browser.navigate(target, wait_until="networkidle")

                # Wait for SPA to fully load
                await asyncio.sleep(3)

                # Get all network requests (API calls)
                requests = browser.get_network_requests()
                for req in requests:
                    url = req.get("url", "")
                    parsed = urlparse(url)

                    # Detect API endpoints
                    if any(pattern in url.lower() for pattern in [
                        "/api/", "/v1/", "/v2/", "/graphql", "/rest/",
                        ".json", "/ajax/", "/xhr/"
                    ]):
                        if url not in result["api_endpoints"]:
                            result["api_endpoints"].append({
                                "url": url,
                                "method": req.get("method", "GET"),
                                "headers": req.get("headers", {}),
                            })

                    # Detect WebSocket
                    if parsed.scheme in ("ws", "wss"):
                        result["websocket_urls"].append(url)

                    # Collect JS files for analysis
                    if url.endswith(".js") and parsed.netloc == urlparse(target).netloc:
                        result["js_files"].append(url)

                # Check for login forms
                page = browser._page
                login_indicators = await page.evaluate('''() => {
                    const indicators = {
                        hasPasswordField: !!document.querySelector('input[type="password"]'),
                        hasLoginForm: false,
                        hasOAuthButtons: false,
                        loginFormAction: null,
                        oauthProviders: []
                    };

                    // Check for login forms
                    const forms = document.querySelectorAll('form');
                    for (const form of forms) {
                        const hasPassword = form.querySelector('input[type="password"]');
                        const hasEmail = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');
                        if (hasPassword || hasEmail) {
                            indicators.hasLoginForm = true;
                            indicators.loginFormAction = form.action || window.location.href;
                            break;
                        }
                    }

                    // Check for OAuth buttons
                    const oauthKeywords = ['google', 'facebook', 'github', 'twitter', 'linkedin', 'apple', 'microsoft'];
                    const buttons = document.querySelectorAll('button, a');
                    for (const btn of buttons) {
                        const text = (btn.textContent || '').toLowerCase();
                        const href = (btn.href || '').toLowerCase();
                        for (const provider of oauthKeywords) {
                            if (text.includes(provider) || href.includes(provider)) {
                                indicators.hasOAuthButtons = true;
                                if (!indicators.oauthProviders.includes(provider)) {
                                    indicators.oauthProviders.push(provider);
                                }
                            }
                        }
                    }

                    return indicators;
                }''')

                result["login_detected"] = (
                    login_indicators.get("hasPasswordField", False) or
                    login_indicators.get("hasLoginForm", False) or
                    login_indicators.get("hasOAuthButtons", False)
                )
                result["login_form"] = login_indicators

                # Get storage data (for token analysis)
                storage_data = await page.evaluate('''() => {
                    const local = {};
                    const session = {};

                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        local[key] = localStorage.getItem(key);
                    }

                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        session[key] = sessionStorage.getItem(key);
                    }

                    return { local, session };
                }''')

                result["local_storage"] = storage_data.get("local", {})
                result["session_storage"] = storage_data.get("session", {})

                # Analyze storage for auth tokens
                token_patterns = ["token", "jwt", "auth", "session", "bearer", "api_key", "apikey"]
                for key, value in result["local_storage"].items():
                    if any(p in key.lower() for p in token_patterns):
                        result["auth_tokens"].append({
                            "source": "localStorage",
                            "key": key,
                            "value_preview": value[:50] + "..." if len(value) > 50 else value,
                        })

                for key, value in result["session_storage"].items():
                    if any(p in key.lower() for p in token_patterns):
                        result["auth_tokens"].append({
                            "source": "sessionStorage",
                            "key": key,
                            "value_preview": value[:50] + "..." if len(value) > 50 else value,
                        })

                # Get cookies via page context
                try:
                    context = page.context
                    cookies = await context.cookies()
                    result["cookies"] = cookies
                except Exception:
                    cookies = []
                    result["cookies"] = []

                # Analyze cookies for session tokens
                for cookie in cookies:
                    name = cookie.get("name", "").lower()
                    if any(p in name for p in token_patterns + ["sess", "sid"]):
                        result["auth_tokens"].append({
                            "source": "cookie",
                            "key": cookie.get("name"),
                            "httpOnly": cookie.get("httpOnly", False),
                            "secure": cookie.get("secure", False),
                            "sameSite": cookie.get("sameSite", "None"),
                        })

                logger.info(f"SPA crawl found: {len(result['api_endpoints'])} API endpoints, "
                           f"login_detected={result['login_detected']}, "
                           f"{len(result['auth_tokens'])} tokens")

        except ImportError:
            logger.warning("Playwright not installed for SPA crawling")
        except Exception as e:
            logger.error(f"SPA crawl error: {e}")

        return result

    def _is_same_domain(self, target: str, url: str) -> bool:
        """Check if URL is on the same domain as target"""
        from urllib.parse import urlparse
        target_parsed = urlparse(target)
        url_parsed = urlparse(url)
        return target_parsed.netloc == url_parsed.netloc

    def should_test_parameter(
        self,
        ctx: IntelligentScanContext,
        url: str,
        param_name: str,
        attack_type: str
    ) -> Tuple[bool, str]:
        """
        Decide if a parameter should be tested for a specific attack
        
        Returns:
            (should_test: bool, reason: str)
        """
        # Get parameter analysis
        if url not in ctx.parameter_analysis:
            ctx.parameter_analysis[url] = self.parameter_analyzer.analyze_url(url)
        
        analysis = ctx.parameter_analysis[url]
        
        # Find the parameter profile
        profile = None
        for p in analysis.profiles:
            if p.name == param_name:
                profile = p
                break
        
        if not profile:
            return (True, "Parameter not analyzed, testing by default")
        
        # Check based on attack type
        attack_lower = attack_type.lower()
        
        if attack_lower in ["xss", "reflected_xss", "dom_xss"]:
            if not profile.should_test_xss():
                ctx.tests_skipped += 1
                return (False, f"XSS not applicable for {profile.detected_type.value}")
        
        elif attack_lower in ["sqli", "sql_injection", "sql"]:
            if not profile.should_test_sqli():
                ctx.tests_skipped += 1
                return (False, f"SQLi not applicable for {profile.detected_type.value}")
        
        elif attack_lower in ["lfi", "path_traversal", "file_inclusion"]:
            if not profile.should_test_path_traversal():
                ctx.tests_skipped += 1
                return (False, f"Path traversal not applicable")
        
        elif attack_lower in ["ssrf", "server_side_request_forgery"]:
            if not profile.should_test_ssrf():
                ctx.tests_skipped += 1
                return (False, f"SSRF not applicable for {profile.detected_type.value}")
        
        elif attack_lower in ["ssti", "template_injection"]:
            if not profile.should_test_ssti():
                ctx.tests_skipped += 1
                return (False, f"SSTI not applicable for {profile.detected_type.value}")
        
        return (True, "Parameter eligible for testing")
    
    def get_payload_pairs(
        self,
        param_type: str,
        attack_category: PayloadCategory,
        reflected: bool = False
    ) -> List[PayloadPair]:
        """Get payload pairs for negative control testing"""
        return self.payload_selector.select_pairs_for_parameter(
            param_type=param_type,
            reflected=reflected,
            is_numeric=(param_type == "integer")
        )
    
    async def validate_finding_with_negative_control(
        self,
        ctx: IntelligentScanContext,
        url: str,
        param: str,
        payload_pair: PayloadPair,
        malicious_response: Any,
        innocent_response: Any
    ) -> Tuple[bool, SignalType, float]:
        """
        Validate a potential finding using negative control
        
        Compares malicious vs innocent response to determine if it's
        a real vulnerability (SIGNAL) or false positive (NOISE).
        
        Returns:
            (is_valid: bool, signal_type: SignalType, confidence: float)
        """
        if not self.config.use_negative_control:
            return (True, SignalType.UNKNOWN, 50.0)
        
        # Compare responses
        mal_status = getattr(malicious_response, 'status_code', 0)
        inn_status = getattr(innocent_response, 'status_code', 0)
        
        mal_len = len(getattr(malicious_response, 'text', ''))
        inn_len = len(getattr(innocent_response, 'text', ''))
        
        mal_time = getattr(malicious_response, 'elapsed', 0)
        inn_time = getattr(innocent_response, 'elapsed', 0)
        
        # Determine signal type
        signal_type = SignalType.NOISE
        confidence = 0.0
        
        # Status code difference
        if mal_status != inn_status:
            signal_type = SignalType.STATUS_CODE_DIFF
            confidence = 70.0
        
        # Response length difference (more than 10%)
        elif mal_len > 0 and abs(mal_len - inn_len) / mal_len > 0.1:
            signal_type = SignalType.LENGTH_DIFF
            confidence = 65.0
        
        # Timing difference (for time-based attacks)
        elif mal_time > inn_time + 3:  # 3 second threshold
            signal_type = SignalType.TIMING_DIFF
            confidence = 80.0
        
        # Content difference (look for error messages, etc.)
        mal_text = getattr(malicious_response, 'text', '').lower()
        inn_text = getattr(innocent_response, 'text', '').lower()
        
        error_indicators = [
            'sql', 'syntax', 'error', 'exception', 'warning',
            'mysql', 'postgresql', 'oracle', 'sqlite', 'mssql'
        ]
        
        for indicator in error_indicators:
            if indicator in mal_text and indicator not in inn_text:
                signal_type = SignalType.CONTENT_DIFF
                confidence = 85.0
                break
        
        is_valid = (
            signal_type != SignalType.NOISE and
            confidence >= self.config.min_confidence
        )
        
        return (is_valid, signal_type, confidence)
    
    def create_finding(
        self,
        ctx: IntelligentScanContext,
        vuln_type: str,
        url: str,
        param: str,
        severity: Severity,
        confidence: float,
        evidence_list: List[Dict[str, Any]]
    ) -> Finding:
        """
        Create a properly managed finding with evidence
        """
        finding = Finding(
            vulnerability_type=vuln_type,
            url=url,
            parameter=param,
            severity=severity,
            confidence_score=confidence
        )
        
        # Add evidence
        for ev in evidence_list:
            finding.add_evidence(Evidence(
                evidence_type=EvidenceType(ev.get("type", "explanation")),
                title=ev.get("title", "Evidence"),
                content=ev.get("content", "")
            ))
        
        # Try to validate if has enough evidence
        if finding.has_minimum_evidence() and confidence >= self.config.min_confidence:
            finding.validate(
                method="negative_control" if self.config.use_negative_control else "heuristic",
                confidence=confidence
            )
        elif self.config.auto_discard_low_confidence and confidence < self.config.min_confidence:
            finding.discard(f"Low confidence: {confidence}")
        
        # Add to manager
        ctx.finding_manager.add_finding(finding)
        
        return finding
    
    def check_scope(
        self,
        ctx: IntelligentScanContext,
        url: str
    ) -> Tuple[bool, Optional[ScopeViolation]]:
        """Check if URL is within scope"""
        allowed, violation = ctx.scope_guard.is_allowed(url)
        if violation:
            ctx.scope_violations.append(violation)
        return (allowed, violation)
    
    def get_oob_payloads(
        self,
        ctx: IntelligentScanContext,
        scan_id: str,
        payload_type: str,
        target_url: str,
        parameter: str
    ) -> List[Dict[str, Any]]:
        """Get OOB payloads for blind vulnerability detection"""
        if not ctx.oob_engine:
            return []
        
        return ctx.oob_engine.generate_oob_payloads(
            scan_id=scan_id,
            payload_type=payload_type,
            target_url=target_url,
            parameter=parameter
        )
    
    def finalize_scan(self, ctx: IntelligentScanContext) -> Dict[str, Any]:
        """
        Finalize scan and generate summary
        """
        ctx.end_time = datetime.now()
        
        # Get finding statistics
        finding_stats = ctx.finding_manager.get_statistics()
        
        # Get scope statistics
        scope_stats = ctx.scope_guard.get_statistics()
        
        duration = (ctx.end_time - ctx.start_time).total_seconds()
        
        return {
            "version": self.VERSION,
            "target": ctx.target,
            "duration_seconds": duration,
            "config": {
                "scope_mode": self.config.scope_mode.value,
                "negative_control": self.config.use_negative_control,
                "oob_enabled": self.config.enable_oob,
            },
            "discovery": {
                "endpoints_discovered": len(ctx.endpoints_discovered),
                "parameters_analyzed": ctx.parameters_analyzed,
            },
            "testing": {
                "tests_executed": ctx.tests_executed,
                "tests_skipped": ctx.tests_skipped,
                "skip_rate": f"{(ctx.tests_skipped / max(1, ctx.tests_executed + ctx.tests_skipped)) * 100:.1f}%"
            },
            "findings": finding_stats,
            "scope_violations": scope_stats,
            "reportable_findings": [
                f.to_dict() for f in ctx.finding_manager.get_reportable_findings()
            ]
        }
    
    def get_attack_recommendations(
        self,
        ctx: IntelligentScanContext,
        url: str
    ) -> Dict[str, List[str]]:
        """
        Get recommended attacks for each parameter based on context
        """
        if url not in ctx.parameter_analysis:
            ctx.parameter_analysis[url] = self.parameter_analyzer.analyze_url(url)
        
        analysis = ctx.parameter_analysis[url]
        recommendations = {}
        
        for profile in analysis.profiles:
            attacks = []
            
            if profile.should_test_xss():
                attacks.append("xss")
            if profile.should_test_sqli():
                attacks.append("sqli")
            if profile.should_test_path_traversal():
                attacks.append("lfi")
            if profile.should_test_ssrf():
                attacks.append("ssrf")
            if profile.should_test_ssti():
                attacks.append("ssti")
            if profile.should_test_cmdi():
                attacks.append("cmdi")
            
            recommendations[profile.name] = attacks
        
        return recommendations


class ScopeViolationError(Exception):
    """Raised when scan target is out of scope"""
    pass


# Convenience function for integration with FullScanner
async def create_intelligent_context(
    target: str,
    settings: Any,
    config: Optional[IntelligentScanConfig] = None
) -> Tuple[IntelligentScanner, IntelligentScanContext]:
    """
    Create an intelligent scanner and prepare scan context
    
    Usage:
        scanner, ctx = await create_intelligent_context(target, settings)
        
        # Before testing each parameter
        should_test, reason = scanner.should_test_parameter(ctx, url, param, "xss")
        if not should_test:
            logger.info(f"Skipping {param}: {reason}")
            continue
        
        # After getting response
        is_valid, signal, confidence = await scanner.validate_finding_with_negative_control(...)
        
        # Create finding if valid
        if is_valid:
            finding = scanner.create_finding(ctx, ...)
    """
    scanner = IntelligentScanner(settings, config)
    ctx = await scanner.prepare_scan(target)
    return scanner, ctx


__all__ = [
    "IntelligentScanner",
    "IntelligentScanConfig",
    "IntelligentScanContext",
    "ScopeViolationError",
    "create_intelligent_context",
]
