"""
Main Orchestrator for the pentesting pipeline - FULL INTEGRATION v2.0
Controls the entire scan workflow with ALL 47 modules integrated.
Updated: Janeiro 2026

SECURITY: Proper exception handling with traceback logging (CWE-390).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class ScanError(Exception):
    """Base exception for scan errors."""

    def __init__(self, message: str, phase: str | None = None, context: dict | None = None):
        super().__init__(message)
        self.phase = phase
        self.context = context or {}
        self.traceback = traceback.format_exc()


class PhaseError(ScanError):
    """Error during a specific scan phase."""
    pass


class ResourceCleanupError(ScanError):
    """Error during resource cleanup."""
    pass


# Version tracking
ORCHESTRATOR_VERSION = "2.1.0"


class ScanPhase(IntEnum):
    """Scan pipeline phases - Extended for full integration."""
    
    INITIALIZATION = 0
    URL_RESOLUTION = 1       # NEW: Canonical URL resolution (HTTP→HTTPS)
    THREAT_MODELING = 2      # Automatic threat modeling
    RECONNAISSANCE = 3
    SCANNING = 4
    ATTACK_CHAIN_ANALYSIS = 5  # Attack chain detection
    AI_ANALYSIS = 6
    EXPLOIT_DEVELOPMENT = 7
    REPORTING = 8


@dataclass
class ScanContext:
    """
    Shared context across all scan phases.
    Contains all data collected during the scan.
    Extended for full module integration.
    """
    
    target: str
    scope: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    # NEW: Canonical URLs resolved before scanning
    canonical_urls: dict[str, str] = field(default_factory=dict)  # original → canonical
    transport_stats: dict[str, Any] = field(default_factory=dict)  # Transport layer stats
    assets: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    ai_insights: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    # NEW: Extended fields
    threat_model: dict[str, Any] = field(default_factory=dict)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    abuse_cases: list[dict[str, Any]] = field(default_factory=list)
    safe_mode_evidence: list[dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self) -> None:
        """Initialize with target in scope."""
        if self.target and self.target not in self.scope:
            self.scope.append(self.target)
    
    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a vulnerability finding."""
        finding["id"] = finding.get("id") or self._generate_finding_id(finding)
        finding["discovered_at"] = datetime.now().isoformat()
        self.findings.append(finding)
    
    def add_error(self, phase: str, error: str, details: dict | None = None) -> None:
        """Record an error."""
        self.errors.append({
            "phase": phase,
            "error": error,
            "details": details or {},
            "timestamp": datetime.now().isoformat(),
        })
    
    def _generate_finding_id(self, finding: dict) -> str:
        """Generate unique ID for a finding."""
        data = f"{finding.get('type', '')}-{finding.get('name', '')}-{finding.get('matched_at', '')}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]
    
    def get_findings_by_severity(self) -> dict[str, list[dict]]:
        """Group findings by severity."""
        by_severity: dict[str, list[dict]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        
        for finding in self.findings:
            sev = finding.get("severity", "INFO").upper()
            if sev in by_severity:
                by_severity[sev].append(finding)
            else:
                by_severity["INFO"].append(finding)
        
        return by_severity
    
    def get_statistics(self) -> dict[str, Any]:
        """Get scan statistics."""
        by_severity = self.get_findings_by_severity()
        
        return {
            "total_findings": len(self.findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "total_hosts": len(self.scope),
            "total_errors": len(self.errors),
            "exploit_chains": len([
                i for i in self.ai_insights
                if i.get("type") == "exploit_chains"
            ]),
        }


@dataclass
class ScanOptions:
    """Configuration options for a scan - Extended."""
    
    # Reconnaissance options
    enum_subdomains: bool = True
    ports: str = "top1000"
    crawl_depth: int = 2
    
    # Scanning options
    scan_modules: str = "all"
    aggressive: bool = False
    
    # NEW: Safety level (passive/safe/cautious/standard/aggressive)
    safety_level: str = "safe"
    
    # NEW: Threat modeling
    run_threat_model: bool = True
    stride_analysis: bool = True
    
    # NEW: Attack chain detection
    detect_attack_chains: bool = True
    visualize_chains: bool = True
    
    # AI options
    skip_ai: bool = False
    filter_false_positives: bool = True
    detect_chains: bool = True
    generate_exploits: bool = False
    
    # Reporting options
    report_formats: list[str] = field(default_factory=lambda: ["pdf"])
    template: str = "professional"
    generate_dashboard: bool = True  # NEW: Interactive dashboard


class PentestOrchestrator:
    """
    Main orchestrator for the pentesting pipeline - FULL INTEGRATION v2.0
    
    Controls the entire workflow with ALL 47 modules:
    0. Initialization & Authorization
    1. Threat Modeling (STRIDE, Abuse Cases) - NEW
    2. Reconnaissance
    3. Vulnerability Scanning (39 modules)
    4. Attack Chain Analysis - NEW
    5. AI Analysis
    6. Exploit Development (optional)
    7. Reporting (including Dashboard) - ENHANCED
    """
    
    VERSION = ORCHESTRATOR_VERSION
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize orchestrator.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        
        # Lazy load managers to avoid circular imports
        self._auth_manager = None
        self._state_manager = None
        self._safe_scanner = None
        self._threat_modeler = None
        self._attack_chain_engine = None
        
        logger.info(f"PentestOrchestrator v{self.VERSION} initialized")
    
    @property
    def auth(self):
        """Get auth manager (lazy load)."""
        if self._auth_manager is None:
            from core.auth_manager import AuthManager
            self._auth_manager = AuthManager(self.settings)
        return self._auth_manager
    
    @property
    def state(self):
        """Get state manager (lazy load)."""
        if self._state_manager is None:
            from core.state_manager import StateManager
            self._state_manager = StateManager(self.settings)
        return self._state_manager
    
    @property
    def threat_modeler(self):
        """Get threat modeler (lazy load)."""
        if self._threat_modeler is None:
            from threat_modeling import ThreatModeler, STRIDEAnalyzer, AbuseCaseGenerator
            self._threat_modeler = ThreatModeler(
                stride_analyzer=STRIDEAnalyzer(),
                abuse_generator=AbuseCaseGenerator(),
            )
        return self._threat_modeler
    
    @property
    def attack_chain_engine(self):
        """Get attack chain engine (lazy load)."""
        if self._attack_chain_engine is None:
            from analysis import AttackChainEngine
            self._attack_chain_engine = AttackChainEngine()
        return self._attack_chain_engine
    
    async def run_full_scan(
        self,
        target: str,
        options: ScanOptions | None = None,
    ) -> str:
        """
        Execute a full pentest scan.
        
        Args:
            target: Primary target (domain/IP)
            options: Scan configuration options
            
        Returns:
            Scan ID for reference
            
        Raises:
            AuthorizationError: If target not authorized
        """
        options = options or ScanOptions()
        
        # Generate scan ID
        scan_id = self._generate_scan_id()
        logger.info(f"Starting scan {scan_id} for target: {target}")
        
        # Initialize context
        context = ScanContext(
            target=target,
            metadata={
                "scan_id": scan_id,
                "started_at": datetime.now().isoformat(),
                "options": options.__dict__,
            },
        )
        
        # Define pipeline phases - EXTENDED with URL_RESOLUTION
        phases = [
            (ScanPhase.INITIALIZATION, self._phase_initialization),
            (ScanPhase.URL_RESOLUTION, self._phase_url_resolution),  # NEW: Resolve canonical URLs
            (ScanPhase.THREAT_MODELING, self._phase_threat_modeling),
            (ScanPhase.RECONNAISSANCE, self._phase_reconnaissance),
            (ScanPhase.SCANNING, self._phase_scanning),
            (ScanPhase.ATTACK_CHAIN_ANALYSIS, self._phase_attack_chain),
            (ScanPhase.AI_ANALYSIS, self._phase_ai_analysis),
            (ScanPhase.EXPLOIT_DEVELOPMENT, self._phase_exploit_development),
            (ScanPhase.REPORTING, self._phase_reporting),
        ]
        
        try:
            for phase, handler in phases:
                logger.info(f"[{scan_id}] Starting phase: {phase.name}")
                
                context = await handler(context, options)
                
                # Save checkpoint after each phase
                self.state.save_checkpoint(scan_id, phase, context)
                
                logger.info(f"[{scan_id}] Completed phase: {phase.name}")
            
            # Mark scan as completed
            context.metadata["completed_at"] = datetime.now().isoformat()
            self.state.mark_completed(scan_id, context)
            
            logger.info(f"[{scan_id}] Scan completed successfully")
            return scan_id
            
        except Exception as e:
            # Log full traceback for debugging (CWE-390 fix)
            tb = traceback.format_exc()
            logger.error(
                f"[{scan_id}] Scan failed: {e}",
                exc_info=True,
                extra={
                    "scan_id": scan_id,
                    "target": target,
                    "phase": phase.name if 'phase' in dir() else "unknown",
                    "traceback": tb,
                },
            )

            # Store error context for debugging
            context.add_error(
                phase=phase.name if 'phase' in dir() else "unknown",
                error=str(e),
                details={"traceback": tb},
            )

            self.state.mark_failed(scan_id, str(e))
            raise PhaseError(
                f"Scan failed during {phase.name if 'phase' in dir() else 'unknown'}: {e}",
                phase=phase.name if 'phase' in dir() else None,
                context={"scan_id": scan_id, "target": target},
            ) from e

    async def resume_scan(self, scan_id: str) -> str:
        """
        Resume a paused or failed scan.
        
        Args:
            scan_id: ID of scan to resume
            
        Returns:
            Scan ID
        """
        if not self.state.can_resume(scan_id):
            raise ValueError(f"Scan {scan_id} cannot be resumed")
        
        context, phase = self.state.load_checkpoint(scan_id)
        if context is None or phase is None:
            raise ValueError(f"Could not load checkpoint for scan {scan_id}")
        
        # Get options from metadata
        options_dict = context.metadata.get("options", {})
        options = ScanOptions(**options_dict)
        
        # Resume from next phase
        logger.info(f"Resuming scan {scan_id} from phase {phase.name}")
        
        # Define remaining phases - EXTENDED with URL_RESOLUTION
        all_phases = [
            (ScanPhase.URL_RESOLUTION, self._phase_url_resolution),
            (ScanPhase.THREAT_MODELING, self._phase_threat_modeling),
            (ScanPhase.RECONNAISSANCE, self._phase_reconnaissance),
            (ScanPhase.SCANNING, self._phase_scanning),
            (ScanPhase.ATTACK_CHAIN_ANALYSIS, self._phase_attack_chain),
            (ScanPhase.AI_ANALYSIS, self._phase_ai_analysis),
            (ScanPhase.EXPLOIT_DEVELOPMENT, self._phase_exploit_development),
            (ScanPhase.REPORTING, self._phase_reporting),
        ]
        
        remaining = [(p, h) for p, h in all_phases if p.value > phase.value]
        
        try:
            for phase, handler in remaining:
                logger.info(f"[{scan_id}] Resuming phase: {phase.name}")
                context = await handler(context, options)
                self.state.save_checkpoint(scan_id, phase, context)
            
            context.metadata["completed_at"] = datetime.now().isoformat()
            self.state.mark_completed(scan_id, context)
            
            return scan_id
            
        except Exception as e:
            # Log full traceback for debugging (CWE-390 fix)
            tb = traceback.format_exc()
            logger.error(
                f"[{scan_id}] Resume failed: {e}",
                exc_info=True,
                extra={
                    "scan_id": scan_id,
                    "phase": phase.name if 'phase' in dir() else "unknown",
                    "traceback": tb,
                },
            )

            # Store error context
            context.add_error(
                phase=phase.name if 'phase' in dir() else "unknown",
                error=str(e),
                details={"traceback": tb, "resumed": True},
            )

            self.state.mark_failed(scan_id, str(e), phase)
            raise PhaseError(
                f"Resume failed during {phase.name if 'phase' in dir() else 'unknown'}: {e}",
                phase=phase.name if 'phase' in dir() else None,
                context={"scan_id": scan_id},
            ) from e

    async def _phase_initialization(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 0: Validate authorization and initialize."""
        from core.auth_manager import AuthorizationError
        
        # Validate target authorization
        if not self.auth.is_authorized(context.target):
            raise AuthorizationError(
                f"Target '{context.target}' is not authorized.\n"
                f"Add with: pentest config add-target {context.target}"
            )
        
        logger.info(f"Target {context.target} authorized for scanning")
        return context
    
    async def _phase_url_resolution(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """
        Phase 1: Canonical URL Resolution (HTTP → HTTPS).

        Ensures all URLs use the correct protocol and redirects are pre-resolved.
        """
        from utils.http_transport import URLCanonicalizer, ProtocolPolicy

        logger.info("🔍 Phase URL_RESOLUTION: Resolving canonical URLs...")

        canonicalizer = URLCanonicalizer(
            protocol_policy=ProtocolPolicy.AUTO_UPGRADE,
            verify_ssl=False,
        )

        # Resolve main target
        await self._resolve_main_target(context, canonicalizer)

        # Resolve additional hosts in scope
        await self._resolve_additional_hosts(context, canonicalizer)

        logger.info(
            f"✅ URL Resolution complete. "
            f"Scope: {len(context.scope)} hosts, "
            f"Resolved: {len(context.canonical_urls)} URLs"
        )

        return context

    async def _resolve_main_target(self, context: ScanContext, canonicalizer: Any) -> None:
        """Resolve canonical URL for the main target."""
        try:
            canonical = await canonicalizer.resolve(context.target)

            if canonical.reachable:
                original_target = context.target
                context.target = canonical.canonical
                context.canonical_urls[original_target] = canonical.canonical

                self._log_resolution(original_target, canonical)
                self._store_resolution_metadata(context, original_target, canonical)
                self._update_scope_with_canonical(context, original_target, canonical.canonical)

                logger.info(f"✅ Canonical URL resolved: {canonical.canonical}")

                if canonical.detected_waf:
                    logger.warning(f"⚠️ WAF detected: {canonical.detected_waf}")
                    context.metadata["detected_waf"] = canonical.detected_waf
            else:
                logger.warning(
                    f"⚠️ Could not resolve canonical URL for {context.target}. "
                    "Proceeding with original URL - some tests may fail."
                )
                context.add_error(
                    "url_resolution",
                    f"Could not resolve canonical URL for {context.target}",
                )

        except Exception as e:
            logger.error(f"URL resolution failed: {e}")
            context.add_error("url_resolution", f"URL resolution failed: {e}")

    async def _resolve_additional_hosts(self, context: ScanContext, canonicalizer: Any) -> None:
        """Resolve canonical URLs for additional hosts in scope."""
        for host in list(context.scope):
            if host == context.target:
                continue

            try:
                canonical = await canonicalizer.resolve(host)
                if canonical.reachable:
                    context.canonical_urls[host] = canonical.canonical

                    if host != canonical.canonical:
                        self._update_scope_with_canonical(context, host, canonical.canonical)
                        logger.debug(f"Resolved {host} → {canonical.canonical}")
            except Exception as e:
                logger.warning(f"Failed to resolve {host}: {e}")

    def _log_resolution(self, original: str, canonical: Any) -> None:
        """Log URL resolution changes."""
        if canonical.protocol_upgraded:
            logger.info(f"🔄 Protocol upgrade: {original} → {canonical.canonical}")
        if canonical.www_normalized:
            logger.info(f"🔄 WWW normalized: {original} → {canonical.canonical}")

    def _store_resolution_metadata(
        self, context: ScanContext, original: str, canonical: Any
    ) -> None:
        """Store URL resolution metadata in context."""
        context.metadata["url_resolution"] = {
            "original": original,
            "canonical": canonical.canonical,
            "protocol_upgraded": canonical.protocol_upgraded,
            "www_normalized": canonical.www_normalized,
            "was_redirected": canonical.was_redirected,
            "final_status_code": canonical.final_status_code,
            "server": canonical.server,
            "detected_waf": canonical.detected_waf,
        }

    def _update_scope_with_canonical(
        self, context: ScanContext, original: str, canonical: str
    ) -> None:
        """Update scope by replacing original URL with canonical."""
        if original in context.scope:
            context.scope.remove(original)
        if canonical not in context.scope:
            context.scope.append(canonical)
    
    async def _phase_threat_modeling(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 1: Automatic threat modeling with STRIDE."""
        if not options.run_threat_model:
            logger.info("Threat modeling skipped (disabled in options)")
            return context
        
        try:
            from threat_modeling import ThreatModeler, STRIDEAnalyzer, AbuseCaseGenerator
            
            # Initialize threat modeling components
            stride = STRIDEAnalyzer()
            abuse_gen = AbuseCaseGenerator()
            modeler = ThreatModeler(stride_analyzer=stride, abuse_generator=abuse_gen)
            
            # Generate threat model based on target
            threat_model = await modeler.analyze_target(
                target=context.target,
                scope=context.scope,
            )
            
            context.threat_model = threat_model
            
            # Generate abuse cases for discovered endpoints
            if options.stride_analysis:
                abuse_cases = await abuse_gen.generate_for_target(context.target)
                context.abuse_cases = abuse_cases
                logger.info(f"Generated {len(abuse_cases)} abuse cases")
            
            logger.info("Threat modeling completed")
            
        except ImportError as e:
            logger.warning(f"Threat modeling module not available: {e}")
        except Exception as e:
            context.add_error("threat_modeling", f"Threat modeling failed: {e}")
            logger.warning(f"Threat modeling failed: {e}")
        
        return context
    
    async def _phase_reconnaissance(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 1: Reconnaissance - discover assets."""
        from reconnaissance import (
            SubdomainEnumerator,
            PortScanner,
            TechDetector,
            WebCrawler,
        )
        
        # Subdomain enumeration
        if options.enum_subdomains:
            try:
                enumerator = SubdomainEnumerator(self.settings)
                subdomains = await enumerator.enumerate(context.target)
                
                # Add to scope (validate each)
                for sub in subdomains:
                    if self.auth.is_authorized(sub):
                        if sub not in context.scope:
                            context.scope.append(sub)
                
                logger.info(f"Found {len(subdomains)} subdomains")
            except Exception as e:
                context.add_error("reconnaissance", f"Subdomain enum failed: {e}")
                logger.warning(f"Subdomain enumeration failed: {e}")
        
        # Port scanning
        try:
            scanner = PortScanner(self.settings)
            
            for host in context.scope:
                ports = await scanner.scan(host, options.ports)
                context.assets[host] = {"ports": ports}
            
            logger.info(f"Port scan completed for {len(context.scope)} hosts")
        except Exception as e:
            context.add_error("reconnaissance", f"Port scan failed: {e}")
            logger.warning(f"Port scan failed: {e}")
        
        # Technology detection
        try:
            detector = TechDetector(self.settings)
            
            for host in context.scope:
                tech = await detector.detect(host)
                context.assets.setdefault(host, {})["technologies"] = tech
            
            logger.info("Technology detection completed")
        except Exception as e:
            context.add_error("reconnaissance", f"Tech detection failed: {e}")
            logger.warning(f"Tech detection failed: {e}")
        
        # Web crawling
        try:
            crawler = WebCrawler(self.settings)
            
            for host in context.scope:
                urls = await crawler.crawl(host, max_depth=options.crawl_depth)
                context.assets.setdefault(host, {})["urls"] = urls
            
            total_urls = sum(
                len(context.assets.get(h, {}).get("urls", []))
                for h in context.scope
            )
            logger.info(f"Crawled {total_urls} URLs")
        except Exception as e:
            context.add_error("reconnaissance", f"Crawling failed: {e}")
            logger.warning(f"Web crawling failed: {e}")
        
        return context
    
    async def _phase_scanning(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 3: Vulnerability scanning with ALL 39 modules."""
        from scanning import VulnerabilityScanner
        
        # Initialize scanner with safety level
        scanner = VulnerabilityScanner(
            self.settings,
            safety_level=options.safety_level,
        )
        
        logger.info(f"Scanner initialized with {len(scanner.modules)} modules (safety: {options.safety_level})")
        
        # Scan each host
        tasks = []
        for host in context.scope:
            asset_data = context.assets.get(host, {})
            task = scanner.scan_host(
                host,
                asset_data,
                modules=options.scan_modules,
            )
            tasks.append(task)
        
        # Execute in parallel with error handling
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                context.add_error("scanning", f"Scan failed for host: {result}")
                logger.error(f"Scan failed: {result}")
                continue
            
            # Add findings
            for vuln in result.get("vulnerabilities", []):
                context.add_finding(vuln)
            
            # Store modules info
            host = context.scope[i] if i < len(context.scope) else "unknown"
            context.metadata.setdefault("scan_details", {})[host] = {
                "modules_run": result.get("modules_run", []),
                "modules_skipped": result.get("modules_skipped", []),
            }
        
        logger.info(f"Found {len(context.findings)} potential vulnerabilities")
        return context
    
    async def _phase_attack_chain(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 4: Attack chain analysis."""
        if not options.detect_attack_chains or not context.findings:
            logger.info("Attack chain analysis skipped")
            return context
        
        try:
            from analysis import AttackChainEngine, ChainVisualizer
            
            engine = AttackChainEngine()
            
            # Detect attack chains from findings
            chains = await engine.detect_chains(
                findings=context.findings,
                assets=context.assets,
            )
            
            context.attack_chains = [chain.to_dict() for chain in chains]
            
            logger.info(f"Detected {len(chains)} attack chains")
            
            # Generate visualizations if requested
            if options.visualize_chains and chains:
                visualizer = ChainVisualizer()
                
                for chain in chains:
                    viz = visualizer.generate_ascii(chain)
                    context.ai_insights.append({
                        "type": "attack_chain_visual",
                        "chain_id": chain.id,
                        "visualization": viz,
                    })
                
                # Generate Mermaid diagrams
                mermaid = visualizer.generate_mermaid(chains)
                context.metadata["attack_chain_mermaid"] = mermaid
                
                logger.info("Attack chain visualizations generated")
                
        except ImportError as e:
            logger.warning(f"Attack chain module not available: {e}")
        except Exception as e:
            context.add_error("attack_chain", f"Attack chain analysis failed: {e}")
            logger.warning(f"Attack chain analysis failed: {e}")
        
        return context
    
    async def _phase_ai_analysis(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 3: AI-powered analysis."""
        if options.skip_ai:
            logger.info("AI analysis skipped (--no-ai flag)")
            return context
        
        from ai_engine import (
            Analyzer,
            FalsePositiveFilter,
            ChainDetector,
            ExploitSuggester,
        )
        
        # Filter false positives
        if options.filter_false_positives:
            try:
                fp_filter = FalsePositiveFilter(self.settings)
                original_count = len(context.findings)
                context.findings = await fp_filter.filter(
                    context.findings,
                    context.assets,
                )
                filtered_count = original_count - len(context.findings)
                logger.info(f"Filtered {filtered_count} false positives")
            except Exception as e:
                context.add_error("ai_analysis", f"FP filtering failed: {e}")
                logger.warning(f"FP filtering failed: {e}")
        
        # Contextual analysis
        try:
            analyzer = Analyzer(self.settings)
            
            for finding in context.findings:
                analysis = await analyzer.analyze(finding, context)
                finding["ai_analysis"] = analysis
            
            logger.info("Contextual analysis completed")
        except Exception as e:
            context.add_error("ai_analysis", f"Analysis failed: {e}")
            logger.warning(f"Contextual analysis failed: {e}")
        
        # Detect exploit chains
        if options.detect_chains:
            try:
                detector = ChainDetector(self.settings)
                chains = await detector.detect(context.findings, context.assets)
                
                context.ai_insights.append({
                    "type": "exploit_chains",
                    "data": chains,
                })
                
                logger.info(f"Detected {len(chains)} exploit chains")
            except Exception as e:
                context.add_error("ai_analysis", f"Chain detection failed: {e}")
                logger.warning(f"Chain detection failed: {e}")
        
        # Exploit suggestions for high-severity findings
        try:
            suggester = ExploitSuggester(self.settings)
            high_severity = {"CRITICAL", "HIGH"}
            
            for finding in context.findings:
                if finding.get("severity", "").upper() in high_severity:
                    suggestion = await suggester.suggest(finding, context)
                    finding["exploit_suggestion"] = suggestion
            
            logger.info("Exploit suggestions generated")
        except Exception as e:
            context.add_error("ai_analysis", f"Exploit suggestion failed: {e}")
            logger.warning(f"Exploit suggestion failed: {e}")
        
        return context
    
    async def _phase_exploit_development(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 4: Custom exploit/PoC development (optional)."""
        if not options.generate_exploits:
            logger.info("Exploit development skipped")
            return context
        
        from ai_engine import ExploitDeveloper
        
        try:
            developer = ExploitDeveloper(self.settings)
            
            for finding in context.findings:
                if finding.get("exploit_suggestion"):
                    poc = await developer.generate_poc(finding, context)
                    finding["proof_of_concept"] = poc
            
            logger.info("PoC generation completed")
        except Exception as e:
            context.add_error("exploit_development", f"PoC generation failed: {e}")
            logger.warning(f"PoC generation failed: {e}")
        
        return context
    
    async def _phase_reporting(
        self,
        context: ScanContext,
        options: ScanOptions,
    ) -> ScanContext:
        """Phase 7: Generate reports including dashboards."""
        from reporting import ReportGenerator
        
        generator = ReportGenerator(self.settings)
        
        generated_reports = []
        
        for fmt in options.report_formats:
            try:
                report_path = await generator.generate(
                    context=context,
                    format=fmt,
                    template=options.template,
                )
                generated_reports.append(report_path)
                logger.info(f"Generated report: {report_path}")
            except Exception as e:
                context.add_error("reporting", f"Report generation failed ({fmt}): {e}")
                logger.error(f"Report generation failed: {e}")
        
        # Generate interactive dashboard if requested
        if options.generate_dashboard and context.attack_chains:
            try:
                from analysis import AttackChainDashboard
                
                dashboard = AttackChainDashboard()
                dashboard_path = await dashboard.generate(
                    findings=context.findings,
                    chains=context.attack_chains,
                    threat_model=context.threat_model,
                    output_dir=self.settings.reporting.output_dir,
                )
                generated_reports.append(dashboard_path)
                logger.info(f"Generated interactive dashboard: {dashboard_path}")
                
            except ImportError:
                logger.warning("Dashboard module not available")
            except Exception as e:
                context.add_error("reporting", f"Dashboard generation failed: {e}")
        
        context.metadata["reports"] = generated_reports
        return context
    
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID."""
        data = f"{datetime.now().isoformat()}-{os.urandom(8).hex()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
