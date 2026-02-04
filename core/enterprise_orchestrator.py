"""
Enterprise Orchestrator - Full pentest capabilities.
Extends base orchestrator with enterprise features.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from core.orchestrator import (
    PentestOrchestrator,
    ScanContext,
    ScanOptions,
    ScanPhase,
)
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


@dataclass
class EnterpriseScanOptions(ScanOptions):
    """Extended options for enterprise scans."""
    
    # Business logic testing
    test_business_logic: bool = True
    test_race_conditions: bool = True
    
    # Authorization testing
    test_authorization: bool = True
    authorization_depth: str = "deep"  # basic, standard, deep
    multi_tenant_mode: bool = False
    
    # Post-exploitation
    post_exploitation: bool = True
    simulate_impact: bool = True
    
    # Compliance
    compliance_mapping: bool = True
    compliance_frameworks: list[str] = field(
        default_factory=lambda: ["OWASP_ASVS", "PCI_DSS", "ISO_27001"]
    )
    
    # Human-in-the-loop
    interactive_mode: bool = False
    require_approval_for_high: bool = True
    
    # Retest & Regression
    enable_tracking: bool = True
    compare_to_previous: bool = True
    
    # Executive reporting
    executive_summary: bool = True
    industry: str = "default"
    annual_revenue: float = 0  # For financial impact calculation


class EnterprisePentestOrchestrator(PentestOrchestrator):
    """
    Enterprise-grade pentesting orchestrator.
    
    Additional phases:
    - Business Logic Testing
    - Deep Authorization Testing
    - Post-Exploitation & Impact
    - Compliance Mapping
    - Executive Summary Generation
    - Retest Tracking
    """
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        
        # Enterprise modules (lazy loaded)
        self._compliance_mapper = None
        self._retest_engine = None
        self._hitl_controller = None
        self._executive_generator = None
    
    @property
    def compliance(self):
        """Get compliance mapper."""
        if self._compliance_mapper is None:
            from compliance import ComplianceMapper
            self._compliance_mapper = ComplianceMapper(self.settings)
        return self._compliance_mapper
    
    @property
    def retest(self):
        """Get retest engine."""
        if self._retest_engine is None:
            from retest import RetestEngine
            self._retest_engine = RetestEngine(self.settings)
        return self._retest_engine
    
    @property
    def hitl(self):
        """Get human-in-the-loop controller."""
        if self._hitl_controller is None:
            from interactive import HumanInTheLoopController
            self._hitl_controller = HumanInTheLoopController(self.settings)
        return self._hitl_controller
    
    @property
    def executive(self):
        """Get executive summary generator."""
        if self._executive_generator is None:
            from reporting import ExecutiveSummaryGenerator
            self._executive_generator = ExecutiveSummaryGenerator(
                self.settings,
                compliance_mapper=self._compliance_mapper,
                retest_engine=self._retest_engine,
            )
        return self._executive_generator
    
    async def run_enterprise_scan(
        self,
        target: str,
        options: EnterpriseScanOptions | None = None,
    ) -> str:
        """
        Execute enterprise-grade pentest.
        
        Includes all standard phases plus:
        - Business logic testing
        - Deep authorization testing
        - Post-exploitation analysis
        - Compliance mapping
        - Executive summary
        """
        options = options or EnterpriseScanOptions()
        
        # Generate scan ID
        scan_id = self._generate_scan_id()
        logger.info(f"Starting enterprise scan {scan_id} for target: {target}")
        
        # Initialize context
        context = ScanContext(
            target=target,
            metadata={
                "scan_id": scan_id,
                "scan_type": "enterprise",
                "started_at": datetime.now().isoformat(),
                "options": options.__dict__,
            },
        )
        
        # Start interactive session if enabled
        if options.interactive_mode:
            await self.hitl.start_session()
        
        # Define enterprise pipeline
        phases = [
            (ScanPhase.INITIALIZATION, self._phase_initialization),
            (ScanPhase.RECONNAISSANCE, self._phase_reconnaissance),
            (ScanPhase.SCANNING, self._phase_enterprise_scanning),
            (ScanPhase.AI_ANALYSIS, self._phase_ai_analysis),
            (ScanPhase.EXPLOIT_DEVELOPMENT, self._phase_post_exploitation),
            (ScanPhase.REPORTING, self._phase_enterprise_reporting),
        ]
        
        try:
            for phase, handler in phases:
                logger.info(f"[{scan_id}] Starting phase: {phase.name}")
                
                context = await handler(context, options)
                self.state.save_checkpoint(scan_id, phase, context)
                
                logger.info(f"[{scan_id}] Completed phase: {phase.name}")
            
            # Track for regression testing
            if options.enable_tracking:
                tracking = self.retest.record_scan_results(
                    context.findings, target
                )
                context.metadata["tracking"] = tracking
            
            context.metadata["completed_at"] = datetime.now().isoformat()
            self.state.mark_completed(scan_id, context)
            
            # End interactive session
            if options.interactive_mode:
                session_stats = await self.hitl.end_session()
                context.metadata["interactive_session"] = session_stats
            
            logger.info(f"[{scan_id}] Enterprise scan completed successfully")
            return scan_id
            
        except Exception as e:
            logger.error(f"[{scan_id}] Enterprise scan failed: {e}")
            self.state.mark_failed(scan_id, str(e))
            raise
    
    async def _phase_enterprise_scanning(
        self,
        context: ScanContext,
        options: EnterpriseScanOptions,
    ) -> ScanContext:
        """Extended scanning phase with enterprise modules."""
        # Run standard scanning first
        context = await self._phase_scanning(context, options)
        
        # Business logic testing
        if options.test_business_logic:
            context = await self._run_business_logic_tests(context, options)
        
        # Deep authorization testing
        if options.test_authorization:
            context = await self._run_authorization_tests(context, options)
        
        return context
    
    async def _run_business_logic_tests(
        self,
        context: ScanContext,
        options: EnterpriseScanOptions,
    ) -> ScanContext:
        """Run business logic vulnerability tests."""
        from scanning.modules import BusinessLogicScanner
        from utils.rate_limiter import RateLimiter
        
        logger.info("Running business logic tests...")
        
        scanner = BusinessLogicScanner(self.settings)
        rate_limiter = RateLimiter(
            tokens_per_second=getattr(self.settings, 'rate_limit', 10)
        )
        
        for host in context.scope:
            try:
                # Request human approval if interactive
                if options.interactive_mode and options.require_approval_for_high:
                    approved = await self.hitl.request_authorization(
                        action="Business Logic Testing",
                        target=host,
                        potential_impact="May trigger business transactions or state changes",
                    )
                    if not approved:
                        logger.info(f"Business logic testing skipped for {host} (not approved)")
                        continue
                
                findings = await scanner.scan(host, {}, rate_limiter)
                
                for finding in findings:
                    # Request review if interactive
                    if options.interactive_mode:
                        feedback = await self.hitl.request_finding_review(finding.__dict__)
                        if not feedback.is_valid:
                            continue
                    
                    context.add_finding(finding.__dict__)
                
            except Exception as e:
                context.add_error("business_logic", f"Test failed for {host}: {e}")
                logger.warning(f"Business logic test failed for {host}: {e}")
        
        return context
    
    async def _run_authorization_tests(
        self,
        context: ScanContext,
        options: EnterpriseScanOptions,
    ) -> ScanContext:
        """Run deep authorization tests."""
        from scanning.modules import AuthorizationEngine
        from utils.rate_limiter import RateLimiter
        
        logger.info("Running authorization tests...")
        
        scanner = AuthorizationEngine(self.settings)
        rate_limiter = RateLimiter(
            tokens_per_second=getattr(self.settings, 'rate_limit', 10)
        )
        
        for host in context.scope:
            try:
                # Request approval
                if options.interactive_mode:
                    approved = await self.hitl.request_authorization(
                        action="Deep Authorization Testing",
                        target=host,
                        potential_impact="Tests access controls with different roles/users",
                    )
                    if not approved:
                        continue
                
                findings = await scanner.scan(host, {}, rate_limiter)
                
                for finding in findings:
                    if options.interactive_mode:
                        feedback = await self.hitl.request_finding_review(finding.__dict__)
                        if not feedback.is_valid:
                            continue
                    
                    context.add_finding(finding.__dict__)
                
            except Exception as e:
                context.add_error("authorization", f"Test failed for {host}: {e}")
                logger.warning(f"Authorization test failed for {host}: {e}")
        
        return context
    
    async def _phase_post_exploitation(
        self,
        context: ScanContext,
        options: EnterpriseScanOptions,
    ) -> ScanContext:
        """Post-exploitation and impact assessment."""
        if not options.post_exploitation:
            return await self._phase_exploit_development(context, options)
        
        from scanning.modules import PostExploitationModule
        from utils.rate_limiter import RateLimiter
        
        logger.info("Running post-exploitation analysis...")
        
        module = PostExploitationModule(self.settings)
        rate_limiter = RateLimiter(
            tokens_per_second=getattr(self.settings, 'rate_limit', 10)
        )
        
        # Need high-severity findings to analyze
        high_severity = [
            f for f in context.findings
            if f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        
        if not high_severity:
            logger.info("No high-severity findings for post-exploitation")
            return context
        
        for host in context.scope:
            try:
                # Request approval for post-exploitation
                if options.interactive_mode:
                    approved = await self.hitl.request_authorization(
                        action="Post-Exploitation Analysis",
                        target=host,
                        potential_impact="Demonstrates full impact of vulnerabilities",
                    )
                    if not approved:
                        continue
                
                findings = await module.scan(host, {"findings": high_severity}, rate_limiter)
                
                for finding in findings:
                    context.add_finding(finding.__dict__)
                
            except Exception as e:
                context.add_error("post_exploitation", f"Analysis failed for {host}: {e}")
                logger.warning(f"Post-exploitation failed for {host}: {e}")
        
        # Add exploit chains to insights
        chains = [
            f for f in context.findings
            if "Exploit Chain" in f.get("name", "")
        ]
        if chains:
            context.ai_insights.append({
                "type": "exploit_chains",
                "data": chains,
            })
        
        return context
    
    async def _phase_enterprise_reporting(
        self,
        context: ScanContext,
        options: EnterpriseScanOptions,
    ) -> ScanContext:
        """Generate enterprise reports including executive summary."""
        # Standard reporting first
        context = await self._phase_reporting(context, options)
        
        # Compliance mapping
        if options.compliance_mapping:
            logger.info("Generating compliance mapping...")
            try:
                compliance_report = self.compliance.generate_compliance_report(
                    context.findings
                )
                context.metadata["compliance"] = compliance_report
                
                logger.info(f"Compliance mapping completed for {len(options.compliance_frameworks)} frameworks")
            except Exception as e:
                context.add_error("compliance", f"Mapping failed: {e}")
                logger.warning(f"Compliance mapping failed: {e}")
        
        # Executive summary
        if options.executive_summary:
            logger.info("Generating executive summary...")
            try:
                # Configure with financial data if provided
                self._executive_generator = None  # Reset to apply new settings
                
                from reporting import ExecutiveSummaryGenerator
                generator = ExecutiveSummaryGenerator(
                    self.settings,
                    industry=options.industry,
                    annual_revenue=options.annual_revenue,
                    compliance_mapper=self._compliance_mapper,
                    retest_engine=self._retest_engine,
                )
                
                summary = generator.generate_summary(
                    context.findings,
                    context.target,
                    context.metadata,
                )
                
                # Render in multiple formats
                for fmt in ["markdown", "json", "html"]:
                    rendered = generator.render_report(summary, fmt)
                    
                    # Save to file
                    output_dir = self.settings.output_dir if hasattr(self.settings, 'output_dir') else "reports"
                    filename = f"{context.metadata['scan_id']}_executive_summary.{fmt if fmt != 'markdown' else 'md'}"
                    filepath = f"{output_dir}/{filename}"
                    
                    import os
                    os.makedirs(output_dir, exist_ok=True)
                    
                    with open(filepath, "w") as f:
                        f.write(rendered)
                    
                    context.metadata.setdefault("reports", []).append(filepath)
                
                context.metadata["executive_summary"] = {
                    "risk_rating": summary.overall_risk_rating,
                    "risk_score": summary.risk_score,
                    "total_exposure": summary.financial_impact.total_risk_exposure,
                }
                
                logger.info("Executive summary generated")
                
            except Exception as e:
                context.add_error("executive_summary", f"Generation failed: {e}")
                logger.warning(f"Executive summary failed: {e}")
        
        # Retest comparison
        if options.compare_to_previous:
            try:
                comparison = self.retest.compare_scans()
                context.metadata["scan_comparison"] = comparison
                
                if comparison.get("improvement"):
                    logger.info("✅ Security posture improved since last scan")
                else:
                    logger.warning("⚠️ Security posture unchanged or degraded")
                    
            except Exception as e:
                logger.warning(f"Scan comparison not available: {e}")
        
        return context
    
    def get_remediation_status(self, target: str | None = None) -> dict[str, Any]:
        """Get remediation status for tracking."""
        return {
            "progress": self.retest.get_remediation_progress(),
            "open_vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "name": v.name,
                    "severity": v.severity,
                    "age_days": (datetime.now() - v.first_found).days,
                }
                for v in self.retest.get_open_vulnerabilities()
            ],
            "report": self.retest.generate_remediation_report(),
        }
    
    async def run_retest(
        self,
        target: str,
        vulnerability_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run targeted retest for specific vulnerabilities."""
        logger.info(f"Running retest for {target}")
        
        # Run limited scan
        options = EnterpriseScanOptions(
            enum_subdomains=False,
            crawl_depth=1,
            test_business_logic=False,
            post_exploitation=False,
            executive_summary=False,
        )
        
        scan_id = await self.run_enterprise_scan(target, options)
        
        # Get comparison
        comparison = self.retest.compare_scans()
        
        return {
            "scan_id": scan_id,
            "comparison": comparison,
            "remediation_progress": self.retest.get_remediation_progress(),
        }
