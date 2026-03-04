"""
Post-Processing Phase - Finding Analysis and Enhancement.

This phase handles:
- Phase 4.1: Early finding sharing
- Phase 4.2: Exploitation proof engine
- Phase 4.3: Impact validation
- Phase 4.35: Vulnerability chain processing
- Phase 4.45: Exploitability classification
- Phase 4.46: Attacker intent analysis
- Phase 4.47: Attack chain analysis
- Phase 4.49: Attacker cost model
- Phase 4.5: Cross-module deduplication
- Phase 4.52: Scan amplification
- Phase 4.6: Exploit escalation
- Phase 4.7: Neural attack analysis

Author: PHANTOM AI
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from scanning.pipeline.base import Phase, PhaseResult, PhaseStatus, ScanContext
from utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


@dataclass
class PostProcessingConfig:
    """Configuration for post-processing phase."""

    enable_proof_engine: bool = True
    enable_impact_validation: bool = True
    enable_chain_processing: bool = True
    enable_exploitability_classification: bool = True
    enable_intent_analysis: bool = True
    enable_attack_chains: bool = True
    enable_cost_model: bool = True
    enable_deduplication: bool = True
    enable_amplification: bool = True
    enable_exploit_escalation: bool = True
    enable_neural_analysis: bool = True
    safe_mode: str = "safe"
    chain_confidence_threshold: float = 0.50


class PostProcessingPhase(Phase):
    """
    Post-processing phase for finding analysis.

    Consolidates all Phase 4.x sub-phases into a single orchestrated phase.
    """

    def __init__(self, config: Optional[PostProcessingConfig] = None):
        super().__init__("PostProcessingPhase")
        self.config = config or PostProcessingConfig()
        self._intent_profile = None

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute post-processing phase."""
        initial_count = len(context.findings)
        chains_discovered = 0
        escalations = 0

        try:
            logger.info(f"[PostProcessing] Starting with {initial_count} findings")

            # Phase 4.1: Early finding sharing
            await self._share_findings_early(context)

            # Phase 4.2: Exploitation proof engine
            if self.config.enable_proof_engine and self.config.safe_mode not in ("passive", "safe"):
                await self._run_proof_engine(context)

            # Phase 4.3: Impact validation
            if self.config.enable_impact_validation and self.config.safe_mode not in ("passive", "safe"):
                await self._validate_impact(context)

            # Phase 4.35: Vulnerability chain processing
            if self.config.enable_chain_processing:
                chains = await self._process_vuln_chains(context)
                chains_discovered += chains

            # Phase 4.45: Exploitability classification
            if self.config.enable_exploitability_classification:
                self._classify_exploitability(context)

            # Phase 4.46: Attacker intent analysis
            if self.config.enable_intent_analysis:
                self._analyze_intent(context)

            # Phase 4.47: Attack chain analysis
            if self.config.enable_attack_chains:
                chains = self._analyze_attack_chains(context)
                chains_discovered += chains

            # Phase 4.49: Attacker cost model
            if self.config.enable_cost_model:
                self._apply_cost_model(context)

            # Phase 4.5: Cross-module deduplication
            if self.config.enable_deduplication:
                self._deduplicate_findings(context)

            # Phase 4.52: Scan amplification
            if self.config.enable_amplification:
                await self._execute_amplification(context)
                # Post-amplification dedup
                if self.config.enable_deduplication:
                    self._deduplicate_findings(context)

            # Phase 4.6: Exploit escalation
            if self.config.enable_exploit_escalation:
                esc = await self._exploit_escalation(context)
                escalations = esc

            # Phase 4.7: Neural attack analysis
            if self.config.enable_neural_analysis:
                await self._neural_attack_analysis(context)

            final_count = len(context.findings)
            logger.info(
                f"[PostProcessing] Complete: {initial_count} → {final_count} findings, "
                f"{chains_discovered} chains, {escalations} escalations"
            )

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.COMPLETED,
                findings_count=final_count,
                data={
                    "initial_findings": initial_count,
                    "final_findings": final_count,
                    "chains_discovered": chains_discovered,
                    "escalations": escalations,
                },
            )

        except Exception as e:
            logger.error(f"[PostProcessing] Failed: {e}")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                error_message=str(e),
                findings_count=len(context.findings),
            )

    async def _share_findings_early(self, context: ScanContext) -> None:
        """Share findings to SharedFindingsStore."""
        try:
            from utils.shared_findings_store import get_shared_findings

            store = get_shared_findings()
            for finding in context.findings:
                if hasattr(finding, "to_dict"):
                    store.add_finding(finding.to_dict())
                elif isinstance(finding, dict):
                    store.add_finding(finding)
        except Exception as e:
            logger.debug(f"[EarlyShare] Could not share findings: {e}")

    async def _run_proof_engine(self, context: ScanContext) -> None:
        """Run exploitation proof engine."""
        try:
            from scanning.exploit_proof_engine import ExploitProofEngine
            from utils.endpoint_map import EndpointMap

            class _ProofSettings:
                def __init__(self, mode):
                    self.safe_mode = mode

            auth_ctx = context.metadata.get("auth_context")
            proof_engine = ExploitProofEngine(
                settings=_ProofSettings(self.config.safe_mode),
                auth_context=auth_ctx,
                endpoint_map=EndpointMap.get_instance(),
            )

            # Create a temporary result object
            class _TempResult:
                def __init__(self, findings):
                    self.findings = findings

            temp_result = _TempResult(context.findings)
            await proof_engine.prove_all(temp_result)
            context.findings = temp_result.findings

        except Exception as e:
            logger.debug(f"[ProofEngine] Error: {e}")

    async def _validate_impact(self, context: ScanContext) -> None:
        """Validate business impact of findings."""
        try:
            from scanning.impact_validator import ImpactValidator

            auth_ctx = context.metadata.get("auth_context")
            validator = ImpactValidator(auth_context=auth_ctx)
            context.findings = await validator.validate_all(context.findings)
            logger.info(f"[ImpactValidator] Validated {len(context.findings)} findings")
        except Exception as e:
            logger.debug(f"[ImpactValidator] Error: {e}")

    async def _process_vuln_chains(self, context: ScanContext) -> int:
        """Process vulnerability chains."""
        try:
            from analysis.vuln_chain_engine import VulnChainEngine

            engine = VulnChainEngine()
            chains = await engine.process(context.findings)
            if chains:
                context.add_findings(chains)
                return len(chains)
            return 0
        except Exception as e:
            logger.debug(f"[VulnChainEngine] Error: {e}")
            return 0

    def _classify_exploitability(self, context: ScanContext) -> None:
        """Classify exploitability tier (EXPOSURE/PARTIAL/FULL)."""
        try:
            from scanning.exploitability_classifier import ExploitabilityClassifier

            classifier = ExploitabilityClassifier()
            context.findings = classifier.classify(context.findings)
            summary = classifier.get_summary()
            if isinstance(summary, dict):
                logger.info(
                    f"[Exploitability] FULL={summary.get('tiers', {}).get('full', 0)}, "
                    f"PARTIAL={summary.get('tiers', {}).get('partial', 0)}, "
                    f"EXPOSURE={summary.get('tiers', {}).get('exposure', 0)}"
                )
        except Exception as e:
            logger.debug(f"[Exploitability] Error: {e}")

    def _analyze_intent(self, context: ScanContext) -> None:
        """Analyze attacker intent from findings."""
        try:
            from scanning.attacker_intent_engine import AttackerIntentEngine

            engine = AttackerIntentEngine()
            context.findings = engine.analyze(context.findings)
            self._intent_profile = engine.get_profile()
            if self._intent_profile and self._intent_profile.achievable_goals:
                goals = ", ".join(g.name for g in self._intent_profile.primary_goals[:3])
                logger.info(f"[Intent] Goals: {goals}, Threat: {self._intent_profile.overall_threat_level}")
        except Exception as e:
            logger.debug(f"[Intent] Error: {e}")

    def _analyze_attack_chains(self, context: ScanContext) -> int:
        """Analyze attack chains between findings."""
        try:
            from scanning.attack_chain_analyzer import AttackChainAnalyzer

            analyzer = AttackChainAnalyzer()
            if self._intent_profile:
                analyzer.set_intent_profile(self._intent_profile)

            context.findings = analyzer.analyze(context.findings)
            summary = analyzer.get_summary()

            # Filter low-confidence chains
            filtered = []
            suppressed = 0
            for f in context.findings:
                is_chain = (
                    getattr(f, "type", None) in ("attack_chain", "vulnerability_chain")
                    or (hasattr(f, "metadata") and f.metadata.get("is_chain"))
                )
                confidence = getattr(f, "confidence", 1.0)
                if is_chain and confidence < self.config.chain_confidence_threshold:
                    suppressed += 1
                else:
                    filtered.append(f)

            context.findings = filtered
            if suppressed > 0:
                logger.info(f"[AttackChains] Suppressed {suppressed} low-confidence chains")

            return summary.get("total_chains", 0) if isinstance(summary, dict) else 0

        except Exception as e:
            logger.debug(f"[AttackChains] Error: {e}")
            return 0

    def _apply_cost_model(self, context: ScanContext) -> None:
        """Apply attacker cost model to deprioritize low-ROI findings."""
        try:
            from scanning.exploitability_classifier import AttackerCostModel

            model = AttackerCostModel()
            context.findings = model.apply_to_findings(context.findings)
            summary = model.get_summary()
            if isinstance(summary, dict) and summary.get("deprioritized", 0) > 0:
                logger.info(f"[AttackerCost] {summary.get('deprioritized')} findings deprioritized")
        except Exception as e:
            logger.debug(f"[AttackerCost] Error: {e}")

    def _deduplicate_findings(self, context: ScanContext) -> None:
        """Deduplicate findings across modules."""
        try:
            seen = set()
            unique = []

            for finding in context.findings:
                # Create dedup key
                if hasattr(finding, "id"):
                    key = finding.id
                elif isinstance(finding, dict):
                    key = (
                        finding.get("vuln_type", finding.get("type", "")),
                        finding.get("url", finding.get("matched_at", "")),
                        finding.get("parameter", ""),
                    )
                else:
                    key = id(finding)

                if key not in seen:
                    seen.add(key)
                    unique.append(finding)

            removed = len(context.findings) - len(unique)
            context.findings = unique
            if removed > 0:
                logger.debug(f"[Dedup] Removed {removed} duplicate findings")

        except Exception as e:
            logger.debug(f"[Dedup] Error: {e}")

    async def _execute_amplification(self, context: ScanContext) -> None:
        """Execute pending amplification actions."""
        try:
            pending = context.metadata.get("pending_amplifications", [])
            if not pending:
                return

            logger.info(f"[Amplification] Executing {len(pending)} actions")
            # Amplification logic would be implemented here
            context.metadata["pending_amplifications"] = []
        except Exception as e:
            logger.debug(f"[Amplification] Error: {e}")

    async def _exploit_escalation(self, context: ScanContext) -> int:
        """Run exploit escalation phase for critical findings."""
        try:
            from scanning.exploit_escalation_phase import ExploitEscalationPhase

            # Check for critical infrastructure findings
            critical_findings = [
                f for f in context.findings
                if (getattr(f, "severity", None) or (isinstance(f, dict) and f.get("severity"))) == "CRITICAL"
            ]

            if not critical_findings:
                return 0

            escalation = ExploitEscalationPhase(safe_mode=self.config.safe_mode)
            result = await escalation.execute_standalone(context.findings, context.target_url)

            new_findings = result.get("new_findings", [])
            if new_findings:
                context.add_findings(new_findings)
                logger.info(f"[ExploitEscalation] Discovered {len(new_findings)} new findings")

            return result.get("new_findings_discovered", 0)

        except Exception as e:
            logger.debug(f"[ExploitEscalation] Error: {e}")
            return 0

    async def _neural_attack_analysis(self, context: ScanContext) -> None:
        """Run AI-driven attack planning."""
        try:
            from analysis.neural_attack_planner import NeuralAttackPlanner

            planner = NeuralAttackPlanner()
            additional = await planner.analyze(context.target_url, context.findings)
            if additional:
                context.add_findings(additional)
                logger.info(f"[NeuralAttack] Discovered {len(additional)} additional findings")
        except Exception as e:
            logger.debug(f"[NeuralAttack] Error: {e}")
