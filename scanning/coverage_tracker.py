"""
PHANTOM AI - Coverage Tracker (Meta-Vision)

Philosophy: "What WASN'T tested is as important as what WAS tested."

This module provides meta-level awareness of scan coverage:
1. COVERAGE MAP — What surfaces were tested, how thoroughly
2. SKIPPED SURFACE REASON — Why each area was skipped (rate limit, auth, timeout, etc.)
3. CONFIDENCE OF ABSENCE — "Not found" because doesn't exist vs "couldn't test"

Output enables answering:
- "Did we test all parameters for SQLi?" vs "We skipped 40% due to rate limiting"
- "No XSS found" → confidence 95% (tested all inputs) or 30% (only tested GET)
- "These endpoints need re-testing" (were skipped, high potential)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class SkipReason(Enum):
    """Why a surface was not tested."""
    # Rate/Budget
    RATE_LIMITED = auto()          # 429 responses, backing off
    BUDGET_EXHAUSTED = auto()      # Hit request limit
    TIMEOUT = auto()               # Scan time limit reached

    # Access
    AUTH_REQUIRED = auto()         # Needs auth we don't have
    SCOPE_OUT = auto()             # Outside authorized scope
    BLOCKED_BY_WAF = auto()        # WAF blocking tests
    SAFETY_BLOCKED = auto()        # L4 FIX: Module blocked by safety mode

    # Technical
    METHOD_NOT_SUPPORTED = auto()  # Endpoint doesn't accept this method
    CONTENT_TYPE_MISMATCH = auto() # Wrong content type for this param
    PARAM_TYPE_MISMATCH = auto()   # SQLi on JWT, XSS on integer

    # Classification
    TECH_MISMATCH = auto()         # Module not relevant (PHP on Node)
    LOW_PRIORITY = auto()          # Deprioritized, never reached
    ALREADY_COVERED = auto()       # Covered by another module

    # Errors
    CONNECTION_ERROR = auto()      # Network failures
    PARSE_ERROR = auto()           # Couldn't parse response
    MODULE_ERROR = auto()          # Scanner module crashed


class TestDepth(Enum):
    """How thoroughly a surface was tested."""
    NOT_TESTED = 0      # Zero tests
    MINIMAL = 1         # 1-2 payloads, quick check
    STANDARD = 2        # Normal payload set
    THOROUGH = 3        # Extended payloads, mutations
    EXHAUSTIVE = 4      # All payloads, all encodings, all methods


class AbsenceConfidence(Enum):
    """Confidence level for "no vulnerability found"."""
    UNKNOWN = 0         # Couldn't test at all
    VERY_LOW = 1        # Minimal testing, likely missed if exists
    LOW = 2             # Some testing, may have missed
    MEDIUM = 3          # Standard testing, probably would find
    HIGH = 4            # Thorough testing, unlikely to miss
    VERY_HIGH = 5       # Exhaustive testing, confident it doesn't exist


@dataclass
class SkippedSurface:
    """A surface (endpoint/param/module) that was skipped."""
    surface_type: str          # "endpoint", "parameter", "module", "vuln_type"
    identifier: str            # URL, param name, module name
    reason: SkipReason
    reason_detail: str = ""    # Human-readable explanation
    potential_impact: str = "" # What we might have missed
    recoverable: bool = True   # Can we retry this?
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Context for retry
    retry_context: dict = field(default_factory=dict)  # Auth token, rate limit reset time, etc.


@dataclass
class StatefulFlow:
    """
    Tracks coverage of a multi-step stateful flow.

    Examples:
    - Checkout: cart → shipping → payment → confirmation
    - Auth: register → verify → login → MFA
    - Transfer: initiate → 2FA → confirm
    """
    flow_name: str                 # e.g., "checkout_flow", "auth_flow"
    domain: str                    # e.g., "ecommerce", "fintech"
    steps: list[str] = field(default_factory=list)  # Step names in order
    steps_completed: list[str] = field(default_factory=list)
    steps_skipped: list[str] = field(default_factory=list)
    steps_blocked: list[str] = field(default_factory=list)
    skip_reasons: dict[str, str] = field(default_factory=dict)  # step → reason
    fully_tested: bool = False
    findings_in_flow: int = 0
    block_point: str = ""          # Where the flow got blocked

    @property
    def progress(self) -> str:
        """Return progress as 'X/Y' string."""
        total = len(self.steps)
        completed = len(self.steps_completed)
        return f"{completed}/{total}"

    @property
    def coverage_pct(self) -> float:
        """Percentage of steps completed."""
        if not self.steps:
            return 0.0
        return (len(self.steps_completed) / len(self.steps)) * 100

    def to_dict(self) -> dict:
        return {
            "flow_name": self.flow_name,
            "domain": self.domain,
            "progress": self.progress,
            "coverage_pct": round(self.coverage_pct, 1),
            "steps_total": len(self.steps),
            "steps_completed": self.steps_completed,
            "steps_skipped": self.steps_skipped,
            "steps_blocked": self.steps_blocked,
            "skip_reasons": self.skip_reasons,
            "fully_tested": self.fully_tested,
            "findings_in_flow": self.findings_in_flow,
            "block_point": self.block_point,
        }


@dataclass
class CoverageEntry:
    """Coverage information for a single surface."""
    surface_type: str          # "endpoint", "parameter", "method"
    identifier: str            # The specific item
    vuln_types_tested: list[str] = field(default_factory=list)
    test_depth: TestDepth = TestDepth.NOT_TESTED
    payloads_sent: int = 0
    findings_count: int = 0
    skip_reasons: list[SkipReason] = field(default_factory=list)
    absence_confidence: AbsenceConfidence = AbsenceConfidence.UNKNOWN
    first_test: str = ""
    last_test: str = ""

    def to_dict(self) -> dict:
        return {
            "surface_type": self.surface_type,
            "identifier": self.identifier,
            "vuln_types_tested": self.vuln_types_tested,
            "test_depth": self.test_depth.name,
            "payloads_sent": self.payloads_sent,
            "findings_count": self.findings_count,
            "skip_reasons": [r.name for r in self.skip_reasons],
            "absence_confidence": self.absence_confidence.name,
            "first_test": self.first_test,
            "last_test": self.last_test,
        }


@dataclass
class ModuleCoverage:
    """Coverage metrics for a scanner module."""
    module_name: str
    endpoints_tested: int = 0
    endpoints_skipped: int = 0
    params_tested: int = 0
    params_skipped: int = 0
    payloads_sent: int = 0
    findings_produced: int = 0
    execution_time_ms: int = 0
    skip_reasons: dict[str, int] = field(default_factory=dict)  # reason → count

    def coverage_percentage(self) -> float:
        """Calculate coverage as percentage of potential surfaces tested."""
        total = self.endpoints_tested + self.endpoints_skipped
        if total == 0:
            return 0.0
        return (self.endpoints_tested / total) * 100


class CoverageTracker:
    """
    Tracks what was tested, what was skipped, and why.

    This provides "meta-vision" — understanding not just what we found,
    but what we COULD have found if conditions were different.
    """

    def __init__(self) -> None:
        self._coverage_map: dict[str, CoverageEntry] = {}
        self._skipped_surfaces: list[SkippedSurface] = []
        self._module_coverage: dict[str, ModuleCoverage] = {}

        # Aggregate stats
        self._total_surfaces: int = 0
        self._tested_surfaces: int = 0
        self._start_time: datetime = datetime.now()

        # Track by vuln type
        self._vuln_type_coverage: dict[str, dict] = {}  # type → {tested, skipped, depth}

        # Stateful flow tracking
        self._stateful_flows: dict[str, StatefulFlow] = {}  # flow_name → StatefulFlow

        # THEME-13: Cross-module skip aggregation tracking
        # Track which modules skipped which endpoints, and which tested them
        self._skips_by_module: dict[str, set[str]] = {}  # module → {endpoint_ids skipped}
        self._tests_by_module: dict[str, set[str]] = {}  # module → {endpoint_ids tested}
        self._registered_modules: set[str] = set()  # All modules that participated

        # Phase tracking
        self._phase_history: list[dict] = []  # Track phase execution

    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE TRACKING
    # ═══════════════════════════════════════════════════════════════════════════

    def record_phase_start(self, phase_name: str, details: dict | None = None) -> None:
        """Record the start of a scan phase for coverage tracking."""
        self._phase_history.append({
            "phase": phase_name,
            "start_time": datetime.now().isoformat(),
            "details": details or {},
        })

    def record_phase_end(self, phase_name: str, findings_count: int = 0) -> None:
        """Record the end of a scan phase."""
        for phase in reversed(self._phase_history):
            if phase["phase"] == phase_name and "end_time" not in phase:
                phase["end_time"] = datetime.now().isoformat()
                phase["findings_count"] = findings_count
                break

    # ═══════════════════════════════════════════════════════════════════════════
    # SURFACE REGISTRATION
    # ═══════════════════════════════════════════════════════════════════════════

    def register_surface(
        self,
        surface_type: str,
        identifier: str,
        vuln_types: list[str] | None = None,
    ) -> None:
        """Register a surface (endpoint/param) that could be tested."""
        key = f"{surface_type}:{identifier}"

        if key not in self._coverage_map:
            self._coverage_map[key] = CoverageEntry(
                surface_type=surface_type,
                identifier=identifier,
                vuln_types_tested=vuln_types or [],
            )
            self._total_surfaces += 1

    def register_endpoint(self, url: str, methods: list[str] | None = None) -> None:
        """Register an endpoint for coverage tracking."""
        self.register_surface("endpoint", url)
        for method in (methods or ["GET"]):
            self.register_surface("method", f"{method}:{url}")

    def register_parameter(
        self,
        endpoint: str,
        param_name: str,
        param_type: str = "query",
    ) -> None:
        """Register a parameter for coverage tracking."""
        identifier = f"{endpoint}::{param_type}:{param_name}"
        self.register_surface("parameter", identifier)

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST RECORDING
    # ═══════════════════════════════════════════════════════════════════════════

    def record_test(
        self,
        surface_type: str,
        identifier: str,
        vuln_type: str,
        payloads_sent: int = 1,
        found_vulnerability: bool = False,
        depth: TestDepth = TestDepth.STANDARD,
        module_name: str = "",
    ) -> None:
        """Record that a test was performed on a surface."""
        key = f"{surface_type}:{identifier}"
        now = datetime.now().isoformat()

        # THEME-13: Track test by module for cross-module aggregation
        if module_name:
            self._registered_modules.add(module_name)
            if module_name not in self._tests_by_module:
                self._tests_by_module[module_name] = set()
            self._tests_by_module[module_name].add(identifier)

        if key not in self._coverage_map:
            self._coverage_map[key] = CoverageEntry(
                surface_type=surface_type,
                identifier=identifier,
                first_test=now,
            )
            self._total_surfaces += 1

        entry = self._coverage_map[key]

        # Update coverage
        if vuln_type not in entry.vuln_types_tested:
            entry.vuln_types_tested.append(vuln_type)

        entry.payloads_sent += payloads_sent
        entry.last_test = now

        if not entry.first_test:
            entry.first_test = now

        # Update depth (keep highest)
        if depth.value > entry.test_depth.value:
            entry.test_depth = depth

        if found_vulnerability:
            entry.findings_count += 1

        # Update absence confidence based on depth
        self._update_absence_confidence(entry)

        # Track as tested
        self._tested_surfaces += 1

        # Update vuln type coverage
        if vuln_type not in self._vuln_type_coverage:
            self._vuln_type_coverage[vuln_type] = {
                "tested": 0,
                "skipped": 0,
                "findings": 0,
                "depth_sum": 0,
            }
        self._vuln_type_coverage[vuln_type]["tested"] += 1
        self._vuln_type_coverage[vuln_type]["depth_sum"] += depth.value
        if found_vulnerability:
            self._vuln_type_coverage[vuln_type]["findings"] += 1

    def _update_absence_confidence(self, entry: CoverageEntry) -> None:
        """Update absence confidence based on testing depth and findings."""
        if entry.findings_count > 0:
            # Found something, absence confidence not applicable
            entry.absence_confidence = AbsenceConfidence.UNKNOWN
            return

        # Map depth to absence confidence
        depth_to_confidence = {
            TestDepth.NOT_TESTED: AbsenceConfidence.UNKNOWN,
            TestDepth.MINIMAL: AbsenceConfidence.VERY_LOW,
            TestDepth.STANDARD: AbsenceConfidence.MEDIUM,
            TestDepth.THOROUGH: AbsenceConfidence.HIGH,
            TestDepth.EXHAUSTIVE: AbsenceConfidence.VERY_HIGH,
        }

        entry.absence_confidence = depth_to_confidence.get(
            entry.test_depth, AbsenceConfidence.LOW
        )

        # Boost confidence if multiple vuln types tested
        if len(entry.vuln_types_tested) >= 5:
            if entry.absence_confidence.value < AbsenceConfidence.HIGH.value:
                entry.absence_confidence = AbsenceConfidence(
                    entry.absence_confidence.value + 1
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # SKIP RECORDING
    # ═══════════════════════════════════════════════════════════════════════════

    def record_skip(
        self,
        surface_type: str,
        identifier: str,
        reason: SkipReason,
        reason_detail: str = "",
        vuln_type: str = "",
        potential_impact: str = "",
        recoverable: bool = True,
        retry_context: dict | None = None,
        module_name: str = "",
    ) -> None:
        """Record that a surface was skipped."""
        key = f"{surface_type}:{identifier}"

        # Create surface entry if needed
        if key not in self._coverage_map:
            self._coverage_map[key] = CoverageEntry(
                surface_type=surface_type,
                identifier=identifier,
            )
            self._total_surfaces += 1

        entry = self._coverage_map[key]
        if reason not in entry.skip_reasons:
            entry.skip_reasons.append(reason)

        # Record detailed skip
        skipped = SkippedSurface(
            surface_type=surface_type,
            identifier=identifier,
            reason=reason,
            reason_detail=reason_detail,
            potential_impact=potential_impact,
            recoverable=recoverable,
            retry_context=retry_context or {},
        )
        self._skipped_surfaces.append(skipped)

        # THEME-13: Track skip by module for cross-module aggregation
        if module_name:
            self._registered_modules.add(module_name)
            if module_name not in self._skips_by_module:
                self._skips_by_module[module_name] = set()
            self._skips_by_module[module_name].add(identifier)

        # Update vuln type coverage
        if vuln_type:
            if vuln_type not in self._vuln_type_coverage:
                self._vuln_type_coverage[vuln_type] = {
                    "tested": 0,
                    "skipped": 0,
                    "findings": 0,
                    "depth_sum": 0,
                }
            self._vuln_type_coverage[vuln_type]["skipped"] += 1

        logger.debug(
            f"[COVERAGE] Skipped {surface_type}:{identifier[:50]} - "
            f"{reason.name}: {reason_detail[:100]}"
        )

    def record_rate_limited(self, endpoint: str, vuln_type: str = "") -> None:
        """Convenience: record a rate-limited skip."""
        self.record_skip(
            surface_type="endpoint",
            identifier=endpoint,
            reason=SkipReason.RATE_LIMITED,
            reason_detail="Received 429 or hit rate limit",
            vuln_type=vuln_type,
            potential_impact="May have missed vulnerabilities due to incomplete testing",
            recoverable=True,
        )

    def record_auth_required(self, endpoint: str, vuln_type: str = "") -> None:
        """Convenience: record an auth-required skip."""
        self.record_skip(
            surface_type="endpoint",
            identifier=endpoint,
            reason=SkipReason.AUTH_REQUIRED,
            reason_detail="Endpoint requires authentication we don't have",
            vuln_type=vuln_type,
            potential_impact="Authenticated attack surface not tested",
            recoverable=True,
            retry_context={"needs": "valid_auth_token"},
        )

    def record_waf_blocked(self, endpoint: str, vuln_type: str = "") -> None:
        """Convenience: record a WAF-blocked skip."""
        self.record_skip(
            surface_type="endpoint",
            identifier=endpoint,
            reason=SkipReason.BLOCKED_BY_WAF,
            reason_detail="WAF blocked the test payloads",
            vuln_type=vuln_type,
            potential_impact="Vulnerability may exist behind WAF",
            recoverable=True,
            retry_context={"needs": "waf_bypass_payloads"},
        )

    def record_param_mismatch(
        self,
        endpoint: str,
        param: str,
        expected_type: str,
        vuln_type: str,
    ) -> None:
        """Convenience: record a parameter type mismatch skip."""
        self.record_skip(
            surface_type="parameter",
            identifier=f"{endpoint}::{param}",
            reason=SkipReason.PARAM_TYPE_MISMATCH,
            reason_detail=f"Parameter expects {expected_type}, incompatible with {vuln_type}",
            vuln_type=vuln_type,
            potential_impact="None - correct behavior",
            recoverable=False,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # MODULE TRACKING
    # ═══════════════════════════════════════════════════════════════════════════

    def start_module(self, module_name: str) -> None:
        """Start tracking a module's coverage."""
        if module_name not in self._module_coverage:
            self._module_coverage[module_name] = ModuleCoverage(module_name=module_name)

    def record_module_test(
        self,
        module_name: str,
        endpoints_tested: int = 0,
        params_tested: int = 0,
        payloads_sent: int = 0,
        findings: int = 0,
    ) -> None:
        """Record module testing activity."""
        if module_name not in self._module_coverage:
            self.start_module(module_name)

        mc = self._module_coverage[module_name]
        mc.endpoints_tested += endpoints_tested
        mc.params_tested += params_tested
        mc.payloads_sent += payloads_sent
        mc.findings_produced += findings

    def record_module_skip(
        self,
        module_name: str,
        endpoints_skipped: int = 0,
        params_skipped: int = 0,
        reason: SkipReason = SkipReason.LOW_PRIORITY,
    ) -> None:
        """Record module skipping activity."""
        if module_name not in self._module_coverage:
            self.start_module(module_name)

        mc = self._module_coverage[module_name]
        mc.endpoints_skipped += endpoints_skipped
        mc.params_skipped += params_skipped

        reason_name = reason.name
        mc.skip_reasons[reason_name] = mc.skip_reasons.get(reason_name, 0) + 1

    def finish_module(self, module_name: str, execution_time_ms: int) -> None:
        """Finalize module tracking with execution time."""
        if module_name in self._module_coverage:
            self._module_coverage[module_name].execution_time_ms = execution_time_ms

    # ═══════════════════════════════════════════════════════════════════════════
    # STATEFUL FLOW TRACKING
    # Tracks multi-step business flows like checkout, auth, payment
    # ═══════════════════════════════════════════════════════════════════════════

    def register_stateful_flow(
        self,
        flow_name: str,
        steps: list[str],
        domain: str = "unknown",
    ) -> None:
        """
        Register a stateful flow for coverage tracking.

        Args:
            flow_name: Name like "checkout_flow", "auth_flow", "transfer_flow"
            steps: Ordered list of step names ["cart", "shipping", "payment", "confirm"]
            domain: Business domain like "ecommerce", "fintech", "auth"
        """
        self._stateful_flows[flow_name] = StatefulFlow(
            flow_name=flow_name,
            domain=domain,
            steps=steps.copy(),
        )
        logger.debug(f"[COVERAGE] Registered flow {flow_name}: {len(steps)} steps")

    def record_flow_step_completed(
        self,
        flow_name: str,
        step: str,
        found_vulnerability: bool = False,
    ) -> None:
        """Record that a flow step was successfully tested."""
        if flow_name not in self._stateful_flows:
            # Auto-register if not present
            self._stateful_flows[flow_name] = StatefulFlow(
                flow_name=flow_name,
                domain="auto",
                steps=[step],
            )

        flow = self._stateful_flows[flow_name]

        if step not in flow.steps:
            flow.steps.append(step)

        if step not in flow.steps_completed:
            flow.steps_completed.append(step)

        if found_vulnerability:
            flow.findings_in_flow += 1

        # Check if fully tested
        flow.fully_tested = set(flow.steps_completed) == set(flow.steps)

    def record_flow_step_skipped(
        self,
        flow_name: str,
        step: str,
        reason: str = "",
    ) -> None:
        """Record that a flow step was skipped."""
        if flow_name not in self._stateful_flows:
            return  # Can't skip a step in unknown flow

        flow = self._stateful_flows[flow_name]

        if step not in flow.steps_skipped:
            flow.steps_skipped.append(step)

        if reason:
            flow.skip_reasons[step] = reason

    def record_flow_blocked(
        self,
        flow_name: str,
        step: str,
        reason: str = "",
    ) -> None:
        """Record that a flow was blocked at a specific step."""
        if flow_name not in self._stateful_flows:
            return

        flow = self._stateful_flows[flow_name]

        if step not in flow.steps_blocked:
            flow.steps_blocked.append(step)

        flow.block_point = step

        if reason:
            flow.skip_reasons[step] = reason

    def get_flow_coverage_summary(self) -> dict[str, Any]:
        """Get summary of stateful flow coverage."""
        if not self._stateful_flows:
            return {
                "total_flows": 0,
                "flows_fully_tested": 0,
                "flows_partially_tested": 0,
                "flows_blocked": 0,
                "progress": "0/0",
            }

        total = len(self._stateful_flows)
        fully_tested = sum(1 for f in self._stateful_flows.values() if f.fully_tested)
        blocked = sum(1 for f in self._stateful_flows.values() if f.block_point)
        partially = total - fully_tested - blocked

        # Calculate overall step progress
        total_steps = sum(len(f.steps) for f in self._stateful_flows.values())
        completed_steps = sum(len(f.steps_completed) for f in self._stateful_flows.values())

        return {
            "total_flows": total,
            "flows_fully_tested": fully_tested,
            "flows_partially_tested": partially,
            "flows_blocked": blocked,
            "total_steps": total_steps,
            "completed_steps": completed_steps,
            "progress": f"{completed_steps}/{total_steps}",
            "tested_flows": [
                f.flow_name for f in self._stateful_flows.values() if f.fully_tested
            ],
            "blocked_flows": [
                {"flow": f.flow_name, "at": f.block_point}
                for f in self._stateful_flows.values() if f.block_point
            ],
            "flows": {
                name: flow.to_dict()
                for name, flow in self._stateful_flows.items()
            },
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # ANALYSIS & REPORTING
    # ═══════════════════════════════════════════════════════════════════════════

    def get_coverage_percentage(self) -> float:
        """Get overall coverage as a percentage."""
        if self._total_surfaces == 0:
            return 0.0
        return (self._tested_surfaces / self._total_surfaces) * 100

    def get_surfaces_needing_retest(self) -> list[SkippedSurface]:
        """Get surfaces that were skipped but could be retested."""
        return [s for s in self._skipped_surfaces if s.recoverable]

    def get_high_value_gaps(self) -> list[dict]:
        """
        Identify high-value surfaces that weren't fully tested.

        These are surfaces where:
        - Low test depth on potentially sensitive endpoints
        - Skipped due to recoverable reasons
        - Low absence confidence
        """
        gaps = []

        # Patterns indicating high-value surfaces
        high_value_patterns = [
            "admin", "login", "auth", "payment", "checkout",
            "user", "account", "api", "internal", "transfer",
            "password", "token", "session", "config",
        ]

        for key, entry in self._coverage_map.items():
            # Check if high-value
            is_high_value = any(
                p in entry.identifier.lower()
                for p in high_value_patterns
            )

            if not is_high_value:
                continue

            # Check for gaps
            is_gap = (
                entry.test_depth.value <= TestDepth.MINIMAL.value or
                entry.absence_confidence.value <= AbsenceConfidence.LOW.value or
                len(entry.skip_reasons) > 0
            )

            if is_gap:
                gaps.append({
                    "surface": entry.identifier,
                    "type": entry.surface_type,
                    "test_depth": entry.test_depth.name,
                    "absence_confidence": entry.absence_confidence.name,
                    "skip_reasons": [r.name for r in entry.skip_reasons],
                    "vuln_types_tested": entry.vuln_types_tested,
                    "recommendation": self._recommend_action(entry),
                })

        return gaps

    def _recommend_action(self, entry: CoverageEntry) -> str:
        """Recommend action for a coverage gap."""
        if SkipReason.AUTH_REQUIRED in entry.skip_reasons:
            return "Provide authentication credentials to test this surface"
        if SkipReason.RATE_LIMITED in entry.skip_reasons:
            return "Retry with lower rate or during off-peak hours"
        if SkipReason.BLOCKED_BY_WAF in entry.skip_reasons:
            return "Use WAF bypass payloads or test from whitelisted IP"
        if entry.test_depth.value <= TestDepth.MINIMAL.value:
            return "Increase testing depth with --safe-mode standard or aggressive"
        if len(entry.vuln_types_tested) < 3:
            return f"Test for additional vuln types (current: {entry.vuln_types_tested})"
        return "Manual review recommended"

    def get_vuln_type_summary(self) -> dict[str, dict]:
        """Get coverage summary by vulnerability type."""
        summary = {}

        for vuln_type, stats in self._vuln_type_coverage.items():
            total = stats["tested"] + stats["skipped"]
            coverage = (stats["tested"] / total * 100) if total > 0 else 0
            avg_depth = (
                stats["depth_sum"] / stats["tested"]
                if stats["tested"] > 0 else 0
            )

            summary[vuln_type] = {
                "tested": stats["tested"],
                "skipped": stats["skipped"],
                "findings": stats["findings"],
                "coverage_pct": round(coverage, 1),
                "avg_depth": round(avg_depth, 1),
                "confidence": self._depth_to_confidence_label(avg_depth),
            }

        return summary

    def _depth_to_confidence_label(self, avg_depth: float) -> str:
        """Convert average depth to confidence label."""
        if avg_depth >= 3.5:
            return "VERY_HIGH"
        if avg_depth >= 2.5:
            return "HIGH"
        if avg_depth >= 1.5:
            return "MEDIUM"
        if avg_depth >= 0.5:
            return "LOW"
        return "UNKNOWN"

    def get_skip_summary(self) -> dict[str, int]:
        """Get summary of skip reasons."""
        summary: dict[str, int] = {}
        for skipped in self._skipped_surfaces:
            reason_name = skipped.reason.name
            summary[reason_name] = summary.get(reason_name, 0) + 1
        return summary

    def get_tested_clean_summary(self) -> dict[str, Any]:
        """
        Get summary of surfaces that were tested and found clean.

        REPORT-02 FIX: Provide "negative results" for analyst confidence.
        Shows what was actively tested and confirmed secure.
        """
        clean_endpoints: list[str] = []
        clean_by_vuln_type: dict[str, int] = {}

        for key, entry in self._coverage_map.items():
            # Surface was tested (not just registered) and no findings
            if entry.test_depth.value >= TestDepth.MINIMAL.value and entry.findings_count == 0:
                clean_endpoints.append(entry.identifier)
                for vtype in entry.vuln_types_tested:
                    clean_by_vuln_type[vtype] = clean_by_vuln_type.get(vtype, 0) + 1

        return {
            "total_clean_surfaces": len(clean_endpoints),
            "clean_by_vuln_type": clean_by_vuln_type,
            "sample_clean_endpoints": clean_endpoints[:10],  # Limit output
            "confidence_note": (
                "These surfaces were actively tested and no vulnerabilities were found. "
                "Confidence depends on test depth (see vuln_type_coverage)."
            ),
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # THEME-13: CROSS-MODULE SKIP ACCUMULATION ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════

    def analyze_skip_accumulation(self) -> dict[str, Any]:
        """
        THEME-13: Analyze cross-module skip patterns to find coverage gaps.

        This detects the "suboptimal decision accumulation" problem where:
        - Each module independently skips 5% of endpoints
        - 77 modules × 5% = some endpoints never tested by ANY module
        - Individual decisions look reasonable; aggregate is not

        Returns analysis of endpoints that were skipped by multiple modules.
        """
        if not self._registered_modules:
            return {
                "total_modules": 0,
                "critical_gaps": [],
                "warning": "No module skip tracking data available",
            }

        total_modules = len(self._registered_modules)

        # Aggregate: which endpoints were skipped by which modules
        endpoint_skip_counts: dict[str, list[str]] = {}  # endpoint → [module names that skipped]
        endpoint_test_counts: dict[str, list[str]] = {}  # endpoint → [module names that tested]

        # Collect all unique endpoints
        all_endpoints: set[str] = set()
        for module_skips in self._skips_by_module.values():
            all_endpoints.update(module_skips)
        for module_tests in self._tests_by_module.values():
            all_endpoints.update(module_tests)

        # Count skips and tests per endpoint
        for endpoint in all_endpoints:
            skipping_modules = []
            testing_modules = []

            for module in self._registered_modules:
                if endpoint in self._skips_by_module.get(module, set()):
                    skipping_modules.append(module)
                if endpoint in self._tests_by_module.get(module, set()):
                    testing_modules.append(module)

            endpoint_skip_counts[endpoint] = skipping_modules
            endpoint_test_counts[endpoint] = testing_modules

        # Find critical gaps: endpoints skipped by >50% of modules
        critical_threshold = total_modules * 0.5
        warning_threshold = total_modules * 0.3

        critical_gaps = []
        warning_gaps = []
        never_tested = []

        for endpoint, skipping_modules in endpoint_skip_counts.items():
            skip_count = len(skipping_modules)
            test_count = len(endpoint_test_counts.get(endpoint, []))

            # Never tested by any module
            if test_count == 0 and skip_count > 0:
                never_tested.append({
                    "endpoint": endpoint,
                    "skipped_by": skip_count,
                    "modules": skipping_modules[:5],  # Limit for readability
                    "severity": "CRITICAL",
                })
            # Skipped by >50% of modules
            elif skip_count >= critical_threshold:
                critical_gaps.append({
                    "endpoint": endpoint,
                    "skipped_by": skip_count,
                    "tested_by": test_count,
                    "skip_ratio": round(skip_count / total_modules * 100, 1),
                    "modules_skipped": skipping_modules[:5],
                    "modules_tested": endpoint_test_counts.get(endpoint, [])[:3],
                    "severity": "HIGH",
                })
            # Skipped by >30% of modules
            elif skip_count >= warning_threshold:
                warning_gaps.append({
                    "endpoint": endpoint,
                    "skipped_by": skip_count,
                    "tested_by": test_count,
                    "skip_ratio": round(skip_count / total_modules * 100, 1),
                    "severity": "MEDIUM",
                })

        # Sort by severity (skip count)
        critical_gaps.sort(key=lambda x: -x["skipped_by"])
        warning_gaps.sort(key=lambda x: -x["skipped_by"])
        never_tested.sort(key=lambda x: -x["skipped_by"])

        # Log critical gaps for audit trail
        if never_tested:
            logger.info(
                f"[AUDIT] Skip accumulation: {len(never_tested)} endpoints NEVER TESTED "
                f"(skipped by all participating modules)"
            )
            for gap in never_tested[:3]:
                logger.info(
                    f"[AUDIT]   - {gap['endpoint'][:60]} skipped by {gap['skipped_by']} modules"
                )

        if critical_gaps:
            logger.info(
                f"[AUDIT] Skip accumulation: {len(critical_gaps)} endpoints skipped by >50% of modules"
            )

        return {
            "total_modules": total_modules,
            "total_endpoints_tracked": len(all_endpoints),
            "never_tested": never_tested[:20],  # Limit output
            "never_tested_count": len(never_tested),
            "critical_gaps": critical_gaps[:20],
            "critical_gap_count": len(critical_gaps),
            "warning_gaps": warning_gaps[:10],
            "warning_gap_count": len(warning_gaps),
            "accumulation_severity": self._classify_accumulation_severity(
                len(never_tested), len(critical_gaps), len(all_endpoints)
            ),
            "recommendation": self._get_accumulation_recommendation(
                len(never_tested), len(critical_gaps)
            ),
        }

    def _classify_accumulation_severity(
        self,
        never_tested: int,
        critical_gaps: int,
        total_endpoints: int,
    ) -> str:
        """Classify the severity of skip accumulation."""
        if total_endpoints == 0:
            return "UNKNOWN"

        gap_ratio = (never_tested + critical_gaps) / total_endpoints

        if never_tested > 10 or gap_ratio > 0.2:
            return "CRITICAL"
        if never_tested > 5 or gap_ratio > 0.1:
            return "HIGH"
        if never_tested > 0 or critical_gaps > 5:
            return "MEDIUM"
        if critical_gaps > 0:
            return "LOW"
        return "OK"

    def _get_accumulation_recommendation(
        self,
        never_tested: int,
        critical_gaps: int,
    ) -> str:
        """Get recommendation based on accumulation analysis."""
        if never_tested > 10:
            return (
                "CRITICAL: Multiple endpoints were never tested by any module. "
                "Review skip reasons and consider targeted re-scans with "
                "different configurations (auth, rate limits, WAF bypass)."
            )
        if never_tested > 0:
            return (
                f"Some endpoints ({never_tested}) were skipped by all modules. "
                "Check if these require special access or have technical barriers."
            )
        if critical_gaps > 5:
            return (
                f"Many endpoints ({critical_gaps}) were skipped by >50% of modules. "
                "Coverage appears fragmented; consider consolidating test approach."
            )
        if critical_gaps > 0:
            return (
                "Minor skip accumulation detected. Some endpoints have reduced "
                "coverage due to multiple modules skipping them independently."
            )
        return "No significant skip accumulation detected. Coverage is well-distributed."

    def get_module_skip_matrix(self) -> dict[str, dict[str, int]]:
        """
        Get matrix showing skip/test counts per module.

        Returns: {module: {tested: N, skipped: M, ratio: P%}}
        """
        matrix = {}
        for module in self._registered_modules:
            tested = len(self._tests_by_module.get(module, set()))
            skipped = len(self._skips_by_module.get(module, set()))
            total = tested + skipped

            matrix[module] = {
                "tested": tested,
                "skipped": skipped,
                "total": total,
                "skip_ratio": round(skipped / total * 100, 1) if total > 0 else 0,
            }

        return matrix

    def to_dict(self) -> dict[str, Any]:
        """Export coverage data as dictionary."""
        duration = (datetime.now() - self._start_time).total_seconds()

        return {
            "summary": {
                "total_surfaces": self._total_surfaces,
                "tested_surfaces": self._tested_surfaces,
                "coverage_percentage": round(self.get_coverage_percentage(), 1),
                "scan_duration_seconds": round(duration, 1),
            },
            "vuln_type_coverage": self.get_vuln_type_summary(),
            "skip_summary": self.get_skip_summary(),
            "high_value_gaps": self.get_high_value_gaps(),
            "surfaces_needing_retest": [
                {
                    "surface": s.identifier,
                    "type": s.surface_type,
                    "reason": s.reason.name,
                    "detail": s.reason_detail,
                    "retry_context": s.retry_context,
                }
                for s in self.get_surfaces_needing_retest()[:20]  # Limit output
            ],
            "module_coverage": {
                name: {
                    "endpoints_tested": mc.endpoints_tested,
                    "endpoints_skipped": mc.endpoints_skipped,
                    "params_tested": mc.params_tested,
                    "params_skipped": mc.params_skipped,
                    "payloads_sent": mc.payloads_sent,
                    "findings": mc.findings_produced,
                    "execution_time_ms": mc.execution_time_ms,
                    "coverage_pct": round(mc.coverage_percentage(), 1),
                }
                for name, mc in self._module_coverage.items()
            },
            # REPORT-02: Add "tested but clean" summary for analyst confidence
            "tested_clean_summary": self.get_tested_clean_summary(),
            # Stateful flow coverage (checkout, auth, payment flows)
            "flow_coverage": self.get_flow_coverage_summary(),
            # THEME-13: Cross-module skip accumulation analysis
            "skip_accumulation": self.analyze_skip_accumulation(),
            "module_skip_matrix": self.get_module_skip_matrix(),
        }

    def log_summary(self) -> None:
        """Log a human-readable coverage summary."""
        pct = self.get_coverage_percentage()
        logger.info(f"[COVERAGE] Overall: {pct:.1f}% ({self._tested_surfaces}/{self._total_surfaces} surfaces)")

        skips = self.get_skip_summary()
        if skips:
            top_skips = sorted(skips.items(), key=lambda x: -x[1])[:3]
            logger.info(f"[COVERAGE] Top skip reasons: {', '.join(f'{k}:{v}' for k, v in top_skips)}")

        gaps = self.get_high_value_gaps()
        if gaps:
            logger.warning(f"[COVERAGE] {len(gaps)} high-value surfaces need attention")

        # THEME-13: Log skip accumulation analysis
        accumulation = self.analyze_skip_accumulation()
        if accumulation.get("never_tested_count", 0) > 0:
            logger.warning(
                f"[COVERAGE] ACCUMULATION: {accumulation['never_tested_count']} endpoints "
                f"never tested (skipped by all modules)"
            )
        if accumulation.get("critical_gap_count", 0) > 0:
            logger.warning(
                f"[COVERAGE] ACCUMULATION: {accumulation['critical_gap_count']} endpoints "
                f"skipped by >50% of modules"
            )
        if accumulation.get("accumulation_severity") in ("CRITICAL", "HIGH"):
            logger.warning(
                f"[COVERAGE] {accumulation.get('recommendation', '')}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ═══════════════════════════════════════════════════════════════════════════════

_coverage_tracker: CoverageTracker | None = None


def get_coverage_tracker() -> CoverageTracker:
    """Get the global coverage tracker instance."""
    global _coverage_tracker
    if _coverage_tracker is None:
        _coverage_tracker = CoverageTracker()
    return _coverage_tracker


def reset_coverage_tracker() -> CoverageTracker:
    """Reset and return a new coverage tracker."""
    global _coverage_tracker
    _coverage_tracker = CoverageTracker()
    return _coverage_tracker
