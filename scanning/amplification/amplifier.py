"""
Scan Amplifier - Adaptive depth and cross-finding amplification engine.

Philosophy: "When you find something, dig deeper."

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING

from .models import AmplificationAction, AmplificationGuardrails
from .tracker import AmplificationTracker

if TYPE_CHECKING:
    from scanning.full_scanner import FullScanner

logger = logging.getLogger("phantom.amplification")


def _get_scanner_limits():
    """Get scanner limits from config, returns None if not available."""
    try:
        from scanning.config.limits import get_scanner_limits
        return get_scanner_limits()
    except ImportError:
        return None


class ScanAmplifier:
    """
    Adaptive Depth & Cross-Finding Amplification Engine.

    Philosophy: "When you find something, dig deeper."

    Implements 3 key capabilities:
    1. ADAPTIVE DEPTH - When a finding is discovered, expand testing:
       - IDOR found → test more IDs (10 → 50)
       - Auth bypass → probe all admin endpoints
       - SQLi → try more extraction queries

    2. CROSS-FINDING AMPLIFICATION - Findings trigger re-tests:
       - IDOR found → re-run business_logic on that endpoint
       - Auth bypass found → re-run authz with bypassed auth
       - JWT weakness → re-test session endpoints

    3. NEGATIVE RESULT ANALYSIS - Turn failures into new paths:
       - If XSS fails with <script> → try event handlers
       - If SQLi fails on GET → try POST
       - If auth bypass fails on /admin → try /api/admin
    """

    # Which modules should run when a finding type is discovered
    AMPLIFICATION_MAP: dict[str, list[str]] = {
        # IDOR → test business logic, session, creative exploiter
        "idor": ["business", "session_abuse", "creative_exploiter"],
        "authorization": ["business", "session_abuse", "idor"],
        "access_control": ["business", "session_abuse", "idor"],

        # Auth bypass → test admin endpoints, privesc, session
        "auth_bypass": ["authz", "session_abuse", "creative_exploiter"],
        "authentication_bypass": ["authz", "session_abuse", "creative_exploiter"],

        # Session weakness → test auth, IDOR, business logic
        "session_abuse": ["auth", "idor", "business"],
        "jwt_weakness": ["auth", "session_abuse", "creative_exploiter"],
        "jwt": ["session_abuse", "auth", "creative_exploiter"],

        # SQLi → try LFI/SSRF on same endpoint (often co-occur)
        "sql_injection": ["lfi", "ssrf", "business"],
        "sqli": ["lfi", "ssrf", "business"],

        # XSS → test CORS, session theft
        "xss": ["cors", "session_abuse", "csrf"],
        "dom_xss": ["cors", "session_abuse", "csrf"],

        # Business logic → test race conditions, session, stateful flows
        "business_logic": ["race", "session_abuse", "creative_exploiter", "stateful_flow"],

        # Stateful flow → test race conditions, session abuse
        "stateful_flow": ["race", "session_abuse", "business"],

        # CORS → test XSS for delivery
        "cors": ["xss", "dom_xss", "session_abuse"],

        # === SMUGGLING AS ENABLER (not terminal finding) ===
        # HTTP Smuggling → amplifies everything (desync enables bypass of WAFs, cache poisoning)
        "http_smuggling": ["xss", "auth", "cache", "cors", "creative_exploiter"],
        "request_smuggling": ["xss", "auth", "cache", "cors", "creative_exploiter"],
        "smuggling": ["xss", "auth", "cache", "cors", "creative_exploiter"],
        "cl_te": ["xss", "auth", "cache", "cors"],
        "te_cl": ["xss", "auth", "cache", "cors"],

        # Cache poisoning → XSS delivery, session abuse
        "cache_poisoning": ["xss", "session_abuse", "auth"],
    }

    # Endpoint patterns that indicate admin functionality
    ADMIN_PATTERNS = [
        r'/admin', r'/administrator', r'/manage', r'/dashboard',
        r'/control', r'/api/admin', r'/api/internal', r'/console',
    ]

    def __init__(self, scanner: "FullScanner") -> None:
        self._scanner = scanner
        self._discovered_types: set[str] = set()
        self._amplification_queue: list[AmplificationAction] = []
        self._executed_amplifications: set[str] = set()
        self._negative_results: dict[str, list[dict]] = {}  # type → list of failed attempts

        # Initialize guardrails and tracker for feedback loop safety
        self._guardrails = AmplificationGuardrails()
        self._tracker = AmplificationTracker(self._guardrails)

        # Load configurable limits
        limits = _get_scanner_limits()
        if limits:
            self._max_actions_per_finding = limits.amplification.max_actions_per_finding
            self._max_total_actions = limits.amplification.max_total_actions
            self._idor_expand_to = limits.idor.max_ids_per_endpoint * 5  # Expand 5x on discovery
            self._race_concurrent = limits.race_condition.concurrent_requests
            # Override guardrails with configured limits
            self._guardrails.max_actions_per_finding = self._max_actions_per_finding
            self._guardrails.global_action_budget = self._max_total_actions * 20  # Budget = 20x max actions
        else:
            # Fallback defaults
            self._max_actions_per_finding = 10
            self._max_total_actions = 50
            self._idor_expand_to = 50
            self._race_concurrent = 10

    def _generate_finding_id(self, finding: dict) -> str:
        """Generate a stable ID for a finding based on its key attributes."""
        finding_type = finding.get("type", "")
        matched_at = finding.get("matched_at", "") or finding.get("url", "")
        name = finding.get("name", "")
        param = finding.get("metadata", {}).get("parameter", "") if finding.get("metadata") else ""

        # Create stable hash from key attributes
        key = f"{finding_type}:{matched_at}:{name}:{param}"
        return hashlib.md5(key.encode()).hexdigest()[:16]

    def _get_action_cost(self, action_name: str) -> int:
        """Get the budget cost for an action type."""
        return self._guardrails.action_costs.get(
            action_name,
            self._guardrails.action_costs.get("default", 1)
        )

    def on_finding_discovered(self, finding: dict) -> list[AmplificationAction]:
        """
        Called when a finding is discovered. Returns amplification actions to take.

        This is the core of adaptive depth - when we find something,
        we determine what additional testing should be triggered.
        """
        actions: list[AmplificationAction] = []

        finding_type = self._normalize_type(finding.get("type", ""))
        severity = finding.get("severity", "MEDIUM")
        matched_at = finding.get("matched_at", "") or finding.get("url", "")
        metadata = finding.get("metadata", {}) or {}

        # Generate stable finding ID for guardrail tracking
        finding_id = self._generate_finding_id(finding)

        # Track discovered types
        self._discovered_types.add(finding_type)

        # Skip if low severity and not injection-related
        if severity in ("LOW", "INFO") and finding_type not in (
            "sqli", "xss", "cmdi", "ssrf", "lfi", "xxe", "ssti"
        ):
            return actions

        # === ADAPTIVE DEPTH ===
        # Expand testing based on what was found

        # 1. IDOR found → test more IDs
        if finding_type in ("idor", "authorization", "access_control"):
            if matched_at:
                params = {"expand_to": self._idor_expand_to}  # Configurable via scanner_limits.idor
                # Only add these if metadata is a dict
                if isinstance(metadata, dict):
                    params["original_id"] = metadata.get("original_id", "")
                    params["working_id"] = metadata.get("test_id", "")
                actions.append(AmplificationAction(
                    trigger_type=finding_type,
                    action="expand_idor_range",
                    target=matched_at,
                    params=params,
                    priority=8,
                    finding_id=finding_id,
                    cost=self._get_action_cost("expand_idor_range"),
                ))
                # Also test different HTTP methods (read → write escalation)
                actions.append(AmplificationAction(
                    trigger_type=finding_type,
                    action="test_method_escalation",
                    target=matched_at,
                    params={"methods": ["PUT", "PATCH", "DELETE", "POST"]},
                    priority=9,
                    finding_id=finding_id,
                    cost=self._get_action_cost("test_method_escalation"),
                ))

        # 2. Auth bypass found → probe all admin endpoints
        if finding_type in ("auth_bypass", "authentication_bypass"):
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="probe_admin_endpoints",
                target=matched_at,
                params={"with_bypass": True},
                priority=10,
                finding_id=finding_id,
                cost=self._get_action_cost("probe_admin_endpoints"),
            ))

        # 3. SQLi found → try more extraction queries
        if finding_type in ("sqli", "sql_injection"):
            db_type = ""
            param = ""
            payload = ""
            if isinstance(metadata, dict):
                db_type = metadata.get("database_type", "").lower()
                param = metadata.get("parameter", "")
                payload = metadata.get("payload", "")
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="expand_sqli_extraction",
                target=matched_at,
                params={
                    "database_type": db_type,
                    "param": param,
                    "payload": payload,
                },
                priority=9,
                finding_id=finding_id,
                cost=self._get_action_cost("expand_sqli_extraction"),
            ))

        # 4. Business logic flaw → test race conditions
        if finding_type == "business_logic":
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="test_race_condition",
                target=matched_at,
                params={"concurrent_requests": self._race_concurrent},  # Configurable
                priority=7,
                finding_id=finding_id,
                cost=self._get_action_cost("test_race_condition"),
            ))

        # 5. HTTP Smuggling found → AMPLIFIER MODE (not terminal finding!)
        # Philosophy: Smuggling enables bypassing WAFs, cache poisoning, request hijacking
        if finding_type in ("http_smuggling", "request_smuggling", "smuggling", "cl_te", "te_cl"):
            # Get smuggling technique details
            smuggling_type = "cl_te"
            smuggling_payload = ""
            if isinstance(metadata, dict):
                smuggling_type = metadata.get("smuggling_type", "cl_te")
                smuggling_payload = metadata.get("payload", "")

            # Action: Test XSS via smuggled request (WAF bypass)
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="xss_via_smuggling",
                target=matched_at,
                params={
                    "smuggling_type": smuggling_type,
                    "smuggling_payload": smuggling_payload,
                    "xss_payloads": ["<script>alert(1)</script>", "<img onerror=alert(1) src=x>"],
                },
                priority=10,  # High priority - WAF bypass enables real exploitation
                finding_id=finding_id,
                cost=self._get_action_cost("xss_via_smuggling"),
            ))

            # Action: Test cache poisoning via smuggled request
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="cache_poison_via_smuggling",
                target=matched_at,
                params={
                    "smuggling_type": smuggling_type,
                    "smuggling_payload": smuggling_payload,
                },
                priority=10,
                finding_id=finding_id,
                cost=self._get_action_cost("cache_poison_via_smuggling"),
            ))

            # Action: Test auth bypass via smuggled request
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="auth_bypass_via_smuggling",
                target=matched_at,
                params={
                    "smuggling_type": smuggling_type,
                    "admin_paths": ["/admin", "/api/admin", "/internal"],
                },
                priority=9,
                finding_id=finding_id,
                cost=self._get_action_cost("auth_bypass_via_smuggling"),
            ))

            # Action: Rescan critical modules WITH desync context
            # These modules should be aware they can use smuggling to bypass protections
            actions.append(AmplificationAction(
                trigger_type=finding_type,
                action="rescan_with_desync",
                target=matched_at,
                params={
                    "desync_context": {
                        "enabled": True,
                        "type": smuggling_type,
                        "endpoint": matched_at,
                    },
                    "modules_to_rescan": ["xss", "sqli", "auth", "cors"],
                },
                priority=8,
                finding_id=finding_id,
                cost=self._get_action_cost("rescan_with_desync"),
            ))

            logger.info(
                f"[AMPLIFIER] HTTP Smuggling found → Enabling desync-aware amplification "
                f"({smuggling_type} at {matched_at})"
            )

        # === CROSS-FINDING AMPLIFICATION ===
        # Trigger other modules based on this finding

        modules_to_trigger = self.AMPLIFICATION_MAP.get(finding_type, [])
        for module in modules_to_trigger:
            action_key = f"cross_module:{finding_type}:{module}:{matched_at}"
            if action_key not in self._executed_amplifications:
                actions.append(AmplificationAction(
                    trigger_type=finding_type,
                    action="run_cross_module",
                    target=matched_at,
                    params={"module": module, "with_context": finding},
                    priority=6,
                    finding_id=finding_id,
                    cost=self._get_action_cost("run_cross_module"),
                ))

        # Apply FocusLock priority boost for focus-aligned actions
        return self._boost_for_focus(actions)

    def record_negative_result(
        self,
        vuln_type: str,
        endpoint: str,
        payload: str,
        reason: str,
    ) -> list[AmplificationAction]:
        """
        Record a failed test attempt and suggest alternative approaches.

        Philosophy: "Why didn't this break? What else can I try?"
        """
        actions: list[AmplificationAction] = []

        # Generate a pseudo finding_id for negative result tracking
        neg_key = f"negative:{vuln_type}:{endpoint}"
        finding_id = hashlib.md5(neg_key.encode()).hexdigest()[:16]

        # Store negative result
        if vuln_type not in self._negative_results:
            self._negative_results[vuln_type] = []
        self._negative_results[vuln_type].append({
            "endpoint": endpoint,
            "payload": payload,
            "reason": reason,
        })

        # === ALTERNATIVE PATH SUGGESTIONS ===

        # XSS failed → suggest encoded variants
        if vuln_type in ("xss", "dom_xss"):
            if "<script" in payload.lower():
                actions.append(AmplificationAction(
                    trigger_type="negative_xss",
                    action="try_xss_alternatives",
                    target=endpoint,
                    params={
                        "alternatives": [
                            "<img src=x onerror=alert(1)>",
                            "<svg onload=alert(1)>",
                            "javascript:alert(1)",
                            "'-alert(1)-'",
                        ]
                    },
                    priority=5,
                    finding_id=finding_id,
                    cost=self._get_action_cost("try_xss_alternatives"),
                ))

        # SQLi on GET failed → try POST
        if vuln_type in ("sqli", "sql_injection"):
            if "method" not in reason.lower():
                actions.append(AmplificationAction(
                    trigger_type="negative_sqli",
                    action="try_sqli_post",
                    target=endpoint,
                    params={"original_payload": payload},
                    priority=6,
                    finding_id=finding_id,
                    cost=self._get_action_cost("try_sqli_post"),
                ))

        # Auth bypass failed on one path → try variants
        if vuln_type == "auth_bypass":
            if "/admin" in endpoint:
                actions.append(AmplificationAction(
                    trigger_type="negative_auth",
                    action="try_auth_bypass_variants",
                    target=endpoint,
                    params={
                        "variants": [
                            endpoint.replace("/admin", "/api/admin"),
                            endpoint.replace("/admin", "/Admin"),
                            endpoint + "/",
                            endpoint + "?",
                        ]
                    },
                    priority=7,
                    finding_id=finding_id,
                    cost=self._get_action_cost("try_auth_bypass_variants"),
                ))

        # Apply FocusLock priority boost for focus-aligned actions
        return self._boost_for_focus(actions)

    def get_amplification_summary(self) -> dict:
        """Get summary of amplification activity including guardrail stats."""
        guardrail_summary = self._tracker.get_summary()
        block_report = self._tracker.get_block_report()

        return {
            "discovered_types": list(self._discovered_types),
            "queued_actions": len(self._amplification_queue),
            "executed_amplifications": len(self._executed_amplifications),
            "negative_results_by_type": {
                k: len(v) for k, v in self._negative_results.items()
            },
            # Enhanced guardrail stats
            "guardrails": {
                "budget_used": guardrail_summary["budget_used"],
                "budget_remaining": guardrail_summary["budget_remaining"],
                "budget_total": guardrail_summary["budget_total"],
                # Suspension stats
                "soft_suspended": guardrail_summary["soft_suspended"],
                "hard_suspended": guardrail_summary["hard_suspended"],
                "total_suspended": guardrail_summary["total_suspended"],
                # Progress stats
                "avg_progress_score": guardrail_summary["avg_progress_score"],
                "dead_targets": guardrail_summary["dead_targets"],
                # Dedup and loop stats
                "actions_deduped": guardrail_summary["actions_deduped"],
                "max_graph_depth": guardrail_summary["max_graph_depth"],
                # Block reasons for client reporting
                "total_blocked": guardrail_summary["total_blocked"],
                "block_reasons": guardrail_summary["block_reasons"],
            },
            # Human-readable block explanation for reports
            "block_explanation": block_report["explanation"],
        }

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for consistent matching."""
        type_lower = vuln_type.lower().strip()
        # Common normalizations
        normalizations = {
            "sql_injection": "sqli",
            "cross_site_scripting": "xss",
            "command_injection": "cmdi",
            "insecure_direct_object_reference": "idor",
            "broken_access_control": "idor",
            "access_control": "idor",
            "authentication_bypass": "auth_bypass",
        }
        return normalizations.get(type_lower, type_lower)

    def _boost_for_focus(self, actions: list[AmplificationAction]) -> list[AmplificationAction]:
        """
        Apply FocusLock priority boost to actions that match the focus category.

        Philosophy: "When in JWT abuse mode, JWT-related amplifications get priority."
        """
        if not hasattr(self._scanner, 'focus_lock') or not self._scanner.focus_lock:
            return actions

        focus_lock = self._scanner.focus_lock
        if not focus_lock.is_focused:
            return actions

        # Map action types to focus categories for matching
        ACTION_TO_FOCUS: dict[str, list[str]] = {
            "expand_idor_range": ["idor", "authorization", "access_control"],
            "test_method_escalation": ["idor", "authorization", "access_control"],
            "expand_sqli_extraction": ["sqli", "sql_injection"],
            "test_race_condition": ["business_logic", "race_condition"],
            "try_xss_alternatives": ["xss", "dom_xss"],
            "try_sqli_post": ["sqli", "sql_injection"],
            "try_auth_bypass_variants": ["auth_bypass", "authentication_bypass"],
            "probe_admin_endpoints": ["auth_bypass", "privilege_escalation"],
        }

        for action in actions:
            # Check if this action aligns with current focus
            action_types = ACTION_TO_FOCUS.get(action.action, [])
            for atype in action_types:
                if atype in focus_lock.FINDING_TO_CATEGORY:
                    action_category = focus_lock.FINDING_TO_CATEGORY[atype]
                    if action_category == focus_lock.active_category:
                        # Boost priority for focus-aligned actions
                        original_priority = action.priority
                        boost = focus_lock.hypothesis.current_priority_boost if focus_lock.hypothesis else 25
                        action.priority = min(10, action.priority + (boost // 10))  # Max priority is 10
                        logger.debug(
                            f"[Amplifier] Action '{action.action}' priority boosted: "
                            f"{original_priority} → {action.priority} (focus: {action_category.name})"
                        )
                        break

        return actions

    # === TRACKER ACCESS ===
    # Expose tracker methods for external use

    @property
    def tracker(self) -> AmplificationTracker:
        """Get the amplification tracker."""
        return self._tracker

    @property
    def guardrails(self) -> AmplificationGuardrails:
        """Get the guardrails configuration."""
        return self._guardrails

    def can_execute_action(
        self,
        action: AmplificationAction,
        finding_id: str,
    ) -> tuple[bool, str | None, str]:
        """Check if an action can be executed (delegates to tracker)."""
        allowed, reason, detail = self._tracker.can_execute_action(action, finding_id)
        return allowed, reason.value if reason else None, detail

    def record_action_start(self, action: AmplificationAction, finding_id: str) -> None:
        """Record action start (delegates to tracker)."""
        self._tracker.record_action_start(action, finding_id)
        self._executed_amplifications.add(f"{action.action}:{action.target}")

    def record_action_result(
        self,
        action: AmplificationAction,
        finding_id: str,
        success: bool,
        **kwargs
    ) -> tuple[float, bool]:
        """Record action result (delegates to tracker)."""
        return self._tracker.record_action_result(action, finding_id, success, **kwargs)
