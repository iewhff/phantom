"""
PHANTOM AI - Attacker Intent Engine

Models realistic attacker behavior to contextualize findings.

Philosophy: "Think like an attacker, not a scanner"

Scanners find vulnerabilities. Attackers achieve goals.
This engine bridges the gap by modeling:

1. INTENT — What does an attacker actually want?
   - Financial gain, data theft, account takeover, privilege escalation

2. CONTEXT — How does this finding fit the attack surface?
   - Same SQLi on login vs search has different value
   - Admin-only vuln requires chain to reach

3. STATE — What state transitions does this enable?
   - Unauthenticated → Authenticated
   - User → Admin
   - Read → Write

4. ATTACK GRAPH — What paths lead to attacker goals?
   - Entry points → Pivot points → Targets
   - Shortest path to each goal

The output is not "here are your vulnerabilities" but
"here's what an attacker can achieve and how".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class AttackerGoal(Enum):
    """What attackers actually want to achieve."""
    FINANCIAL_GAIN = auto()         # Steal money, goods, services
    DATA_THEFT = auto()             # Exfiltrate PII, credentials, secrets
    ACCOUNT_TAKEOVER = auto()       # Access as victim user
    ADMIN_ACCESS = auto()           # Become administrator
    CODE_EXECUTION = auto()         # Run arbitrary code
    LATERAL_MOVEMENT = auto()       # Pivot to other systems
    DISRUPTION = auto()             # DOS, defacement, destruction
    PERSISTENCE = auto()            # Maintain long-term access


class AttackPhase(Enum):
    """Phase in the attack lifecycle."""
    RECONNAISSANCE = auto()         # Gathering information
    INITIAL_ACCESS = auto()         # First foothold
    PRIVILEGE_ESCALATION = auto()   # Elevating access
    LATERAL_MOVEMENT = auto()       # Moving to other targets
    DATA_EXFILTRATION = auto()      # Extracting value
    IMPACT = auto()                 # Achieving final goal


class AccessLevel(Enum):
    """Current access level in the application."""
    ANONYMOUS = 0                   # No authentication
    AUTHENTICATED = 1               # Valid user session
    PRIVILEGED = 2                  # Elevated user (manager, etc.)
    ADMIN = 3                       # Full administrative access
    SYSTEM = 4                      # Server/infrastructure access


@dataclass
class AttackNode:
    """A node in the attack graph."""
    finding: dict
    access_level: AccessLevel
    phase: AttackPhase
    enables_goals: list[AttackerGoal] = field(default_factory=list)
    requires_access: AccessLevel = AccessLevel.ANONYMOUS
    state_change: str = ""          # What state transition this enables
    next_nodes: list[str] = field(default_factory=list)  # Finding IDs


@dataclass
class AttackPath:
    """A complete path from entry to goal."""
    goal: AttackerGoal
    steps: list[AttackNode] = field(default_factory=list)
    total_complexity: int = 0       # Sum of step complexities
    requires_interaction: bool = False
    requires_conditions: list[str] = field(default_factory=list)
    success_probability: float = 0.0
    narrative: str = ""


@dataclass
class AttackerProfile:
    """Models what an attacker would do with these findings."""
    primary_goals: list[AttackerGoal] = field(default_factory=list)
    achievable_goals: list[AttackerGoal] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    current_access: AccessLevel = AccessLevel.ANONYMOUS
    max_achievable_access: AccessLevel = AccessLevel.ANONYMOUS
    time_to_impact: str = ""        # "minutes", "hours", "days"
    skill_required: str = ""        # "script_kiddie", "intermediate", "advanced"
    overall_threat_level: str = ""  # "LOW", "MEDIUM", "HIGH", "CRITICAL"


# ═══════════════════════════════════════════════════════════════════════════════
# GOAL INDICATORS — What findings suggest which attacker goals?
# ═══════════════════════════════════════════════════════════════════════════════

GOAL_INDICATORS = {
    AttackerGoal.FINANCIAL_GAIN: {
        "vuln_types": ["business_logic", "idor", "price", "quantity", "payment"],
        "url_patterns": [r"/cart", r"/checkout", r"/payment", r"/order", r"/transfer", r"/wallet"],
        "data_keys": ["price", "total", "amount", "discount", "coupon"],
    },
    AttackerGoal.DATA_THEFT: {
        "vuln_types": ["sql_injection", "sqli", "xxe", "lfi", "idor", "cors"],
        "url_patterns": [r"/user", r"/account", r"/profile", r"/api", r"/export", r"/download"],
        "data_keys": ["extracted_data", "credentials", "file_content", "users"],
    },
    AttackerGoal.ACCOUNT_TAKEOVER: {
        "vuln_types": ["xss", "dom_xss", "session", "session_abuse", "csrf", "cors"],
        "url_patterns": [r"/login", r"/auth", r"/session", r"/password", r"/oauth"],
        "data_keys": ["token", "session", "cookie", "jwt"],
    },
    AttackerGoal.ADMIN_ACCESS: {
        "vuln_types": ["session_abuse", "authorization", "idor", "sqli"],
        "url_patterns": [r"/admin", r"/dashboard", r"/manage", r"/config", r"/settings"],
        "data_keys": ["admin", "role", "privilege", "escalat"],
    },
    AttackerGoal.CODE_EXECUTION: {
        "vuln_types": ["ssti", "rce", "cmdi", "deserialization", "upload"],
        "url_patterns": [r"/upload", r"/execute", r"/run", r"/shell", r"/template"],
        "data_keys": ["rce_output", "command_output", "file_write"],
    },
    AttackerGoal.LATERAL_MOVEMENT: {
        "vuln_types": ["ssrf", "xxe", "sqli", "rce"],
        "url_patterns": [r"/proxy", r"/fetch", r"/internal", r"/api"],
        "data_keys": ["internal_ip", "metadata", "cloud", "aws", "azure"],
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONTEXT PATTERNS — How context affects severity
# ═══════════════════════════════════════════════════════════════════════════════

CONTEXT_SEVERITY_MODIFIERS = {
    # (vuln_type, url_context) → severity_modifier
    ("sql_injection", "login"): +2,      # SQLi on login = auth bypass = CRITICAL
    ("sql_injection", "search"): +1,     # SQLi on search = data theft = HIGH
    ("sql_injection", "admin"): -1,      # SQLi on admin = needs access first
    ("xss", "login"): +1,                # XSS on login = credential theft
    ("xss", "profile"): 0,               # XSS on profile = stored XSS
    ("xss", "search"): -1,               # XSS on search = reflected, needs click
    ("idor", "user"): +1,                # IDOR on user data = privacy breach
    ("idor", "admin"): +2,               # IDOR to admin = privilege escalation
    ("cors", "api"): +1,                 # CORS on API = data theft
    ("cors", "static"): -2,              # CORS on static = low impact
    ("session_abuse", "any"): +1,        # Session issues are always significant
    ("business_logic", "payment"): +2,   # Business logic in payment = fraud
    ("business_logic", "cart"): +1,      # Business logic in cart = theft
}

# ═══════════════════════════════════════════════════════════════════════════════
# STATE TRANSITIONS — What state changes do findings enable?
# ═══════════════════════════════════════════════════════════════════════════════

STATE_TRANSITIONS = {
    "sql_injection": [
        ("ANONYMOUS", "DATA_ACCESS", "Extract data without authentication"),
        ("ANONYMOUS", "AUTHENTICATED", "Auth bypass via SQLi"),
        ("AUTHENTICATED", "ADMIN", "Escalate via credential extraction"),
    ],
    "xss": [
        ("ANONYMOUS", "VICTIM_SESSION", "Steal victim's session"),
        ("VICTIM_SESSION", "ACCOUNT_TAKEOVER", "Act as victim"),
    ],
    "session_abuse": [
        ("AUTHENTICATED", "ADMIN", "Forge admin token"),
        ("ANONYMOUS", "AUTHENTICATED", "Session prediction/fixation"),
    ],
    "idor": [
        ("AUTHENTICATED", "OTHER_USER_DATA", "Access other users' resources"),
        ("AUTHENTICATED", "ADMIN_DATA", "Access admin resources"),
    ],
    "cors": [
        ("ATTACKER_ORIGIN", "VICTIM_DATA", "Cross-origin data theft"),
    ],
    "business_logic": [
        ("AUTHENTICATED", "FINANCIAL_GAIN", "Exploit business rules"),
    ],
    "ssti": [
        ("ANONYMOUS", "CODE_EXECUTION", "RCE via template injection"),
    ],
    "ssrf": [
        ("EXTERNAL", "INTERNAL_ACCESS", "Access internal services"),
    ],
}


class AttackerIntentEngine:
    """
    Models attacker intent to contextualize vulnerability findings.

    Instead of reporting "you have SQLi", reports:
    "An attacker can achieve ADMIN ACCESS by exploiting SQLi on /login
    to bypass authentication, then using the extracted credentials to
    access the admin panel. Time to impact: minutes."
    """

    def __init__(self) -> None:
        self._findings: list[dict] = []
        self._nodes: dict[str, AttackNode] = {}
        self._profile: AttackerProfile = AttackerProfile()
        self._app_context: dict[str, Any] = {}

    def analyze(self, findings: list[dict], app_context: dict | None = None) -> list[dict]:
        """
        Analyze findings from attacker's perspective.

        Args:
            findings: List of finding dicts from scanners
            app_context: Optional context about the application

        Returns:
            Enhanced findings with attacker intent metadata
        """
        self._findings = findings
        self._app_context = app_context or {}

        logger.info(f"[INTENT] Analyzing {len(findings)} findings from attacker perspective")

        # Phase 1: Build attack graph
        self._build_attack_graph()

        # Phase 2: Identify achievable goals
        self._identify_goals()

        # Phase 3: Find attack paths
        self._find_attack_paths()

        # Phase 4: Calculate threat profile
        self._calculate_threat_profile()

        # Phase 5: Enhance findings with intent context
        enhanced = self._enhance_findings()

        # Phase 6: Generate intent summary finding
        if self._profile.attack_paths:
            intent_finding = self._generate_intent_summary()
            enhanced.append(intent_finding)

        logger.info(
            f"[INTENT] Analysis complete: {len(self._profile.achievable_goals)} goals achievable, "
            f"{len(self._profile.attack_paths)} attack paths, "
            f"threat level: {self._profile.overall_threat_level}"
        )

        return enhanced

    def _build_attack_graph(self) -> None:
        """Build graph of attack nodes from findings."""
        for i, finding in enumerate(self._findings):
            node_id = f"node_{i}"

            vuln_type = self._normalize_type(finding.get("vulnerability_type", ""))
            url = finding.get("matched_at", "")
            metadata = finding.get("metadata", {})

            # Determine access level required
            requires_access = self._determine_required_access(finding)

            # Determine what goals this enables
            enables_goals = self._determine_enabled_goals(finding)

            # Determine phase in attack lifecycle
            phase = self._determine_phase(finding, requires_access)

            # Determine state change
            state_change = self._determine_state_change(vuln_type, metadata)

            node = AttackNode(
                finding=finding,
                access_level=requires_access,
                phase=phase,
                enables_goals=enables_goals,
                requires_access=requires_access,
                state_change=state_change,
            )

            self._nodes[node_id] = node

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type."""
        if not vuln_type:
            return ""
        t = vuln_type.lower().replace("-", "_").replace(" ", "_")
        if "sql" in t and "inject" in t:
            return "sql_injection"
        if t.startswith("cors"):
            return "cors"
        return t

    def _determine_required_access(self, finding: dict) -> AccessLevel:
        """Determine what access level is needed to exploit this finding."""
        url = finding.get("matched_at", "").lower()
        metadata = finding.get("metadata", {})

        # Check if it's on an admin endpoint
        if any(p in url for p in ["/admin", "/manage", "/dashboard", "/config"]):
            return AccessLevel.ADMIN

        # Check if authenticated endpoint
        if isinstance(metadata, dict):
            if metadata.get("requires_auth") or metadata.get("authenticated"):
                return AccessLevel.AUTHENTICATED

        # Check exploitability metadata
        if isinstance(metadata, dict):
            expl = metadata.get("exploitability", {})
        if expl.get("requires_auth"):
            return AccessLevel.AUTHENTICATED

        # Default to anonymous
        return AccessLevel.ANONYMOUS

    def _determine_enabled_goals(self, finding: dict) -> list[AttackerGoal]:
        """Determine which attacker goals this finding enables."""
        goals = []

        vuln_type = self._normalize_type(finding.get("vulnerability_type", ""))
        url = finding.get("matched_at", "").lower()
        metadata = finding.get("metadata", {})

        for goal, indicators in GOAL_INDICATORS.items():
            score = 0
            has_vuln_type_match = False  # P3-2: Track vuln type match separately

            # Check vuln type match (MANDATORY for goal assignment)
            if any(vt in vuln_type for vt in indicators["vuln_types"]):
                score += 2
                has_vuln_type_match = True

            # Check URL pattern match
            for pattern in indicators["url_patterns"]:
                if re.search(pattern, url, re.IGNORECASE):
                    score += 1
                    break

            # Check data indicators
            metadata_str = str(metadata).lower()
            for key in indicators["data_keys"]:
                if key in metadata_str:
                    score += 1
                    break

            # P3-2 FIX: Require vuln_type match AND total score >= 3
            # This prevents goals being assigned based on just URL/data matches
            if has_vuln_type_match and score >= 3:
                goals.append(goal)

        return goals

    def _determine_phase(self, finding: dict, access_level: AccessLevel) -> AttackPhase:
        """Determine which attack phase this finding belongs to."""
        vuln_type = self._normalize_type(finding.get("vulnerability_type", ""))
        metadata = finding.get("metadata", {})

        # Check for data extraction (exfiltration phase)
        if isinstance(metadata, dict):
            if metadata.get("extracted_data") or metadata.get("file_content"):
                return AttackPhase.DATA_EXFILTRATION

        # Check for privilege escalation indicators
        if isinstance(metadata, dict):
            if metadata.get("privilege_escalation") or "admin" in str(metadata.get("proof", {})):
                return AttackPhase.PRIVILEGE_ESCALATION

        # Check for code execution (impact phase)
        if isinstance(metadata, dict):
            if vuln_type in ("ssti", "rce", "cmdi") or metadata.get("rce_output"):
                return AttackPhase.IMPACT

        # Session/auth issues are initial access
        if vuln_type in ("session", "session_abuse", "xss", "cors"):
            return AttackPhase.INITIAL_ACCESS

        # Default based on access level
        if access_level == AccessLevel.ANONYMOUS:
            return AttackPhase.INITIAL_ACCESS
        elif access_level == AccessLevel.AUTHENTICATED:
            return AttackPhase.PRIVILEGE_ESCALATION
        else:
            return AttackPhase.LATERAL_MOVEMENT

    def _determine_state_change(self, vuln_type: str, metadata: dict) -> str:
        """Determine what state transition this finding enables."""
        transitions = STATE_TRANSITIONS.get(vuln_type, [])

        if not transitions:
            return ""

        # Check metadata for clues about which transition applies
        metadata_str = str(metadata).lower()

        for from_state, to_state, description in transitions:
            # Check if metadata suggests this transition
            if to_state.lower() in metadata_str or from_state.lower() in metadata_str:
                return f"{from_state} → {to_state}: {description}"

        # Return first applicable transition
        return f"{transitions[0][0]} → {transitions[0][1]}: {transitions[0][2]}"

    def _identify_goals(self) -> None:
        """Identify all achievable attacker goals."""
        all_goals = set()

        for node in self._nodes.values():
            for goal in node.enables_goals:
                all_goals.add(goal)

        self._profile.achievable_goals = list(all_goals)

        # Determine primary goals (most impactful)
        primary = []
        if AttackerGoal.ADMIN_ACCESS in all_goals:
            primary.append(AttackerGoal.ADMIN_ACCESS)
        if AttackerGoal.CODE_EXECUTION in all_goals:
            primary.append(AttackerGoal.CODE_EXECUTION)
        if AttackerGoal.FINANCIAL_GAIN in all_goals:
            primary.append(AttackerGoal.FINANCIAL_GAIN)
        if AttackerGoal.DATA_THEFT in all_goals:
            primary.append(AttackerGoal.DATA_THEFT)
        if AttackerGoal.ACCOUNT_TAKEOVER in all_goals:
            primary.append(AttackerGoal.ACCOUNT_TAKEOVER)

        self._profile.primary_goals = primary[:3]  # Top 3

    def _find_attack_paths(self) -> None:
        """Find realistic attack paths to each goal."""
        paths = []

        for goal in self._profile.achievable_goals:
            # Find all nodes that enable this goal
            goal_nodes = [
                (node_id, node) for node_id, node in self._nodes.items()
                if goal in node.enables_goals
            ]

            for node_id, node in goal_nodes:
                # Build path to this node
                path = self._build_path_to_node(node_id, node, goal)
                if path:
                    paths.append(path)

        # Sort by probability and complexity
        paths.sort(key=lambda p: (-p.success_probability, p.total_complexity))

        self._profile.attack_paths = paths[:10]  # Keep top 10

    def _build_path_to_node(
        self,
        node_id: str,
        node: AttackNode,
        goal: AttackerGoal,
    ) -> AttackPath | None:
        """Build an attack path to a goal node."""
        steps = [node]
        requires_conditions = []
        requires_interaction = False
        total_complexity = 1

        # Check if node requires prior access
        if node.requires_access != AccessLevel.ANONYMOUS:
            # Need to find a node that grants this access
            access_node = self._find_access_granting_node(node.requires_access)
            if access_node:
                steps.insert(0, access_node)
                total_complexity += 1
            else:
                requires_conditions.append(f"Requires {node.requires_access.name} access")

        # Check for user interaction requirements
        vuln_type = self._normalize_type(node.finding.get("vulnerability_type", ""))
        if vuln_type in ("xss", "csrf", "clickjacking"):
            requires_interaction = True
            requires_conditions.append("Requires victim interaction")

        # Calculate success probability
        base_prob = 85
        if requires_interaction:
            base_prob -= 20
        if len(requires_conditions) > 1:
            base_prob -= 10 * len(requires_conditions)

        # Boost if we have proof
        metadata = node.finding.get("metadata", {})
        if isinstance(metadata, dict):
            if metadata.get("proof", {}).get("can_repeat"):
                base_prob += 5
        if isinstance(metadata, dict):
            if metadata.get("extracted_data"):
                base_prob += 10

        probability = max(20, min(95, base_prob))

        # Generate narrative
        narrative = self._generate_path_narrative(steps, goal, requires_conditions)

        return AttackPath(
            goal=goal,
            steps=steps,
            total_complexity=total_complexity,
            requires_interaction=requires_interaction,
            requires_conditions=requires_conditions,
            success_probability=probability,
            narrative=narrative,
        )

    def _find_access_granting_node(self, required_access: AccessLevel) -> AttackNode | None:
        """Find a node that grants the required access level."""
        for node in self._nodes.values():
            state_change = node.state_change.lower()

            if required_access == AccessLevel.AUTHENTICATED:
                if "authenticated" in state_change or "session" in state_change:
                    return node
            elif required_access == AccessLevel.ADMIN:
                if "admin" in state_change or "privilege" in state_change:
                    return node

        return None

    def _generate_path_narrative(
        self,
        steps: list[AttackNode],
        goal: AttackerGoal,
        conditions: list[str],
    ) -> str:
        """Generate human-readable attack narrative."""
        parts = [f"To achieve {goal.name.replace('_', ' ').title()}:"]

        for i, step in enumerate(steps, 1):
            finding_name = step.finding.get("name", "Unknown vulnerability")
            url = step.finding.get("matched_at", "")
            action = step.state_change or f"Exploit {finding_name}"

            parts.append(f"\n{i}. {action}")
            if url:
                parts.append(f"   Target: {url}")

        if conditions:
            parts.append(f"\nConditions: {', '.join(conditions)}")

        return "".join(parts)

    def _calculate_threat_profile(self) -> None:
        """Calculate overall threat profile."""
        # Determine max achievable access
        max_access = AccessLevel.ANONYMOUS
        for node in self._nodes.values():
            if "admin" in node.state_change.lower():
                if AccessLevel.ADMIN.value > max_access.value:
                    max_access = AccessLevel.ADMIN
            elif "authenticated" in node.state_change.lower():
                if AccessLevel.AUTHENTICATED.value > max_access.value:
                    max_access = AccessLevel.AUTHENTICATED

        self._profile.max_achievable_access = max_access

        # Determine time to impact
        if self._profile.attack_paths:
            shortest_path = min(p.total_complexity for p in self._profile.attack_paths)
            if shortest_path == 1:
                self._profile.time_to_impact = "minutes"
            elif shortest_path <= 3:
                self._profile.time_to_impact = "hours"
            else:
                self._profile.time_to_impact = "days"

        # Determine skill required
        has_simple_exploit = any(
            p.total_complexity == 1 and not p.requires_interaction
            for p in self._profile.attack_paths
        )
        has_rce = AttackerGoal.CODE_EXECUTION in self._profile.achievable_goals

        if has_simple_exploit:
            self._profile.skill_required = "script_kiddie"
        elif has_rce:
            self._profile.skill_required = "intermediate"
        else:
            self._profile.skill_required = "beginner"

        # Determine overall threat level
        critical_goals = {
            AttackerGoal.ADMIN_ACCESS, AttackerGoal.CODE_EXECUTION,
            AttackerGoal.FINANCIAL_GAIN
        }
        high_goals = {AttackerGoal.DATA_THEFT, AttackerGoal.ACCOUNT_TAKEOVER}

        if critical_goals & set(self._profile.achievable_goals):
            if self._profile.time_to_impact == "minutes":
                self._profile.overall_threat_level = "CRITICAL"
            else:
                self._profile.overall_threat_level = "HIGH"
        elif high_goals & set(self._profile.achievable_goals):
            self._profile.overall_threat_level = "HIGH"
        elif self._profile.achievable_goals:
            self._profile.overall_threat_level = "MEDIUM"
        else:
            self._profile.overall_threat_level = "LOW"

    def _enhance_findings(self) -> list[dict]:
        """Enhance findings with attacker intent context."""
        enhanced = []

        for i, finding in enumerate(self._findings):
            node_id = f"node_{i}"
            node = self._nodes.get(node_id)

            if node:
                # Add intent metadata
                finding = dict(finding)  # Copy
                metadata = dict(finding.get("metadata", {}))

                if isinstance(metadata, dict):
                    metadata["attacker_intent"] = {
                    "enables_goals": [g.name for g in node.enables_goals],
                    "attack_phase": node.phase.name,
                    "state_change": node.state_change,
                    "requires_access": node.requires_access.name,
                    "context_severity_modifier": self._get_context_modifier(finding),
                }

                finding["metadata"] = metadata

                # P3-3 FIX: Only adjust severity based on context if confidence >= 0.70
                # This prevents low-confidence findings from being artificially elevated
                confidence = finding.get("confidence_score", finding.get("confidence", 0.0))
                if isinstance(confidence, str):
                    confidence = {"high": 0.90, "medium": 0.70, "low": 0.50}.get(confidence.lower(), 0.50)

                modifier = self._get_context_modifier(finding)
                if modifier != 0 and confidence >= 0.70:
                    current_severity = finding.get("severity", "MEDIUM")
                    finding["severity"] = self._adjust_severity(current_severity, modifier)
                    if isinstance(metadata, dict):
                        metadata["attacker_intent"]["severity_adjusted"] = True
                    if isinstance(metadata, dict):
                        metadata["attacker_intent"]["original_severity"] = current_severity
                elif modifier != 0:
                    # Record that modifier was available but not applied
                    if isinstance(metadata, dict):
                        metadata["attacker_intent"]["modifier_skipped"] = True
                    if isinstance(metadata, dict):
                        metadata["attacker_intent"]["skip_reason"] = f"confidence {confidence:.2f} < 0.70"

            enhanced.append(finding)

        return enhanced

    def _get_context_modifier(self, finding: dict) -> int:
        """Get severity modifier based on context."""
        vuln_type = self._normalize_type(finding.get("vulnerability_type", ""))
        url = finding.get("matched_at", "").lower()

        # Determine URL context
        if "/login" in url or "/auth" in url:
            context = "login"
        elif "/admin" in url or "/manage" in url:
            context = "admin"
        elif "/user" in url or "/profile" in url:
            context = "user"
        elif "/api" in url:
            context = "api"
        elif "/search" in url:
            context = "search"
        elif "/cart" in url or "/checkout" in url or "/payment" in url:
            context = "payment"
        else:
            context = "any"

        # Look up modifier
        key = (vuln_type, context)
        if key in CONTEXT_SEVERITY_MODIFIERS:
            return CONTEXT_SEVERITY_MODIFIERS[key]

        # Try with "any" context
        key = (vuln_type, "any")
        return CONTEXT_SEVERITY_MODIFIERS.get(key, 0)

    def _adjust_severity(self, current: str, modifier: int) -> str:
        """Adjust severity by modifier."""
        levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        current_upper = current.upper()

        if current_upper not in levels:
            return current

        idx = levels.index(current_upper)
        new_idx = max(0, min(len(levels) - 1, idx + modifier))

        return levels[new_idx]

    def _generate_intent_summary(self) -> dict:
        """Generate a summary finding describing the attacker's perspective."""
        goals_str = ", ".join(g.name.replace("_", " ").title() for g in self._profile.primary_goals)

        # Build narrative
        narrative_parts = [
            f"**Attacker Perspective Analysis**\n",
            f"An attacker targeting this application can achieve: {goals_str}.\n",
        ]

        if self._profile.attack_paths:
            best_path = self._profile.attack_paths[0]
            narrative_parts.append(f"\n**Most Likely Attack Path** (Success: {best_path.success_probability}%):\n")
            narrative_parts.append(best_path.narrative)

        narrative_parts.append(f"\n\n**Threat Assessment:**")
        narrative_parts.append(f"\n- Overall Threat Level: {self._profile.overall_threat_level}")
        narrative_parts.append(f"\n- Time to Impact: {self._profile.time_to_impact}")
        narrative_parts.append(f"\n- Skill Required: {self._profile.skill_required.replace('_', ' ')}")
        narrative_parts.append(f"\n- Maximum Access Achievable: {self._profile.max_achievable_access.name}")

        return {
            "name": "Attacker Intent Analysis",
            "severity": self._profile.overall_threat_level,
            "confidence": 85,
            "vulnerability_type": "attacker_intent",
            "module_name": "attacker_intent_engine",
            "description": "".join(narrative_parts),
            "matched_at": "Application-wide",
            "evidence": [
                f"Achievable goals: {len(self._profile.achievable_goals)}",
                f"Attack paths identified: {len(self._profile.attack_paths)}",
                f"Primary goals: {goals_str}",
            ],
            "metadata": {
                "is_summary": True,
                "threat_profile": {
                    "achievable_goals": [g.name for g in self._profile.achievable_goals],
                    "primary_goals": [g.name for g in self._profile.primary_goals],
                    "max_access": self._profile.max_achievable_access.name,
                    "time_to_impact": self._profile.time_to_impact,
                    "skill_required": self._profile.skill_required,
                    "threat_level": self._profile.overall_threat_level,
                },
                "attack_paths": [
                    {
                        "goal": p.goal.name,
                        "steps": len(p.steps),
                        "probability": p.success_probability,
                        "narrative": p.narrative,
                    }
                    for p in self._profile.attack_paths[:5]
                ],
            },
        }

    def get_profile(self) -> AttackerProfile:
        """Get the computed attacker profile."""
        return self._profile

    # ═══════════════════════════════════════════════════════════════════════════
    # INTENT-DRIVEN MODULE PRIORITIZATION
    # ═══════════════════════════════════════════════════════════════════════════

    def get_module_priorities(self, app_context: dict | None = None) -> dict[str, int]:
        """
        Get module priorities based on detected attacker goals and app context.

        Returns:
            Dict mapping module name to priority (1-100, higher = more important)
        """
        # Base priorities for all modules
        priorities = {mod: 50 for mod in self._get_all_modules()}

        # Boost modules based on achievable goals
        goal_module_map = {
            AttackerGoal.FINANCIAL_GAIN: {
                "business_logic": 30, "race": 25, "idor": 20, "workflow_inference": 20,
                "creative_exploiter": 15, "session_abuse": 10,
            },
            AttackerGoal.DATA_THEFT: {
                "sqli": 30, "idor": 25, "xxe": 20, "lfi": 20, "ssrf": 15,
                "nosql": 15, "api": 10, "graphql": 10,
            },
            AttackerGoal.ACCOUNT_TAKEOVER: {
                "xss": 30, "session_abuse": 25, "cors": 20, "csrf": 20,
                "dom_xss": 20, "oauth": 15, "jwt": 15, "auth": 10,
            },
            AttackerGoal.ADMIN_ACCESS: {
                "session_abuse": 30, "authz": 25, "idor": 20, "sqli": 20,
                "permission_matrix": 20, "creative_exploiter": 15, "auth": 10,
            },
            AttackerGoal.CODE_EXECUTION: {
                "ssti": 30, "cmdi": 30, "deser": 25, "file_upload": 20,
                "xxe": 15, "sqli": 10,
            },
            AttackerGoal.LATERAL_MOVEMENT: {
                "ssrf": 30, "xxe": 25, "sqli": 20, "cloud": 20, "k8s": 15,
                "dns_rebind": 10,
            },
        }

        # Apply goal-based boosts
        for goal in self._profile.achievable_goals:
            if goal in goal_module_map:
                for module, boost in goal_module_map[goal].items():
                    if module in priorities:
                        priorities[module] = min(100, priorities[module] + boost)

        # Boost based on app context
        if app_context:
            self._apply_context_boosts(priorities, app_context)

        # Sort by priority descending
        return dict(sorted(priorities.items(), key=lambda x: -x[1]))

    def _get_all_modules(self) -> list[str]:
        """Get list of all scanner modules."""
        return [
            "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
            "nosql", "ssti", "ldap", "crlf", "auth", "oauth", "saml",
            "mfa", "jwt", "authz", "idor", "session_abuse", "api",
            "graphql", "grpc", "websocket", "sse", "ssl", "headers",
            "cors", "cloud", "k8s", "dns_rebind", "smuggling", "cache",
            "deser", "prototype", "business_logic", "race", "mass_assign",
            "ratelimit", "creative_exploiter", "dir", "cms", "nuclei",
            "backend", "supabase", "firebase", "rls_bypass", "mobile",
            "email", "host_header", "file_upload", "cookie", "csrf",
            "workflow_inference", "abac_context", "permission_matrix",
        ]

    def _apply_context_boosts(self, priorities: dict[str, int], app_context: dict) -> None:
        """Apply module priority boosts based on application context."""
        # Boost based on detected technologies
        tech_stack = app_context.get("tech_stack", [])
        tech_names = [t.lower() if isinstance(t, str) else t.get("name", "").lower() for t in tech_stack]

        if any("graphql" in t for t in tech_names):
            priorities["graphql"] = min(100, priorities.get("graphql", 50) + 30)

        if any("jwt" in t or "jsonwebtoken" in t for t in tech_names):
            priorities["jwt"] = min(100, priorities.get("jwt", 50) + 25)
            priorities["session_abuse"] = min(100, priorities.get("session_abuse", 50) + 20)

        if any("websocket" in t for t in tech_names):
            priorities["websocket"] = min(100, priorities.get("websocket", 50) + 25)

        if any("grpc" in t for t in tech_names):
            priorities["grpc"] = min(100, priorities.get("grpc", 50) + 25)

        if any("supabase" in t for t in tech_names):
            priorities["supabase"] = min(100, priorities.get("supabase", 50) + 30)
            priorities["rls_bypass"] = min(100, priorities.get("rls_bypass", 50) + 25)

        if any("firebase" in t for t in tech_names):
            priorities["firebase"] = min(100, priorities.get("firebase", 50) + 30)

        # Boost based on detected features
        features = app_context.get("detected_features", [])

        if "authentication" in features or "login" in features:
            priorities["auth"] = min(100, priorities.get("auth", 50) + 20)
            priorities["session_abuse"] = min(100, priorities.get("session_abuse", 50) + 15)

        if "payment" in features or "checkout" in features:
            priorities["business_logic"] = min(100, priorities.get("business_logic", 50) + 25)
            priorities["race"] = min(100, priorities.get("race", 50) + 20)

        if "file_upload" in features:
            priorities["file_upload"] = min(100, priorities.get("file_upload", 50) + 30)

        if "oauth" in features:
            priorities["oauth"] = min(100, priorities.get("oauth", 50) + 25)

    def suggest_scan_order(self, available_modules: list[str], app_context: dict | None = None) -> list[str]:
        """
        Suggest optimal module execution order based on intent analysis.

        Args:
            available_modules: List of modules that can be run
            app_context: Optional application context from recon

        Returns:
            Ordered list of modules, highest priority first
        """
        priorities = self.get_module_priorities(app_context)

        # Filter to only available modules
        available_priorities = {m: p for m, p in priorities.items() if m in available_modules}

        # Sort by priority descending
        ordered = sorted(available_priorities.keys(), key=lambda m: -available_priorities[m])

        logger.debug(f"[INTENT] Module order: {ordered[:10]}... (top 10)")
        return ordered

    def should_skip_module(
        self,
        module_name: str,
        app_context: dict | None = None,
    ) -> tuple[bool, str]:
        """
        Determine if a module should be skipped based on intent analysis.

        Returns:
            (should_skip, reason) tuple
        """
        priorities = self.get_module_priorities(app_context)
        priority = priorities.get(module_name, 50)

        # Skip very low priority modules if we have clear goals
        if self._profile.primary_goals and priority < 20:
            return True, f"Low priority ({priority}) for current goals"

        return False, ""

    def get_chain_priorities(self) -> dict[str, int]:
        """
        Get priorities for attack chains based on goals.

        Returns:
            Dict mapping chain type to priority
        """
        chain_priorities = {}

        # Map goals to chain types
        goal_to_chains = {
            AttackerGoal.ACCOUNT_TAKEOVER: ["xss_cors", "xss_session", "cors_session"],
            AttackerGoal.DATA_THEFT: ["sqli_idor", "sqli_lfi", "xxe_ssrf"],
            AttackerGoal.ADMIN_ACCESS: ["sqli_auth", "idor_session", "auth_bypass_privesc"],
            AttackerGoal.CODE_EXECUTION: ["ssti_rce", "xxe_lfi", "deser_rce"],
            AttackerGoal.FINANCIAL_GAIN: ["business_race", "idor_business", "session_business"],
        }

        for goal in self._profile.primary_goals:
            if goal in goal_to_chains:
                for chain in goal_to_chains[goal]:
                    chain_priorities[chain] = chain_priorities.get(chain, 0) + 30

        return chain_priorities
