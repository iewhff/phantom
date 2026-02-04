"""
Human-in-the-Loop Interactive Mode.
Enables human confirmation and guided exploitation.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable, Awaitable

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class InteractionType(Enum):
    """Type of human interaction required."""
    CONFIRM_EXPLOIT = auto()
    REVIEW_FINDING = auto()
    CUSTOM_PAYLOAD = auto()
    AUTHORIZATION_CHECK = auto()
    SENSITIVE_ACTION = auto()
    MANUAL_STEP = auto()


class UserDecision(Enum):
    """User's decision on an interaction."""
    APPROVE = "approve"
    REJECT = "reject"
    MODIFY = "modify"
    SKIP = "skip"
    ABORT = "abort"


@dataclass
class PendingInteraction:
    """An interaction waiting for human input."""
    id: str
    interaction_type: InteractionType
    title: str
    description: str
    context: dict[str, Any]
    payload: str | None = None
    risk_level: str = "MEDIUM"
    created_at: datetime = field(default_factory=datetime.now)
    timeout_seconds: int = 300  # 5 minute default timeout
    
    # Results
    decision: UserDecision | None = None
    user_notes: str | None = None
    modified_payload: str | None = None
    decided_at: datetime | None = None


@dataclass
class HumanFeedback:
    """Feedback from human operator."""
    finding_id: str
    is_valid: bool
    severity_adjustment: str | None = None
    notes: str = ""
    additional_context: str = ""


class HumanInTheLoopController:
    """
    Manages human-in-the-loop interactions for the pentest framework.
    
    Features:
    - Finding validation (AI finds → human confirms)
    - Payload crafting assistance
    - Guided manual exploitation
    - Authorization checks before sensitive actions
    - Session management for interactive mode
    """
    
    def __init__(
        self,
        settings: Settings,
        auto_mode: bool = False,
        callback: Callable[[PendingInteraction], Awaitable[UserDecision]] | None = None,
    ):
        self.settings = settings
        self.auto_mode = auto_mode  # If True, auto-approve low-risk actions
        self.callback = callback
        
        self.pending_interactions: dict[str, PendingInteraction] = {}
        self.interaction_history: list[PendingInteraction] = []
        self.human_feedback: list[HumanFeedback] = []
        
        self._interaction_counter = 0
        self._session_active = False
    
    def _generate_id(self) -> str:
        """Generate unique interaction ID."""
        self._interaction_counter += 1
        return f"INT-{self._interaction_counter:04d}"
    
    async def start_session(self) -> None:
        """Start interactive session."""
        self._session_active = True
        logger.info("Human-in-the-loop session started")
    
    async def end_session(self) -> dict[str, Any]:
        """End interactive session and return summary."""
        self._session_active = False
        
        summary = {
            "total_interactions": len(self.interaction_history),
            "approved": sum(1 for i in self.interaction_history if i.decision == UserDecision.APPROVE),
            "rejected": sum(1 for i in self.interaction_history if i.decision == UserDecision.REJECT),
            "modified": sum(1 for i in self.interaction_history if i.decision == UserDecision.MODIFY),
            "skipped": sum(1 for i in self.interaction_history if i.decision == UserDecision.SKIP),
            "pending": len(self.pending_interactions),
            "feedback_count": len(self.human_feedback),
        }
        
        logger.info(f"Human-in-the-loop session ended: {summary}")
        return summary
    
    async def request_confirmation(
        self,
        title: str,
        description: str,
        context: dict[str, Any],
        risk_level: str = "MEDIUM",
        payload: str | None = None,
    ) -> tuple[UserDecision, str | None]:
        """
        Request human confirmation for an action.
        
        Returns:
            Tuple of (decision, modified_payload or notes)
        """
        interaction = PendingInteraction(
            id=self._generate_id(),
            interaction_type=InteractionType.CONFIRM_EXPLOIT,
            title=title,
            description=description,
            context=context,
            payload=payload,
            risk_level=risk_level,
        )
        
        # Auto-approve in auto mode for low-risk
        if self.auto_mode and risk_level in ["LOW", "INFO"]:
            interaction.decision = UserDecision.APPROVE
            interaction.decided_at = datetime.now()
            self.interaction_history.append(interaction)
            return UserDecision.APPROVE, None
        
        return await self._wait_for_decision(interaction)
    
    async def request_finding_review(
        self,
        finding: dict[str, Any],
    ) -> HumanFeedback:
        """Request human review of a finding."""
        
        interaction = PendingInteraction(
            id=self._generate_id(),
            interaction_type=InteractionType.REVIEW_FINDING,
            title=f"Review: {finding.get('name', 'Unknown Finding')}",
            description=f"Severity: {finding.get('severity', 'MEDIUM')}\n"
                       f"Location: {finding.get('matched_at', 'Unknown')}\n"
                       f"Evidence: {len(finding.get('evidence', []))} items",
            context={"finding": finding},
            risk_level=finding.get("severity", "MEDIUM"),
        )
        
        decision, notes = await self._wait_for_decision(interaction)
        
        # Convert decision to feedback
        feedback = HumanFeedback(
            finding_id=finding.get("id", self._generate_id()),
            is_valid=decision in [UserDecision.APPROVE, UserDecision.MODIFY],
            notes=notes or "",
        )
        
        self.human_feedback.append(feedback)
        return feedback
    
    async def request_custom_payload(
        self,
        target: str,
        vuln_type: str,
        suggested_payload: str,
        context: dict[str, Any],
    ) -> tuple[UserDecision, str]:
        """Request human to craft or modify a payload."""
        
        interaction = PendingInteraction(
            id=self._generate_id(),
            interaction_type=InteractionType.CUSTOM_PAYLOAD,
            title=f"Payload Crafting: {vuln_type}",
            description=f"Target: {target}\n"
                       f"Vulnerability: {vuln_type}\n"
                       f"Suggested payload provided for review/modification",
            context=context,
            payload=suggested_payload,
            risk_level="HIGH",
        )
        
        decision, modified = await self._wait_for_decision(interaction)
        
        # Return modified payload or original
        final_payload = modified if modified and decision == UserDecision.MODIFY else suggested_payload
        
        return decision, final_payload
    
    async def request_authorization(
        self,
        action: str,
        target: str,
        potential_impact: str,
    ) -> bool:
        """Request authorization before sensitive action."""
        
        interaction = PendingInteraction(
            id=self._generate_id(),
            interaction_type=InteractionType.AUTHORIZATION_CHECK,
            title=f"Authorization Required: {action}",
            description=f"Target: {target}\n"
                       f"Potential Impact: {potential_impact}\n\n"
                       f"This action requires explicit authorization before proceeding.",
            context={
                "action": action,
                "target": target,
                "potential_impact": potential_impact,
            },
            risk_level="CRITICAL",
        )
        
        decision, _ = await self._wait_for_decision(interaction)
        return decision == UserDecision.APPROVE
    
    async def guide_manual_exploitation(
        self,
        vuln_type: str,
        target: str,
        steps: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        """Guide human through manual exploitation steps."""
        
        results = []
        
        for i, step in enumerate(steps, 1):
            interaction = PendingInteraction(
                id=self._generate_id(),
                interaction_type=InteractionType.MANUAL_STEP,
                title=f"Manual Step {i}/{len(steps)}: {step.get('title', 'Action')}",
                description=step.get("description", ""),
                context={
                    "step_number": i,
                    "total_steps": len(steps),
                    "vuln_type": vuln_type,
                    "target": target,
                    "instructions": step.get("instructions", ""),
                    "expected_outcome": step.get("expected_outcome", ""),
                },
                risk_level=step.get("risk_level", "MEDIUM"),
            )
            
            decision, notes = await self._wait_for_decision(interaction)
            
            results.append({
                "step": i,
                "title": step.get("title"),
                "decision": decision.value if decision else "timeout",
                "notes": notes,
                "completed": decision == UserDecision.APPROVE,
            })
            
            # Stop if user aborts
            if decision == UserDecision.ABORT:
                break
        
        return results
    
    async def _wait_for_decision(
        self,
        interaction: PendingInteraction,
    ) -> tuple[UserDecision, str | None]:
        """Wait for human decision on an interaction."""
        
        self.pending_interactions[interaction.id] = interaction
        
        # If callback provided, use it
        if self.callback:
            try:
                decision = await asyncio.wait_for(
                    self.callback(interaction),
                    timeout=interaction.timeout_seconds
                )
                interaction.decision = decision
                interaction.decided_at = datetime.now()
            except asyncio.TimeoutError:
                interaction.decision = UserDecision.SKIP
                interaction.user_notes = "Timeout - auto-skipped"
                interaction.decided_at = datetime.now()
        else:
            # CLI fallback - print and wait
            decision, notes = await self._cli_prompt(interaction)
            interaction.decision = decision
            interaction.user_notes = notes
            interaction.decided_at = datetime.now()
        
        # Move to history
        del self.pending_interactions[interaction.id]
        self.interaction_history.append(interaction)
        
        return interaction.decision, interaction.modified_payload or interaction.user_notes
    
    async def _cli_prompt(
        self,
        interaction: PendingInteraction,
    ) -> tuple[UserDecision, str | None]:
        """CLI prompt for human decision."""
        
        print("\n" + "=" * 60)
        print(f"🔔 HUMAN INPUT REQUIRED [{interaction.id}]")
        print("=" * 60)
        print(f"\nType: {interaction.interaction_type.name}")
        print(f"Risk Level: {interaction.risk_level}")
        print(f"\n📌 {interaction.title}")
        print("-" * 40)
        print(interaction.description)
        
        if interaction.payload:
            print(f"\n📦 Payload:")
            print(f"   {interaction.payload[:200]}{'...' if len(interaction.payload) > 200 else ''}")
        
        if interaction.context:
            print(f"\n📋 Context:")
            for key, value in interaction.context.items():
                if isinstance(value, dict):
                    print(f"   {key}: [complex data]")
                else:
                    print(f"   {key}: {str(value)[:100]}")
        
        print("\n" + "-" * 40)
        print("Options:")
        print("  [A]pprove - Proceed with action")
        print("  [R]eject  - Do not proceed")
        print("  [M]odify  - Modify payload/parameters")
        print("  [S]kip    - Skip this action")
        print("  [X]Abort  - Abort entire operation")
        
        # In real implementation, this would be async input
        # For now, we'll use a simple sync approach
        try:
            choice = input("\nYour choice [A/R/M/S/X]: ").strip().upper()
            
            decision_map = {
                "A": UserDecision.APPROVE,
                "R": UserDecision.REJECT,
                "M": UserDecision.MODIFY,
                "S": UserDecision.SKIP,
                "X": UserDecision.ABORT,
            }
            
            decision = decision_map.get(choice, UserDecision.SKIP)
            notes = None
            
            if decision == UserDecision.MODIFY:
                notes = input("Enter modified payload/notes: ")
                interaction.modified_payload = notes
            elif decision == UserDecision.REJECT:
                notes = input("Reason for rejection (optional): ")
            
            return decision, notes
            
        except (EOFError, KeyboardInterrupt):
            return UserDecision.ABORT, "User interrupted"
    
    def get_session_stats(self) -> dict[str, Any]:
        """Get current session statistics."""
        return {
            "session_active": self._session_active,
            "auto_mode": self.auto_mode,
            "pending_count": len(self.pending_interactions),
            "history_count": len(self.interaction_history),
            "feedback_count": len(self.human_feedback),
            "approval_rate": self._calculate_approval_rate(),
        }
    
    def _calculate_approval_rate(self) -> float:
        """Calculate approval rate from history."""
        if not self.interaction_history:
            return 0.0
        
        approved = sum(
            1 for i in self.interaction_history
            if i.decision in [UserDecision.APPROVE, UserDecision.MODIFY]
        )
        
        return round(approved / len(self.interaction_history) * 100, 1)
    
    def export_session(self) -> dict[str, Any]:
        """Export session data for reporting."""
        return {
            "exported_at": datetime.now().isoformat(),
            "stats": self.get_session_stats(),
            "interactions": [
                {
                    "id": i.id,
                    "type": i.interaction_type.name,
                    "title": i.title,
                    "risk_level": i.risk_level,
                    "decision": i.decision.value if i.decision else None,
                    "created_at": i.created_at.isoformat(),
                    "decided_at": i.decided_at.isoformat() if i.decided_at else None,
                    "notes": i.user_notes,
                }
                for i in self.interaction_history
            ],
            "feedback": [
                {
                    "finding_id": f.finding_id,
                    "is_valid": f.is_valid,
                    "severity_adjustment": f.severity_adjustment,
                    "notes": f.notes,
                }
                for f in self.human_feedback
            ],
        }


# Pre-built exploitation guides
EXPLOITATION_GUIDES = {
    "sql_injection": [
        {
            "title": "Confirm Injection Point",
            "description": "Verify the SQL injection vulnerability exists",
            "instructions": "1. Insert a single quote (') in the parameter\n"
                          "2. Observe error message or behavior change\n"
                          "3. Try boolean-based payloads: ' OR '1'='1",
            "expected_outcome": "Database error or altered behavior",
            "risk_level": "MEDIUM",
        },
        {
            "title": "Identify Database Type",
            "description": "Determine the backend database system",
            "instructions": "1. Try version functions:\n"
                          "   - MySQL: @@version\n"
                          "   - PostgreSQL: version()\n"
                          "   - MSSQL: @@version\n"
                          "   - Oracle: banner from v$version",
            "expected_outcome": "Database version information",
            "risk_level": "MEDIUM",
        },
        {
            "title": "Enumerate Tables",
            "description": "List database tables (with authorization)",
            "instructions": "Use UNION-based or error-based techniques:\n"
                          "1. Determine column count with ORDER BY\n"
                          "2. Find displayable columns\n"
                          "3. Query information_schema.tables",
            "expected_outcome": "List of table names",
            "risk_level": "HIGH",
        },
        {
            "title": "Extract Sample Data",
            "description": "Extract minimal data to prove impact",
            "instructions": "Extract only what's needed to demonstrate risk:\n"
                          "1. Select single row from target table\n"
                          "2. Document evidence\n"
                          "3. DO NOT extract bulk data",
            "expected_outcome": "Proof of data access capability",
            "risk_level": "CRITICAL",
        },
    ],
    "xss": [
        {
            "title": "Confirm XSS Vector",
            "description": "Verify cross-site scripting is possible",
            "instructions": "1. Inject benign alert payload: <script>alert(1)</script>\n"
                          "2. Try various contexts (HTML, attribute, JS)\n"
                          "3. Test for filter bypasses if needed",
            "expected_outcome": "JavaScript execution in browser",
            "risk_level": "MEDIUM",
        },
        {
            "title": "Demonstrate Cookie Access",
            "description": "Show that session cookies could be stolen",
            "instructions": "1. Create payload that reads document.cookie\n"
                          "2. Display in alert or controlled endpoint\n"
                          "3. DO NOT send to external server",
            "expected_outcome": "Cookie value displayed",
            "risk_level": "HIGH",
        },
        {
            "title": "Document Persistence",
            "description": "Check if XSS is stored/persistent",
            "instructions": "1. Submit payload that persists\n"
                          "2. Verify it executes for other sessions\n"
                          "3. Document scope of impact",
            "expected_outcome": "Confirmation of stored vs reflected",
            "risk_level": "HIGH",
        },
    ],
    "authentication_bypass": [
        {
            "title": "Test Default Credentials",
            "description": "Check for default or common credentials",
            "instructions": "Test common combinations:\n"
                          "- admin:admin, admin:password\n"
                          "- root:root, test:test\n"
                          "- Review product documentation for defaults",
            "expected_outcome": "Successful authentication",
            "risk_level": "MEDIUM",
        },
        {
            "title": "Test Authentication Logic",
            "description": "Probe for logic flaws",
            "instructions": "1. Test parameter manipulation\n"
                          "2. Try SQL injection in login\n"
                          "3. Check for response manipulation\n"
                          "4. Test 2FA bypass if present",
            "expected_outcome": "Unauthorized access achieved",
            "risk_level": "HIGH",
        },
    ],
}
