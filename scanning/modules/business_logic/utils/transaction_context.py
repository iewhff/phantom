"""
Business Logic Scanner - Transaction Context Management.

Manages transaction state for multi-step business logic testing.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from utils.logger import get_logger

from scanning.modules.business_logic.business_base import (
    TransactionContext,
    WorkflowState,
    VALID_TRANSITIONS,
)

logger = get_logger(__name__)


def create_transaction_context(
    session_id: str = "",
    user_id: str = "",
) -> TransactionContext:
    """Create a new transaction context with optional initial values."""
    return TransactionContext(
        session_id=session_id or hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
        user_id=user_id,
    )


class TransactionManager:
    """Manages multiple transaction contexts for parallel testing."""

    def __init__(self) -> None:
        self._contexts: dict[str, TransactionContext] = {}
        self._active_context: str = ""

    def create_context(self, name: str, **kwargs: Any) -> TransactionContext:
        """Create and register a new transaction context."""
        ctx = create_transaction_context(**kwargs)
        self._contexts[name] = ctx
        if not self._active_context:
            self._active_context = name
        return ctx

    def get_context(self, name: str) -> TransactionContext | None:
        """Get a transaction context by name."""
        return self._contexts.get(name)

    def get_active_context(self) -> TransactionContext | None:
        """Get the currently active transaction context."""
        return self._contexts.get(self._active_context)

    def set_active(self, name: str) -> bool:
        """Set the active transaction context."""
        if name in self._contexts:
            self._active_context = name
            return True
        return False

    def transition(
        self,
        name: str,
        new_state: WorkflowState,
    ) -> tuple[bool, bool]:
        """Attempt a state transition.

        Returns:
            Tuple of (transition_succeeded, was_valid_transition)
        """
        ctx = self._contexts.get(name)
        if not ctx:
            return False, False

        was_valid = ctx.transition_to(new_state)
        return True, was_valid

    def detect_bypass_attempt(self, name: str) -> list[tuple[WorkflowState, WorkflowState]]:
        """Detect any invalid state transitions (potential bypass attempts)."""
        ctx = self._contexts.get(name)
        if not ctx:
            return []

        invalid_transitions = []
        for from_state, to_state in ctx.state_history:
            valid_next = VALID_TRANSITIONS.get(from_state, [])
            if to_state not in valid_next:
                invalid_transitions.append((from_state, to_state))

        return invalid_transitions

    def store_financial_value(
        self,
        name: str,
        key: str,
        value: float,
    ) -> None:
        """Store a financial value in the transaction context."""
        ctx = self._contexts.get(name)
        if ctx:
            ctx.financial_values[key] = value

    def detect_value_manipulation(
        self,
        name: str,
        key: str,
        current_value: float,
    ) -> tuple[bool, float]:
        """Detect if a financial value has been manipulated.

        Returns:
            Tuple of (was_manipulated, original_value)
        """
        ctx = self._contexts.get(name)
        if not ctx or key not in ctx.financial_values:
            return False, current_value

        original = ctx.financial_values[key]
        # Consider manipulation if value changed by more than 1%
        # or if signs differ (positive → negative)
        if original != 0:
            change_pct = abs(current_value - original) / abs(original)
            sign_changed = (original > 0) != (current_value > 0)
            manipulated = change_pct > 0.01 or sign_changed
        else:
            manipulated = current_value != 0

        return manipulated, original

    def get_all_contexts(self) -> dict[str, TransactionContext]:
        """Get all transaction contexts."""
        return dict(self._contexts)

    def clear(self) -> None:
        """Clear all transaction contexts."""
        self._contexts.clear()
        self._active_context = ""


__all__ = ["TransactionManager", "create_transaction_context"]
