"""
Business Logic Scanner - Vulnerability Categories.

This package contains category-based implementations for business logic testing:
- base.py: BusinessCategory Protocol and CategoryContext
- financial_edge_cases.py: Price manipulation, negative values, overflow
- race_conditions.py: Concurrent request testing, double-spend
- workflow_bypass.py: State machine bypass, multi-step transaction abuse
- idor_testing.py: Account enumeration, response fingerprinting
- idempotency_abuse.py: Replay attacks, time-based bypass
- inventory_manipulation.py: Stock manipulation, limit bypass

Each category implements the BusinessCategory Protocol and can be tested independently.

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from scanning.modules.business_logic.categories.base import (
    BusinessCategory,
    BaseBusinessCategory,
    CategoryContext,
    CategoryResult,
)
from scanning.modules.business_logic.categories.financial_edge_cases import FinancialEdgeCasesCategory
from scanning.modules.business_logic.categories.race_conditions import RaceConditionsCategory
from scanning.modules.business_logic.categories.workflow_bypass import WorkflowBypassCategory
from scanning.modules.business_logic.categories.idor_testing import IDORTestingCategory
from scanning.modules.business_logic.categories.idempotency_abuse import IdempotencyAbuseCategory
from scanning.modules.business_logic.categories.inventory_manipulation import InventoryManipulationCategory

__all__ = [
    # Base types
    "BusinessCategory",
    "BaseBusinessCategory",
    "CategoryContext",
    "CategoryResult",
    # Categories
    "FinancialEdgeCasesCategory",
    "RaceConditionsCategory",
    "WorkflowBypassCategory",
    "IDORTestingCategory",
    "IdempotencyAbuseCategory",
    "InventoryManipulationCategory",
]
