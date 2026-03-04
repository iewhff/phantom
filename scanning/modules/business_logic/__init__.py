"""
Business Logic Scanner - Refactored Module.

This package contains the modular business logic scanner with:
- business_base.py: Enums, dataclasses, constants, priority tiers
- orchestrator.py: Main scanner orchestrator
- categories/: Vulnerability category implementations
- utils/: Helper classes (anomaly detector, transaction context)

Extracted from business_logic_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from scanning.modules.business_logic.business_base import (
    # Version
    BUSINESS_LOGIC_SCANNER_VERSION,
    # Safety
    SAFE_MODE,
    ALLOW_WRITES,
    ALLOW_DESTRUCTIVE,
    # Priority
    BUSINESS_LOGIC_PRIORITY,
    get_business_priority,
    # Workflow
    WorkflowState,
    VALID_TRANSITIONS,
    # Dataclasses
    TransactionContext,
    RaceConditionResult,
    FinancialTestCase,
    BusinessFlow,
    ResponseBehavior,
    AnomalyResult,
    # Test cases
    FINANCIAL_TEST_CASES,
    RACE_CONDITION_SCENARIOS,
    FINANCIAL_RACE_PAYLOADS,
)

# Orchestrator
from scanning.modules.business_logic.orchestrator import (
    BusinessLogicOrchestrator,
    OrchestratorConfig,
    ScanResult,
)

__all__ = [
    # Version
    "BUSINESS_LOGIC_SCANNER_VERSION",
    # Safety
    "SAFE_MODE",
    "ALLOW_WRITES",
    "ALLOW_DESTRUCTIVE",
    # Priority
    "BUSINESS_LOGIC_PRIORITY",
    "get_business_priority",
    # Workflow
    "WorkflowState",
    "VALID_TRANSITIONS",
    # Dataclasses
    "TransactionContext",
    "RaceConditionResult",
    "FinancialTestCase",
    "BusinessFlow",
    "ResponseBehavior",
    "AnomalyResult",
    # Orchestrator
    "BusinessLogicOrchestrator",
    "OrchestratorConfig",
    "ScanResult",
    # Test cases
    "FINANCIAL_TEST_CASES",
    "RACE_CONDITION_SCENARIOS",
    "FINANCIAL_RACE_PAYLOADS",
]
