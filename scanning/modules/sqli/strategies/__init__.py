"""
SQL Injection Scanner - Injection Strategies.

This package contains the Strategy Pattern implementations for SQLi detection:
- base.py: InjectionStrategy Protocol and StrategyContext
- error_based.py: ErrorBasedStrategy
- boolean_blind.py: BooleanBlindStrategy
- time_blind.py: TimeBlindStrategy
- union_based.py: UnionBasedStrategy
- stacked_queries.py: StackedQueriesStrategy
- out_of_band.py: OutOfBandStrategy

Each strategy implements the InjectionStrategy Protocol and can be tested independently.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from scanning.modules.sqli.strategies.base import (
    InjectionStrategy,
    BaseStrategy,
    StrategyContext,
    StrategyResult,
)
from scanning.modules.sqli.strategies.error_based import ErrorBasedStrategy
from scanning.modules.sqli.strategies.boolean_blind import BooleanBlindStrategy
from scanning.modules.sqli.strategies.time_blind import TimeBlindStrategy
from scanning.modules.sqli.strategies.union_based import UnionBasedStrategy
from scanning.modules.sqli.strategies.stacked_queries import StackedQueriesStrategy
from scanning.modules.sqli.strategies.out_of_band import OutOfBandStrategy

__all__ = [
    # Base types
    "InjectionStrategy",
    "BaseStrategy",
    "StrategyContext",
    "StrategyResult",
    # Strategies
    "ErrorBasedStrategy",
    "BooleanBlindStrategy",
    "TimeBlindStrategy",
    "UnionBasedStrategy",
    "StackedQueriesStrategy",
    "OutOfBandStrategy",
]
