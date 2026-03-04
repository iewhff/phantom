"""
Orchestrator Module - Scan Execution Coordination.

Provides components for coordinating module execution:
- CircuitBreakerManager: Rate limiting protection
- ExecutionConfig: Timeout and concurrency settings
- Module categorization utilities

Extracted from full_scanner.py for modularization.
"""

from .circuit_breaker import (
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitBreakerManager,
    get_circuit_breaker_manager,
    reset_circuit_breaker_manager,
)
from .execution import (
    TimeoutConfig,
    JitterConfig,
    ConcurrencyConfig,
    ExecutionConfig,
    HEAVY_MODULES,
    BROWSER_MODULES,
    STATEFUL_MODULES,
    EXTERNAL_MODULES,
    is_heavy_module,
    is_browser_module,
    is_stateful_module,
    is_external_module,
)

__all__ = [
    # Circuit Breaker
    "CircuitBreakerConfig",
    "CircuitBreakerState",
    "CircuitBreakerManager",
    "get_circuit_breaker_manager",
    "reset_circuit_breaker_manager",
    # Execution Config
    "TimeoutConfig",
    "JitterConfig",
    "ConcurrencyConfig",
    "ExecutionConfig",
    # Module Categories
    "HEAVY_MODULES",
    "BROWSER_MODULES",
    "STATEFUL_MODULES",
    "EXTERNAL_MODULES",
    "is_heavy_module",
    "is_browser_module",
    "is_stateful_module",
    "is_external_module",
]
