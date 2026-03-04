"""
Module Executor - Module Execution Infrastructure.

This module provides infrastructure for executing scanner modules:
- Module interface categorization
- Single module execution (runner)
- Concurrent module orchestration

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from scanning.module_executor.interfaces import (
    # Enum
    ModuleInterface,
    # Module sets
    OLD_3ARG_MODULES,
    STRING_ENDPOINTS_MODULES,
    TYPED_ENDPOINTS_MODULES,
    TWO_ARG_MODULES,
    PORT_PARAMS_MODULES,
    SIMPLE_INTERFACE_MODULES,
    HEAVY_MODULES,
    # Functions
    get_module_interface,
    is_heavy_module,
    is_signature_mismatch,
)

from scanning.module_executor.runner import (
    # Config
    RunnerConfig,
    RunContext,
    # Main class
    ModuleRunner,
    # Convenience function
    run_module,
)

from scanning.module_executor.orchestrator import (
    # Config
    OrchestratorConfig,
    CircuitBreakerState,
    ModuleResult,
    # Classes
    CircuitBreaker,
    ModuleOrchestrator,
    # Convenience function
    execute_modules,
)

__all__ = [
    # Interfaces
    "ModuleInterface",
    "OLD_3ARG_MODULES",
    "STRING_ENDPOINTS_MODULES",
    "TYPED_ENDPOINTS_MODULES",
    "TWO_ARG_MODULES",
    "PORT_PARAMS_MODULES",
    "SIMPLE_INTERFACE_MODULES",
    "HEAVY_MODULES",
    "get_module_interface",
    "is_heavy_module",
    "is_signature_mismatch",
    # Runner
    "RunnerConfig",
    "RunContext",
    "ModuleRunner",
    "run_module",
    # Orchestrator
    "OrchestratorConfig",
    "CircuitBreakerState",
    "ModuleResult",
    "CircuitBreaker",
    "ModuleOrchestrator",
    "execute_modules",
]
