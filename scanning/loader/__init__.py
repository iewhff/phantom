"""
Scanner Module Loader.

Provides dynamic loading of scanner modules with:
- ModuleRegistry integration
- Safety level checking
- Caching for performance
- Cleanup management
- **Phase 8: Dependency Injection support** (2026-02-26)

Extracted from full_scanner.py for modularization.
"""

from .loader import (
    ModuleLoader,
    ModuleLoadResult,
    LoadStatus,
    # Phase 8: DI helpers
    DI_PARAMETER_MAP,
    get_di_parameters,
)

__all__ = [
    "ModuleLoader",
    "ModuleLoadResult",
    "LoadStatus",
    # Phase 8: DI support
    "DI_PARAMETER_MAP",
    "get_di_parameters",
]
