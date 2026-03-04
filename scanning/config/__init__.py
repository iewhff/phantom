"""
Scanner Configuration Module.

Centralized configuration for the scanning system:
- Module definitions and mappings
- Safety levels and hierarchy
- Module categories and presets

Extracted from full_scanner.py for modularization.
"""

from .modules import (
    ALL_MODULES,
    SHORT_TO_REGISTRY_NAME,
    get_module_path,
    get_registry_name,
)
from .safety import (
    SAFETY_HIERARCHY,
    MODULE_SAFETY_LEVELS,
    get_module_safety_level,
    is_safe_for_mode,
)
from .categories import (
    CATEGORIES,
    get_category_modules,
    get_all_category_names,
)
from .signatures import (
    STRING_ENDPOINTS_MODULES,
    TYPED_ENDPOINTS_MODULES,
    TWO_ARG_MODULES,
    SIMPLE_INTERFACE_MODULES,
    PORT_PARAMS_MODULES,
    OLD_3ARG_MODULES,
    get_module_signature_type,
)

__all__ = [
    # Modules
    "ALL_MODULES",
    "SHORT_TO_REGISTRY_NAME",
    "get_module_path",
    "get_registry_name",
    # Safety
    "SAFETY_HIERARCHY",
    "MODULE_SAFETY_LEVELS",
    "get_module_safety_level",
    "is_safe_for_mode",
    # Categories
    "CATEGORIES",
    "get_category_modules",
    "get_all_category_names",
    # Signatures
    "STRING_ENDPOINTS_MODULES",
    "TYPED_ENDPOINTS_MODULES",
    "TWO_ARG_MODULES",
    "SIMPLE_INTERFACE_MODULES",
    "PORT_PARAMS_MODULES",
    "OLD_3ARG_MODULES",
    "get_module_signature_type",
]
