"""
Scanning module initialization v2.0.0 - INTELLIGENT SCANNING EDITION.

Exports:
- VulnerabilityScanner: Base scanner
- FullScanner: 39+ modules with intelligent infrastructure
- IntelligentScanner: Intelligent scanning orchestrator
- ScannerGroup: Scanner grouping abstraction
"""

from scanning.vuln_scanner import VulnerabilityScanner
from scanning.full_scanner import FullScanner, ScanResult, SCANNER_VERSION
from scanning.intelligent_scanner import (
    IntelligentScanner,
    IntelligentScanConfig,
    IntelligentScanContext,
    ScopeViolationError,
    create_intelligent_context,
)
from scanning.scanner_group import (
    ScannerGroup,
    GroupExecutionMode,
    GroupResult,
    InjectionScannerGroup,
    AuthScannerGroup,
    APIScannerGroup,
    AccessControlScannerGroup,
    InfrastructureScannerGroup,
    BusinessLogicScannerGroup,
    AdvancedScannerGroup,
    get_scanner_group,
)
from scanning.module_registry import (
    ModuleRegistry,
    ModuleCategory,
    ModulePriority,
    ModuleInfo,
    get_module_registry,
)

__all__ = [
    # Core scanners
    "VulnerabilityScanner",
    "FullScanner",
    "ScanResult",
    "SCANNER_VERSION",
    # Intelligent scanning
    "IntelligentScanner",
    "IntelligentScanConfig",
    "IntelligentScanContext",
    "ScopeViolationError",
    "create_intelligent_context",
    # Scanner groups
    "ScannerGroup",
    "GroupExecutionMode",
    "GroupResult",
    "InjectionScannerGroup",
    "AuthScannerGroup",
    "APIScannerGroup",
    "AccessControlScannerGroup",
    "InfrastructureScannerGroup",
    "BusinessLogicScannerGroup",
    "AdvancedScannerGroup",
    "get_scanner_group",
    # Module registry
    "ModuleRegistry",
    "ModuleCategory",
    "ModulePriority",
    "ModuleInfo",
    "get_module_registry",
]
