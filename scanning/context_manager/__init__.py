"""
Context Manager - Context Coordination for Scans.

This module provides coordination between different context types:
- AuthContext (authentication state)
- IntelligentContext (intelligent scanning context)
- ScanContext (pipeline context)

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from scanning.context_manager.coordinator import (
    # Protocols
    AuthContextProtocol,
    IntelligentContextProtocol,
    # Data classes
    ContextState,
    # Main class
    ContextCoordinator,
    # Factory functions
    create_coordinator,
    build_minimal_asset_data,
)

__all__ = [
    # Protocols
    "AuthContextProtocol",
    "IntelligentContextProtocol",
    # Data classes
    "ContextState",
    # Main class
    "ContextCoordinator",
    # Factory functions
    "create_coordinator",
    "build_minimal_asset_data",
]
