"""
Asset Builder - Asset Data Construction for Scanner Modules.

This module provides infrastructure for building asset_data dictionaries
passed to scanner modules, including:
- Endpoint aggregation from multiple sources
- Parameter extraction from intelligent context
- Technology detection
- Context integration (auth, forms, etc.)

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

from scanning.asset_builder.builder import (
    # Config
    AssetBuilderConfig,
    # Data
    AssetData,
    # Main class
    AssetDataBuilder,
    # Functions
    extract_parameters_from_analysis,
    build_asset_data,
    create_builder,
    build_asset_data_from_scanner,
)

__all__ = [
    # Config
    "AssetBuilderConfig",
    # Data
    "AssetData",
    # Main class
    "AssetDataBuilder",
    # Functions
    "extract_parameters_from_analysis",
    "build_asset_data",
    "create_builder",
    "build_asset_data_from_scanner",
]
