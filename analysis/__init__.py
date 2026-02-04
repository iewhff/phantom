"""
Analysis Module - Attack Chain Analysis and Visualization.

This module provides:
- Attack chain detection and analysis
- Visual representation of attack paths
- Business impact assessment
- Executive reporting
- Interactive dashboards
- Advanced graph visualizations
"""

from analysis.attack_chain_engine import (
    AttackPhase,
    ImpactType,
    ChainNode,
    AttackChain,
    AttackChainEngine,
)

from analysis.chain_visualizer import ChainVisualizer

from analysis.chain_dashboard import AttackChainDashboard

from analysis.chain_integration import AttackChainIntegration

from analysis.chain_graph_generator import ChainGraphGenerator

__all__ = [
    # Core Engine
    "AttackPhase",
    "ImpactType",
    "ChainNode",
    "AttackChain",
    "AttackChainEngine",
    
    # Visualizer
    "ChainVisualizer",
    
    # Dashboard
    "AttackChainDashboard",
    
    # Integration
    "AttackChainIntegration",
    
    # Graph Generator
    "ChainGraphGenerator",
]
