"""
Analysis Module - Attack Chain Analysis and Visualization.

This module provides:
- Attack chain detection and analysis (AttackChainEngine)
- Visual representation of attack paths (ChainVisualizer, AttackChainDashboard)
- Neural attack planning (NeuralAttackPlanner)
- Vulnerability chain exploitation LOW->HIGH (VulnChainEngine)
"""

from analysis.attack_chain_engine import (
    AttackPhase,
    ImpactType,
    ChainNode,
    AttackChain,
    AttackChainEngine,
)

from analysis.chain_rendering import (
    ChainVisualizer,
    AttackChainDashboard,
    SEVERITY_COLORS,
    PHASE_ICONS,
)

from analysis.neural_attack_planner import NeuralAttackPlanner
from analysis.vuln_chain_engine import VulnChainEngine

__all__ = [
    # Core Engine
    "AttackPhase",
    "ImpactType",
    "ChainNode",
    "AttackChain",
    "AttackChainEngine",

    # Rendering
    "ChainVisualizer",
    "AttackChainDashboard",
    "SEVERITY_COLORS",
    "PHASE_ICONS",

    # Neural Planner
    "NeuralAttackPlanner",

    # Vuln Chain Engine (LOW->HIGH)
    "VulnChainEngine",
]
