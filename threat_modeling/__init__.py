"""
Threat Modeling Module - Automatic threat analysis using STRIDE methodology.

This module provides:
- Automatic STRIDE threat mapping
- Abuse case generation per endpoint
- Attack surface analysis
- Data flow diagram generation
- Security control recommendations
"""

from threat_modeling.stride_analyzer import (
    STRIDECategory,
    Threat,
    AbuseCaseSeverity,
    AbuseCase,
    STRIDEAnalyzer,
)

from threat_modeling.threat_modeler import (
    ThreatModeler,
    ThreatModel,
    DataFlow,
    TrustBoundary,
)

from threat_modeling.abuse_case_generator import (
    AbuseCaseGenerator,
    EndpointAnalysis,
)

__all__ = [
    # STRIDE Analyzer
    "STRIDECategory",
    "Threat",
    "AbuseCaseSeverity",
    "AbuseCase",
    "STRIDEAnalyzer",
    
    # Threat Modeler
    "ThreatModeler",
    "ThreatModel",
    "DataFlow",
    "TrustBoundary",
    
    # Abuse Case Generator
    "AbuseCaseGenerator",
    "EndpointAnalysis",
]
