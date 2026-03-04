"""
XSS Scanner - Utilities.

Contains helper classes:
- payload_mutator.py: WAF bypass payload mutation
- csp_analyzer.py: Content-Security-Policy analysis
"""

from __future__ import annotations

from scanning.modules.xss.utils.payload_mutator import PayloadMutator
from scanning.modules.xss.utils.csp_analyzer import CSPAnalyzer

__all__ = [
    "PayloadMutator",
    "CSPAnalyzer",
]
