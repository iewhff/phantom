"""
SQL Injection Scanner - Utilities.

Contains helper classes:
- database_fingerprinter.py: Database type and version detection
- payload_mutator.py: WAF bypass payload mutation
- response_analysis.py: Anomaly detection and response analysis
"""

from __future__ import annotations

from scanning.modules.sqli.utils.database_fingerprinter import DatabaseFingerprinter
from scanning.modules.sqli.utils.payload_mutator import PayloadMutator
from scanning.modules.sqli.utils.response_analysis import AnomalyDetector

__all__ = [
    "DatabaseFingerprinter",
    "PayloadMutator",
    "AnomalyDetector",
]
