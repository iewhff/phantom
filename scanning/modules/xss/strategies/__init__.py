"""
XSS Scanner - Detection Strategies.

This package contains the Strategy Pattern implementations for XSS detection:
- base.py: XSSStrategy Protocol and XSSStrategyContext
- url_param.py: URL parameter testing
- form_test.py: Form field testing
- header_test.py: HTTP header injection
- json_body.py: JSON body testing
- template_injection.py: SSTI detection
- stored_xss.py: Stored XSS testing
- second_order.py: Second-order XSS detection

Each strategy implements the XSSStrategy Protocol and can be tested independently.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from scanning.modules.xss.strategies.base import (
    XSSStrategy,
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)
from scanning.modules.xss.strategies.url_param import URLParamStrategy
from scanning.modules.xss.strategies.form_test import FormTestStrategy
from scanning.modules.xss.strategies.header_test import HeaderTestStrategy
from scanning.modules.xss.strategies.json_body import JSONBodyStrategy
from scanning.modules.xss.strategies.template_injection import TemplateInjectionStrategy
from scanning.modules.xss.strategies.stored_xss import StoredXSSStrategy
from scanning.modules.xss.strategies.second_order import SecondOrderStrategy

__all__ = [
    # Base types
    "XSSStrategy",
    "BaseXSSStrategy",
    "XSSStrategyContext",
    "XSSStrategyResult",
    # Strategies
    "URLParamStrategy",
    "FormTestStrategy",
    "HeaderTestStrategy",
    "JSONBodyStrategy",
    "TemplateInjectionStrategy",
    "StoredXSSStrategy",
    "SecondOrderStrategy",
]
