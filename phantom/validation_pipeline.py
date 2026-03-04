"""
PHANTOM AI - 6-Stage Validation Pipeline

Backward-compatibility shim. Real implementation in phantom.validation.
"""

from phantom.validation import *  # noqa: F401,F403
from phantom.validation.models import __all__ as _models_all  # noqa: F401
