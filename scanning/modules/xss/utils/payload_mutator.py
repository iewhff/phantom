"""
XSS Scanner - Payload Mutator.

Provides intelligent payload mutation for WAF bypass and coverage.
Integrates with WAFBypassEngine for sophisticated behavioural bypass.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)

# WAF Bypass Engine integration
_WAF_BYPASS_ENGINE_AVAILABLE = True
try:
    from phantom.waf_bypass_engine import (
        WAFDetectionResult, get_waf_bypass_engine_sync,
    )
except ImportError:
    _WAF_BYPASS_ENGINE_AVAILABLE = False
    WAFDetectionResult = None  # type: ignore


class PayloadMutator:
    """Mutate XSS payloads to bypass filters.

    2026-02-20: Enhanced with WAFBypassEngine integration.
    When a WAFDetectionResult is provided, uses sophisticated behavioural bypass
    strategies from phantom/waf_bypass_engine.py for better evasion.
    """

    @staticmethod
    def mutate(
        payload: str,
        mutation_level: int = 3,
        waf_detection: Any = None,  # WAFDetectionResult
    ) -> list[str]:
        """Generate payload mutations.

        Args:
            payload: Original XSS payload
            mutation_level: Mutation complexity (1-3)
            waf_detection: Full WAFDetectionResult from WAFBypassEngine (optional)

        Returns:
            List of mutated payloads for WAF bypass
        """
        mutations = [payload]  # Original

        # Use WAFBypassEngine if available
        if _WAF_BYPASS_ENGINE_AVAILABLE and waf_detection is not None and waf_detection.detected:
            try:
                bypass_mutations = PayloadMutator._apply_waf_bypass_engine(payload, waf_detection)
                if bypass_mutations:
                    mutations.extend(bypass_mutations)
                    logger.debug(
                        f"[XSS] WAFBypassEngine generated {len(bypass_mutations)} bypass variants "
                        f"for {waf_detection.waf_name}"
                    )
            except Exception as e:
                logger.debug(f"[XSS] WAFBypassEngine mutation failed: {e}")

        if mutation_level >= 1:
            # Case variations
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(PayloadMutator._random_case(payload))

            # URL encoding
            mutations.append(quote(payload))
            mutations.append(quote(payload, safe=''))

        if mutation_level >= 2:
            # Double encoding
            mutations.append(quote(quote(payload)))

            # HTML entities
            mutations.append(PayloadMutator._html_encode(payload))
            mutations.append(PayloadMutator._html_encode_decimal(payload))
            mutations.append(PayloadMutator._html_encode_hex(payload))

            # Unicode
            mutations.append(PayloadMutator._unicode_encode(payload))

        if mutation_level >= 3:
            # Whitespace variations
            mutations.append(payload.replace(" ", "\t"))
            mutations.append(payload.replace(" ", "\n"))
            mutations.append(payload.replace(" ", "\x0c"))
            mutations.append(payload.replace(" ", "/"))

            # Comment insertion
            mutations.append(PayloadMutator._insert_comments(payload))

            # Null bytes
            mutations.append(payload.replace("<", "<\x00"))
            mutations.append(payload.replace(">", ">\x00"))

            # Tag breaking
            mutations.append(payload.replace("<script", "<scr\x00ipt"))
            mutations.append(payload.replace("<script", "<scr\tipt"))

        return list(set(mutations))

    @staticmethod
    def _random_case(s: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def _html_encode(s: str) -> str:
        return ''.join(f"&#{ord(c)};" for c in s)

    @staticmethod
    def _html_encode_decimal(s: str) -> str:
        return ''.join(f"&#{ord(c)};" if c in '<>"\'/()=' else c for c in s)

    @staticmethod
    def _html_encode_hex(s: str) -> str:
        return ''.join(f"&#x{ord(c):x};" for c in s)

    @staticmethod
    def _unicode_encode(s: str) -> str:
        result = ""
        for c in s:
            if c in '<>"\'/()=':
                result += f"\\u{ord(c):04x}"
            else:
                result += c
        return result

    @staticmethod
    def _insert_comments(payload: str) -> str:
        """Insert HTML comments to break filters."""
        result = payload
        for tag in ["script", "img", "svg", "body", "iframe"]:
            result = result.replace(f"<{tag}", f"<{tag}<!---->")
        return result

    @staticmethod
    def _apply_waf_bypass_engine(
        payload: str,
        waf_detection: Any,  # WAFDetectionResult
    ) -> list[str]:
        """Apply WAFBypassEngine bypass strategies to XSS payload."""
        if not _WAF_BYPASS_ENGINE_AVAILABLE:
            return []

        try:
            engine = get_waf_bypass_engine_sync()

            # Generate bypass variants using the engine
            variants = engine.generate_bypass_variants(
                payload=payload,
                detection=waf_detection,
                context="xss",
                max_variants=8,
            )

            # Extract just the payloads
            bypassed_payloads = [v[0] for v in variants if v[0] != payload]

            return bypassed_payloads

        except Exception as e:
            logger.debug(f"[XSS] WAFBypassEngine error: {e}")
            return []


__all__ = ["PayloadMutator"]
