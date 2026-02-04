"""
Scanner Helper Utilities

Consolidated helper classes used across multiple scanning modules:
- WAFType: Enum for Web Application Firewall types
- WAFDetector: Detect and identify WAF presence
- PayloadMutator: Generate payload variations for bypass
- ResponseFingerprint: Fingerprint HTTP responses for comparison

This module eliminates code duplication across sqli_scanner, xss_scanner,
lfi_scanner, ssrf_scanner, cmdi_scanner, xxe_scanner, and nosql_scanner.

Author: PetNTester AI Enterprise
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# WAF TYPE ENUM
# =============================================================================

class WAFType(Enum):
    """Web Application Firewall types."""
    NONE = auto()
    UNKNOWN = auto()
    CLOUDFLARE = auto()
    AWS_WAF = auto()
    AKAMAI = auto()
    IMPERVA = auto()
    MODSECURITY = auto()
    F5_BIG_IP = auto()
    FORTINET = auto()
    SUCURI = auto()
    WORDFENCE = auto()
    BARRACUDA = auto()
    AZURE_WAF = auto()
    GOOGLE_CLOUD_ARMOR = auto()
    NGINX = auto()
    APACHE = auto()


# =============================================================================
# WAF DETECTOR
# =============================================================================

class WAFDetector:
    """
    Detect and identify Web Application Firewalls.

    Combines signatures from multiple scanner implementations for
    comprehensive WAF detection including header, cookie, and body analysis.
    """

    # WAF signatures: (pattern, location) where location is 'header', 'cookie', 'body', or 'server'
    SIGNATURES: dict[WAFType, list[tuple[str, str]]] = {
        WAFType.CLOUDFLARE: [
            (r'cloudflare', 'body'),
            (r'cloudflare', 'server'),
            (r'cf-ray', 'header'),
            (r'cf-cache-status', 'header'),
            (r'__cfduid', 'cookie'),
            (r'cf_', 'cookie'),
            (r'cloudflare-nginx', 'server'),
        ],
        WAFType.AWS_WAF: [
            (r'awswaf', 'header'),
            (r'x-amzn-requestid', 'header'),
            (r'x-amz-cf-id', 'header'),
            (r'x-amz-apigw-id', 'header'),
        ],
        WAFType.AKAMAI: [
            (r'akamai', 'body'),
            (r'akamai', 'server'),
            (r'akamai-ghost', 'server'),
            (r'ak_bmsc', 'cookie'),
            (r'x-akamai', 'header'),
            (r'akamai-origin-hop', 'header'),
        ],
        WAFType.IMPERVA: [
            (r'imperva', 'body'),
            (r'incapsula', 'body'),
            (r'visid_incap', 'cookie'),
            (r'incap_ses', 'cookie'),
            (r'x-iinfo', 'header'),
            (r'x-cdn.*imperva', 'header'),
        ],
        WAFType.MODSECURITY: [
            (r'mod_security', 'body'),
            (r'modsecurity', 'body'),
            (r'mod_security', 'server'),
            (r'noyb', 'header'),
            (r'x-mod-sec-rule', 'header'),
        ],
        WAFType.F5_BIG_IP: [
            (r'bigipserver', 'cookie'),
            (r'bigip', 'server'),
            (r'f5', 'body'),
            (r'ts[a-z0-9]+', 'cookie'),
            (r'x-wa-info', 'header'),
        ],
        WAFType.FORTINET: [
            (r'fortigate', 'body'),
            (r'fortiwaf', 'body'),
            (r'fortiweb', 'server'),
        ],
        WAFType.SUCURI: [
            (r'sucuri', 'body'),
            (r'sucuri', 'server'),
            (r'x-sucuri', 'header'),
            (r'x-sucuri-id', 'header'),
            (r'x-sucuri-cache', 'header'),
        ],
        WAFType.WORDFENCE: [
            (r'wordfence', 'body'),
            (r'wfwaf', 'body'),
            (r'x-wordfence', 'header'),
            (r'wordfence_', 'cookie'),
        ],
        WAFType.BARRACUDA: [
            (r'barracuda', 'server'),
            (r'barra_counter_session', 'cookie'),
        ],
        WAFType.AZURE_WAF: [
            (r'x-azure-ref', 'header'),
            (r'x-ms-request-id', 'header'),
        ],
        WAFType.GOOGLE_CLOUD_ARMOR: [
            (r'x-goog-', 'header'),
            (r'x-cloud-trace-context', 'header'),
        ],
    }

    # Patterns indicating request was blocked
    BLOCK_PATTERNS: list[str] = [
        r'blocked',
        r'forbidden',
        r'access.denied',
        r'request.blocked',
        r'security.violation',
        r'malicious',
        r'attack.detected',
        r'suspicious.activity',
        r'waf.block',
        r'web.application.firewall',
        r'your.ip.has.been.blocked',
        r'firewall',
    ]

    @classmethod
    def detect(cls, response: httpx.Response) -> tuple[WAFType, bool]:
        """
        Detect WAF type and if request was blocked.

        Args:
            response: HTTP response to analyze

        Returns:
            Tuple of (waf_type, is_blocked)
        """
        content = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        cookies = response.headers.get('set-cookie', '').lower()
        server = headers.get('server', '')

        # Check for block indicators
        is_blocked = response.status_code == 403
        if not is_blocked:
            is_blocked = any(re.search(p, content) for p in cls.BLOCK_PATTERNS)

        # Detect WAF type
        for waf_type, signatures in cls.SIGNATURES.items():
            for pattern, location in signatures:
                try:
                    if location == 'body' and re.search(pattern, content):
                        logger.debug(f"WAF detected: {waf_type.name} via body pattern '{pattern}'")
                        return waf_type, is_blocked
                    elif location == 'header' and any(re.search(pattern, h) for h in headers):
                        logger.debug(f"WAF detected: {waf_type.name} via header pattern '{pattern}'")
                        return waf_type, is_blocked
                    elif location == 'cookie' and re.search(pattern, cookies):
                        logger.debug(f"WAF detected: {waf_type.name} via cookie pattern '{pattern}'")
                        return waf_type, is_blocked
                    elif location == 'server' and re.search(pattern, server):
                        logger.debug(f"WAF detected: {waf_type.name} via server pattern '{pattern}'")
                        return waf_type, is_blocked
                except re.error as e:
                    logger.warning(f"Invalid WAF pattern '{pattern}': {e}")

        if is_blocked:
            return WAFType.UNKNOWN, True

        return WAFType.NONE, False

    @classmethod
    def get_bypass_headers(cls, waf_type: WAFType) -> dict[str, str]:
        """Get headers that may help bypass specific WAF types."""
        common_headers = {
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
        }

        waf_specific = {
            WAFType.CLOUDFLARE: {"CF-Connecting-IP": "127.0.0.1"},
            WAFType.AWS_WAF: {"X-Amzn-Trace-Id": "Root=1-0-0"},
            WAFType.AKAMAI: {"True-Client-IP": "127.0.0.1"},
        }

        return {**common_headers, **waf_specific.get(waf_type, {})}


# =============================================================================
# PAYLOAD MUTATOR
# =============================================================================

class PayloadMutator:
    """
    Generate payload variations to bypass WAF and filters.

    Supports multiple encoding and obfuscation techniques:
    - Case variation
    - URL encoding
    - Double URL encoding
    - HTML entity encoding
    - Comment insertion
    - Whitespace obfuscation
    - Unicode normalization bypass
    """

    @staticmethod
    def mutate(payload: str, max_mutations: int = 10) -> list[str]:
        """
        Generate multiple mutations of a payload.

        Args:
            payload: Original payload to mutate
            max_mutations: Maximum number of mutations to generate

        Returns:
            List of mutated payloads (including original)
        """
        mutations = [payload]

        # Case mutations
        mutations.append(payload.upper())
        mutations.append(payload.lower())
        mutations.append(PayloadMutator._random_case(payload))

        # Encoding mutations
        mutations.append(PayloadMutator._url_encode(payload))
        mutations.append(PayloadMutator._double_url_encode(payload))
        mutations.append(PayloadMutator._html_encode(payload))

        # Obfuscation mutations
        mutations.append(PayloadMutator._insert_comments(payload))
        mutations.append(PayloadMutator._whitespace_obfuscate(payload))
        mutations.append(PayloadMutator._unicode_normalize(payload))

        # Remove duplicates and limit
        unique_mutations = list(dict.fromkeys(mutations))
        return unique_mutations[:max_mutations]

    @staticmethod
    def _random_case(payload: str) -> str:
        """Apply random case to each character."""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )

    @staticmethod
    def _url_encode(payload: str) -> str:
        """URL encode special characters."""
        encoded = ""
        for c in payload:
            if c.isalnum():
                encoded += c
            else:
                encoded += f"%{ord(c):02X}"
        return encoded

    @staticmethod
    def _double_url_encode(payload: str) -> str:
        """Double URL encode special characters."""
        encoded = ""
        for c in payload:
            if c.isalnum():
                encoded += c
            else:
                # %XX becomes %25XX
                encoded += f"%25{ord(c):02X}"
        return encoded

    @staticmethod
    def _html_encode(payload: str) -> str:
        """HTML entity encode special characters."""
        # Must replace & first to avoid double-encoding
        result = payload.replace('&', '&amp;')
        result = result.replace('<', '&lt;')
        result = result.replace('>', '&gt;')
        result = result.replace('"', '&quot;')
        result = result.replace("'", '&#39;')
        return result

    @staticmethod
    def _insert_comments(payload: str) -> str:
        """Insert SQL/HTML comments to break up keywords."""
        # SQL comment insertion
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        for keyword in keywords:
            if keyword.upper() in result.upper():
                # Insert /**/ in the middle
                mid = len(keyword) // 2
                replacement = keyword[:mid] + "/**/" + keyword[mid:]
                result = re.sub(keyword, replacement, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def _whitespace_obfuscate(payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        alternatives = ['\t', '\n', '\r', '%09', '%0a', '%0d', '+', '/**/']
        return payload.replace(' ', random.choice(alternatives))

    @staticmethod
    def _unicode_normalize(payload: str) -> str:
        """Use Unicode homoglyphs for bypass."""
        homoglyphs = {
            'a': 'а',  # Cyrillic
            'e': 'е',
            'o': 'о',
            'p': 'р',
            'c': 'с',
            'x': 'х',
        }
        result = ""
        for c in payload:
            if c.lower() in homoglyphs and random.random() > 0.7:
                result += homoglyphs[c.lower()]
            else:
                result += c
        return result


# =============================================================================
# RESPONSE FINGERPRINT
# =============================================================================

@dataclass
class ResponseFingerprint:
    """
    Fingerprint an HTTP response for comparison.

    Used to detect differences between normal and injected responses
    to identify potential vulnerabilities.
    """
    status_code: int
    content_length: int
    content_hash: str
    word_count: int
    line_count: int
    title: str
    has_error: bool
    error_keywords: list[str]

    @classmethod
    def from_response(cls, response: httpx.Response) -> "ResponseFingerprint":
        """Create fingerprint from HTTP response."""
        content = response.text

        # Extract title
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else ""

        # Check for error keywords
        error_keywords_found = []
        error_patterns = [
            r'error', r'exception', r'warning', r'fatal',
            r'syntax', r'undefined', r'null', r'invalid',
            r'denied', r'forbidden', r'not found',
        ]
        for pattern in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                error_keywords_found.append(pattern)

        return cls(
            status_code=response.status_code,
            content_length=len(content),
            content_hash=hashlib.md5(content.encode()).hexdigest(),
            word_count=len(content.split()),
            line_count=content.count('\n'),
            title=title,
            has_error=bool(error_keywords_found),
            error_keywords=error_keywords_found,
        )

    def similarity_score(self, other: "ResponseFingerprint") -> float:
        """
        Calculate similarity score with another fingerprint.

        Returns:
            Float between 0.0 (completely different) and 1.0 (identical)
        """
        if self.content_hash == other.content_hash:
            return 1.0

        score = 0.0

        # Status code match
        if self.status_code == other.status_code:
            score += 0.2

        # Content length similarity
        if self.content_length > 0 and other.content_length > 0:
            ratio = min(self.content_length, other.content_length) / max(self.content_length, other.content_length)
            score += 0.3 * ratio

        # Word count similarity
        if self.word_count > 0 and other.word_count > 0:
            ratio = min(self.word_count, other.word_count) / max(self.word_count, other.word_count)
            score += 0.2 * ratio

        # Title match
        if self.title == other.title:
            score += 0.15

        # Error state match
        if self.has_error == other.has_error:
            score += 0.15

        return min(score, 1.0)

    def is_significantly_different(self, other: "ResponseFingerprint", threshold: float = 0.7) -> bool:
        """Check if two fingerprints are significantly different."""
        return self.similarity_score(other) < threshold


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness/unpredictability.
    """
    if not data:
        return 0.0

    from math import log2

    # Count character frequencies
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        entropy -= probability * log2(probability)

    return entropy


def is_dynamic_content(response1: httpx.Response, response2: httpx.Response) -> bool:
    """
    Check if content between two responses is dynamic.

    Useful for detecting if differences are due to injection
    or just dynamic page content (timestamps, tokens, etc.)
    """
    fp1 = ResponseFingerprint.from_response(response1)
    fp2 = ResponseFingerprint.from_response(response2)

    # If content hash is different but structure is similar, it's dynamic
    if fp1.content_hash != fp2.content_hash:
        # Check if word count and line count are similar
        word_diff = abs(fp1.word_count - fp2.word_count) / max(fp1.word_count, 1)
        line_diff = abs(fp1.line_count - fp2.line_count) / max(fp1.line_count, 1)

        if word_diff < 0.1 and line_diff < 0.1:
            return True

    return False
